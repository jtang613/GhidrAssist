package ghidrassist.services;

import ghidrassist.AnalysisDB;
import ghidrassist.GhidrAssistPlugin;
import ghidrassist.LlmApi;
import ghidrassist.apiprovider.APIProviderConfig;
import ghidrassist.apiprovider.ChatMessage;
import ghidrassist.chat.PersistedChatMessage;
import ghidrassist.chat.message.MessageRepository;
import ghidrassist.chat.message.MessageStore;
import ghidrassist.chat.message.ThreadSafeMessageStore;
import ghidrassist.chat.persistence.ChatHistoryDAO;
import ghidrassist.chat.persistence.SqliteTransactionManager;
import ghidrassist.chat.persistence.TransactionManager;
import ghidrassist.chat.session.ChatSession;
import ghidrassist.chat.session.ChatSessionManager;
import ghidrassist.chat.session.ChatSessionRepository;
import ghidrassist.chat.util.RoleNormalizer;
import ghidrassist.core.QueryProcessor;
import ghidrassist.mcp2.tools.MCPToolManager;
import ghidrassist.tools.native_.NativeToolManager;
import ghidrassist.tools.registry.ToolRegistry;
import ghidrassist.graphrag.GraphRAGService;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Service for handling custom queries and conversations.
 * Responsible for processing user queries, RAG integration, and conversation management.
 *
 * Refactored to use:
 * - MessageStore for thread-safe in-memory message storage (eliminates dual storage)
 * - ChatSessionManager for thread-safe session lifecycle
 * - ChatHistoryDAO for database operations
 * - RoleNormalizer for consistent role handling
 */
public class QueryService {

    private final GhidrAssistPlugin plugin;
    private final AnalysisDB analysisDB;  // Keep for ReAct and backward compatibility
    private final AnalysisDataService analysisDataService;
    private final ToolRegistry toolRegistry;

    // New architecture components
    private final MessageStore messageStore;
    private final ChatSessionManager sessionManager;
    private final MessageRepository messageRepository;
    private final ChatSessionRepository sessionRepository;

    public QueryService(GhidrAssistPlugin plugin) {
        this.plugin = plugin;
        this.analysisDB = new AnalysisDB();
        this.analysisDataService = new AnalysisDataService(plugin);

        // Initialize tool registry with native tools
        this.toolRegistry = new ToolRegistry();
        try {
            NativeToolManager nativeManager = new NativeToolManager(analysisDB);
            toolRegistry.registerProvider(nativeManager);
        } catch (Exception e) {
            ghidra.util.Msg.warn(this, "Failed to initialize native tools: " + e.getMessage());
        }

        // Initialize new architecture components
        TransactionManager transactionManager = new SqliteTransactionManager(analysisDB.getConnection());
        ChatHistoryDAO dao = new ChatHistoryDAO(transactionManager);

        this.messageStore = new ThreadSafeMessageStore();
        this.messageRepository = dao;
        this.sessionRepository = dao;
        this.sessionManager = new ChatSessionManager(sessionRepository, messageRepository, messageStore);
    }

    // ==================== Query Request Creation ====================

    /**
     * Process a user query with optional RAG context (backwards compatibility)
     */
    public QueryRequest createQueryRequest(String query, boolean useRAG) throws Exception {
        return createQueryRequest(query, useRAG, false);
    }

    /**
     * Process a user query with optional RAG context and MCP integration
     */
    public QueryRequest createQueryRequest(String query, boolean useRAG, boolean useMCP) throws Exception {
        String processedQuery = QueryProcessor.processMacrosInQuery(query, plugin);

        if (useRAG) {
            try {
                processedQuery = QueryProcessor.appendRAGContext(processedQuery);
            } catch (Exception e) {
                throw new Exception("Failed to perform RAG search: " + e.getMessage(), e);
            }
        }

        // Add user message to message store and database
        addUserMessage(processedQuery, messageStore.getCurrentProviderType(), null);

        return new QueryRequest(processedQuery, messageStore.getFormattedConversation(), useMCP);
    }

    // ==================== Query Execution ====================

    /**
     * Execute a query request
     */
    public void executeQuery(QueryRequest request, LlmApi.LlmResponseHandler handler) throws Exception {
        APIProviderConfig config = GhidrAssistPlugin.getCurrentProviderConfig();
        if (config == null) {
            throw new Exception("No API provider configured.");
        }

        LlmApi llmApi = new LlmApi(config, plugin);

        // Apply saved reasoning config to the LlmApi
        ghidra.program.model.listing.Program currentProgram = plugin.getCurrentProgram();
        if (currentProgram != null) {
            String programHash = currentProgram.getExecutableSHA256();
            String savedEffort = analysisDB.getReasoningEffort(programHash);
            if (savedEffort != null && !savedEffort.equalsIgnoreCase("none")) {
                ghidrassist.apiprovider.ReasoningConfig reasoningConfig =
                        ghidrassist.apiprovider.ReasoningConfig.fromString(savedEffort);
                llmApi.setReasoningConfig(reasoningConfig);
            }
        }

        // Initialize GraphRAGService with LLM provider for background semantic analysis
        initializeGraphRAGService(config);

        executeQuery(request, llmApi, handler);
    }

    /**
     * Initialize GraphRAGService with LLM provider and current program context.
     * This enables background semantic analysis when queries trigger on-demand indexing.
     */
    private void initializeGraphRAGService(APIProviderConfig config) {
        try {
            GraphRAGService graphRAG = GraphRAGService.getInstance(analysisDB);

            // Set LLM provider for background semantic analysis
            if (config != null) {
                ghidrassist.apiprovider.APIProvider provider = config.createProvider();

                // Apply saved reasoning config to the new provider
                ghidra.program.model.listing.Program currentProgram = plugin.getCurrentProgram();
                if (currentProgram != null) {
                    String programHash = currentProgram.getExecutableSHA256();
                    String savedEffort = analysisDB.getReasoningEffort(programHash);
                    if (savedEffort != null && !savedEffort.equalsIgnoreCase("none")) {
                        ghidrassist.apiprovider.ReasoningConfig reasoningConfig =
                                ghidrassist.apiprovider.ReasoningConfig.fromString(savedEffort);
                        provider.setReasoningConfig(reasoningConfig);
                    }
                }

                graphRAG.setLLMProvider(provider);
            }

            // Set current program context
            ghidra.program.model.listing.Program currentProgram = plugin.getCurrentProgram();
            if (currentProgram != null) {
                graphRAG.setCurrentProgram(currentProgram);
            }
        } catch (Exception e) {
            ghidra.util.Msg.warn(this, "Failed to initialize GraphRAGService: " + e.getMessage());
        }
    }

    /**
     * Execute a query request with provided LlmApi instance
     */
    public void executeQuery(QueryRequest request, LlmApi llmApi, LlmApi.LlmResponseHandler handler) throws Exception {
        if (request.shouldUseMCP()) {
            try {
                MCPToolManager toolManager = MCPToolManager.getInstance();

                if (!toolManager.isInitialized()) {
                    toolManager.initializeServers()
                        .thenRun(() -> {
                            try {
                                executeMCPQuery(request, llmApi, toolManager, handler);
                            } catch (Exception e) {
                                ghidra.util.Msg.warn(this, "MCP query execution failed: " + e.getMessage());
                                try {
                                    executeRegularQuery(request, llmApi, handler);
                                } catch (Exception e2) {
                                    ghidra.util.Msg.error(this, "Failed to execute regular query: " + e2.getMessage());
                                    handler.onError(e2);
                                }
                            }
                        })
                        .exceptionally(throwable -> {
                            ghidra.util.Msg.warn(this, "MCP initialization failed: " + throwable.getMessage());
                            try {
                                executeRegularQuery(request, llmApi, handler);
                            } catch (Exception e) {
                                handler.onError(e);
                            }
                            return null;
                        });
                    return;
                } else {
                    try {
                        executeMCPQuery(request, llmApi, toolManager, handler);
                        return;
                    } catch (Exception e) {
                        ghidra.util.Msg.warn(this, "MCP query failed, falling back: " + e.getMessage());
                    }
                }
            } catch (Exception e) {
                ghidra.util.Msg.warn(this, "MCP initialization failed: " + e.getMessage());
            }
        }

        // MCP is disabled, but native tools (semantics, etc.) should still be available
        executeNativeToolQuery(request, llmApi, handler);
    }

    /**
     * Execute a query with native tools only (no MCP tools).
     * Native tools include semantics analysis, knowledge graph queries, etc.
     */
    private void executeNativeToolQuery(QueryRequest request, LlmApi llmApi,
                                         LlmApi.LlmResponseHandler handler) throws Exception {
        // Set full context (program + address) for native tool providers
        ghidra.program.model.listing.Program currentProgram = plugin.getCurrentProgram();
        ghidra.program.model.address.Address currentAddress = plugin.getCurrentAddress();
        if (currentProgram != null) {
            toolRegistry.setFullContext(currentProgram, currentAddress);
        }

        // Get native tools only (MCP tools won't be registered since MCP is disabled)
        java.util.List<java.util.Map<String, Object>> nativeFunctions = toolRegistry.getToolsAsFunction();

        ghidra.util.Msg.info(this, "Native tool registry has " + nativeFunctions.size() + " tools available");

        if (!nativeFunctions.isEmpty()) {
            int maxToolRounds = analysisDataService.getMaxToolCalls();

            // Get existing history with thinking data preserved for multi-turn conversations
            List<ChatMessage> fullHistory = messageStore.getMessagesForApi();
            List<ChatMessage> existingHistory;

            if (fullHistory == null || fullHistory.size() <= 1) {
                existingHistory = new ArrayList<>();
            } else {
                existingHistory = new ArrayList<>(fullHistory.subList(0, fullHistory.size() - 1));
            }

            // Use history-aware method to preserve thinking data across turns
            llmApi.sendConversationalToolRequestWithHistory(
                existingHistory,
                request.getProcessedQuery(),
                nativeFunctions,
                handler,
                maxToolRounds,
                toolRegistry
            );
        } else {
            // No native tools available, fall back to regular query
            executeRegularQuery(request, llmApi, handler);
        }
    }

    private void executeMCPQuery(QueryRequest request, LlmApi llmApi, MCPToolManager toolManager,
                                  LlmApi.LlmResponseHandler handler) throws Exception {
        // Register MCP tool manager with the tool registry (if not already registered)
        // This ensures both native and MCP tools are available
        if (!toolRegistry.hasProvider(toolManager.getProviderName())) {
            toolRegistry.registerProvider(toolManager);
        }

        // Set full context (program + address) for all tool providers
        ghidra.program.model.listing.Program currentProgram = plugin.getCurrentProgram();
        ghidra.program.model.address.Address currentAddress = plugin.getCurrentAddress();
        if (currentProgram != null) {
            toolRegistry.setFullContext(currentProgram, currentAddress);
        }

        // Get ALL tools from registry (includes native tools + MCP tools)
        java.util.List<java.util.Map<String, Object>> allFunctions = toolRegistry.getToolsAsFunction();

        ghidra.util.Msg.info(this, "Tool registry has " + allFunctions.size() + " tools available");

        if (!allFunctions.isEmpty()) {
            int maxToolRounds = analysisDataService.getMaxToolCalls();

            // Get existing history with thinking data preserved for multi-turn conversations
            // The current user message is already in the store, so get all PREVIOUS messages
            List<ChatMessage> fullHistory = messageStore.getMessagesForApi();
            List<ChatMessage> existingHistory;

            if (fullHistory == null || fullHistory.size() <= 1) {
                // No previous history or only the current user message - start fresh
                existingHistory = new ArrayList<>();
            } else {
                // Get all messages except the last one (current user message)
                // This preserves thinking data from previous assistant responses
                existingHistory = new ArrayList<>(fullHistory.subList(0, fullHistory.size() - 1));
            }

            // Use history-aware method to preserve thinking data across turns
            llmApi.sendConversationalToolRequestWithHistory(
                existingHistory,
                request.getProcessedQuery(),
                allFunctions,
                handler,
                maxToolRounds,
                toolRegistry
            );
        } else {
            executeRegularQuery(request, llmApi, handler);
        }
    }

    private void executeRegularQuery(QueryRequest request, LlmApi llmApi,
                                      LlmApi.LlmResponseHandler handler) throws Exception {
        llmApi.sendRequestAsync(request.getFullConversation(), handler);
    }

    // ==================== Message Management ====================

    /**
     * Add user query to conversation (legacy method)
     */
    public void addUserQuery(String query) {
        addUserMessage(query, messageStore.getCurrentProviderType(), null);
    }

    /**
     * Add user message with provider info
     */
    public void addUserMessage(String query, String providerType, ChatMessage apiMessage) {
        messageStore.addUserMessage(query, providerType, apiMessage);

        // Ensure session exists and save to database
        String programHash = getProgramHash();
        if (programHash != null) {
            int sessionId = sessionManager.ensureSession(programHash);
            if (sessionId != ChatSessionManager.NO_SESSION) {
                PersistedChatMessage msg = getLastMessage();
                if (msg != null) {
                    messageRepository.saveMessage(programHash, sessionId, msg);
                }
            }
        }
    }

    /**
     * Add assistant response (legacy method)
     */
    public void addAssistantResponse(String response) {
        addAssistantMessage(response, messageStore.getCurrentProviderType(), null);
    }

    /**
     * Add assistant message with provider info
     */
    public void addAssistantMessage(String response, String providerType, ChatMessage apiMessage) {
        messageStore.addAssistantMessage(response, providerType, apiMessage);

        // Save to database
        String programHash = getProgramHash();
        int sessionId = sessionManager.getCurrentSessionId();
        if (programHash != null && sessionId != ChatSessionManager.NO_SESSION) {
            PersistedChatMessage msg = getLastMessage();
            if (msg != null) {
                messageRepository.saveMessage(programHash, sessionId, msg);
            }
        }
    }

    /**
     * Add tool call message
     */
    public void addToolCallMessage(String toolName, String args, String result) {
        messageStore.addToolCallMessage(toolName, args, result);

        // Save to database
        String programHash = getProgramHash();
        int sessionId = sessionManager.getCurrentSessionId();
        if (programHash != null && sessionId != ChatSessionManager.NO_SESSION) {
            PersistedChatMessage msg = getLastMessage();
            if (msg != null) {
                messageRepository.saveMessage(programHash, sessionId, msg);
            }
        }
    }

    /**
     * Add error message
     */
    public void addError(String errorMessage) {
        messageStore.addErrorMessage(errorMessage);

        // Save to database
        String programHash = getProgramHash();
        int sessionId = sessionManager.getCurrentSessionId();
        if (programHash != null && sessionId != ChatSessionManager.NO_SESSION) {
            PersistedChatMessage msg = getLastMessage();
            if (msg != null) {
                messageRepository.saveMessage(programHash, sessionId, msg);
            }
        }
    }

    // ==================== Conversation Access ====================

    /**
     * Get current conversation history
     */
    public String getConversationHistory() {
        return messageStore.getFormattedConversation();
    }

    /**
     * Clear conversation history
     */
    public void clearConversationHistory() {
        messageStore.clear();
    }

    /**
     * Get the list of persisted messages
     */
    public List<PersistedChatMessage> getMessages() {
        return messageStore.getMessages();
    }

    /**
     * Set the message list (used when loading or after editing)
     */
    public void setMessages(List<PersistedChatMessage> messages) {
        messageStore.setMessages(messages);
    }

    /**
     * Replace all messages in both memory and database.
     * Used for edit operations where the entire conversation is rebuilt.
     *
     * @param messages The new message list
     * @return true if successful
     */
    public boolean replaceAllMessages(List<PersistedChatMessage> messages) {
        String programHash = getProgramHash();
        int sessionId = sessionManager.getCurrentSessionId();

        if (programHash == null || sessionId == ChatSessionManager.NO_SESSION) {
            return false;
        }

        // Update in-memory state
        messageStore.setMessages(messages);

        // Persist to database atomically
        return messageRepository.replaceAllMessages(programHash, sessionId, messages);
    }

    /**
     * Get current provider type
     */
    public String getCurrentProviderType() {
        return messageStore.getCurrentProviderType();
    }

    /**
     * Set current provider type
     */
    public void setCurrentProviderType(String providerType) {
        messageStore.setCurrentProviderType(providerType);
    }

    // ==================== Session Management ====================

    /**
     * Create a new chat session
     */
    public int createNewChatSession() {
        String programHash = getProgramHash();
        if (programHash == null) {
            return -1;
        }
        return sessionManager.createNewSession(programHash);
    }

    /**
     * Get all chat sessions for current program
     */
    public java.util.List<AnalysisDB.ChatSession> getChatSessions() {
        String programHash = getProgramHash();
        if (programHash == null) {
            return new java.util.ArrayList<>();
        }

        // Convert new ChatSession to legacy format for backward compatibility
        List<ChatSession> sessions = sessionManager.getSessions(programHash);
        java.util.List<AnalysisDB.ChatSession> legacySessions = new java.util.ArrayList<>();
        for (ChatSession session : sessions) {
            legacySessions.add(new AnalysisDB.ChatSession(
                session.getId(),
                session.getDescription(),
                session.getLastUpdate()
            ));
        }
        return legacySessions;
    }

    /**
     * Switch to a specific chat session
     */
    public boolean switchToChatSession(int sessionId) {
        String programHash = getProgramHash();
        if (programHash == null) {
            return false;
        }

        // Check if this is a ReAct session (needs special handling)
        if (analysisDB.isReActSession(sessionId)) {
            return switchToReActSession(programHash, sessionId);
        }

        return sessionManager.switchToSession(programHash, sessionId);
    }

    private boolean switchToReActSession(String programHash, int sessionId) {
        java.util.List<ghidrassist.apiprovider.ChatMessage> messages =
            analysisDB.getReActMessages(programHash, sessionId);

        if (messages != null && !messages.isEmpty()) {
            messageStore.clear();

            // Format and set as single message for display
            String formattedConversation = formatReActConversation(messages, sessionId);
            PersistedChatMessage displayMsg = new PersistedChatMessage(
                null, "assistant", formattedConversation,
                new Timestamp(System.currentTimeMillis()), 0
            );
            List<PersistedChatMessage> displayList = new ArrayList<>();
            displayList.add(displayMsg);
            messageStore.setMessages(displayList);

            // Update session manager's current session
            // (ReAct sessions bypass normal session switching)
            return true;
        }
        return false;
    }

    /**
     * Delete current chat session
     */
    public boolean deleteCurrentSession() {
        return sessionManager.deleteCurrentSession();
    }

    /**
     * Delete a specific chat session by ID
     */
    public boolean deleteSession(int sessionId) {
        return sessionManager.deleteSession(sessionId);
    }

    /**
     * Update chat session description
     */
    public void updateChatDescription(int sessionId, String description) {
        sessionManager.updateSessionDescription(sessionId, description);
    }

    /**
     * Get current session ID
     */
    public int getCurrentSessionId() {
        return sessionManager.getCurrentSessionId();
    }

    /**
     * Ensure session exists
     */
    public void ensureSession() {
        String programHash = getProgramHash();
        if (programHash != null && !messageStore.isEmpty()) {
            sessionManager.ensureSession(programHash);
        }
    }

    // ==================== Migration Support ====================

    /**
     * Check if current session has been migrated to per-message storage
     */
    public boolean isMigrated() {
        int sessionId = sessionManager.getCurrentSessionId();
        if (sessionId == ChatSessionManager.NO_SESSION) {
            return false;
        }
        String programHash = getProgramHash();
        return programHash != null && messageRepository.hasMessages(programHash, sessionId);
    }

    /**
     * Migrate legacy conversation blob to per-message storage
     */
    public List<PersistedChatMessage> migrateFromLegacyBlob(String conversation) {
        List<PersistedChatMessage> messages = new ArrayList<>();
        if (conversation == null || conversation.isEmpty()) {
            return messages;
        }

        Pattern pattern = Pattern.compile(
            "\\*\\*(User|Assistant|Error|Tool Call)\\*\\*:\\s*\\n(.*?)(?=\\*\\*(User|Assistant|Error|Tool Call)\\*\\*:|$)",
            Pattern.DOTALL
        );

        Matcher matcher = pattern.matcher(conversation);
        int order = 0;
        while (matcher.find()) {
            String role = RoleNormalizer.normalize(matcher.group(1));
            String content = matcher.group(2).trim();

            PersistedChatMessage msg = new PersistedChatMessage(
                null, role, content,
                new Timestamp(System.currentTimeMillis()),
                order++
            );
            msg.setProviderType("migrated");
            msg.setMessageType("standard");
            msg.setNativeMessageData("{}");
            messages.add(msg);
        }

        return messages;
    }

    /**
     * Load messages from database for current session
     */
    public void loadMessagesFromDatabase() {
        int sessionId = sessionManager.getCurrentSessionId();
        if (sessionId == ChatSessionManager.NO_SESSION) {
            return;
        }
        String programHash = getProgramHash();
        if (programHash == null) {
            return;
        }

        List<PersistedChatMessage> dbMessages = messageRepository.loadMessages(programHash, sessionId);
        if (!dbMessages.isEmpty()) {
            messageStore.setMessages(dbMessages);
        } else {
            // Fall back to legacy blob and migrate
            String conversation = sessionRepository.getLegacyConversation(sessionId);
            if (conversation != null && !conversation.isEmpty()) {
                List<PersistedChatMessage> migrated = migrateFromLegacyBlob(conversation);
                messageStore.setMessages(migrated);

                // Save migrated messages
                for (PersistedChatMessage msg : migrated) {
                    messageRepository.saveMessage(programHash, sessionId, msg);
                }
            }
        }
    }

    // ==================== ReAct Support ====================

    /**
     * Save ReAct analysis to database with full investigation history.
     */
    public void saveReActAnalysis(String userQuery, String investigationHistory, String finalResult) {
        ensureSession();

        int sessionId = sessionManager.getCurrentSessionId();
        if (sessionId == ChatSessionManager.NO_SESSION || plugin.getCurrentProgram() == null) {
            return;
        }

        String programHash = plugin.getCurrentProgram().getExecutableSHA256();

        int existingMessageCount = analysisDB.getReActMessages(programHash, sessionId).size();
        int messageOrder = existingMessageCount;
        int iterationNumber = analysisDB.getMaxReActIteration(programHash, sessionId) + 1;

        // Save user query
        ghidrassist.apiprovider.ChatMessage userMsg =
            new ghidrassist.apiprovider.ChatMessage("user", userQuery);
        analysisDB.saveReActMessage(programHash, sessionId, messageOrder++,
            "planning", null, userMsg);

        // Save investigation history
        if (investigationHistory != null && !investigationHistory.isEmpty()) {
            ghidrassist.apiprovider.ChatMessage investigationMsg =
                new ghidrassist.apiprovider.ChatMessage("assistant", investigationHistory);
            analysisDB.saveReActMessage(programHash, sessionId, messageOrder++,
                "investigation", iterationNumber, investigationMsg);

            analysisDB.saveReActIterationChunk(programHash, sessionId, iterationNumber,
                investigationHistory, messageOrder - 1, messageOrder - 1);
        }

        // Save final synthesis
        ghidrassist.apiprovider.ChatMessage finalMsg =
            new ghidrassist.apiprovider.ChatMessage("assistant", finalResult);
        analysisDB.saveReActMessage(programHash, sessionId, messageOrder++,
            "synthesis", null, finalMsg);
    }

    private String formatReActConversation(java.util.List<ghidrassist.apiprovider.ChatMessage> messages,
                                            int sessionId) {
        StringBuilder conversation = new StringBuilder();
        String userQuery = null;
        String investigationHistory = null;
        String finalSynthesis = null;

        for (ghidrassist.apiprovider.ChatMessage msg : messages) {
            if ("user".equals(msg.getRole())) {
                userQuery = msg.getContent();
            } else if ("assistant".equals(msg.getRole())) {
                if (msg.getContent() != null) {
                    if (investigationHistory == null ||
                        msg.getContent().length() > investigationHistory.length()) {
                        if (investigationHistory != null) {
                            finalSynthesis = investigationHistory;
                        }
                        investigationHistory = msg.getContent();
                    } else {
                        finalSynthesis = msg.getContent();
                    }
                }
            }
        }

        if (userQuery != null) {
            conversation.append("**User**: ").append(userQuery).append("\n\n");
        }
        if (investigationHistory != null) {
            conversation.append(investigationHistory);
            if (finalSynthesis != null && !investigationHistory.contains("# Final")) {
                conversation.append("\n\n---\n\n");
            }
        }
        if (finalSynthesis != null) {
            if (!finalSynthesis.trim().startsWith("#")) {
                conversation.append("# Final Analysis\n\n");
            }
            conversation.append(finalSynthesis).append("\n\n");
        }

        return conversation.toString();
    }

    // ==================== Utility Methods ====================

    private String getProgramHash() {
        if (plugin.getCurrentProgram() != null) {
            return plugin.getCurrentProgram().getExecutableSHA256();
        }
        return null;
    }

    private PersistedChatMessage getLastMessage() {
        List<PersistedChatMessage> messages = messageStore.getMessages();
        if (!messages.isEmpty()) {
            return messages.get(messages.size() - 1);
        }
        return null;
    }

    /**
     * Get the AnalysisDB instance (for backward compatibility)
     */
    public AnalysisDB getAnalysisDB() {
        return analysisDB;
    }

    // ==================== Query Request ====================

    /**
     * Request object for query operations
     */
    public static class QueryRequest {
        private final String processedQuery;
        private final String fullConversation;
        private final boolean useMCP;

        public QueryRequest(String processedQuery, String fullConversation, boolean useMCP) {
            this.processedQuery = processedQuery;
            this.fullConversation = fullConversation;
            this.useMCP = useMCP;
        }

        public String getProcessedQuery() { return processedQuery; }
        public String getFullConversation() { return fullConversation; }
        public boolean shouldUseMCP() { return useMCP; }
    }
}
