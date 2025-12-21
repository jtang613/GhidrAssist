package ghidrassist.services;

import ghidrassist.AnalysisDB;
import ghidrassist.GhidrAssistPlugin;
import ghidrassist.LlmApi;
import ghidrassist.apiprovider.APIProviderConfig;
import ghidrassist.apiprovider.ChatMessage;
import ghidrassist.chat.PersistedChatMessage;
import ghidrassist.core.QueryProcessor;
import ghidrassist.mcp2.tools.MCPToolManager;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Service for handling custom queries and conversations.
 * Responsible for processing user queries, RAG integration, and conversation management.
 */
public class QueryService {
    
    private final GhidrAssistPlugin plugin;
    private final StringBuilder conversationHistory;
    private final AnalysisDB analysisDB;
    private int currentSessionId = -1;
    private List<PersistedChatMessage> messageList = new ArrayList<>();
    private String currentProviderType = "unknown";
    
    public QueryService(GhidrAssistPlugin plugin) {
        this.plugin = plugin;
        this.conversationHistory = new StringBuilder();
        this.analysisDB = new AnalysisDB();
    }
    
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
        
        // Add to conversation history
        conversationHistory.append("**User**:\n").append(processedQuery).append("\n\n");
        
        // Ensure we have a session for this conversation
        ensureSession();
        
        return new QueryRequest(processedQuery, conversationHistory.toString(), useMCP);
    }
    
    /**
     * Execute a query request
     */
    public void executeQuery(QueryRequest request, LlmApi.LlmResponseHandler handler) throws Exception {
        APIProviderConfig config = GhidrAssistPlugin.getCurrentProviderConfig();
        if (config == null) {
            throw new Exception("No API provider configured.");
        }
        
        LlmApi llmApi = new LlmApi(config, plugin);
        executeQuery(request, llmApi, handler);
    }
    
    /**
     * Execute a query request with provided LlmApi instance
     */
    public void executeQuery(QueryRequest request, LlmApi llmApi, LlmApi.LlmResponseHandler handler) throws Exception {
        // Use conversational tool calling with MCP tools if MCP is enabled and available
        if (request.shouldUseMCP()) {
            try {
                MCPToolManager toolManager = MCPToolManager.getInstance();
                
                // Initialize servers asynchronously if not already done
                if (!toolManager.isInitialized()) {
                    // Start initialization in background and handle result asynchronously
                    toolManager.initializeServers()
                        .thenRun(() -> {
                            // Once initialized, execute the query with MCP tools
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
                            ghidra.util.Msg.warn(this, "MCP initialization failed, falling back to regular query: " + throwable.getMessage());
                            try {
                                executeRegularQuery(request, llmApi, handler);
                            } catch (Exception e) {
                                ghidra.util.Msg.error(this, "Failed to execute regular query: " + e.getMessage());
                                handler.onError(e);
                            }
                            return null;
                        });
                    return; // Exit early, will continue asynchronously
                } else {
                    // Already initialized, execute immediately
                    try {
                        executeMCPQuery(request, llmApi, toolManager, handler);
                        return;
                    } catch (Exception e) {
                        ghidra.util.Msg.warn(this, "MCP query execution failed, falling back to regular query: " + e.getMessage());
                    }
                }
            } catch (Exception e) {
                ghidra.util.Msg.warn(this, "MCP initialization failed, falling back to regular query: " + e.getMessage());
            }
        }
        
        // Fall back to regular query execution
        executeRegularQuery(request, llmApi, handler);
    }
    
    /**
     * Execute MCP-enabled query with conversational tool calling
     */
    private void executeMCPQuery(QueryRequest request, LlmApi llmApi, MCPToolManager toolManager, LlmApi.LlmResponseHandler handler) throws Exception {
        // Get MCP tools as function schemas
        java.util.List<java.util.Map<String, Object>> mcpFunctions = 
            toolManager.getToolsAsFunction();
        
        if (!mcpFunctions.isEmpty()) {
            // Use conversational tool calling with finish_reason monitoring
            llmApi.sendConversationalToolRequest(request.getFullConversation(), 
                mcpFunctions, handler);
        } else {
            // No MCP tools available, fall back to regular query
            executeRegularQuery(request, llmApi, handler);
        }
    }
    
    /**
     * Execute regular query without MCP
     */
    private void executeRegularQuery(QueryRequest request, LlmApi llmApi, LlmApi.LlmResponseHandler handler) throws Exception {
        llmApi.sendRequestAsync(request.getFullConversation(), handler);
    }
    
    /**
     * Add user query to conversation history (legacy method)
     */
    public void addUserQuery(String query) {
        addUserMessage(query, currentProviderType, null);
    }

    /**
     * Add user message with provider info and optional API message
     */
    public void addUserMessage(String query, String providerType, ChatMessage apiMessage) {
        // Add to legacy conversation history
        conversationHistory.append("**User**:\n").append(query).append("\n\n");

        // Create persisted message
        PersistedChatMessage msg = new PersistedChatMessage(
                null, "user", query,
                new Timestamp(System.currentTimeMillis()),
                messageList.size()
        );
        msg.setProviderType(providerType != null ? providerType : currentProviderType);
        msg.setNativeMessageData(serializeToolInfo(apiMessage));
        msg.setMessageType("standard");
        messageList.add(msg);

        // Ensure we have a session for this conversation
        ensureSession();

        // Save to per-message storage
        if (currentSessionId != -1) {
            String programHash = getProgramHash();
            if (programHash != null) {
                analysisDB.saveMessage(
                        programHash, currentSessionId, msg.getOrder(),
                        msg.getProviderType(), msg.getNativeMessageData(),
                        msg.getRole(), msg.getContent(), msg.getMessageType()
                );
            }
        }
    }

    /**
     * Add assistant response to conversation history (legacy method)
     */
    public void addAssistantResponse(String response) {
        addAssistantMessage(response, currentProviderType, null);
    }

    /**
     * Add assistant message with provider info and optional API message
     */
    public void addAssistantMessage(String response, String providerType, ChatMessage apiMessage) {
        // Add to legacy conversation history
        conversationHistory.append("**Assistant**:\n").append(response).append("\n\n");

        // Create persisted message
        PersistedChatMessage msg = new PersistedChatMessage(
                null, "assistant", response,
                new Timestamp(System.currentTimeMillis()),
                messageList.size()
        );
        msg.setProviderType(providerType != null ? providerType : currentProviderType);
        msg.setNativeMessageData(serializeToolInfo(apiMessage));

        // Determine message type based on API message
        if (apiMessage != null && apiMessage.getToolCalls() != null) {
            msg.setMessageType("tool_call");
        } else {
            msg.setMessageType("standard");
        }
        messageList.add(msg);

        // Save to per-message storage
        if (currentSessionId != -1) {
            String programHash = getProgramHash();
            if (programHash != null) {
                analysisDB.saveMessage(
                        programHash, currentSessionId, msg.getOrder(),
                        msg.getProviderType(), msg.getNativeMessageData(),
                        msg.getRole(), msg.getContent(), msg.getMessageType()
                );
            }
        }
    }

    /**
     * Add tool call message
     */
    public void addToolCallMessage(String toolName, String args, String result) {
        String content = String.format("Tool: %s\nArguments: %s\nResult: %s", toolName, args, result);
        conversationHistory.append("**Tool Call**:\n").append(content).append("\n\n");

        PersistedChatMessage msg = new PersistedChatMessage(
                null, "tool_call", content,
                new Timestamp(System.currentTimeMillis()),
                messageList.size()
        );
        msg.setProviderType(currentProviderType);
        msg.setNativeMessageData(String.format("{\"tool\":\"%s\",\"args\":%s,\"result\":\"%s\"}",
                escapeJson(toolName), args, escapeJson(result)));
        msg.setMessageType("tool_call");
        messageList.add(msg);

        if (currentSessionId != -1) {
            String programHash = getProgramHash();
            if (programHash != null) {
                analysisDB.saveMessage(
                        programHash, currentSessionId, msg.getOrder(),
                        msg.getProviderType(), msg.getNativeMessageData(),
                        msg.getRole(), msg.getContent(), msg.getMessageType()
                );
            }
        }
    }

    /**
     * Add error to conversation history
     */
    public void addError(String errorMessage) {
        conversationHistory.append("**Error**:\n").append(errorMessage).append("\n\n");

        PersistedChatMessage msg = new PersistedChatMessage(
                null, "error", errorMessage,
                new Timestamp(System.currentTimeMillis()),
                messageList.size()
        );
        msg.setProviderType(currentProviderType);
        msg.setNativeMessageData("{}");
        msg.setMessageType("standard");
        messageList.add(msg);

        if (currentSessionId != -1) {
            String programHash = getProgramHash();
            if (programHash != null) {
                analysisDB.saveMessage(
                        programHash, currentSessionId, msg.getOrder(),
                        msg.getProviderType(), msg.getNativeMessageData(),
                        msg.getRole(), msg.getContent(), msg.getMessageType()
                );
            }
        }
    }
    
    /**
     * Get current conversation history
     */
    public String getConversationHistory() {
        return conversationHistory.toString();
    }
    
    /**
     * Clear conversation history
     */
    public void clearConversationHistory() {
        conversationHistory.setLength(0);
        messageList.clear();
    }

    /**
     * Get the list of persisted messages
     */
    public List<PersistedChatMessage> getMessages() {
        return new ArrayList<>(messageList);
    }

    /**
     * Set the message list (used when loading or after editing)
     */
    public void setMessages(List<PersistedChatMessage> messages) {
        this.messageList = new ArrayList<>(messages);
        rebuildConversationHistory();
    }

    /**
     * Check if current session has been migrated to per-message storage
     */
    public boolean isMigrated() {
        if (currentSessionId == -1) {
            return false;
        }
        String programHash = getProgramHash();
        if (programHash == null) {
            return false;
        }
        return analysisDB.hasPerMessageStorage(programHash, currentSessionId);
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
            String role = normalizeRole(matcher.group(1));
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
        if (currentSessionId == -1) {
            return;
        }
        String programHash = getProgramHash();
        if (programHash == null) {
            return;
        }

        // Try to load from per-message storage first
        List<PersistedChatMessage> dbMessages = analysisDB.getMessages(programHash, currentSessionId);
        if (!dbMessages.isEmpty()) {
            messageList = dbMessages;
            rebuildConversationHistory();
        } else {
            // Fall back to legacy blob and migrate
            String conversation = analysisDB.getChatConversation(currentSessionId);
            if (conversation != null && !conversation.isEmpty()) {
                messageList = migrateFromLegacyBlob(conversation);
                // Save migrated messages to per-message storage
                for (PersistedChatMessage msg : messageList) {
                    analysisDB.saveMessage(
                            programHash, currentSessionId, msg.getOrder(),
                            msg.getProviderType(), msg.getNativeMessageData(),
                            msg.getRole(), msg.getContent(), msg.getMessageType()
                    );
                }
                rebuildConversationHistory();
            }
        }
    }

    /**
     * Set the current provider type
     */
    public void setCurrentProviderType(String providerType) {
        this.currentProviderType = providerType;
    }

    /**
     * Get the current provider type
     */
    public String getCurrentProviderType() {
        return currentProviderType;
    }
    
    // Chat Session Management
    
    /**
     * Create a new chat session and make it current
     */
    public int createNewChatSession() {
        if (plugin.getCurrentProgram() == null) {
            return -1;
        }
        String programHash = plugin.getCurrentProgram().getExecutableSHA256();
        
        // Get next session ID for auto-generated description
        java.util.List<AnalysisDB.ChatSession> sessions = analysisDB.getChatSessions(programHash);
        int nextId = sessions.size() + 1;
        String description = "Chat " + nextId;
        
        // Create session with current conversation
        currentSessionId = analysisDB.createChatSession(programHash, description, conversationHistory.toString());
        return currentSessionId;
    }
    
    /**
     * Get all chat sessions for current program
     */
    public java.util.List<AnalysisDB.ChatSession> getChatSessions() {
        if (plugin.getCurrentProgram() == null) {
            return new java.util.ArrayList<>();
        }
        String programHash = plugin.getCurrentProgram().getExecutableSHA256();
        return analysisDB.getChatSessions(programHash);
    }
    
    /**
     * Switch to a specific chat session
     */
    public boolean switchToChatSession(int sessionId) {
        if (plugin.getCurrentProgram() == null) {
            return false;
        }

        String programHash = plugin.getCurrentProgram().getExecutableSHA256();

        // Set current session ID first
        currentSessionId = sessionId;

        // Check if this is a ReAct session
        if (analysisDB.isReActSession(sessionId)) {
            // Load ReAct messages from dedicated table
            java.util.List<ghidrassist.apiprovider.ChatMessage> messages =
                analysisDB.getReActMessages(programHash, sessionId);

            if (messages != null && !messages.isEmpty()) {
                conversationHistory.setLength(0);
                messageList.clear();

                // Format ReAct messages as conversation
                String formattedConversation = formatReActConversation(messages, sessionId);
                conversationHistory.append(formattedConversation);
                return true;
            }
            return false;
        } else {
            // Load regular conversation from per-message storage
            conversationHistory.setLength(0);
            messageList.clear();

            // Load messages from database and rebuild conversation
            loadMessagesFromDatabase();

            // If no messages were loaded, fall back to legacy blob
            if (messageList.isEmpty()) {
                String conversation = analysisDB.getChatConversation(sessionId);
                if (conversation != null) {
                    conversationHistory.append(conversation);
                    return true;
                }
                return false;
            }

            return true;
        }
    }

    /**
     * Format ReAct messages into markdown conversation format.
     * Restores the complete investigation: user query, full investigation history, and final synthesis.
     */
    private String formatReActConversation(java.util.List<ghidrassist.apiprovider.ChatMessage> messages, int sessionId) {
        StringBuilder conversation = new StringBuilder();

        String userQuery = null;
        String investigationHistory = null;
        String finalSynthesis = null;

        // Extract components from messages
        for (ghidrassist.apiprovider.ChatMessage msg : messages) {
            if ("user".equals(msg.getRole())) {
                userQuery = msg.getContent();
            } else if ("assistant".equals(msg.getRole())) {
                // Investigation history is the longest message (contains all iteration details)
                // Synthesis is typically shorter
                if (msg.getContent() != null) {
                    if (investigationHistory == null || msg.getContent().length() > investigationHistory.length()) {
                        // This is likely the investigation history (comprehensive)
                        // Save previous as potential synthesis
                        if (investigationHistory != null) {
                            finalSynthesis = investigationHistory;
                        }
                        investigationHistory = msg.getContent();
                    } else {
                        // This is likely the synthesis (shorter, more focused)
                        finalSynthesis = msg.getContent();
                    }
                }
            }
        }

        // Build formatted conversation in order
        // 1. User query at the top
        if (userQuery != null) {
            conversation.append("**User**: ").append(userQuery).append("\n\n");
        }

        // 2. Full investigation history (all iterations with details)
        if (investigationHistory != null) {
            conversation.append(investigationHistory);
            // Add separator if we have synthesis coming
            if (finalSynthesis != null && !investigationHistory.contains("# Final")) {
                conversation.append("\n\n---\n\n");
            }
        }

        // 3. Final synthesis/analysis
        if (finalSynthesis != null) {
            // Only add header if not already present in the synthesis
            if (!finalSynthesis.trim().startsWith("#")) {
                conversation.append("# Final Analysis\n\n");
            }
            conversation.append(finalSynthesis).append("\n\n");
        }

        return conversation.toString();
    }
    
    /**
     * Delete current chat session
     */
    public boolean deleteCurrentSession() {
        if (currentSessionId != -1) {
            boolean deleted = analysisDB.deleteChatSession(currentSessionId);
            if (deleted) {
                currentSessionId = -1;
                clearConversationHistory();
                return true;
            }
        }
        return false;
    }
    
    /**
     * Update chat session description
     */
    public void updateChatDescription(int sessionId, String description) {
        analysisDB.updateChatDescription(sessionId, description);
    }
    
    /**
     * Get current session ID
     */
    public int getCurrentSessionId() {
        return currentSessionId;
    }
    
    /**
     * Create session if none exists and conversation has content
     */
    public void ensureSession() {
        if (currentSessionId == -1 && conversationHistory.length() > 0) {
            createNewChatSession();
        }
    }

    // Private helper methods

    /**
     * Get program hash for current program
     */
    private String getProgramHash() {
        if (plugin.getCurrentProgram() != null) {
            return plugin.getCurrentProgram().getExecutableSHA256();
        }
        return null;
    }

    /**
     * Rebuild conversation history from message list
     */
    private void rebuildConversationHistory() {
        conversationHistory.setLength(0);
        for (PersistedChatMessage msg : messageList) {
            String roleHeader = formatRoleHeader(msg.getRole());
            conversationHistory.append("**").append(roleHeader).append("**:\n")
                    .append(msg.getContent()).append("\n\n");
        }
    }

    /**
     * Format role for conversation history header
     */
    private String formatRoleHeader(String role) {
        if (role == null) {
            return "Unknown";
        }
        switch (role.toLowerCase()) {
            case "user":
                return "User";
            case "assistant":
                return "Assistant";
            case "tool_call":
                return "Tool Call";
            case "tool_response":
                return "Tool Response";
            case "error":
                return "Error";
            default:
                return role.substring(0, 1).toUpperCase() + role.substring(1);
        }
    }

    /**
     * Normalize role string from various formats
     */
    private String normalizeRole(String role) {
        if (role == null) {
            return "unknown";
        }
        switch (role.toLowerCase()) {
            case "user":
                return "user";
            case "assistant":
                return "assistant";
            case "tool call":
            case "tool_call":
                return "tool_call";
            case "tool response":
            case "tool_response":
                return "tool_response";
            case "error":
                return "error";
            default:
                return role.toLowerCase();
        }
    }

    /**
     * Serialize essential tool info from ChatMessage to JSON
     */
    private String serializeToolInfo(ChatMessage apiMessage) {
        if (apiMessage == null) {
            return "{}";
        }

        // Only store essential tool info, not full provider response
        if (apiMessage.getToolCalls() != null) {
            try {
                // Use simple JSON construction for essential info
                StringBuilder json = new StringBuilder("{\"tool_calls\":[");
                String toolCallsStr = apiMessage.getToolCalls().toString();
                json.append(toolCallsStr);
                json.append("]}");
                return json.toString();
            } catch (Exception e) {
                return "{}";
            }
        }

        return "{}";
    }

    /**
     * Escape string for JSON
     */
    private String escapeJson(String input) {
        if (input == null) {
            return "";
        }
        return input.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    /**
     * Get the AnalysisDB instance
     */
    public AnalysisDB getAnalysisDB() {
        return analysisDB;
    }

    /**
     * Save ReAct analysis to database with full investigation history.
     * Stores complete chronological investigation to GHReActMessages table.
     * Preserves all details: planning, iterations, tool calls, reflections, synthesis.
     *
     * @param userQuery Original user query
     * @param investigationHistory Full chronological history (all iterations with details)
     * @param finalResult Final answer from ReAct synthesis
     */
    public void saveReActAnalysis(String userQuery, String investigationHistory, String finalResult) {
        ensureSession();

        if (currentSessionId == -1 || plugin.getCurrentProgram() == null) {
            return;
        }

        String programHash = plugin.getCurrentProgram().getExecutableSHA256();

        // Get current message count to avoid overwriting existing messages
        int existingMessageCount = analysisDB.getReActMessages(programHash, currentSessionId).size();
        int messageOrder = existingMessageCount;

        // Get max existing iteration number for proper offset
        int iterationNumber = analysisDB.getMaxReActIteration(programHash, currentSessionId) + 1;

        // Append user query to conversation history (if not already there)
        if (!conversationHistory.toString().contains(userQuery)) {
            conversationHistory.append("**User**: ").append(userQuery).append("\n\n");
        }

        // Save user query as first ReAct message
        ghidrassist.apiprovider.ChatMessage userMsg =
            new ghidrassist.apiprovider.ChatMessage("user", userQuery);
        analysisDB.saveReActMessage(programHash, currentSessionId, messageOrder++,
            "planning", null, userMsg);

        // Save FULL investigation history as investigation message
        // This includes: planning, all iterations (thoughts, tool calls, observations),
        // reflections, todos progression, findings - everything streamed to the user
        if (investigationHistory != null && !investigationHistory.isEmpty()) {
            ghidrassist.apiprovider.ChatMessage investigationMsg =
                new ghidrassist.apiprovider.ChatMessage("assistant", investigationHistory);
            analysisDB.saveReActMessage(programHash, currentSessionId, messageOrder++,
                "investigation", iterationNumber, investigationMsg);

            // Save iteration chunk with full history
            analysisDB.saveReActIterationChunk(programHash, currentSessionId, iterationNumber,
                investigationHistory, messageOrder - 1, messageOrder - 1);

            // Append to conversation history
            conversationHistory.append("**Assistant** (ReAct Investigation):\n\n");
            conversationHistory.append(investigationHistory).append("\n\n");
        }

        // Save final synthesis as last message
        ghidrassist.apiprovider.ChatMessage finalMsg =
            new ghidrassist.apiprovider.ChatMessage("assistant", finalResult);
        analysisDB.saveReActMessage(programHash, currentSessionId, messageOrder++,
            "synthesis", null, finalMsg);

        // Append final result to conversation history
        conversationHistory.append("**Assistant** (Final Analysis):\n").append(finalResult).append("\n\n");
    }

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