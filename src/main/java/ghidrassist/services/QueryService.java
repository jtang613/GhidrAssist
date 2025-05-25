package ghidrassist.services;

import ghidrassist.GhidrAssistPlugin;
import ghidrassist.LlmApi;
import ghidrassist.apiprovider.APIProviderConfig;
import ghidrassist.core.QueryProcessor;
import ghidrassist.mcp2.tools.MCPToolManager;

/**
 * Service for handling custom queries and conversations.
 * Responsible for processing user queries, RAG integration, and conversation management.
 */
public class QueryService {
    
    private final GhidrAssistPlugin plugin;
    private final StringBuilder conversationHistory;
    
    public QueryService(GhidrAssistPlugin plugin) {
        this.plugin = plugin;
        this.conversationHistory = new StringBuilder();
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
     * Add assistant response to conversation history
     */
    public void addAssistantResponse(String response) {
        conversationHistory.append("**Assistant**:\n").append(response).append("\n\n");
    }
    
    /**
     * Add error to conversation history
     */
    public void addError(String errorMessage) {
        conversationHistory.append("**Error**:\n").append(errorMessage).append("\n\n");
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