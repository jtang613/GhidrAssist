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
        
        // Use function calling with MCP tools if MCP is enabled and available
        if (request.shouldUseMCP()) {
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
        }
        
        // Fall back to regular query execution
        executeRegularQuery(request, llmApi, handler);
    }
    
    /**
     * Execute MCP-enabled query
     */
    private void executeMCPQuery(QueryRequest request, LlmApi llmApi, MCPToolManager toolManager, LlmApi.LlmResponseHandler handler) throws Exception {
        // Get MCP tools as function schemas
        java.util.List<java.util.Map<String, Object>> mcpFunctions = 
            toolManager.getToolsAsFunction();
        
        if (!mcpFunctions.isEmpty()) {
            // Create MCP-aware response handler
            LlmApi.LlmResponseHandler mcpHandler = createMCPHandler(handler, toolManager);
            llmApi.sendRequestAsyncWithFunctions(request.getFullConversation(), 
                mcpFunctions, mcpHandler);
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
     * Create MCP-aware response handler that can execute MCP tools
     */
    private LlmApi.LlmResponseHandler createMCPHandler(LlmApi.LlmResponseHandler originalHandler, MCPToolManager toolManager) {
        return new LlmApi.LlmResponseHandler() {
            @Override
            public void onStart() {
                originalHandler.onStart();
            }
            
            @Override
            public void onUpdate(String partialResponse) {
                originalHandler.onUpdate(partialResponse);
            }
            
            @Override
            public void onComplete(String response) {
                // Check if response contains MCP tool calls
                if (containsToolCalls(response)) {
                    handleMCPResponse(response, originalHandler);
                } else {
                    originalHandler.onComplete(response);
                }
            }
            
            @Override
            public void onError(Throwable error) {
                originalHandler.onError(error);
            }
            
            @Override
            public boolean shouldContinue() {
                return originalHandler.shouldContinue();
            }
        };
    }
    
    /**
     * Check if response contains tool calls
     */
    private boolean containsToolCalls(String response) {
        try {
            String jsonStr = extractToolCallsJson(response);
            com.google.gson.JsonObject jsonObject = new com.google.gson.Gson().fromJson(jsonStr, com.google.gson.JsonObject.class);
            return jsonObject != null && jsonObject.has("tool_calls");
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Handle response that contains MCP tool calls
     */
    private void handleMCPResponse(String response, LlmApi.LlmResponseHandler originalHandler) {
        MCPToolManager toolManager = MCPToolManager.getInstance();
        try {
            String jsonStr = extractToolCallsJson(response);
            com.google.gson.JsonObject jsonObject = new com.google.gson.Gson().fromJson(jsonStr, com.google.gson.JsonObject.class);
            com.google.gson.JsonArray toolCalls = jsonObject.getAsJsonArray("tool_calls");
            
            StringBuilder toolResults = new StringBuilder();
            toolResults.append("**Tool Execution Results:**\n\n");
            
            // Execute each tool call
            for (com.google.gson.JsonElement toolCall : toolCalls) {
                com.google.gson.JsonObject toolObj = toolCall.getAsJsonObject();
                
                // Handle different provider formats
                String toolName;
                com.google.gson.JsonObject arguments;
                
                if (toolObj.has("function")) {
                    // OpenAI format: {"function": {"name": "...", "arguments": "..."}}
                    com.google.gson.JsonObject functionObj = toolObj.getAsJsonObject("function");
                    toolName = functionObj.get("name").getAsString();
                    
                    // Arguments might be a string that needs parsing
                    if (functionObj.has("arguments")) {
                        com.google.gson.JsonElement argsElement = functionObj.get("arguments");
                        if (argsElement.isJsonPrimitive() && argsElement.getAsJsonPrimitive().isString()) {
                            // Parse string as JSON
                            try {
                                arguments = new com.google.gson.Gson().fromJson(argsElement.getAsString(), com.google.gson.JsonObject.class);
                            } catch (Exception e) {
                                arguments = new com.google.gson.JsonObject();
                            }
                        } else if (argsElement.isJsonObject()) {
                            arguments = argsElement.getAsJsonObject();
                        } else {
                            arguments = new com.google.gson.JsonObject();
                        }
                    } else {
                        arguments = new com.google.gson.JsonObject();
                    }
                } else if (toolObj.has("name")) {
                    // Anthropic/direct format: {"name": "...", "arguments": {...}}
                    toolName = toolObj.get("name").getAsString();
                    arguments = toolObj.has("arguments") ? 
                        toolObj.getAsJsonObject("arguments") : new com.google.gson.JsonObject();
                } else {
                    // Skip invalid tool calls
                    ghidra.util.Msg.warn(this, "Skipping invalid tool call: " + toolObj);
                    continue;
                }
                
                toolResults.append("**").append(toolName).append(":**\n");
                
                // Execute MCP tool
                toolManager.executeTool(toolName, arguments)
                    .thenAccept(result -> {
                        String resultText = result.getResultText();
                        
                        javax.swing.SwingUtilities.invokeLater(() -> {
                            // Update conversation history
                            conversationHistory.append("**Tool: ").append(toolName).append("**\n")
                                             .append(resultText).append("\n\n");
                            
                            // Send tool result to UI
                            originalHandler.onUpdate("\n\n**" + toolName + ":**\n" + resultText + "\n");
                        });
                    })
                    .exceptionally(throwable -> {
                        String errorMsg = "Tool execution failed: " + throwable.getMessage();
                        
                        javax.swing.SwingUtilities.invokeLater(() -> {
                            conversationHistory.append("**Tool Error (").append(toolName).append(")**\n")
                                             .append(errorMsg).append("\n\n");
                            
                            originalHandler.onUpdate("\n\n**" + toolName + " Error:**\n" + errorMsg + "\n");
                        });
                        return null;
                    });
            }
            
            // Complete the response after all tools are executed
            originalHandler.onComplete(response);
            
        } catch (Exception e) {
            ghidra.util.Msg.error(this, "Failed to handle MCP response: " + e.getMessage());
            originalHandler.onComplete(response);
        }
    }
    
    /**
     * Extract tool calls JSON (reusing logic from ActionParser)
     */
    private String extractToolCallsJson(String response) throws Exception {
        // First check if this is already a tool calls JSON object
        try {
            com.google.gson.JsonObject responseObj = new com.google.gson.Gson().fromJson(response, com.google.gson.JsonObject.class);
            
            // Check if this is already tool calls JSON
            if (responseObj.has("tool_calls")) {
                return response;
            }
            
            // Check if this is an Anthropic response with content array
            if (responseObj.has("content") && responseObj.get("content").isJsonArray()) {
                com.google.gson.JsonArray contentArray = responseObj.getAsJsonArray("content");
                if (contentArray.size() > 0) {
                    com.google.gson.JsonObject firstContent = contentArray.get(0).getAsJsonObject();
                    if (firstContent.has("type") && "text".equals(firstContent.get("type").getAsString()) 
                        && firstContent.has("text")) {
                        String textContent = firstContent.get("text").getAsString();
                        return preprocessJsonResponse(textContent);
                    }
                }
            }
        } catch (com.google.gson.JsonSyntaxException e) {
            // Not a JSON object, treat as raw text that needs preprocessing
        }
        
        // This is likely text content that needs preprocessing
        return preprocessJsonResponse(response);
    }
    
    /**
     * Preprocess response to extract JSON from code blocks
     */
    private String preprocessJsonResponse(String response) {
        String json = response.trim();

        // Define regex patterns to match code block markers
        java.util.regex.Pattern codeBlockPattern = java.util.regex.Pattern.compile("(?s)^[`']{3}(\\w+)?\\s*(.*?)\\s*[`']{3}$");
        java.util.regex.Matcher matcher = codeBlockPattern.matcher(json);

        if (matcher.find()) {
            // Extract the content inside the code block
            json = matcher.group(2).trim();
        } else {
            // If no code block markers, attempt to find the JSON content directly
            // Remove any leading or trailing quotes (but be careful about JSON strings)
            if ((json.startsWith("\"") && json.endsWith("\"")) || 
                (json.startsWith("'") && json.endsWith("'"))) {
                // Only remove if it's wrapping the entire content, not part of JSON
                String withoutQuotes = json.substring(1, json.length() - 1).trim();
                try {
                    // Test if removing quotes gives us valid JSON
                    new com.google.gson.Gson().fromJson(withoutQuotes, com.google.gson.JsonElement.class);
                    json = withoutQuotes;
                } catch (com.google.gson.JsonSyntaxException e) {
                    // Keep original if removing quotes breaks JSON
                }
            }
        }
        
        // Handle escaped quotes in JSON strings from Anthropic
        if (json.contains("\\\"")) {
            // Try to parse with escaped quotes
            try {
                new com.google.gson.Gson().fromJson(json, com.google.gson.JsonElement.class);
                // If it parses, return as-is
                return json;
            } catch (com.google.gson.JsonSyntaxException e) {
                // If parsing fails, try unescaping quotes
                json = json.replace("\\\"", "\"");
            }
        }
        
        // Clean up escaped whitespace
        json = json.replace("\\n", "\n").replace("\\t", "\t").replace("\\r", "\r");
        
        // Clean up some specific malformed patterns but preserve valid escapes
        json = json.replace(":\"{\"", ":{\"").replace("\"}\"}", "\"}}");
        
        return json;
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