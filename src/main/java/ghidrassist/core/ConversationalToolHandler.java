package ghidrassist.core;

import ghidrassist.LlmApi;
import ghidrassist.apiprovider.ChatMessage;
import ghidrassist.apiprovider.exceptions.RateLimitException;
import ghidrassist.mcp2.tools.MCPToolManager;
import ghidrassist.mcp2.tools.MCPToolResult;
import ghidra.util.Msg;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * Handles conversational tool calling with proper finish_reason monitoring.
 * Manages the turn-by-turn conversation flow with the LLM and MCP tool execution.
 */
public class ConversationalToolHandler {
    
    private final LlmApiClient apiClient;
    private final List<Map<String, Object>> availableFunctions;
    private final ResponseProcessor responseProcessor;
    private final LlmApi.LlmResponseHandler userHandler;
    private final LlmErrorHandler errorHandler;
    private final Runnable onCompletionCallback;
    
    private final List<ChatMessage> conversationHistory;
    private volatile boolean isConversationActive = false;
    private volatile boolean isCancelled = false;
    private int rateLimitRetries = 0;
    private static final int MAX_RATE_LIMIT_RETRIES = 3;
    private static final int MAX_CONVERSATION_HISTORY = 20; // Keep last 20 messages to prevent token overflow
    
    public ConversationalToolHandler(
            LlmApiClient apiClient,
            List<Map<String, Object>> functions,
            ResponseProcessor responseProcessor,
            LlmApi.LlmResponseHandler userHandler,
            LlmErrorHandler errorHandler,
            Runnable onCompletionCallback) {
        
        this.apiClient = apiClient;
        this.availableFunctions = functions;
        this.responseProcessor = responseProcessor;
        this.userHandler = userHandler;
        this.errorHandler = errorHandler;
        this.onCompletionCallback = onCompletionCallback;
        this.conversationHistory = new ArrayList<>();
    }
    
    /**
     * Start the conversational tool calling session
     */
    public void startConversation(String userPrompt) {
        if (isConversationActive) {
            Msg.warn(this, "Conversation already active, ignoring new request");
            return;
        }
        
        isConversationActive = true;
        isCancelled = false; // Reset cancellation flag
        conversationHistory.clear();
        rateLimitRetries = 0; // Reset retry counter
        
        // Add initial user message
        conversationHistory.addAll(apiClient.createFunctionMessages(userPrompt));
        
        // Start the conversation loop
        userHandler.onStart();
        
        // Provide user feedback about automatic rate limit handling
        userHandler.onUpdate("🔄 Starting conversational tool calling (automatic retry on rate limits)...\n\n");
        
        continueConversation();
    }
    
    /**
     * Cancel the ongoing conversation
     */
    public void cancel() {
        isCancelled = true;
        isConversationActive = false;
        userHandler.onUpdate("\n❌ **Cancelled**\n");
        userHandler.onComplete("Conversation cancelled");
        
        // Notify completion callback
        if (onCompletionCallback != null) {
            onCompletionCallback.run();
        }
    }
    
    /**
     * Continue the conversation with the current message history
     */
    private void continueConversation() {
        if (!isConversationActive || isCancelled) {
            return;
        }
        
        try {
            // Trim conversation history to prevent token overflow
            trimConversationHistory();
            
            // Call LLM with current conversation history
            CompletableFuture.runAsync(() -> {
                try {
                    // Check cancellation before making API call
                    if (isCancelled) {
                        return;
                    }
                    
                    String fullResponse = apiClient.createChatCompletionWithFunctionsFullResponse(
                        conversationHistory, availableFunctions);
                    
                    // Check cancellation after API call
                    if (isCancelled) {
                        return;
                    }
                    
                    // Parse the response to check for tool calls and finish_reason
                    handleLLMResponse(fullResponse);
                    
                } catch (Exception e) {
                    // Handle rate limit errors with additional backoff and retry
                    if (e instanceof ghidrassist.apiprovider.exceptions.RateLimitException ||
                        e.getMessage().contains("rate limit") || 
                        e.getMessage().contains("429")) {
                        
                        rateLimitRetries++;
                        
                        if (rateLimitRetries <= MAX_RATE_LIMIT_RETRIES) {
                            Msg.warn(this, String.format("Rate limit exceeded during conversational tool calling (attempt %d/%d). Implementing additional backoff...", 
                                rateLimitRetries, MAX_RATE_LIMIT_RETRIES));
                            
                            // Implement progressively longer backoff
                            int backoffSeconds = 30 * rateLimitRetries; // 30s, 60s, 90s
                            userHandler.onUpdate(String.format("⏳ Rate limit exceeded. Pausing for %d seconds...\n", 
                                backoffSeconds));
                            
                            // Schedule retry after progressively longer delay
                            CompletableFuture.delayedExecutor(backoffSeconds, java.util.concurrent.TimeUnit.SECONDS)
                                .execute(() -> {
                                    if (isConversationActive && !isCancelled) {
                                        userHandler.onUpdate("🔄 Resuming...\n");
                                        continueConversation();
                                    }
                                });
                        } else {
                            // Too many rate limit retries - give up
                            isConversationActive = false;
                            userHandler.onUpdate("❌ Too many rate limit errors. Please try again later.\n");
                            userHandler.onError(new Exception("Rate limit exceeded maximum retry attempts. Please try again later or reduce query complexity."));
                            
                            // Notify completion callback
                            if (onCompletionCallback != null) {
                                onCompletionCallback.run();
                            }
                        }
                    } else {
                        // Non-rate-limit errors stop the conversation
                        isConversationActive = false;
                        userHandler.onError(e);
                        
                        // Notify completion callback
                        if (onCompletionCallback != null) {
                            onCompletionCallback.run();
                        }
                    }
                }
            });
            
        } catch (Exception e) {
            isConversationActive = false;
            userHandler.onError(e);
            
            // Notify completion callback
            if (onCompletionCallback != null) {
                onCompletionCallback.run();
            }
        }
    }
    
    /**
     * Handle the LLM response and determine next action based on finish_reason
     */
    private void handleLLMResponse(String rawResponse) {
        try {
            // Check cancellation before processing response
            if (isCancelled) {
                return;
            }
            
            Msg.debug(this, "Raw LLM response: " + (rawResponse != null ? rawResponse : "NULL"));
            
            // Validate response is not null or empty
            if (rawResponse == null || rawResponse.trim().isEmpty()) {
                throw new IllegalArgumentException("LLM response is null or empty");
            }
            
            // Parse the complete response including metadata
            JsonElement responseElement = JsonParser.parseString(rawResponse);
            if (responseElement == null || responseElement.isJsonNull()) {
                throw new IllegalArgumentException("LLM response parsed to null JSON");
            }
            
            if (!responseElement.isJsonObject()) {
                throw new IllegalArgumentException("LLM response is not a JSON object: " + responseElement.getClass().getSimpleName());
            }
            
            JsonObject responseObj = responseElement.getAsJsonObject();
            
            // Extract finish_reason from choices array
            String finishReason = extractFinishReason(responseObj);
            JsonObject assistantMessage = extractAssistantMessage(responseObj);
            
            Msg.debug(this, "LLM finish_reason: " + finishReason);
            
            if ("tool_calls".equals(finishReason) || "tool_use".equals(finishReason)) {
                handleToolCalls(assistantMessage, rawResponse);
            } else if ("stop".equals(finishReason) || "unknown".equals(finishReason)) {
                // Handle normal completion (no tools needed) or unknown finish_reason
                handleConversationEnd(assistantMessage);
            } else {
                // Other finish_reason types (length, content_filter, etc.)
                Msg.debug(this, "LLM finished with reason: " + finishReason + ", ending conversation");
                handleConversationEnd(assistantMessage);
            }
            
        } catch (Exception e) {
            Msg.error(this, "Error handling LLM response: " + e.getMessage());
            Msg.error(this, "Response content: " + (rawResponse != null ? rawResponse.substring(0, Math.min(500, rawResponse.length())) : "NULL"));
            isConversationActive = false;
            userHandler.onError(e);
            
            // Notify completion callback
            if (onCompletionCallback != null) {
                onCompletionCallback.run();
            }
        }
    }
    
    /**
     * Extract finish_reason from the LLM response
     */
    private String extractFinishReason(JsonObject responseObj) {
        try {
            if (responseObj != null && responseObj.has("choices")) {
                JsonElement choicesElement = responseObj.get("choices");
                if (choicesElement != null && !choicesElement.isJsonNull() && choicesElement.isJsonArray()) {
                    JsonArray choices = choicesElement.getAsJsonArray();
                    if (choices.size() > 0) {
                        JsonElement firstChoiceElement = choices.get(0);
                        if (firstChoiceElement != null && !firstChoiceElement.isJsonNull() && firstChoiceElement.isJsonObject()) {
                            JsonObject firstChoice = firstChoiceElement.getAsJsonObject();
                            if (firstChoice.has("finish_reason")) {
                                JsonElement finishReasonElement = firstChoice.get("finish_reason");
                                if (finishReasonElement != null && !finishReasonElement.isJsonNull()) {
                                    return finishReasonElement.getAsString();
                                }
                            }
                        }
                    }
                }
            }
            return "unknown";
        } catch (Exception e) {
            Msg.warn(this, "Could not extract finish_reason: " + e.getMessage());
            return "unknown";
        }
    }
    
    /**
     * Extract the assistant message from the LLM response
     */
    private JsonObject extractAssistantMessage(JsonObject responseObj) {
        try {
            if (responseObj != null && responseObj.has("choices")) {
                JsonElement choicesElement = responseObj.get("choices");
                if (choicesElement != null && !choicesElement.isJsonNull() && choicesElement.isJsonArray()) {
                    JsonArray choices = choicesElement.getAsJsonArray();
                    if (choices.size() > 0) {
                        JsonElement firstChoiceElement = choices.get(0);
                        if (firstChoiceElement != null && !firstChoiceElement.isJsonNull() && firstChoiceElement.isJsonObject()) {
                            JsonObject firstChoice = firstChoiceElement.getAsJsonObject();
                            if (firstChoice.has("message")) {
                                JsonElement messageElement = firstChoice.get("message");
                                if (messageElement != null && !messageElement.isJsonNull() && messageElement.isJsonObject()) {
                                    return messageElement.getAsJsonObject();
                                }
                            }
                        }
                    }
                }
            }
            // Fallback: try to find message directly
            if (responseObj != null && responseObj.has("message")) {
                JsonElement messageElement = responseObj.get("message");
                if (messageElement != null && !messageElement.isJsonNull() && messageElement.isJsonObject()) {
                    return messageElement.getAsJsonObject();
                }
            }
            return new JsonObject();
        } catch (Exception e) {
            Msg.warn(this, "Could not extract assistant message: " + e.getMessage());
            return new JsonObject();
        }
    }
    
    /**
     * Handle tool calls when finish_reason is "tool_calls"
     */
    private void handleToolCalls(JsonObject assistantMessage, String rawResponse) {
        try {
            // Create assistant message with tool calls
            String content = null;
            if (assistantMessage.has("content")) {
                JsonElement contentElement = assistantMessage.get("content");
                if (contentElement != null && !contentElement.isJsonNull()) {
                    content = contentElement.getAsString();
                }
            }
            
            ChatMessage assistantMsg = new ChatMessage(
                ChatMessage.ChatMessageRole.ASSISTANT, 
                content
            );
            
            // Add tool calls to the assistant message
            if (assistantMessage.has("tool_calls")) {
                assistantMsg.setToolCalls(assistantMessage.getAsJsonArray("tool_calls"));
            }
            
            conversationHistory.add(assistantMsg);
            
            // Extract tool calls
            JsonArray toolCalls = null;
            if (assistantMessage.has("tool_calls")) {
                toolCalls = assistantMessage.getAsJsonArray("tool_calls");
            } else if (assistantMessage.has("content")) {
                // Try to parse tool calls from content
                // This line should not be reached now, but adding safety
                String contentStr = "";
                if (assistantMessage.has("content")) {
                    JsonElement contentElement = assistantMessage.get("content");
                    if (contentElement != null && !contentElement.isJsonNull()) {
                        contentStr = contentElement.getAsString();
                    }
                }
                JsonObject contentObj = JsonParser.parseString(contentStr).getAsJsonObject();
                if (contentObj.has("tool_calls")) {
                    toolCalls = contentObj.getAsJsonArray("tool_calls");
                }
            }
            
            if (toolCalls == null || toolCalls.size() == 0) {
                Msg.warn(this, "No tool calls found despite finish_reason being tool_calls");
                handleConversationEnd(assistantMessage);
                return;
            }
            
            // Display text response if present, before tool execution metadata
            if (content != null && !content.trim().isEmpty()) {
                String filteredContent = responseProcessor.filterThinkBlocks(content);
                if (filteredContent != null && !filteredContent.trim().isEmpty()) {
                    javax.swing.SwingUtilities.invokeLater(() -> {
                        userHandler.onUpdate("\n" + filteredContent + "\n\n");
                    });
                }
            }
            
            // Update UI with tool calling status
            String toolExecutionHeader = "🔧 **Executing tools...**\n";
            javax.swing.SwingUtilities.invokeLater(() -> {
                userHandler.onUpdate(toolExecutionHeader);
            });
            
            // Execute tools and collect results
            executeToolsSequentially(toolCalls, 0, new ArrayList<>());
            
        } catch (Exception e) {
            Msg.error(this, "Error handling tool calls: " + e.getMessage());
            isConversationActive = false;
            userHandler.onError(e);
            
            // Notify completion callback
            if (onCompletionCallback != null) {
                onCompletionCallback.run();
            }
        }
    }
    
    /**
     * Execute tools sequentially and collect results
     */
    private void executeToolsSequentially(JsonArray toolCalls, int index, List<JsonObject> toolResults) {
        // Check cancellation before processing next tool
        if (isCancelled) {
            return;
        }
        
        if (index >= toolCalls.size()) {
            // All tools executed, add results to conversation and continue
            addToolResultsToConversation(toolResults);
            
            // Add a small delay before making the next API call to avoid rapid sequential requests
            // that could trigger rate limits
            CompletableFuture.delayedExecutor(500, java.util.concurrent.TimeUnit.MILLISECONDS)
                .execute(() -> {
                    if (!isCancelled) {
                        continueConversation();
                    }
                });
            return;
        }
        
        JsonObject toolCall = toolCalls.get(index).getAsJsonObject();
        executeSingleTool(toolCall)
            .thenAccept(result -> {
                if (!isCancelled) {
                    toolResults.add(result);
                    
                    // Add small delay between tool executions to be gentle on API rate limits
                    CompletableFuture.delayedExecutor(200, java.util.concurrent.TimeUnit.MILLISECONDS)
                        .execute(() -> {
                            if (!isCancelled) {
                                executeToolsSequentially(toolCalls, index + 1, toolResults);
                            }
                        });
                }
            })
            .exceptionally(throwable -> {
                if (!isCancelled) {
                    Msg.error(this, "Tool execution failed: " + throwable.getMessage());
                    
                    // Create error result and continue
                    JsonObject errorResult = new JsonObject();
                    errorResult.addProperty("tool_call_id", extractToolCallId(toolCall));
                    errorResult.addProperty("role", "tool");
                    errorResult.addProperty("content", "Error: " + throwable.getMessage());
                    toolResults.add(errorResult);
                    
                    // Add same delay for error case to maintain consistent pacing
                    CompletableFuture.delayedExecutor(200, java.util.concurrent.TimeUnit.MILLISECONDS)
                        .execute(() -> {
                            if (!isCancelled) {
                                executeToolsSequentially(toolCalls, index + 1, toolResults);
                            }
                        });
                }
                return null;
            });
    }
    
    /**
     * Execute a single tool and return the result
     */
    private CompletableFuture<JsonObject> executeSingleTool(JsonObject toolCall) {
        try {
            // Check cancellation before executing tool
            if (isCancelled) {
                return CompletableFuture.failedFuture(new Exception("Execution cancelled"));
            }
            
            String toolName = extractToolName(toolCall);
            JsonObject arguments = extractToolArguments(toolCall);
            String toolCallId = extractToolCallId(toolCall);
            
            // Update UI with current tool execution including parameters
            String paramDisplay = formatToolParameters(arguments);
            String executingMessage = "🛠️ Tool call in progress: *" + toolName + "(" + paramDisplay + ")*\n";
            javax.swing.SwingUtilities.invokeLater(() -> {
                userHandler.onUpdate(executingMessage);
            });
            
            // Execute via MCP with proper transaction handling
            MCPToolManager toolManager = MCPToolManager.getInstance();
            return executeToolWithTransaction(toolManager, toolName, arguments)
                .thenApply(mcpResult -> {
                    // Check cancellation before processing result
                    if (isCancelled) {
                        throw new RuntimeException("Execution cancelled");
                    }
                    
                    // Debug logging for development (keep for troubleshooting)
                    Msg.debug(this, String.format("MCP Tool '%s' completed: success=%s, length=%d", 
                        toolName, mcpResult.isSuccess(), 
                        mcpResult.getResultText() != null ? mcpResult.getResultText().length() : 0));
                    
                    // Don't show verbose tool results to user - they'll be included in LLM response
                    String paramDisplayComplete = formatToolParameters(arguments);
                    String completionMessage = "✓ Completed: *" + toolName + "(" + paramDisplayComplete + ")*\n";
                    
                    javax.swing.SwingUtilities.invokeLater(() -> {
                        if (!isCancelled) {
                            userHandler.onUpdate(completionMessage);
                        }
                    });
                    
                    // Create tool result for conversation
                    JsonObject toolResult = new JsonObject();
                    toolResult.addProperty("tool_call_id", toolCallId);
                    toolResult.addProperty("role", "tool");
                    toolResult.addProperty("content", mcpResult.getResultText());
                    
                    return toolResult;
                });
            
        } catch (Exception e) {
            return CompletableFuture.failedFuture(e);
        }
    }
    
    /**
     * Add tool results to conversation history
     */
    private void addToolResultsToConversation(List<JsonObject> toolResults) {
        for (JsonObject result : toolResults) {
            // Safely extract content
            String content = "";
            if (result.has("content")) {
                JsonElement contentElement = result.get("content");
                if (contentElement != null && !contentElement.isJsonNull()) {
                    content = contentElement.getAsString();
                }
            }
            
            // Safely extract tool_call_id
            String toolCallId = "";
            if (result.has("tool_call_id")) {
                JsonElement idElement = result.get("tool_call_id");
                if (idElement != null && !idElement.isJsonNull()) {
                    toolCallId = idElement.getAsString();
                }
            }
            
            ChatMessage toolMessage = new ChatMessage(ChatMessage.ChatMessageRole.TOOL, content);
            toolMessage.setToolCallId(toolCallId);
            conversationHistory.add(toolMessage);
        }
    }
    
    /**
     * Handle conversation end when finish_reason is "stop"
     */
    private void handleConversationEnd(JsonObject assistantMessage) {
        isConversationActive = false;
        
        try {
            // Extract and filter the final response
            String content = "";
            if (assistantMessage != null && assistantMessage.has("content")) {
                JsonElement contentElement = assistantMessage.get("content");
                if (contentElement != null && !contentElement.isJsonNull()) {
                    content = contentElement.getAsString();
                }
            }
            
            // Handle case where content is null or empty
            if (content == null || content.trim().isEmpty()) {
                content = "I'm ready to help you with this function analysis.";
                Msg.info(this, "LLM response had no content, using default message");
            }
            
            String filteredContent = responseProcessor.filterThinkBlocks(content);
            
            // Debug logging for final response
            Msg.info(this, String.format("Final LLM response: length=%d", 
                filteredContent != null ? filteredContent.length() : 0));
            if (filteredContent != null && filteredContent.length() > 0) {
                Msg.info(this, "Final response preview: " + 
                    (filteredContent.length() > 200 ? filteredContent.substring(0, 200) + "..." : filteredContent));
            }
            
            // Send only the final LLM response (tool execution messages were already sent individually)
            javax.swing.SwingUtilities.invokeLater(() -> {
                userHandler.onUpdate("\n" + filteredContent);
                userHandler.onComplete("\n" + filteredContent);
            });
            
        } catch (Exception e) {
            Msg.error(this, "Error handling conversation end: " + e.getMessage());
            // Provide fallback response
            javax.swing.SwingUtilities.invokeLater(() -> {
                userHandler.onUpdate("I encountered an error processing the response. Please try again.");
                userHandler.onComplete("Error processing response");
            });
        }
        
        // Notify completion callback
        if (onCompletionCallback != null) {
            onCompletionCallback.run();
        }
    }
    
    /**
     * Extract tool name from tool call
     */
    private String extractToolName(JsonObject toolCall) {
        if (toolCall.has("function")) {
            JsonObject function = toolCall.getAsJsonObject("function");
            return function.get("name").getAsString();
        } else if (toolCall.has("name")) {
            return toolCall.get("name").getAsString();
        }
        throw new IllegalArgumentException("No tool name found in tool call");
    }
    
    /**
     * Extract arguments from tool call
     */
    private JsonObject extractToolArguments(JsonObject toolCall) {
        JsonObject arguments = new JsonObject();
        
        if (toolCall.has("function")) {
            JsonObject function = toolCall.getAsJsonObject("function");
            if (function.has("arguments")) {
                JsonElement argsElement = function.get("arguments");
                if (argsElement.isJsonObject()) {
                    arguments = argsElement.getAsJsonObject();
                } else if (argsElement.isJsonPrimitive()) {
                    // Parse string arguments
                    String argsStr = argsElement.getAsString();
                    arguments = JsonParser.parseString(argsStr).getAsJsonObject();
                }
            }
        } else if (toolCall.has("arguments")) {
            JsonElement argsElement = toolCall.get("arguments");
            if (argsElement.isJsonObject()) {
                arguments = argsElement.getAsJsonObject();
            }
        }
        
        return arguments;
    }
    
    /**
     * Extract tool call ID from tool call
     */
    private String extractToolCallId(JsonObject toolCall) {
        if (toolCall.has("id")) {
            return toolCall.get("id").getAsString();
        }
        // Generate a fallback ID
        return "call_" + System.currentTimeMillis();
    }
    
    /**
     * Trim conversation history to prevent token overflow
     * Keeps the first message and ensures tool call/result pairs stay together
     */
    private void trimConversationHistory() {
        if (conversationHistory.size() <= MAX_CONVERSATION_HISTORY) {
            return; // No trimming needed
        }
        
        List<ChatMessage> trimmedHistory = new ArrayList<>();
        
        // Always keep the first message (initial user prompt)
        if (!conversationHistory.isEmpty()) {
            trimmedHistory.add(conversationHistory.get(0));
        }
        
        // Find a safe cutoff point that doesn't break tool call/result pairs
        int safeStartIndex = findSafeTrimPoint();
        
        // Add messages from safe point to end
        for (int i = safeStartIndex; i < conversationHistory.size(); i++) {
            trimmedHistory.add(conversationHistory.get(i));
        }
        
        // Replace conversation history
        conversationHistory.clear();
        conversationHistory.addAll(trimmedHistory);
        
        Msg.info(this, String.format("Trimmed conversation history to %d messages (safe tool-call trimming)", 
            conversationHistory.size()));
    }
    
    /**
     * Find a safe point to start trimming that doesn't break tool call/result pairs
     */
    private int findSafeTrimPoint() {
        int targetSize = MAX_CONVERSATION_HISTORY - 1; // -1 for first message we always keep
        int startFromEnd = Math.min(targetSize, conversationHistory.size() - 1);
        
        // Start from desired point and look backwards for a safe boundary
        for (int lookback = 0; lookback < startFromEnd; lookback++) {
            int candidateIndex = conversationHistory.size() - startFromEnd + lookback;
            
            // Check if this is a safe cut point (not in middle of tool call/result sequence)
            if (isSafeTrimPoint(candidateIndex)) {
                return candidateIndex;
            }
        }
        
        // Fallback: keep last half of conversation
        return Math.max(1, conversationHistory.size() / 2);
    }
    
    /**
     * Check if we can safely trim at this point without breaking tool call/result pairs
     */
    private boolean isSafeTrimPoint(int index) {
        if (index <= 0 || index >= conversationHistory.size()) {
            return false;
        }
        
        ChatMessage prevMessage = conversationHistory.get(index - 1);
        ChatMessage currentMessage = conversationHistory.get(index);
        
        // Don't trim if previous message has tool calls (next messages might be tool results)
        if (prevMessage.getToolCalls() != null && prevMessage.getToolCalls().size() > 0) {
            return false;
        }
        
        // Don't trim if current message is a tool result (it needs its tool call)
        if (ChatMessage.ChatMessageRole.TOOL.equals(currentMessage.getRole())) {
            return false;
        }
        
        return true;
    }
    
    /**
     * Format tool parameters for display in execution logs
     */
    private String formatToolParameters(JsonObject arguments) {
        if (arguments == null || arguments.size() == 0) {
            return "";
        }
        
        StringBuilder params = new StringBuilder();
        boolean first = true;
        
        for (String key : arguments.keySet()) {
            if (!first) {
                params.append(", ");
            }
            first = false;
            
            JsonElement value = arguments.get(key);
            if (value.isJsonPrimitive()) {
                String strValue = value.getAsString();
                // Add quotes around string values for clarity
                if (value.getAsJsonPrimitive().isString()) {
                    params.append("\"").append(strValue).append("\"");
                } else {
                    params.append(strValue);
                }
            } else {
                // For complex objects, just show the key
                params.append(key).append("=").append(value.toString());
            }
        }
        
        return params.toString();
    }
    
    /**
     * Execute MCP tool with proper Ghidra transaction handling
     * Run transaction on Swing EDT to match how Actions tab works
     */
    private CompletableFuture<MCPToolResult> executeToolWithTransaction(MCPToolManager toolManager, String toolName, JsonObject arguments) {
        CompletableFuture<MCPToolResult> future = new CompletableFuture<>();
        
        ghidra.program.model.listing.Program program = apiClient.getPlugin().getCurrentProgram();
        
        if (program == null) {
            // If no program is loaded, execute without transaction off EDT
            return toolManager.executeTool(toolName, arguments);
        }
        
        // Execute MCP call on background thread to avoid blocking EDT
        CompletableFuture.runAsync(() -> {
            // Start transaction on EDT
            final int[] transaction = new int[1];
            try {
                javax.swing.SwingUtilities.invokeAndWait(() -> {
                    transaction[0] = program.startTransaction("MCP Tool: " + toolName);
                });
            } catch (Exception e) {
                throw new RuntimeException("Failed to start transaction", e);
            }
            
            // Execute MCP call on background thread
            toolManager.executeTool(toolName, arguments)
                .thenAccept(result -> {
                    // End transaction on EDT
                    javax.swing.SwingUtilities.invokeLater(() -> {
                        boolean success = result.isSuccess();
                        program.endTransaction(transaction[0], success);
                        future.complete(result);
                    });
                })
                .exceptionally(throwable -> {
                    // End transaction on EDT with failure
                    javax.swing.SwingUtilities.invokeLater(() -> {
                        program.endTransaction(transaction[0], false);
                        Msg.error(this, "MCP tool execution failed: " + throwable.getMessage());
                        future.complete(MCPToolResult.error("Tool execution failed: " + throwable.getMessage()));
                    });
                    return null;
                });
                
        }).exceptionally(throwable -> {
            Msg.error(this, "Failed to start transaction: " + throwable.getMessage());
            future.complete(MCPToolResult.error("Failed to start transaction: " + throwable.getMessage()));
            return null;
        });
        
        return future;
    }
}