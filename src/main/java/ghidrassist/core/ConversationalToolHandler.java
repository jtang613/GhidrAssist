package ghidrassist.core;

import ghidrassist.LlmApi;
import ghidrassist.apiprovider.ChatMessage;
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
    
    private final List<ChatMessage> conversationHistory;
    private final StringBuilder conversationOutput;
    private volatile boolean isConversationActive = false;
    
    public ConversationalToolHandler(
            LlmApiClient apiClient,
            List<Map<String, Object>> functions,
            ResponseProcessor responseProcessor,
            LlmApi.LlmResponseHandler userHandler,
            LlmErrorHandler errorHandler) {
        
        this.apiClient = apiClient;
        this.availableFunctions = functions;
        this.responseProcessor = responseProcessor;
        this.userHandler = userHandler;
        this.errorHandler = errorHandler;
        this.conversationHistory = new ArrayList<>();
        this.conversationOutput = new StringBuilder();
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
        conversationHistory.clear();
        conversationOutput.setLength(0);
        
        // Add initial user message
        conversationHistory.addAll(apiClient.createFunctionMessages(userPrompt));
        
        // Start the conversation loop
        userHandler.onStart();
        continueConversation();
    }
    
    /**
     * Continue the conversation with the current message history
     */
    private void continueConversation() {
        if (!isConversationActive) {
            return;
        }
        
        try {
            // Call LLM with current conversation history
            CompletableFuture.runAsync(() -> {
                try {
                    String fullResponse = apiClient.createChatCompletionWithFunctionsFullResponse(
                        conversationHistory, availableFunctions);
                    
                    // Parse the response to check for tool calls and finish_reason
                    handleLLMResponse(fullResponse);
                    
                } catch (Exception e) {
                    isConversationActive = false;
                    userHandler.onError(e);
                }
            });
            
        } catch (Exception e) {
            isConversationActive = false;
            userHandler.onError(e);
        }
    }
    
    /**
     * Handle the LLM response and determine next action based on finish_reason
     */
    private void handleLLMResponse(String rawResponse) {
        try {
            Msg.info(this, "Raw LLM response: " + (rawResponse != null ? rawResponse : "NULL"));
            
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
            
            Msg.info(this, "LLM finish_reason: " + finishReason);
            
            if ("tool_calls".equals(finishReason) || "tool_use".equals(finishReason)) {
                handleToolCalls(assistantMessage, rawResponse);
            } else if ("stop".equals(finishReason) || "unknown".equals(finishReason)) {
                // Handle normal completion (no tools needed) or unknown finish_reason
                handleConversationEnd(assistantMessage);
            } else {
                // Other finish_reason types (length, content_filter, etc.)
                Msg.info(this, "LLM finished with reason: " + finishReason + ", ending conversation");
                handleConversationEnd(assistantMessage);
            }
            
        } catch (Exception e) {
            Msg.error(this, "Error handling LLM response: " + e.getMessage());
            Msg.error(this, "Response content: " + (rawResponse != null ? rawResponse.substring(0, Math.min(500, rawResponse.length())) : "NULL"));
            isConversationActive = false;
            userHandler.onError(e);
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
            
            // Update UI with tool calling status
            String toolExecutionHeader = "\n\n**🔧 Executing Tools...**\n";
            conversationOutput.append(toolExecutionHeader);
            javax.swing.SwingUtilities.invokeLater(() -> {
                userHandler.onUpdate(toolExecutionHeader);
            });
            
            // Execute tools and collect results
            executeToolsSequentially(toolCalls, 0, new ArrayList<>());
            
        } catch (Exception e) {
            Msg.error(this, "Error handling tool calls: " + e.getMessage());
            isConversationActive = false;
            userHandler.onError(e);
        }
    }
    
    /**
     * Execute tools sequentially and collect results
     */
    private void executeToolsSequentially(JsonArray toolCalls, int index, List<JsonObject> toolResults) {
        if (index >= toolCalls.size()) {
            // All tools executed, add results to conversation and continue
            addToolResultsToConversation(toolResults);
            continueConversation();
            return;
        }
        
        JsonObject toolCall = toolCalls.get(index).getAsJsonObject();
        executeSingleTool(toolCall)
            .thenAccept(result -> {
                toolResults.add(result);
                executeToolsSequentially(toolCalls, index + 1, toolResults);
            })
            .exceptionally(throwable -> {
                Msg.error(this, "Tool execution failed: " + throwable.getMessage());
                
                // Create error result and continue
                JsonObject errorResult = new JsonObject();
                errorResult.addProperty("tool_call_id", extractToolCallId(toolCall));
                errorResult.addProperty("role", "tool");
                errorResult.addProperty("content", "Error: " + throwable.getMessage());
                toolResults.add(errorResult);
                
                executeToolsSequentially(toolCalls, index + 1, toolResults);
                return null;
            });
    }
    
    /**
     * Execute a single tool and return the result
     */
    private CompletableFuture<JsonObject> executeSingleTool(JsonObject toolCall) {
        try {
            String toolName = extractToolName(toolCall);
            JsonObject arguments = extractToolArguments(toolCall);
            String toolCallId = extractToolCallId(toolCall);
            
            // Update UI with current tool execution
            String executingMessage = "**Executing: " + toolName + "**\n";
            conversationOutput.append(executingMessage);
            javax.swing.SwingUtilities.invokeLater(() -> {
                userHandler.onUpdate(executingMessage);
            });
            
            // Execute via MCP
            MCPToolManager toolManager = MCPToolManager.getInstance();
            return toolManager.executeTool(toolName, arguments)
                .thenApply(mcpResult -> {
                    // Update UI with tool result
                    String resultText = mcpResult.getResultText();
                    String resultMessage = "**" + toolName + " Result:**\n" + resultText + "\n\n";
                    conversationOutput.append(resultMessage);
                    
                    javax.swing.SwingUtilities.invokeLater(() -> {
                        userHandler.onUpdate(resultMessage);
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
            
            // Combine the accumulated conversation output with the final response
            String completeResponse;
            if (conversationOutput.length() > 0) {
                completeResponse = conversationOutput.toString() + "\n" + filteredContent;
            } else {
                completeResponse = filteredContent;
            }
            
            // Update UI with final response that includes all tool execution history
            javax.swing.SwingUtilities.invokeLater(() -> {
                userHandler.onUpdate(completeResponse);
                userHandler.onComplete(completeResponse);
            });
            
        } catch (Exception e) {
            Msg.error(this, "Error handling conversation end: " + e.getMessage());
            // Provide fallback response
            javax.swing.SwingUtilities.invokeLater(() -> {
                userHandler.onUpdate("I encountered an error processing the response. Please try again.");
                userHandler.onComplete("Error processing response");
            });
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
}