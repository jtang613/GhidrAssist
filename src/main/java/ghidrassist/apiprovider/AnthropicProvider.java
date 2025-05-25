package ghidrassist.apiprovider;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidrassist.LlmApi.LlmResponseHandler;
import ghidrassist.apiprovider.exceptions.APIProviderException;
import ghidrassist.apiprovider.capabilities.FunctionCallingProvider;
import ghidrassist.apiprovider.capabilities.ModelListProvider;
import okhttp3.*;
import okio.BufferedSource;

import javax.net.ssl.*;
import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class AnthropicProvider extends APIProvider implements FunctionCallingProvider, ModelListProvider {
    private static final Gson gson = new Gson();
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    private static final String ANTHROPIC_MESSAGES_ENDPOINT = "v1/messages";
    private static final String ANTHROPIC_MODELS_ENDPOINT = "v1/models";
    private static final int MAX_RETRY_ATTEMPTS = 3;
    private volatile boolean isCancelled = false;

    public AnthropicProvider(String name, String model, Integer maxTokens, String url, String key, boolean disableTlsVerification, Integer timeout) {
        super(name, ProviderType.ANTHROPIC, model, maxTokens, url, key, disableTlsVerification, timeout);
    }

    @Override
    protected OkHttpClient buildClient() {
        try {
            OkHttpClient.Builder builder = new OkHttpClient.Builder()
                .connectTimeout(super.timeout)
                .readTimeout(super.timeout)
                .writeTimeout(super.timeout)
                .retryOnConnectionFailure(true)
                .addInterceptor(chain -> {
                    Request originalRequest = chain.request();
                    Request.Builder requestBuilder = originalRequest.newBuilder()
                        .header("x-api-key", key)
                        .header("anthropic-version", "2023-06-01")
                        .header("Content-Type", "application/json");
                    
                    return chain.proceed(requestBuilder.build());
                });

            if (disableTlsVerification) {
                TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        @Override
                        public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {}
                        @Override
                        public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {}
                        @Override
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                            return new java.security.cert.X509Certificate[]{};
                        }
                    }
                };

                SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
                builder.sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) trustAllCerts[0])
                       .hostnameVerifier((hostname, session) -> true);
            }

            return builder.build();
        } catch (Exception e) {
            throw new RuntimeException("Failed to build HTTP client", e);
        }
    }

    @Override
    public String createChatCompletion(List<ChatMessage> messages) throws APIProviderException {
        JsonObject payload = buildMessagesPayload(messages, false);
        
        Request request = new Request.Builder()
            .url(url + ANTHROPIC_MESSAGES_ENDPOINT)
            .post(RequestBody.create(JSON, gson.toJson(payload)))
            .build();

        try (Response response = executeWithRetry(request, "createChatCompletion")) {
            JsonObject responseObj = gson.fromJson(response.body().string(), JsonObject.class);
            return responseObj.getAsJsonObject("content").get("text").getAsString();
        } catch (IOException e) {
            throw handleNetworkError(e, "createChatCompletion");
        }
    }

    @Override
    public void streamChatCompletion(List<ChatMessage> messages, LlmResponseHandler handler) throws APIProviderException {
        JsonObject payload = buildMessagesPayload(messages, true);

        Request request = new Request.Builder()
            .url(url + ANTHROPIC_MESSAGES_ENDPOINT)
            .post(RequestBody.create(JSON, gson.toJson(payload)))
            .build();

        client.newCall(request).enqueue(new Callback() {
            private boolean isFirst = true;
            private StringBuilder contentBuilder = new StringBuilder();

            @Override
            public void onFailure(Call call, IOException e) {
                handler.onError(handleNetworkError(e, "streamChatCompletion"));
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                try (ResponseBody responseBody = response.body()) {
                    if (!response.isSuccessful()) {
                        String errorBody = responseBody != null ? responseBody.string() : null;
                        handler.onError(handleHttpError(response, errorBody, "streamChatCompletion"));
                        return;
                    }

                    BufferedSource source = responseBody.source();
                    while (!source.exhausted() && !isCancelled && handler.shouldContinue()) {
                        String line = source.readUtf8Line();
                        if (line == null || line.isEmpty()) continue;
                        
                        // Skip ping events
                        if (line.equals("event: ping")) {
                            source.readUtf8Line(); // Skip data line
                            continue;
                        }
                        
                        if (line.startsWith("data: ")) {
                            String data = line.substring(6).trim();
                            if (data.equals("[DONE]")) {
                                handler.onComplete(contentBuilder.toString());
                                return;
                            }

                            JsonObject event = gson.fromJson(data, JsonObject.class);
                            
                            // Check for error events
                            if (event.has("type") && event.get("type").getAsString().equals("error")) {
                                handler.onError(new APIProviderException(APIProviderException.ErrorCategory.SERVICE_ERROR,
                                    name, "streamChatCompletion", event.get("error").getAsString()));
                                return;
                            }
                            
                            // Extract content from delta
                            if (event.has("type") && event.get("type").getAsString().equals("content_block_delta")) {
                                JsonObject delta = event.getAsJsonObject("delta");
                                String text = delta.get("text").getAsString();
                                
                                if (isFirst) {
                                    handler.onStart();
                                    isFirst = false;
                                }
                                contentBuilder.append(text);
                                handler.onUpdate(text);
                            }
                        }
                    }

                    if (isCancelled) {
                        handler.onError(new APIProviderException(APIProviderException.ErrorCategory.CANCELLED,
                            name, "streamChatCompletion", "Request cancelled"));
                    } else {
                        handler.onComplete(contentBuilder.toString());
                    }
                }
            }
        });
    }

    @Override
    public String createChatCompletionWithFunctionsFullResponse(List<ChatMessage> messages, List<Map<String, Object>> functions) throws APIProviderException {
        // Build payload with native Anthropic tools support
        JsonObject payload = buildMessagesPayload(messages, false);
        
        // Convert OpenAI function format to Anthropic tools format
        JsonArray anthropicTools = new JsonArray();
        for (Map<String, Object> tool : functions) {
            Map<String, Object> function = (Map<String, Object>) tool.get("function");
            
            JsonObject anthropicTool = new JsonObject();
            anthropicTool.addProperty("name", (String) function.get("name"));
            anthropicTool.addProperty("description", (String) function.get("description"));
            
            // Convert parameters schema to input_schema
            Map<String, Object> parameters = (Map<String, Object>) function.get("parameters");
            if (parameters != null) {
                anthropicTool.add("input_schema", gson.toJsonTree(parameters));
            }
            
            anthropicTools.add(anthropicTool);
        }
        
        payload.add("tools", anthropicTools);

        Request request = new Request.Builder()
            .url(url + ANTHROPIC_MESSAGES_ENDPOINT)
            .post(RequestBody.create(JSON, gson.toJson(payload)))
            .build();

        try (Response response = executeWithRetry(request, "createChatCompletionWithFunctionsFullResponse")) {
            JsonObject responseObj = gson.fromJson(response.body().string(), JsonObject.class);
            
            // Convert Anthropic response to OpenAI format
            JsonObject fullResponse = new JsonObject();
            JsonArray choices = new JsonArray();
            JsonObject choice = new JsonObject();
            JsonObject message = new JsonObject();
            
            message.addProperty("role", "assistant");
            
            // Parse Anthropic's content array for tool_use blocks
            String finishReason = "stop";
            JsonArray toolCalls = null;
            StringBuilder textContent = new StringBuilder();
            
            if (responseObj.has("content")) {
                JsonArray contentArray = responseObj.getAsJsonArray("content");
                
                for (JsonElement contentElement : contentArray) {
                    JsonObject contentBlock = contentElement.getAsJsonObject();
                    String type = contentBlock.get("type").getAsString();
                    
                    if ("tool_use".equals(type)) {
                        // Convert Anthropic tool_use to OpenAI tool_calls format
                        if (toolCalls == null) {
                            toolCalls = new JsonArray();
                            finishReason = "tool_calls";
                        }
                        
                        JsonObject toolCall = new JsonObject();
                        toolCall.addProperty("id", contentBlock.get("id").getAsString());
                        toolCall.addProperty("type", "function");
                        
                        JsonObject function = new JsonObject();
                        function.addProperty("name", contentBlock.get("name").getAsString());
                        function.addProperty("arguments", gson.toJson(contentBlock.get("input")));
                        toolCall.add("function", function);
                        
                        toolCalls.add(toolCall);
                        
                    } else if ("text".equals(type)) {
                        // Collect text content
                        if (contentBlock.has("text")) {
                            textContent.append(contentBlock.get("text").getAsString());
                        }
                    }
                }
            }
            
            // Set message content based on what we found
            if (toolCalls != null) {
                message.add("tool_calls", toolCalls);
                // Include any text content alongside tool calls
                if (textContent.length() > 0) {
                    message.addProperty("content", textContent.toString());
                }
            } else {
                message.addProperty("content", textContent.toString());
            }
            
            // Check stop_reason from Anthropic response
            if (responseObj.has("stop_reason")) {
                String anthropicStopReason = responseObj.get("stop_reason").getAsString();
                if ("tool_use".equals(anthropicStopReason)) {
                    finishReason = "tool_calls";
                } else {
                    finishReason = "stop";
                }
            }
            
            choice.add("message", message);
            choice.addProperty("finish_reason", finishReason);
            choice.addProperty("index", 0);
            choices.add(choice);
            
            fullResponse.add("choices", choices);
            fullResponse.addProperty("id", "chatcmpl-anthropic-" + System.currentTimeMillis());
            fullResponse.addProperty("object", "chat.completion");
            fullResponse.addProperty("created", System.currentTimeMillis() / 1000);
            fullResponse.addProperty("model", this.model);
            
            return gson.toJson(fullResponse);
            
        } catch (IOException e) {
            throw handleNetworkError(e, "createChatCompletionWithFunctionsFullResponse");
        }
    }
    

    @Override
    public String createChatCompletionWithFunctions(List<ChatMessage> messages, List<Map<String, Object>> functions) throws APIProviderException {
        // Build payload with native Anthropic tools support
        JsonObject payload = buildMessagesPayload(messages, false);
        
        // Convert OpenAI function format to Anthropic tools format
        JsonArray anthropicTools = new JsonArray();
        for (Map<String, Object> tool : functions) {
            @SuppressWarnings("unchecked")
            Map<String, Object> function = (Map<String, Object>) tool.get("function");
            
            JsonObject anthropicTool = new JsonObject();
            anthropicTool.addProperty("name", (String) function.get("name"));
            anthropicTool.addProperty("description", (String) function.get("description"));
            
            // Convert parameters schema to input_schema
            @SuppressWarnings("unchecked")
            Map<String, Object> parameters = (Map<String, Object>) function.get("parameters");
            if (parameters != null) {
                anthropicTool.add("input_schema", gson.toJsonTree(parameters));
            }
            
            anthropicTools.add(anthropicTool);
        }
        
        payload.add("tools", anthropicTools);

        Request request = new Request.Builder()
            .url(url + ANTHROPIC_MESSAGES_ENDPOINT)
            .post(RequestBody.create(JSON, gson.toJson(payload)))
            .build();

        try (Response response = executeWithRetry(request, "createChatCompletionWithFunctions")) {
            JsonObject responseObj = gson.fromJson(response.body().string(), JsonObject.class);
            
            // Extract content from Anthropic's response format
            JsonArray toolCallsArray = new JsonArray();
            StringBuilder textContent = new StringBuilder();
            
            if (responseObj.has("content")) {
                JsonArray contentArray = responseObj.getAsJsonArray("content");
                
                for (JsonElement contentElement : contentArray) {
                    JsonObject contentBlock = contentElement.getAsJsonObject();
                    String type = contentBlock.get("type").getAsString();
                    
                    if ("tool_use".equals(type)) {
                        // Convert tool_use to legacy OpenAI-style tool call format
                        JsonObject toolCall = new JsonObject();
                        toolCall.addProperty("id", contentBlock.get("id").getAsString());
                        toolCall.addProperty("type", "function");
                        
                        JsonObject function = new JsonObject();
                        function.addProperty("name", contentBlock.get("name").getAsString());
                        function.addProperty("arguments", gson.toJson(contentBlock.get("input")));
                        toolCall.add("function", function);
                        
                        toolCallsArray.add(toolCall);
                        
                    } else if ("text".equals(type)) {
                        // Append text content
                        if (contentBlock.has("text")) {
                            textContent.append(contentBlock.get("text").getAsString());
                        }
                    }
                }
            }
            
            // Return format expected by ActionParser
            if (toolCallsArray.size() > 0) {
                JsonObject result = new JsonObject();
                result.add("tool_calls", toolCallsArray);
                return gson.toJson(result);
            } else {
                return textContent.toString();
            }
            
        } catch (IOException e) {
            throw handleNetworkError(e, "createChatCompletionWithFunctions");
        }
    }

    @Override
    public List<String> getAvailableModels() throws APIProviderException {
        Request request = new Request.Builder()
            .url(url + ANTHROPIC_MODELS_ENDPOINT)
            .build();

        try (Response response = executeWithRetry(request, "getAvailableModels")) {
            JsonObject responseObj = gson.fromJson(response.body().string(), JsonObject.class);
            List<String> modelIds = new ArrayList<>();
            JsonArray models = responseObj.getAsJsonArray("models");
            
            for (JsonElement model : models) {
                modelIds.add(model.getAsJsonObject().get("id").getAsString());
            }
            
            return modelIds;
        } catch (IOException e) {
            throw handleNetworkError(e, "getAvailableModels");
        }
    }

    @Override
    public void getEmbeddingsAsync(String text, EmbeddingCallback callback) {
        // Anthropic does not currently provide a public embeddings endpoint
        callback.onError(new UnsupportedOperationException("Embeddings are not supported by the Anthropic API"));
    }

    private JsonObject buildMessagesPayload(List<ChatMessage> messages, boolean stream) {
        JsonObject payload = new JsonObject();
        payload.addProperty("model", super.getModel());
        payload.addProperty("max_tokens", super.getMaxTokens());
        payload.addProperty("stream", stream);

        // Convert the messages to Anthropic's format
        JsonArray messagesArray = new JsonArray();
        for (ChatMessage message : messages) {
            if (message.getRole().equals(ChatMessage.ChatMessageRole.SYSTEM)) {
                payload.addProperty("system", message.getContent());
            } else {
                JsonObject messageObj = new JsonObject();
                messageObj.addProperty("role", convertRole(message.getRole()));
                
                // Handle different message types for Anthropic format
                if (message.getRole().equals(ChatMessage.ChatMessageRole.TOOL)) {
                    // Tool result message - use tool_result content block
                    JsonArray contentArray = new JsonArray();
                    JsonObject toolResultBlock = new JsonObject();
                    toolResultBlock.addProperty("type", "tool_result");
                    toolResultBlock.addProperty("tool_use_id", message.getToolCallId());
                    toolResultBlock.addProperty("content", message.getContent());
                    
                    contentArray.add(toolResultBlock);
                    messageObj.add("content", contentArray);
                } else if (message.getToolCalls() != null) {
                    // Assistant message with tool calls - need to convert to content blocks
                    JsonArray contentArray = new JsonArray();
                    
                    // Add text content if present
                    if (message.getContent() != null && !message.getContent().isEmpty()) {
                        JsonObject textBlock = new JsonObject();
                        textBlock.addProperty("type", "text");
                        textBlock.addProperty("text", message.getContent());
                        contentArray.add(textBlock);
                    }
                    
                    // Convert tool_calls to tool_use blocks
                    JsonArray toolCalls = message.getToolCalls();
                    for (JsonElement toolCallElement : toolCalls) {
                        JsonObject toolCall = toolCallElement.getAsJsonObject();
                        JsonObject function = toolCall.getAsJsonObject("function");
                        
                        JsonObject toolUseBlock = new JsonObject();
                        toolUseBlock.addProperty("type", "tool_use");
                        toolUseBlock.addProperty("id", toolCall.get("id").getAsString());
                        toolUseBlock.addProperty("name", function.get("name").getAsString());
                        
                        // Parse arguments JSON string back to object
                        try {
                            JsonElement arguments = gson.fromJson(function.get("arguments").getAsString(), JsonElement.class);
                            toolUseBlock.add("input", arguments);
                        } catch (Exception e) {
                            // If parsing fails, use empty object
                            toolUseBlock.add("input", new JsonObject());
                        }
                        
                        contentArray.add(toolUseBlock);
                    }
                    
                    messageObj.add("content", contentArray);
                } else {
                    // Regular text message
                    messageObj.addProperty("content", message.getContent());
                }
                
                messagesArray.add(messageObj);
            }
        }
        payload.add("messages", messagesArray);

        return payload;
    }

    private String convertRole(String role) {
        switch (role) {
            case ChatMessage.ChatMessageRole.USER:
                return "user";
            case ChatMessage.ChatMessageRole.ASSISTANT:
                return "assistant";
            case ChatMessage.ChatMessageRole.FUNCTION:
                return "assistant"; // Anthropic doesn't have function messages, treat as assistant
            case ChatMessage.ChatMessageRole.TOOL:
                return "user"; // Tool results are sent as user messages in Anthropic
            default:
                return role;
        }
    }

    public void cancelRequest() {
        isCancelled = true;
    }
}