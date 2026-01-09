package ghidrassist.apiprovider;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.util.Msg;
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

    // Retry settings for streaming calls (matching RetryHandler defaults)
    private static final int MAX_STREAMING_RETRIES = 10;
    private static final int MIN_RETRY_BACKOFF_MS = 10000;  // 10 seconds
    private static final int MAX_RETRY_BACKOFF_MS = 30000;  // 30 seconds

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

            // Anthropic returns content as an array of content blocks
            // Extract text from all text blocks
            StringBuilder textContent = new StringBuilder();
            if (responseObj.has("content")) {
                JsonArray contentArray = responseObj.getAsJsonArray("content");
                for (JsonElement contentElement : contentArray) {
                    JsonObject contentBlock = contentElement.getAsJsonObject();
                    String type = contentBlock.get("type").getAsString();
                    if ("text".equals(type) && contentBlock.has("text")) {
                        textContent.append(contentBlock.get("text").getAsString());
                    }
                }
            }
            return textContent.toString();
        } catch (IOException e) {
            throw handleNetworkError(e, "createChatCompletion");
        }
    }

    @Override
    public void streamChatCompletion(List<ChatMessage> messages, LlmResponseHandler handler) throws APIProviderException {
        JsonObject payload = buildMessagesPayload(messages, true);
        executeStreamingWithRetry(payload, handler, "streamChatCompletion", 0);
    }

    /**
     * Execute streaming request with retry logic for rate limits and transient errors.
     */
    private void executeStreamingWithRetry(JsonObject payload, LlmResponseHandler handler,
                                           String operation, int attemptNumber) {
        if (isCancelled) {
            handler.onError(new APIProviderException(APIProviderException.ErrorCategory.CANCELLED,
                name, operation, "Request cancelled"));
            return;
        }

        Request request = new Request.Builder()
            .url(url + ANTHROPIC_MESSAGES_ENDPOINT)
            .post(RequestBody.create(JSON, gson.toJson(payload)))
            .build();

        client.newCall(request).enqueue(new Callback() {
            private boolean isFirst = true;
            private StringBuilder contentBuilder = new StringBuilder();

            @Override
            public void onFailure(Call call, IOException e) {
                APIProviderException error = handleNetworkError(e, operation);
                if (shouldRetryStreaming(error, attemptNumber)) {
                    retryStreamingAfterDelay(payload, handler, operation, attemptNumber, error);
                } else {
                    handler.onError(error);
                }
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                try (ResponseBody responseBody = response.body()) {
                    if (!response.isSuccessful()) {
                        String errorBody = responseBody != null ? responseBody.string() : null;
                        APIProviderException error = handleHttpError(response, errorBody, operation);

                        if (shouldRetryStreaming(error, attemptNumber)) {
                            retryStreamingAfterDelay(payload, handler, operation, attemptNumber, error);
                        } else {
                            handler.onError(error);
                        }
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
                                    name, operation, event.get("error").getAsString()));
                                return;
                            }

                            // Extract content from delta
                            if (event.has("type") && event.get("type").getAsString().equals("content_block_delta")) {
                                JsonObject delta = event.getAsJsonObject("delta");

                                // Check if this is a text delta (skip thinking deltas)
                                if (delta.has("text")) {
                                    String text = delta.get("text").getAsString();

                                    if (isFirst) {
                                        handler.onStart();
                                        isFirst = false;
                                    }
                                    contentBuilder.append(text);
                                    handler.onUpdate(text);
                                }
                                // Thinking deltas are silently ignored (not displayed)
                            }
                        }
                    }

                    if (isCancelled) {
                        handler.onError(new APIProviderException(APIProviderException.ErrorCategory.CANCELLED,
                            name, operation, "Request cancelled"));
                    } else {
                        handler.onComplete(contentBuilder.toString());
                    }
                }
            }
        });
    }

    /**
     * Check if a streaming error should be retried.
     */
    private boolean shouldRetryStreaming(APIProviderException error, int attemptNumber) {
        if (attemptNumber >= MAX_STREAMING_RETRIES) {
            return false;
        }

        switch (error.getCategory()) {
            case RATE_LIMIT:
            case NETWORK:
            case TIMEOUT:
            case SERVICE_ERROR:
                return true;
            default:
                return false;
        }
    }

    /**
     * Retry streaming request after appropriate delay.
     */
    private void retryStreamingAfterDelay(JsonObject payload, LlmResponseHandler handler,
                                          String operation, int attemptNumber, APIProviderException error) {
        int nextAttempt = attemptNumber + 1;
        int waitTimeMs = calculateStreamingRetryWait(error);

        Msg.warn(this, String.format("Streaming retry %d/%d for %s: %s. Waiting %d seconds...",
            nextAttempt, MAX_STREAMING_RETRIES, operation,
            error.getCategory().getDisplayName(), waitTimeMs / 1000));

        // Schedule retry on a background thread
        new Thread(() -> {
            try {
                Thread.sleep(waitTimeMs);
                if (!isCancelled) {
                    executeStreamingWithRetry(payload, handler, operation, nextAttempt);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                handler.onError(new APIProviderException(APIProviderException.ErrorCategory.CANCELLED,
                    name, operation, "Retry interrupted"));
            }
        }, "AnthropicProvider-StreamRetry").start();
    }

    /**
     * Calculate wait time for streaming retry with jitter.
     */
    private int calculateStreamingRetryWait(APIProviderException error) {
        // For rate limits, use retry-after if available
        if (error.getCategory() == APIProviderException.ErrorCategory.RATE_LIMIT) {
            Integer retryAfter = error.getRetryAfterSeconds();
            if (retryAfter != null && retryAfter > 0) {
                return retryAfter * 1000;
            }
        }
        // Random backoff between MIN and MAX
        return MIN_RETRY_BACKOFF_MS + (int) (Math.random() * (MAX_RETRY_BACKOFF_MS - MIN_RETRY_BACKOFF_MS));
    }

    /**
     * Retry streaming function call request after appropriate delay.
     */
    private void retryStreamingFunctionsAfterDelay(JsonObject payload, StreamingFunctionHandler handler,
                                                   String operation, int attemptNumber, APIProviderException error) {
        int nextAttempt = attemptNumber + 1;
        int waitTimeMs = calculateStreamingRetryWait(error);

        Msg.warn(this, String.format("Streaming functions retry %d/%d for %s: %s. Waiting %d seconds...",
            nextAttempt, MAX_STREAMING_RETRIES, operation,
            error.getCategory().getDisplayName(), waitTimeMs / 1000));

        // Schedule retry on a background thread
        new Thread(() -> {
            try {
                Thread.sleep(waitTimeMs);
                if (!isCancelled) {
                    executeStreamingFunctionsWithRetry(payload, handler, operation, nextAttempt);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                handler.onError(new APIProviderException(APIProviderException.ErrorCategory.CANCELLED,
                    name, operation, "Retry interrupted"));
            }
        }, "AnthropicProvider-StreamFunctionsRetry").start();
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

        // Force tool use - "any" means model must use at least one tool
        JsonObject toolChoice = new JsonObject();
        toolChoice.addProperty("type", "any");
        payload.add("tool_choice", toolChoice);

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
            JsonObject result = new JsonObject();
            result.add("tool_calls", toolCallsArray);
            return gson.toJson(result);
            
        } catch (IOException e) {
            throw handleNetworkError(e, "createChatCompletionWithFunctions");
        }
    }

    /**
     * Stream chat completion with function calling support.
     * Text blocks stream immediately; tool_use blocks are buffered until complete.
     */
    public void streamChatCompletionWithFunctions(
        List<ChatMessage> messages,
        List<Map<String, Object>> functions,
        StreamingFunctionHandler handler
    ) throws APIProviderException {
        // Build payload with native Anthropic tools support
        JsonObject payload = buildMessagesPayload(messages, true); // true for streaming

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

        executeStreamingFunctionsWithRetry(payload, handler, "streamChatCompletionWithFunctions", 0);
    }

    /**
     * Execute streaming function call request with retry logic.
     */
    private void executeStreamingFunctionsWithRetry(JsonObject payload, StreamingFunctionHandler handler,
                                                    String operation, int attemptNumber) {
        if (isCancelled) {
            handler.onError(new APIProviderException(APIProviderException.ErrorCategory.CANCELLED,
                name, operation, "Request cancelled"));
            return;
        }

        Request request = new Request.Builder()
            .url(url + ANTHROPIC_MESSAGES_ENDPOINT)
            .post(RequestBody.create(JSON, gson.toJson(payload)))
            .build();

        client.newCall(request).enqueue(new Callback() {
            private final java.util.Map<Integer, ContentBlock> contentBlocks = new java.util.HashMap<>();
            private String stopReason = null;

            @Override
            public void onFailure(Call call, IOException e) {
                APIProviderException error = handleNetworkError(e, operation);
                if (shouldRetryStreaming(error, attemptNumber)) {
                    retryStreamingFunctionsAfterDelay(payload, handler, operation, attemptNumber, error);
                } else {
                    handler.onError(error);
                }
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                try (ResponseBody responseBody = response.body()) {
                    if (!response.isSuccessful()) {
                        String errorBody = responseBody != null ? responseBody.string() : null;
                        APIProviderException error = handleHttpError(response, errorBody, operation);

                        if (shouldRetryStreaming(error, attemptNumber)) {
                            retryStreamingFunctionsAfterDelay(payload, handler, operation, attemptNumber, error);
                        } else {
                            handler.onError(error);
                        }
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
                                processStreamComplete();
                                return;
                            }

                            try {
                                JsonObject event = gson.fromJson(data, JsonObject.class);

                                // Check for error events
                                if (event.has("type") && event.get("type").getAsString().equals("error")) {
                                    String errorMsg = event.has("error") ?
                                        event.getAsJsonObject("error").get("message").getAsString() :
                                        "Unknown streaming error";
                                    handler.onError(new APIProviderException(
                                        APIProviderException.ErrorCategory.SERVICE_ERROR,
                                        name, "streamChatCompletionWithFunctions", errorMsg));
                                    return;
                                }

                                processEvent(event);

                            } catch (Exception e) {
                                handler.onError(new APIProviderException(
                                    APIProviderException.ErrorCategory.RESPONSE_ERROR,
                                    name, "streamChatCompletionWithFunctions",
                                    "Failed to parse streaming event: " + e.getMessage()));
                                return;
                            }
                        }
                    }

                    if (isCancelled) {
                        handler.onError(new APIProviderException(
                            APIProviderException.ErrorCategory.CANCELLED,
                            name, "streamChatCompletionWithFunctions", "Request cancelled"));
                    } else {
                        processStreamComplete();
                    }
                }
            }

            private void processEvent(JsonObject event) {
                String eventType = event.get("type").getAsString();

                switch (eventType) {
                    case "content_block_start":
                        handleContentBlockStart(event);
                        break;
                    case "content_block_delta":
                        handleContentBlockDelta(event);
                        break;
                    case "message_delta":
                        handleMessageDelta(event);
                        break;
                    case "message_stop":
                        // Final event - will be handled after loop exits
                        break;
                }
            }

            private void handleContentBlockStart(JsonObject event) {
                int index = event.get("index").getAsInt();
                JsonObject contentBlock = event.getAsJsonObject("content_block");
                String type = contentBlock.get("type").getAsString();

                ContentBlock block = new ContentBlock(index, type);

                // If tool_use, extract id and name
                if ("tool_use".equals(type)) {
                    block.toolId = contentBlock.get("id").getAsString();
                    block.toolName = contentBlock.get("name").getAsString();
                }

                contentBlocks.put(index, block);
            }

            private void handleContentBlockDelta(JsonObject event) {
                int index = event.get("index").getAsInt();
                ContentBlock block = contentBlocks.get(index);
                if (block == null) return;

                JsonObject delta = event.getAsJsonObject("delta");

                if ("text".equals(block.type) && delta.has("text")) {
                    // Stream text immediately
                    String textDelta = delta.get("text").getAsString();
                    block.textBuffer.append(textDelta);
                    handler.onTextUpdate(textDelta);

                } else if ("tool_use".equals(block.type) && delta.has("partial_json")) {
                    // Buffer tool input deltas
                    String inputDelta = delta.get("partial_json").getAsString();
                    block.inputBuffer.append(inputDelta);

                } else if ("thinking".equals(block.type) && delta.has("thinking")) {
                    // Buffer thinking content (don't stream to UI)
                    // Store for potential future "Show Thinking" feature
                    String thinkingDelta = delta.get("thinking").getAsString();
                    block.textBuffer.append(thinkingDelta);
                    // Note: We intentionally don't call handler.onTextUpdate() for thinking blocks

                } else if ("thinking".equals(block.type) && delta.has("signature")) {
                    // Buffer signature for thinking blocks
                    String signatureDelta = delta.get("signature").getAsString();
                    block.signatureBuffer.append(signatureDelta);
                }
            }

            private void handleMessageDelta(JsonObject event) {
                JsonObject delta = event.getAsJsonObject("delta");
                if (delta.has("stop_reason")) {
                    stopReason = delta.get("stop_reason").getAsString();
                }
            }

            private void processStreamComplete() {
                // Extract full text from text blocks
                String fullText = contentBlocks.values().stream()
                    .filter(b -> "text".equals(b.type))
                    .sorted((a, b) -> Integer.compare(a.index, b.index))
                    .map(b -> b.textBuffer.toString())
                    .collect(java.util.stream.Collectors.joining());

                // Extract thinking content and signature from thinking blocks
                String thinkingContent = contentBlocks.values().stream()
                    .filter(b -> "thinking".equals(b.type))
                    .sorted((a, b) -> Integer.compare(a.index, b.index))
                    .map(b -> b.textBuffer.toString())
                    .collect(java.util.stream.Collectors.joining());

                String thinkingSignature = contentBlocks.values().stream()
                    .filter(b -> "thinking".equals(b.type))
                    .sorted((a, b) -> Integer.compare(a.index, b.index))
                    .map(b -> b.signatureBuffer.toString())
                    .collect(java.util.stream.Collectors.joining());

                // Parse tool calls from tool_use blocks
                List<ToolCall> toolCalls = new ArrayList<>();
                for (ContentBlock block : contentBlocks.values()) {
                    if ("tool_use".equals(block.type)) {
                        String arguments = block.inputBuffer.toString().trim();

                        // Ensure we have valid arguments (not empty)
                        // If empty, use empty object as default
                        if (arguments.isEmpty()) {
                            arguments = "{}";
                        }

                        toolCalls.add(new ToolCall(
                            block.toolId,
                            block.toolName,
                            arguments
                        ));
                    }
                }

                // Sort tool calls by index
                toolCalls.sort((a, b) -> {
                    int indexA = contentBlocks.values().stream()
                        .filter(cb -> cb.toolId != null && cb.toolId.equals(a.id))
                        .findFirst()
                        .map(cb -> cb.index)
                        .orElse(0);
                    int indexB = contentBlocks.values().stream()
                        .filter(cb -> cb.toolId != null && cb.toolId.equals(b.id))
                        .findFirst()
                        .map(cb -> cb.index)
                        .orElse(0);
                    return Integer.compare(indexA, indexB);
                });

                // Callback with complete data including thinking content and signature
                handler.onStreamComplete(
                    stopReason != null ? stopReason : "end_turn",
                    fullText,
                    thinkingContent.isEmpty() ? null : thinkingContent,
                    thinkingSignature.isEmpty() ? null : thinkingSignature,
                    toolCalls
                );
            }
        });
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
        //payload.addProperty("max_tokens", 64000);
        payload.addProperty("stream", stream);

        // Check if thinking can be enabled - all assistant messages must have valid thinking data
        // Anthropic requires that when thinking is enabled, ALL assistant messages MUST start with
        // a thinking block. If any assistant message lacks thinking data (e.g., old conversations
        // before thinking persistence was implemented), we must disable thinking for this request.
        ReasoningConfig reasoning = getReasoningConfig();
        boolean canEnableThinking = reasoning != null && reasoning.isEnabled();

        if (canEnableThinking) {
            // Scan messages to check if all assistant messages have valid thinking data
            for (ChatMessage message : messages) {
                if (message.getRole().equals(ChatMessage.ChatMessageRole.ASSISTANT)) {
                    String thinkingContent = message.getThinkingContent();
                    String thinkingSignature = message.getThinkingSignature();

                    // If ANY assistant message lacks valid thinking data, we cannot use thinking
                    if (thinkingContent == null || thinkingContent.isEmpty() ||
                        thinkingSignature == null || thinkingSignature.isEmpty()) {
                        Msg.debug(this, "Disabling thinking for this request - an assistant message " +
                            "lacks valid thinking content/signature (may be from older conversation)");
                        canEnableThinking = false;
                        break;
                    }
                }
            }
        }

        if (canEnableThinking) {
            int budget = reasoning.getAnthropicBudget();
            // Ensure budget_tokens is less than max_tokens
            Integer maxTokens = super.getMaxTokens();
            if (maxTokens != null && budget >= maxTokens) {
                budget = Math.max(1024, maxTokens - 1000);
            }
            JsonObject thinking = new JsonObject();
            thinking.addProperty("type", "enabled");
            thinking.addProperty("budget_tokens", budget);
            payload.add("thinking", thinking);
        }

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

                    // When thinking is enabled AND valid for all messages (canEnableThinking),
                    // include thinking blocks from the original API response.
                    if (canEnableThinking) {
                        String thinkingContent = message.getThinkingContent();
                        String thinkingSignature = message.getThinkingSignature();

                        // We already verified all messages have valid thinking data in the pre-check,
                        // so we can safely add the thinking block here
                        if (thinkingContent != null && !thinkingContent.isEmpty() &&
                            thinkingSignature != null && !thinkingSignature.isEmpty()) {
                            JsonObject thinkingBlock = new JsonObject();
                            thinkingBlock.addProperty("type", "thinking");
                            thinkingBlock.addProperty("thinking", thinkingContent);
                            thinkingBlock.addProperty("signature", thinkingSignature);
                            contentArray.add(thinkingBlock);
                        }
                    }

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
                            JsonElement argumentsElement = function.get("arguments");
                            if (argumentsElement != null && !argumentsElement.isJsonNull()) {
                                String argumentsStr = argumentsElement.getAsString();
                                if (argumentsStr != null && !argumentsStr.trim().isEmpty()) {
                                    JsonElement arguments = gson.fromJson(argumentsStr, JsonElement.class);
                                    toolUseBlock.add("input", arguments);
                                } else {
                                    // Empty arguments string, use empty object
                                    toolUseBlock.add("input", new JsonObject());
                                }
                            } else {
                                // No arguments field, use empty object
                                toolUseBlock.add("input", new JsonObject());
                            }
                        } catch (Exception e) {
                            // If parsing fails, use empty object
                            System.err.println("AnthropicProvider: Failed to parse tool arguments: " + e.getMessage());
                            toolUseBlock.add("input", new JsonObject());
                        }
                        
                        contentArray.add(toolUseBlock);
                    }
                    
                    messageObj.add("content", contentArray);
                } else {
                    // Regular text message - ensure content is not null or empty
                    String content = message.getContent();
                    if (content == null || content.trim().isEmpty()) {
                        // Skip messages with empty content (Anthropic rejects them)
                        // This can happen on first load or with malformed conversation history
                        Msg.debug(this, "Skipping message with empty content, role=" + message.getRole());
                        continue;
                    }
                    messageObj.addProperty("content", content);
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

    /**
     * Callback interface for streaming function calling responses.
     * Allows text content to stream immediately while buffering tool calls.
     */
    public interface StreamingFunctionHandler {
        /**
         * Called when a text delta arrives during streaming.
         * @param textDelta The incremental text content
         */
        void onTextUpdate(String textDelta);

        /**
         * Called when streaming completes with all content blocks processed.
         * @param stopReason The reason streaming stopped ("end_turn" or "tool_use")
         * @param fullText Complete text content from all text blocks
         * @param thinkingContent Complete thinking/reasoning content (may be null)
         * @param thinkingSignature Thinking signature for verification (may be null)
         * @param toolCalls List of tool calls to execute (may be empty)
         */
        void onStreamComplete(String stopReason, String fullText, String thinkingContent, String thinkingSignature, List<ToolCall> toolCalls);

        /**
         * Called if an error occurs during streaming.
         * @param error The error that occurred
         */
        void onError(Throwable error);

        /**
         * Check if streaming should continue.
         * @return true if streaming should continue, false to cancel
         */
        boolean shouldContinue();
    }

    /**
     * Represents a tool call extracted from streaming response.
     */
    public static class ToolCall {
        public final String id;
        public final String name;
        public final String arguments;

        public ToolCall(String id, String name, String arguments) {
            this.id = id;
            this.name = name;
            this.arguments = arguments;
        }
    }

    /**
     * Helper class to track content blocks during streaming.
     */
    private static class ContentBlock {
        final int index;
        final String type;
        final StringBuilder textBuffer = new StringBuilder();
        final StringBuilder signatureBuffer = new StringBuilder();  // For thinking signatures

        // For tool_use blocks
        String toolId;
        String toolName;
        final StringBuilder inputBuffer = new StringBuilder();

        ContentBlock(int index, String type) {
            this.index = index;
            this.type = type;
        }
    }

    public void cancelRequest() {
        isCancelled = true;
    }
}