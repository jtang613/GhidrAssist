package ghidrassist.apiprovider;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidrassist.LlmApi.LlmResponseHandler;
import ghidrassist.apiprovider.exceptions.APIProviderException;
import ghidrassist.apiprovider.capabilities.FunctionCallingProvider;
import ghidrassist.apiprovider.capabilities.ModelListProvider;
import ghidrassist.apiprovider.capabilities.EmbeddingProvider;
import okhttp3.*;
import okio.BufferedSource;

import javax.net.ssl.*;
import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class LMStudioProvider extends APIProvider implements FunctionCallingProvider, ModelListProvider, EmbeddingProvider {
    private static final Gson gson = new Gson();
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    private static final String LMSTUDIO_CHAT_ENDPOINT = "v1/chat/completions";
    private static final String LMSTUDIO_MODELS_ENDPOINT = "v1/models";
    private static final String LMSTUDIO_EMBEDDINGS_ENDPOINT = "v1/embeddings";
    private volatile boolean isCancelled = false;

    public LMStudioProvider(String name, String model, Integer maxTokens, String url, String key, boolean disableTlsVerification, Integer timeout) {
        super(name, ProviderType.LMSTUDIO, model, maxTokens, url, key, disableTlsVerification, timeout);
    }

    @Override
    protected OkHttpClient buildClient() {
        try {
            OkHttpClient.Builder builder = new OkHttpClient.Builder()
                .connectTimeout(super.timeout)
                .readTimeout(super.timeout)
                .writeTimeout(super.timeout)
                .retryOnConnectionFailure(true);

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
        JsonObject payload = buildChatCompletionPayload(messages, false);
        
        Request request = new Request.Builder()
            .url(super.getUrl() + LMSTUDIO_CHAT_ENDPOINT)
            .post(RequestBody.create(JSON, gson.toJson(payload)))
            .build();

        try (Response response = executeWithRetry(request, "createChatCompletion")) {
            JsonObject responseObj = gson.fromJson(response.body().string(), JsonObject.class);
            return extractContentFromResponse(responseObj);
        } catch (IOException e) {
            throw handleNetworkError(e, "createChatCompletion");
        }
    }

    @Override
    public void streamChatCompletion(List<ChatMessage> messages, LlmResponseHandler handler) throws APIProviderException {
        JsonObject payload = buildChatCompletionPayload(messages, true);

        Request request = new Request.Builder()
            .url(super.getUrl() + LMSTUDIO_CHAT_ENDPOINT)
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
                        if (line.startsWith("data: ")) {
                            String data = line.substring(6).trim();
                            if (data.equals("[DONE]")) {
                                handler.onComplete(contentBuilder.toString());
                                return;
                            }

                            JsonObject chunk = gson.fromJson(data, JsonObject.class);
                            String content = extractDeltaContent(chunk);
                            
                            if (content != null) {
                                if (isFirst) {
                                    handler.onStart();
                                    isFirst = false;
                                }
                                contentBuilder.append(content);
                                handler.onUpdate(content);
                            }
                        }
                    }

                    if (isCancelled) {
                        handler.onError(new APIProviderException(APIProviderException.ErrorCategory.CANCELLED,
                            name, "streamChatCompletion", "Request cancelled"));
                    }
                }
            }
        });
    }

    @Override
    public String createChatCompletionWithFunctionsFullResponse(List<ChatMessage> messages, List<Map<String, Object>> functions) throws APIProviderException {
        JsonObject payload = buildChatCompletionPayload(messages, true); // Enable streaming

        // LMStudio uses the modern 'tools' format, not 'functions'
        payload.add("tools", gson.toJsonTree(functions));

        Request request = new Request.Builder()
            .url(super.getUrl() + LMSTUDIO_CHAT_ENDPOINT)
            .post(RequestBody.create(JSON, gson.toJson(payload)))
            .build();

        try (Response response = executeWithRetry(request, "createChatCompletionWithFunctionsFullResponse")) {
            // Handle streaming response - accumulate all chunks
            StringBuilder contentBuilder = new StringBuilder();
            java.util.Map<Integer, JsonObject> toolCallsMap = new java.util.HashMap<>();
            String finishReason = "stop";
            String responseId = null;

            try (ResponseBody responseBody = response.body()) {
                BufferedSource source = responseBody.source();
                while (!source.exhausted()) {
                    String line = source.readUtf8Line();
                    if (line == null || line.isEmpty()) continue;

                    if (line.startsWith("data: ")) {
                        String data = line.substring(6).trim();
                        if (data.equals("[DONE]")) {
                            break;
                        }

                        JsonObject chunk = gson.fromJson(data, JsonObject.class);

                        // Capture response ID from first chunk
                        if (responseId == null && chunk.has("id")) {
                            responseId = chunk.get("id").getAsString();
                        }

                        // Accumulate content and tool_calls from deltas
                        if (chunk.has("choices")) {
                            JsonArray choices = chunk.getAsJsonArray("choices");
                            if (choices.size() > 0) {
                                JsonObject choice = choices.get(0).getAsJsonObject();

                                // Handle delta content
                                if (choice.has("delta")) {
                                    JsonObject delta = choice.getAsJsonObject("delta");

                                    // Accumulate text content
                                    if (delta.has("content") && !delta.get("content").isJsonNull()) {
                                        contentBuilder.append(delta.get("content").getAsString());
                                    }

                                    // Accumulate tool_calls - they come as deltas that need to be merged
                                    if (delta.has("tool_calls")) {
                                        JsonArray toolCallDeltas = delta.getAsJsonArray("tool_calls");
                                        for (JsonElement tcElement : toolCallDeltas) {
                                            JsonObject toolCallDelta = tcElement.getAsJsonObject();

                                            // Each delta has an index to identify which tool call it belongs to
                                            int index = toolCallDelta.has("index") ? toolCallDelta.get("index").getAsInt() : 0;

                                            // Get or create the accumulated tool call for this index
                                            JsonObject accumulatedToolCall = toolCallsMap.computeIfAbsent(index, k -> new JsonObject());

                                            // Merge fields from delta into accumulated tool call
                                            if (toolCallDelta.has("id")) {
                                                accumulatedToolCall.addProperty("id", toolCallDelta.get("id").getAsString());
                                            }
                                            if (toolCallDelta.has("type")) {
                                                accumulatedToolCall.addProperty("type", toolCallDelta.get("type").getAsString());
                                            }
                                            if (toolCallDelta.has("index")) {
                                                accumulatedToolCall.addProperty("index", index);
                                            }

                                            // Merge function object
                                            if (toolCallDelta.has("function")) {
                                                JsonObject functionDelta = toolCallDelta.getAsJsonObject("function");
                                                JsonObject accumulatedFunction = accumulatedToolCall.has("function")
                                                    ? accumulatedToolCall.getAsJsonObject("function")
                                                    : new JsonObject();

                                                // Accumulate function name
                                                if (functionDelta.has("name")) {
                                                    accumulatedFunction.addProperty("name", functionDelta.get("name").getAsString());
                                                }

                                                // Accumulate function arguments (they come in chunks)
                                                if (functionDelta.has("arguments")) {
                                                    String existingArgs = accumulatedFunction.has("arguments")
                                                        ? accumulatedFunction.get("arguments").getAsString()
                                                        : "";
                                                    String newArgs = functionDelta.get("arguments").getAsString();
                                                    accumulatedFunction.addProperty("arguments", existingArgs + newArgs);
                                                }

                                                accumulatedToolCall.add("function", accumulatedFunction);
                                            }
                                        }
                                    }
                                }

                                // Capture finish_reason from final chunk
                                if (choice.has("finish_reason") && !choice.get("finish_reason").isJsonNull()) {
                                    finishReason = choice.get("finish_reason").getAsString();
                                }
                            }
                        }
                    }
                }
            }

            // Build a complete OpenAI-format response from accumulated data
            JsonObject responseObj = new JsonObject();
            responseObj.addProperty("id", responseId != null ? responseId : "chatcmpl-lmstudio-" + System.currentTimeMillis());
            responseObj.addProperty("object", "chat.completion");
            responseObj.addProperty("created", System.currentTimeMillis() / 1000);
            responseObj.addProperty("model", this.model);

            JsonArray choices = new JsonArray();
            JsonObject choice = new JsonObject();
            choice.addProperty("index", 0);

            // Build the message object from accumulated content
            JsonObject message = new JsonObject();
            message.addProperty("role", "assistant");
            message.addProperty("content", contentBuilder.toString());

            // Convert accumulated tool_calls map to array
            if (!toolCallsMap.isEmpty()) {
                JsonArray toolCallsArray = new JsonArray();
                // Sort by index to maintain order
                toolCallsMap.entrySet().stream()
                    .sorted(java.util.Map.Entry.comparingByKey())
                    .forEach(entry -> toolCallsArray.add(entry.getValue()));

                message.add("tool_calls", toolCallsArray);
                finishReason = "tool_calls";
            }

            choice.add("message", message);
            choice.addProperty("finish_reason", finishReason);
            choices.add(choice);
            responseObj.add("choices", choices);

            return gson.toJson(responseObj);
            
        } catch (IOException e) {
            throw handleNetworkError(e, "createChatCompletionWithFunctionsFullResponse");
        }
    }

    @Override
    public String createChatCompletionWithFunctions(List<ChatMessage> messages, List<Map<String, Object>> functions) throws APIProviderException {
        JsonObject payload = buildChatCompletionPayload(messages, false);

        // LMStudio uses the modern 'tools' format, not 'functions'
        payload.add("tools", gson.toJsonTree(functions));

        // Use tool_choice instead of function_call for modern tools API
        payload.addProperty("tool_choice", "auto");

        Request request = new Request.Builder()
            .url(super.getUrl() + LMSTUDIO_CHAT_ENDPOINT)
            .post(RequestBody.create(JSON, gson.toJson(payload)))
            .build();

        try (Response response = executeWithRetry(request, "createChatCompletionWithFunctions")) {
            JsonObject responseObj = gson.fromJson(response.body().string(), JsonObject.class);
            JsonObject message = responseObj.getAsJsonArray("choices")
                .get(0).getAsJsonObject()
                .getAsJsonObject("message");

            // Check if tool_calls already exists (modern format)
            if (message.has("tool_calls")) {
                JsonArray toolCalls = message.getAsJsonArray("tool_calls");
                return "{\"tool_calls\":" + toolCalls.toString() + "}";
            }

            // Check for legacy function_call format
            if (message.has("function_call")) {
                JsonObject functionCall = message.getAsJsonObject("function_call");
                // Convert to tool_calls format for ActionParser compatibility
                JsonArray toolCalls = new JsonArray();
                JsonObject toolCall = new JsonObject();
                toolCall.addProperty("id", "call_" + System.currentTimeMillis());
                toolCall.addProperty("type", "function");

                JsonObject function = new JsonObject();
                function.addProperty("name", functionCall.get("name").getAsString());
                function.add("arguments", functionCall.get("arguments"));
                toolCall.add("function", function);

                toolCalls.add(toolCall);
                return "{\"tool_calls\":" + toolCalls.toString() + "}";
            }

            // No function call - return empty tool_calls array
            return "{\"tool_calls\":[]}";
        } catch (IOException e) {
            throw handleNetworkError(e, "createChatCompletionWithFunctions");
        }
    }

    @Override
    public List<String> getAvailableModels() throws APIProviderException {
        Request request = new Request.Builder()
            .url(super.getUrl() + LMSTUDIO_MODELS_ENDPOINT)
            .build();

        try (Response response = executeWithRetry(request, "getAvailableModels")) {
            JsonObject responseObj = gson.fromJson(response.body().string(), JsonObject.class);
            List<String> modelIds = new ArrayList<>();
            JsonArray models = responseObj.getAsJsonArray("data");
            
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
        JsonObject payload = new JsonObject();
        payload.addProperty("model", "text-embedding-nomic-embed-text-v1.5");
        payload.addProperty("input", text);

        Request request = new Request.Builder()
            .url(super.getUrl() + LMSTUDIO_EMBEDDINGS_ENDPOINT)
            .post(RequestBody.create(JSON, gson.toJson(payload)))
            .build();

        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                callback.onError(e);
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                try (ResponseBody responseBody = response.body()) {
                    if (!response.isSuccessful()) {
                        callback.onError(new IOException("Failed to get embeddings: " + 
                            response.code() + " " + response.message()));
                        return;
                    }

                    JsonObject responseObj = gson.fromJson(responseBody.string(), JsonObject.class);
                    JsonArray embedding = responseObj.getAsJsonArray("data")
                        .get(0).getAsJsonObject()
                        .getAsJsonArray("embedding");

                    double[] embeddingArray = new double[embedding.size()];
                    for (int i = 0; i < embedding.size(); i++) {
                        embeddingArray[i] = embedding.get(i).getAsDouble();
                    }
                    
                    callback.onSuccess(embeddingArray);
                } catch (Exception e) {
                    callback.onError(e);
                }
            }
        });
    }

    private JsonObject buildChatCompletionPayload(List<ChatMessage> messages, boolean stream) {
        JsonObject payload = new JsonObject();
        payload.addProperty("model", super.getModel());
        payload.addProperty("max_tokens", super.getMaxTokens());
        payload.addProperty("stream", stream);

        JsonArray messagesArray = new JsonArray();
        for (ChatMessage message : messages) {
            JsonObject messageObj = new JsonObject();
            messageObj.addProperty("role", message.getRole());
            messageObj.addProperty("content", message.getContent());
            messagesArray.add(messageObj);
        }
        payload.add("messages", messagesArray);

        return payload;
    }

    private String extractContentFromResponse(JsonObject responseObj) {
        return responseObj.getAsJsonArray("choices")
            .get(0).getAsJsonObject()
            .getAsJsonObject("message")
            .get("content").getAsString();
    }

    private String extractDeltaContent(JsonObject chunk) {
        try {
            JsonObject delta = chunk.getAsJsonArray("choices")
                .get(0).getAsJsonObject()
                .getAsJsonObject("delta");
            
            if (delta.has("content")) {
                return delta.get("content").getAsString();
            }
        } catch (Exception e) {
            // Handle any JSON parsing errors silently and return null
        }
        return null;
    }

    public void cancelRequest() {
        isCancelled = true;
    }
}