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
        JsonObject payload = buildChatCompletionPayload(messages, false);
        
        payload.add("functions", gson.toJsonTree(functions));
        
        Request request = new Request.Builder()
            .url(super.getUrl() + LMSTUDIO_CHAT_ENDPOINT)
            .post(RequestBody.create(JSON, gson.toJson(payload)))
            .build();

        try (Response response = executeWithRetry(request, "createChatCompletionWithFunctionsFullResponse")) {
            String responseBody = response.body().string();
            JsonObject responseObj = gson.fromJson(responseBody, JsonObject.class);
            
            // LMStudio should return OpenAI-compatible response already
            // But let's ensure finish_reason is set properly
            if (responseObj.has("choices")) {
                JsonArray choices = responseObj.getAsJsonArray("choices");
                if (choices.size() > 0) {
                    JsonObject choice = choices.get(0).getAsJsonObject();
                    JsonObject message = choice.getAsJsonObject("message");
                    
                    // Check if there's a function_call and convert to tool_calls format
                    if (message.has("function_call")) {
                        JsonObject functionCall = message.getAsJsonObject("function_call");
                        
                        // Convert to tool_calls format
                        JsonArray toolCalls = new JsonArray();
                        JsonObject toolCall = new JsonObject();
                        toolCall.addProperty("id", "call_" + System.currentTimeMillis());
                        toolCall.addProperty("type", "function");
                        
                        JsonObject function = new JsonObject();
                        function.addProperty("name", functionCall.get("name").getAsString());
                        function.addProperty("arguments", functionCall.get("arguments").getAsString());
                        toolCall.add("function", function);
                        
                        toolCalls.add(toolCall);
                        message.add("tool_calls", toolCalls);
                        message.remove("function_call");
                        
                        choice.addProperty("finish_reason", "tool_calls");
                    } else if (!choice.has("finish_reason")) {
                        choice.addProperty("finish_reason", "stop");
                    }
                }
            }
            
            return gson.toJson(responseObj);
            
        } catch (IOException e) {
            throw handleNetworkError(e, "createChatCompletionWithFunctionsFullResponse");
        }
    }

    @Override
    public String createChatCompletionWithFunctions(List<ChatMessage> messages, List<Map<String, Object>> functions) throws APIProviderException {
        JsonObject payload = buildChatCompletionPayload(messages, false);
        
        payload.add("functions", gson.toJsonTree(functions));
        
        Request request = new Request.Builder()
            .url(super.getUrl() + LMSTUDIO_CHAT_ENDPOINT)
            .post(RequestBody.create(JSON, gson.toJson(payload)))
            .build();

        try (Response response = executeWithRetry(request, "createChatCompletionWithFunctions")) {
            JsonObject responseObj = gson.fromJson(response.body().string(), JsonObject.class);
            JsonObject message = responseObj.getAsJsonArray("choices")
                .get(0).getAsJsonObject()
                .getAsJsonObject("message");

            if (message.has("function_call")) {
                JsonObject functionCall = message.getAsJsonObject("function_call");
                return String.format("{\"name\": \"%s\", \"arguments\": %s}", 
                    functionCall.get("name").getAsString(),
                    functionCall.get("arguments").toString());
            }

            return message.get("content").getAsString();
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