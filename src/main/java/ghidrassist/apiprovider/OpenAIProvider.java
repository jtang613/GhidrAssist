package ghidrassist.apiprovider;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidrassist.LlmApi;
import okhttp3.*;
import okio.BufferedSource;
import javax.net.ssl.*;
import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class OpenAIProvider extends APIProvider {
    private static final Gson gson = new Gson();
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    private static final String OPENAI_CHAT_ENDPOINT = "chat/completions";
    private static final String OPENAI_MODELS_ENDPOINT = "models";
    private static final String OPENAI_EMBEDDINGS_ENDPOINT = "embeddings";
    private static final String OPENAI_EMBEDDING_MODEL = "text-embedding-ada-002";
    private volatile boolean isCancelled = false;

    public OpenAIProvider(String name, String model, Integer maxTokens, String url, String key, boolean disableTlsVerification) {
        super(name, ProviderType.OPENAI, model, maxTokens, url, key, disableTlsVerification);
    }

    public static OpenAIProvider fromConfig(APIProviderConfig config) {
        return new OpenAIProvider(
            config.getName(),
            config.getModel(),
            config.getMaxTokens(),
            config.getUrl(),
            config.getKey(),
            config.isDisableTlsVerification()
        );
    }

    @Override
    protected OkHttpClient buildClient() {
        try {
            OkHttpClient.Builder builder = new OkHttpClient.Builder()
                .connectTimeout(Duration.ofSeconds(30))
                .readTimeout(Duration.ofSeconds(60))
                .writeTimeout(Duration.ofSeconds(30))
                .retryOnConnectionFailure(true)
                .addInterceptor(chain -> {
                    Request originalRequest = chain.request();
                    Request.Builder requestBuilder = originalRequest.newBuilder()
                        .header("Authorization", "Bearer " + key)
                        .header("Content-Type", "application/json");
                    
                    if (!originalRequest.method().equals("GET")) {
                        requestBuilder.header("Accept", "application/json");
                    }
                    
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
    public String createChatCompletion(List<ChatMessage> messages) throws IOException {
        JsonObject payload = buildChatCompletionPayload(messages, false);
        
        Request request = new Request.Builder()
            .url(url + OPENAI_CHAT_ENDPOINT)
            .post(RequestBody.create(JSON, gson.toJson(payload)))
            .build();

        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                String errorBody = response.body() != null ? response.body().string() : "No error body";
                throw new IOException("Failed to get completion: " + response.code() + 
                    " " + response.message() + "\nError: " + errorBody);
            }

            JsonObject responseObj = gson.fromJson(response.body().string(), JsonObject.class);
            return extractContentFromResponse(responseObj);
        }
    }

    @Override
    public void streamChatCompletion(List<ChatMessage> messages, LlmApi.LlmResponseHandler handler) throws IOException {
        JsonObject payload = buildChatCompletionPayload(messages, true);

        Request request = new Request.Builder()
            .url(url + OPENAI_CHAT_ENDPOINT)
            .post(RequestBody.create(JSON, gson.toJson(payload)))
            .build();

        client.newCall(request).enqueue(new Callback() {
            private boolean isFirst = true;

            @Override
            public void onFailure(Call call, IOException e) {
                handler.onError(e);
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                try (ResponseBody responseBody = response.body()) {
                    if (!response.isSuccessful()) {
                        String errorBody = responseBody != null ? responseBody.string() : "No error body";
                        handler.onError(new IOException("Failed to get completion: " + response.code() + 
                            "\nError: " + errorBody));
                        return;
                    }

                    BufferedSource source = responseBody.source();
                    StringBuilder contentBuilder = new StringBuilder();

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
                        handler.onError(new IOException("Request cancelled"));
                    }
                }
            }
        });
    }

    @Override
    public String createChatCompletionWithFunctions(List<ChatMessage> messages, List<Map<String, Object>> functions) throws IOException {
        JsonObject payload = buildChatCompletionPayload(messages, false);
        
        payload.add("functions", gson.toJsonTree(functions));
        
        Request request = new Request.Builder()
            .url(super.getUrl() + OPENAI_CHAT_ENDPOINT)
            .post(RequestBody.create(JSON, gson.toJson(payload)))
            .build();

        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to get completion: " + response.code() + " The model either does not support tool calling or you do not have access to this model.");
            }

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
        }
    }

    @Override
    public List<String> getAvailableModels() throws IOException {
        Request request = new Request.Builder()
            .url(super.getUrl() + OPENAI_MODELS_ENDPOINT)
            .build();

        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to get models: " + response.code() + " " + response.message());
            }

            JsonObject responseObj = gson.fromJson(response.body().string(), JsonObject.class);
            List<String> modelIds = new ArrayList<>();
            JsonArray models = responseObj.getAsJsonArray("data");
            
            for (JsonElement model : models) {
                modelIds.add(model.getAsJsonObject().get("id").getAsString());
            }
            
            return modelIds;
        }
    }

    @Override
    public void getEmbeddingsAsync(String text, EmbeddingCallback callback) {
        JsonObject payload = new JsonObject();
        payload.addProperty("model", OPENAI_EMBEDDING_MODEL);
        payload.addProperty("input", text);

        Request request = new Request.Builder()
            .url(super.getUrl() + OPENAI_EMBEDDINGS_ENDPOINT)
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

        // Handle different token field names based on model
        String modelName = super.getModel();
        if (modelName != null && (modelName.startsWith("o1-") || modelName.startsWith("o3-"))) {
            payload.addProperty("max_completion_tokens", super.getMaxTokens());
        } else {
            payload.addProperty("max_tokens", super.getMaxTokens());
        }
        
        if (stream) {
            payload.addProperty("stream", true);
        }

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