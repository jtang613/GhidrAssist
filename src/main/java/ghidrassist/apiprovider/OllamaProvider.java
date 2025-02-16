package ghidrassist.apiprovider;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidrassist.LlmApi.LlmResponseHandler;
import okhttp3.*;
import okio.BufferedSource;

import javax.net.ssl.*;
import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class OllamaProvider extends APIProvider {
    private static final Gson gson = new Gson();
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    private static final String OLLAMA_CHAT_ENDPOINT = "api/chat";
    private static final String OLLAMA_EMBEDDINGS_ENDPOINT = "api/embed";
    private static final String OLLAMA_MODELS_ENDPOINT = "api/tags";
    private volatile boolean isCancelled = false;

    public OllamaProvider(String name, String model, Integer maxTokens, String url, String key, boolean disableTlsVerification) {
        super(name, ProviderType.OLLAMA, model, maxTokens, url, key, disableTlsVerification);
    }

    @Override
    protected OkHttpClient buildClient() {
        try {
            OkHttpClient.Builder builder = new OkHttpClient.Builder()
                .connectTimeout(Duration.ofSeconds(30))
                .readTimeout(Duration.ofSeconds(60))
                .writeTimeout(Duration.ofSeconds(30))
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
    public String createChatCompletion(List<ChatMessage> messages) throws IOException {
        JsonObject payload = buildChatCompletionPayload(messages, false);
        
        Request request = new Request.Builder()
            .url(url + OLLAMA_CHAT_ENDPOINT)
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
    public void streamChatCompletion(List<ChatMessage> messages, LlmResponseHandler handler) throws IOException {
        JsonObject payload = buildChatCompletionPayload(messages, true);

        Request request = new Request.Builder()
            .url(url + OLLAMA_CHAT_ENDPOINT)
            .post(RequestBody.create(JSON, gson.toJson(payload)))
            .build();

        client.newCall(request).enqueue(new Callback() {
            private boolean isFirst = true;
            private StringBuilder contentBuilder = new StringBuilder();

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
                    while (!source.exhausted() && !isCancelled && handler.shouldContinue()) {
                        String line = source.readUtf8Line();
                        if (line == null || line.isEmpty()) continue;

                        JsonObject chunk = gson.fromJson(line, JsonObject.class);
                        String content = extractStreamContent(chunk);
                        
                        if (content != null) {
                            if (isFirst) {
                                handler.onStart();
                                isFirst = false;
                            }
                            contentBuilder.append(content);
                            handler.onUpdate(content);
                        }

                        if (chunk.has("done") && chunk.get("done").getAsBoolean()) {
                            handler.onComplete(contentBuilder.toString());
                            return;
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
        
        // Add tools (functions) to the payload
        payload.add("tools", gson.toJsonTree(functions));

        // Specify json output
        payload.add("format", gson.toJsonTree("json"));
        
        Request request = new Request.Builder()
            .url(super.getUrl() + OLLAMA_CHAT_ENDPOINT)
            .post(RequestBody.create(JSON, gson.toJson(payload)))
            .build();

        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to get completion: " + response.code() + " " + response.message());
            }

            JsonObject responseObj = gson.fromJson(response.body().string(), JsonObject.class);
            JsonObject message = responseObj.getAsJsonObject("message");

            if (message.has("tool_calls")) {
                JsonArray toolCalls = message.getAsJsonArray("tool_calls");
                JsonObject firstToolCall = toolCalls.get(0).getAsJsonObject();
                return String.format("{\"name\": \"%s\", \"arguments\": %s}", 
                    firstToolCall.get("function").getAsJsonObject().get("name").getAsString(),
                    firstToolCall.get("function").getAsJsonObject().get("arguments").toString());
            }

            return message.get("content").getAsString();
        }
    }

    @Override
    public List<String> getAvailableModels() throws IOException {
        Request request = new Request.Builder()
            .url(super.getUrl() + OLLAMA_MODELS_ENDPOINT)
            .build();

        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to get models: " + response.code() + " " + response.message());
            }

            JsonObject responseObj = gson.fromJson(response.body().string(), JsonObject.class);
            List<String> modelIds = new ArrayList<>();
            JsonArray models = responseObj.getAsJsonArray("models");
            
            for (JsonElement model : models) {
                JsonObject modelObj = model.getAsJsonObject();
                String name = modelObj.get("name").getAsString();
                // Don't include model tags/versions in the name
                if (name.contains(":")) {
                    name = name.substring(0, name.indexOf(":"));
                }
                if (!modelIds.contains(name)) {
                    modelIds.add(name);
                }
            }
            
            return modelIds;
        }
    }

    @Override
    public void getEmbeddingsAsync(String text, EmbeddingCallback callback) {
        JsonObject payload = new JsonObject();
        payload.addProperty("model", super.getModel());
        payload.addProperty("input", text);

        Request request = new Request.Builder()
            .url(super.getUrl() + OLLAMA_EMBEDDINGS_ENDPOINT)
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
                    JsonArray embeddingsArray = responseObj.getAsJsonArray("embeddings");


                    JsonArray embeddings = (JsonArray) embeddingsArray.get(0);
                    double[] embeddingArray = new double[embeddings.size()];
                    for (int i = 0; i < embeddings.size(); i++) {
                        embeddingArray[i] = embeddings.get(i).getAsDouble();
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
        return responseObj.get("message")
            .getAsJsonObject()
            .get("content")
            .getAsString();
    }

    private String extractStreamContent(JsonObject chunk) {
        try {
            if (chunk.has("message")) {
                JsonObject message = chunk.getAsJsonObject("message");
                if (message.has("content")) {
                    return message.get("content").getAsString();
                }
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