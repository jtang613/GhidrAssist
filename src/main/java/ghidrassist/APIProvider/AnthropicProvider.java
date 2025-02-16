package ghidrassist.APIProvider;

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

public class AnthropicProvider extends APIProvider {
    private static final Gson gson = new Gson();
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    private static final String ANTHROPIC_MESSAGES_ENDPOINT = "v1/messages";
    private static final String ANTHROPIC_MODELS_ENDPOINT = "v1/models";
    private static final int MAX_RETRY_ATTEMPTS = 3;
    private volatile boolean isCancelled = false;

    public AnthropicProvider(String name, String model, Integer maxTokens, String url, String key, boolean disableTlsVerification) {
        super(name, ProviderType.ANTHROPIC, model, maxTokens, url, key, disableTlsVerification);
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
    public String createChatCompletion(List<ChatMessage> messages) throws IOException {
        JsonObject payload = buildMessagesPayload(messages, false);
        
        Request request = new Request.Builder()
            .url(url + ANTHROPIC_MESSAGES_ENDPOINT)
            .post(RequestBody.create(JSON, gson.toJson(payload)))
            .build();

        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                String errorBody = response.body() != null ? response.body().string() : "No error body";
                throw new IOException("Failed to get completion: " + response.code() + 
                    " " + response.message() + "\nError: " + errorBody);
            }

            JsonObject responseObj = gson.fromJson(response.body().string(), JsonObject.class);
            return responseObj.getAsJsonObject("content").get("text").getAsString();
        }
    }

    @Override
    public void streamChatCompletion(List<ChatMessage> messages, LlmResponseHandler handler) throws IOException {
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
                                handler.onError(new IOException(event.get("error").getAsString()));
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
                        handler.onError(new IOException("Request cancelled"));
                    } else {
                        handler.onComplete(contentBuilder.toString());
                    }
                }
            }
        });
    }

    @Override
    public String createChatCompletionWithFunctions(List<ChatMessage> messages, List<Map<String, Object>> functions) throws IOException {
        // Create a system message that instructs Claude about the available functions
        StringBuilder systemMessage = new StringBuilder("You can call these functions:\n");
        for (Map<String, Object> function : functions) {
            systemMessage.append("- ").append(function.get("name")).append(": ")
                        .append(function.get("description")).append("\n");
            
            @SuppressWarnings("unchecked")
            Map<String, Object> parameters = (Map<String, Object>) function.get("parameters");
            if (parameters != null && parameters.containsKey("properties")) {
                systemMessage.append("  Parameters:\n");
                @SuppressWarnings("unchecked")
                Map<String, Object> properties = (Map<String, Object>) parameters.get("properties");
                for (Map.Entry<String, Object> property : properties.entrySet()) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> propertyDetails = (Map<String, Object>) property.getValue();
                    systemMessage.append("  - ").append(property.getKey())
                                .append(" (").append(propertyDetails.get("type")).append("): ")
                                .append(propertyDetails.get("description")).append("\n");
                }
            }
        }
        systemMessage.append("\nTo call a function, respond with JSON in this format:\n")
                    .append("{\n  \"name\": \"function_name\",\n  \"arguments\": {\n    \"param1\": \"value1\"\n  }\n}\n");

        // Add system message to start of messages list
        List<ChatMessage> augmentedMessages = new ArrayList<>();
        augmentedMessages.add(new ChatMessage(ChatMessage.ChatMessageRole.SYSTEM, systemMessage.toString()));
        augmentedMessages.addAll(messages);

        // Request JSON response format
        JsonObject payload = buildMessagesPayload(augmentedMessages, false);
        payload.addProperty("format", "json");

        Request request = new Request.Builder()
            .url(url + ANTHROPIC_MESSAGES_ENDPOINT)
            .post(RequestBody.create(JSON, gson.toJson(payload)))
            .build();

        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to get completion: " + response.code());
            }

            JsonObject responseObj = gson.fromJson(response.body().string(), JsonObject.class);
            return responseObj.getAsJsonObject("content").get("text").getAsString();
        }
    }

    @Override
    public List<String> getAvailableModels() throws IOException {
        Request request = new Request.Builder()
            .url(super.getUrl() + ANTHROPIC_MODELS_ENDPOINT)
            .build();

        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to get models: " + response.code() + " " + response.message());
            }

            JsonObject responseObj = gson.fromJson(response.body().string(), JsonObject.class);
            List<String> modelIds = new ArrayList<>();
            JsonArray models = responseObj.getAsJsonArray("models");
            
            for (JsonElement model : models) {
                modelIds.add(model.getAsJsonObject().get("id").getAsString());
            }
            
            return modelIds;
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
        
        if (stream) {
            payload.addProperty("stream", true);
        }

        // Convert the messages to Anthropic's format
        JsonArray messagesArray = new JsonArray();
        for (ChatMessage message : messages) {
            if (message.getRole().equals(ChatMessage.ChatMessageRole.SYSTEM)) {
                payload.addProperty("system", message.getContent());
            } else {
                JsonObject messageObj = new JsonObject();
                messageObj.addProperty("role", convertRole(message.getRole()));
                messageObj.addProperty("content", message.getContent());
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
            default:
                return role;
        }
    }

    public void cancelRequest() {
        isCancelled = true;
    }
}