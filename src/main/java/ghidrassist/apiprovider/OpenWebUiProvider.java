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
import java.util.UUID;
import java.util.Base64;
import java.security.SecureRandom;

public class OpenWebUiProvider extends APIProvider {
    private static final Gson gson = new Gson();
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    private static final String OPENWEBUI_CHAT_NEW_ENDPOINT = "api/v1/chats/new";
    private static final String OPENWEBUI_CHAT_ENDPOINT = "api/v1/chats/";
    private static final String OPENWEBUI_OLLAMA_CHAT_ENDPOINT = "ollama/api/chat";
    private static final String OPENWEBUI_COMPLETED_ENDPOINT = "api/chat/completed";
    private static final String OPENWEBUI_KNOWLEDGE_ENDPOINT = "api/v1/knowledge/";
    private static final String OLLAMA_MODELS_ENDPOINT = "ollama/api/tags";
    private static final String OLLAMA_EMBEDDINGS_ENDPOINT = "ollama/api/embeddings";
    private volatile boolean isCancelled = false;

    public OpenWebUiProvider(String name, String model, Integer maxTokens, String url, String key, boolean disableTlsVerification) {
        super(name, ProviderType.OPENWEBUI, model, maxTokens, url, key, disableTlsVerification);
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

    private JsonObject createChatPayload(List<ChatMessage> messages, String chatId) {
        JsonObject payload = new JsonObject();
        JsonObject chat = new JsonObject();
        chat.addProperty("id", chatId.isEmpty() ? "" : chatId);
        chat.addProperty("title", "GhidrAssist Chat");
        
        JsonArray modelsArray = new JsonArray();
        modelsArray.add(super.getModel());
        chat.add("models", modelsArray);
        
        chat.add("params", new JsonObject());
        
        // Build messages for history
        JsonObject messagesDict = new JsonObject();
        JsonArray messagesList = new JsonArray();
        String currentId = "";
        
        for (int i = 0; i < messages.size(); i++) {
            ChatMessage msg = messages.get(i);
            String msgId = UUID.randomUUID().toString();
            if (i == messages.size() - 1) {
                currentId = msgId;
            }
            
            JsonObject msgObj = new JsonObject();
            msgObj.addProperty("id", msgId);
            msgObj.addProperty("parentId", i > 0 ? messagesList.get(i-1).getAsJsonObject().get("id").getAsString() : null);
            msgObj.add("childrenIds", new JsonArray());
            msgObj.addProperty("role", msg.getRole());
            msgObj.addProperty("content", msg.getContent());
            msgObj.add("files", new JsonArray());
            msgObj.addProperty("timestamp", System.currentTimeMillis() / 1000);
            JsonArray msgModels = new JsonArray();
            msgModels.add(super.getModel());
            msgObj.add("models", msgModels);
            
            messagesList.add(msgObj);
            messagesDict.add(msgId, msgObj);
        }
        
        JsonObject history = new JsonObject();
        history.add("messages", messagesDict);
        history.addProperty("currentId", currentId);
        
        chat.add("history", history);
        chat.add("messages", messagesList);
        chat.add("tags", new JsonArray());
        chat.addProperty("timestamp", System.currentTimeMillis());
        
        payload.add("chat", chat);
        return payload;
    }

    private String createOrUpdateChat(List<ChatMessage> messages, String chatId) throws IOException {
        JsonObject payload = createChatPayload(messages, chatId);
        String endpoint = chatId.isEmpty() ? OPENWEBUI_CHAT_NEW_ENDPOINT : OPENWEBUI_CHAT_ENDPOINT + chatId;
        
        Request request = new Request.Builder()
            .url(url + endpoint)
            .post(RequestBody.create(JSON, gson.toJson(payload)))
            .build();

        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to create/update chat: " + response.code());
            }
            return gson.fromJson(response.body().string(), JsonObject.class)
                      .get("id").getAsString();
        }
    }

    private String generateSessionId() {
        byte[] randomBytes = new byte[8];
        new SecureRandom().nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    @Override
    public String createChatCompletion(List<ChatMessage> messages) throws IOException {
        String chatId = createOrUpdateChat(messages, "");
        String sessionId = generateSessionId();
        
        JsonObject ollamaPayload = new JsonObject();
        ollamaPayload.addProperty("chat_id", chatId);
        ollamaPayload.addProperty("id", UUID.randomUUID().toString());
        ollamaPayload.addProperty("session_id", sessionId);
        ollamaPayload.addProperty("model", super.getModel());
        ollamaPayload.add("options", new JsonObject());
        ollamaPayload.addProperty("stream", false);
        ollamaPayload.add("files", new JsonArray());
        
        JsonArray messagesArray = new JsonArray();
        for (ChatMessage message : messages) {
            JsonObject messageObj = new JsonObject();
            messageObj.addProperty("role", message.getRole());
            messageObj.addProperty("content", message.getContent());
            messagesArray.add(messageObj);
        }
        ollamaPayload.add("messages", messagesArray);

        Request request = new Request.Builder()
            .url(url + OPENWEBUI_OLLAMA_CHAT_ENDPOINT)
            .post(RequestBody.create(JSON, gson.toJson(ollamaPayload)))
            .build();

        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to get completion: " + response.code());
            }
            
            JsonObject responseObj = gson.fromJson(response.body().string(), JsonObject.class);
            String content = responseObj.getAsJsonObject("message").get("content").getAsString();
            
            // Create assistant response message
            String assistantMsgId = UUID.randomUUID().toString();
            
            // Update the chat with the assistant's response
            JsonObject updatedPayload = createChatPayload(messages, chatId);
            JsonObject updatedChat = updatedPayload.getAsJsonObject("chat");
            JsonObject messagesDict = updatedChat.getAsJsonObject("history").getAsJsonObject("messages");
            JsonArray messagesList = updatedChat.getAsJsonArray("messages");
            
            // Add assistant's message
            JsonObject assistantMsg = new JsonObject();
            assistantMsg.addProperty("id", assistantMsgId);
            assistantMsg.addProperty("parentId", messagesList.get(messagesList.size() - 1).getAsJsonObject().get("id").getAsString());
            assistantMsg.add("childrenIds", new JsonArray());
            assistantMsg.addProperty("role", "assistant");
            assistantMsg.addProperty("content", content);
            assistantMsg.add("files", new JsonArray());
            assistantMsg.addProperty("timestamp", System.currentTimeMillis() / 1000);
            JsonArray msgModels = new JsonArray();
            msgModels.add(super.getModel());
            assistantMsg.add("models", msgModels);
            
            messagesList.add(assistantMsg);
            messagesDict.add(assistantMsgId, assistantMsg);
            updatedChat.getAsJsonObject("history").addProperty("currentId", assistantMsgId);
            
            // Update the chat
            Request updateRequest = new Request.Builder()
                .url(url + OPENWEBUI_CHAT_ENDPOINT + chatId)
                .post(RequestBody.create(JSON, gson.toJson(updatedPayload)))
                .build();
                
            Response updateResponse = client.newCall(updateRequest).execute();
            updateResponse.close();

            // Mark chat as completed
            JsonObject completedPayload = new JsonObject();
            completedPayload.addProperty("chat_id", chatId);
            completedPayload.addProperty("id", ollamaPayload.get("id").getAsString());
            completedPayload.addProperty("session_id", sessionId);
            completedPayload.addProperty("model", super.getModel());
            completedPayload.add("messages", messagesList);
            
            Request completedRequest = new Request.Builder()
                .url(url + OPENWEBUI_COMPLETED_ENDPOINT)
                .post(RequestBody.create(JSON, gson.toJson(completedPayload)))
                .build();
                
            Response completedResponse = client.newCall(completedRequest).execute();
            completedResponse.close();
            
            return content;
        }
    }

    @Override
    public void streamChatCompletion(List<ChatMessage> messages, LlmResponseHandler handler) throws IOException {
        String chatId = createOrUpdateChat(messages, "");
        String sessionId = generateSessionId();
        
        JsonObject ollamaPayload = new JsonObject();
        ollamaPayload.addProperty("chat_id", chatId);
        ollamaPayload.addProperty("id", UUID.randomUUID().toString());
        ollamaPayload.addProperty("session_id", sessionId);
        ollamaPayload.addProperty("model", super.getModel());
        ollamaPayload.add("options", new JsonObject());
        ollamaPayload.addProperty("stream", true);
        ollamaPayload.add("files", new JsonArray());
        
        JsonArray messagesArray = new JsonArray();
        for (ChatMessage message : messages) {
            JsonObject messageObj = new JsonObject();
            messageObj.addProperty("role", message.getRole());
            messageObj.addProperty("content", message.getContent());
            messagesArray.add(messageObj);
        }
        ollamaPayload.add("messages", messagesArray);

        Request request = new Request.Builder()
            .url(url + OPENWEBUI_OLLAMA_CHAT_ENDPOINT)
            .post(RequestBody.create(JSON, gson.toJson(ollamaPayload)))
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
                        handler.onError(new IOException("Failed to get completion: " + response.code()));
                        return;
                    }

                    BufferedSource source = responseBody.source();
                    while (!source.exhausted() && !isCancelled && handler.shouldContinue()) {
                        String line = source.readUtf8Line();
                        if (line == null || line.isEmpty()) continue;

                        JsonObject chunk = gson.fromJson(line, JsonObject.class);
                        if (chunk.has("message")) {
                            JsonObject message = chunk.getAsJsonObject("message");
                            if (message.has("content")) {
                                String content = message.get("content").getAsString();
                                if (isFirst) {
                                    handler.onStart();
                                    isFirst = false;
                                }
                                contentBuilder.append(content);
                                handler.onUpdate(content);
                            }
                        }

                        if (chunk.has("done") && chunk.get("done").getAsBoolean()) {
                            // Update the chat with the assistant's response
                            String assistantMsgId = UUID.randomUUID().toString();
                            JsonObject updatedPayload = createChatPayload(messages, chatId);
                            JsonObject updatedChat = updatedPayload.getAsJsonObject("chat");
                            JsonObject messagesDict = updatedChat.getAsJsonObject("history").getAsJsonObject("messages");
                            JsonArray messagesList = updatedChat.getAsJsonArray("messages");
                            
                            // Add assistant's message
                            JsonObject assistantMsg = new JsonObject();
                            assistantMsg.addProperty("id", assistantMsgId);
                            assistantMsg.addProperty("parentId", messagesList.get(messagesList.size() - 1).getAsJsonObject().get("id").getAsString());
                            assistantMsg.add("childrenIds", new JsonArray());
                            assistantMsg.addProperty("role", "assistant");
                            assistantMsg.addProperty("content", contentBuilder.toString());
                            assistantMsg.add("files", new JsonArray());
                            assistantMsg.addProperty("timestamp", System.currentTimeMillis() / 1000);
                            JsonArray msgModels = new JsonArray();
                            msgModels.add(getModel());
                            assistantMsg.add("models", msgModels);
                            
                            messagesList.add(assistantMsg);
                            messagesDict.add(assistantMsgId, assistantMsg);
                            updatedChat.getAsJsonObject("history").addProperty("currentId", assistantMsgId);
                            
                            // Update the chat
                            Request updateRequest = new Request.Builder()
                                .url(url + OPENWEBUI_CHAT_ENDPOINT + chatId)
                                .post(RequestBody.create(JSON, gson.toJson(updatedPayload)))
                                .build();
                                
                            Response updateResponse = client.newCall(updateRequest).execute();
                            updateResponse.close();

                            // Mark chat as completed
                            JsonObject completedPayload = new JsonObject();
                            completedPayload.addProperty("chat_id", chatId);
                            completedPayload.addProperty("id", ollamaPayload.get("id").getAsString());
                            completedPayload.addProperty("session_id", sessionId);
                            completedPayload.addProperty("model", getModel());
                            completedPayload.add("messages", messagesList);
                            
                            Request completedRequest = new Request.Builder()
                                .url(url + OPENWEBUI_COMPLETED_ENDPOINT)
                                .post(RequestBody.create(JSON, gson.toJson(completedPayload)))
                                .build();
                                
                            Response completedResponse = client.newCall(completedRequest).execute();
                            completedResponse.close();
                            
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
        // Function calling should be handled by the underlying Ollama model
        JsonObject ollamaPayload = new JsonObject();
        ollamaPayload.add("tools", gson.toJsonTree(functions));
        ollamaPayload.addProperty("format", "json");
        
        String chatId = createOrUpdateChat(messages, "");
        String sessionId = generateSessionId();
        
        ollamaPayload.addProperty("chat_id", chatId);
        ollamaPayload.addProperty("id", UUID.randomUUID().toString());
        ollamaPayload.addProperty("session_id", sessionId);
        ollamaPayload.addProperty("model", super.getModel());
        ollamaPayload.add("options", new JsonObject());
        ollamaPayload.addProperty("stream", false);
        ollamaPayload.add("files", new JsonArray());
        
        JsonArray messagesArray = new JsonArray();
        for (ChatMessage message : messages) {
            JsonObject messageObj = new JsonObject();
            messageObj.addProperty("role", message.getRole());
            messageObj.addProperty("content", message.getContent());
            messagesArray.add(messageObj);
        }
        ollamaPayload.add("messages", messagesArray);

        Request request = new Request.Builder()
            .url(url + OPENWEBUI_OLLAMA_CHAT_ENDPOINT)
            .post(RequestBody.create(JSON, gson.toJson(ollamaPayload)))
            .build();

        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to get completion: " + response.code());
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
        // Use Ollama's tags endpoint through OpenWebUI
        Request request = new Request.Builder()
            .url(url + OLLAMA_MODELS_ENDPOINT)
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
        payload.addProperty("prompt", text);

        Request request = new Request.Builder()
            .url(url + OLLAMA_EMBEDDINGS_ENDPOINT)
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
                    JsonArray embeddingsArray = responseObj.getAsJsonArray("embedding");

                    double[] embeddingArray = new double[embeddingsArray.size()];
                    for (int i = 0; i < embeddingsArray.size(); i++) {
                        embeddingArray[i] = embeddingsArray.get(i).getAsDouble();
                    }
                    
                    callback.onSuccess(embeddingArray);
                } catch (Exception e) {
                    callback.onError(e);
                }
            }
        });
    }

    public void cancelRequest() {
        isCancelled = true;
    }
}
