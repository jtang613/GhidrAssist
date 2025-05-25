package ghidrassist.apiprovider;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import com.google.gson.stream.JsonReader;

import ghidrassist.LlmApi.LlmResponseHandler;
import ghidrassist.apiprovider.exceptions.APIProviderException;
import ghidrassist.apiprovider.capabilities.FunctionCallingProvider;
import ghidrassist.apiprovider.capabilities.ModelListProvider;
import ghidrassist.apiprovider.capabilities.EmbeddingProvider;
import okhttp3.*;
import okio.BufferedSource;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.StringReader;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class OllamaProvider extends APIProvider implements FunctionCallingProvider, ModelListProvider, EmbeddingProvider {
    private static final Gson gson = new Gson();
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    private static final String OLLAMA_CHAT_ENDPOINT = "api/chat";
    private static final String OLLAMA_EMBEDDINGS_ENDPOINT = "api/embed";
    private static final String OLLAMA_MODELS_ENDPOINT = "api/tags";
    private volatile boolean isCancelled = false;

    public OllamaProvider(String name, String model, Integer maxTokens, String url, String key, boolean disableTlsVerification, Integer timeout) {
        super(name, ProviderType.OLLAMA, model, maxTokens, url, key, disableTlsVerification, timeout);
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
    public String createChatCompletion(List<ChatMessage> messages) throws APIProviderException {
        JsonObject payload = buildChatCompletionPayload(messages, false);
        
        Request request = new Request.Builder()
            .url(super.getUrl() + OLLAMA_CHAT_ENDPOINT)
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
            .url(super.getUrl() + OLLAMA_CHAT_ENDPOINT)
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
                        handler.onError(handleHttpError(response, "streamChatCompletion"));
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
        
        // Add tools (functions) to the payload
        payload.add("tools", gson.toJsonTree(functions));

        // Specify json output
        payload.addProperty("format", "json");

        Request request = new Request.Builder()
            .url(super.getUrl() + OLLAMA_CHAT_ENDPOINT)
            .post(RequestBody.create(JSON, gson.toJson(payload)))
            .build();

        try (Response response = executeWithRetry(request, "createChatCompletionWithFunctionsFullResponse")) {
            JsonObject responseObj = gson.fromJson(response.body().string(), JsonObject.class);
            
            // Parse the response to create OpenAI-compatible format
            JsonObject fullResponse = new JsonObject();
            JsonArray choices = new JsonArray();
            JsonObject choice = new JsonObject();
            JsonObject message = new JsonObject();
            
            message.addProperty("role", "assistant");
            
            String finishReason = "stop";
            JsonArray toolCalls = null;
            String content = "";
            
            // Extract message from response
            if (responseObj.has("message")) {
                JsonObject responseMessage = responseObj.getAsJsonObject("message");
                
                // Check for native tool_calls first
                if (responseMessage.has("tool_calls")) {
                    JsonArray nativeToolCalls = responseMessage.getAsJsonArray("tool_calls");
                    toolCalls = convertNativeToolCallsToOpenAI(nativeToolCalls);
                    finishReason = "tool_calls";
                }
                
                // Extract content
                if (responseMessage.has("content")) {
                    content = responseMessage.get("content").getAsString();
                }
                
                // If no native tool calls, try parsing from content
                if (toolCalls == null || toolCalls.size() == 0) {
                    toolCalls = parseToolCallsFromContent(content);
                    if (toolCalls != null && toolCalls.size() > 0) {
                        finishReason = "tool_calls";
                    }
                }
            }
            
            // Set message content based on what we found
            if (toolCalls != null && toolCalls.size() > 0) {
                message.add("tool_calls", toolCalls);
                // Include content if present
                if (content != null && !content.trim().isEmpty()) {
                    message.addProperty("content", content);
                }
            } else {
                message.addProperty("content", content);
            }
            
            choice.add("message", message);
            choice.addProperty("finish_reason", finishReason);
            choice.addProperty("index", 0);
            choices.add(choice);
            
            fullResponse.add("choices", choices);
            fullResponse.addProperty("id", "chatcmpl-ollama-" + System.currentTimeMillis());
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
        JsonObject payload = buildChatCompletionPayload(messages, false);
        
        // Add tools (functions) to the payload
        payload.add("tools", gson.toJsonTree(functions));

        // Specify json output
        payload.add("format", gson.toJsonTree("json"));
        
        Request request = new Request.Builder()
            .url(super.getUrl() + OLLAMA_CHAT_ENDPOINT)
            .post(RequestBody.create(JSON, gson.toJson(payload)))
            .build();

        try (Response response = executeWithRetry(request, "createChatCompletionWithFunctions")) {
            // Create a lenient JsonReader
            JsonReader jsonReader = new JsonReader(new StringReader(response.body().string()));
            jsonReader.setLenient(true);

            // Parse with lenient reader
            JsonObject responseObj = JsonParser.parseReader(jsonReader).getAsJsonObject();
            JsonObject message = responseObj.getAsJsonObject("message");

            // Check if tool_calls exists directly
            if (message.has("tool_calls")) {
                return "{\"tool_calls\":" + message.get("tool_calls").toString() + "}";
            }

            // If no tool_calls, check if content contains a JSON object
            if (message.has("content")) {
                String content = message.get("content").getAsString().trim();
                
                // Try to parse content as JSON if it looks like JSON
                if (content.startsWith("{") || content.startsWith("[")) {
                    try {
                        JsonElement contentJson = JsonParser.parseString(content);
                        
                        // Case 1: Content is a single function call
                        if (contentJson.isJsonObject()) {
                            JsonObject funcObj = contentJson.getAsJsonObject();
                            if (funcObj.has("name") && funcObj.has("arguments")) {
                                // Convert to tool_calls format
                                JsonArray toolCalls = new JsonArray();
                                JsonObject toolCall = new JsonObject();
                                JsonObject function = new JsonObject();
                                function.add("name", funcObj.get("name"));
                                function.add("arguments", funcObj.get("arguments"));
                                toolCall.add("function", function);
                                toolCalls.add(toolCall);
                                return "{\"tool_calls\":" + toolCalls.toString() + "}";
                            }
                        }
                        
                        // Case 2: Content is already a tool_calls array
                        if (contentJson.isJsonObject() && contentJson.getAsJsonObject().has("tool_calls")) {
                            return content;
                        }
                        
                        // Case 3: Content is an array of function calls
                        if (contentJson.isJsonArray()) {
                            JsonArray array = contentJson.getAsJsonArray();
                            JsonArray toolCalls = new JsonArray();
                            for (JsonElement elem : array) {
                                if (elem.isJsonObject()) {
                                    JsonObject funcObj = elem.getAsJsonObject();
                                    if (funcObj.has("name") && funcObj.has("arguments")) {
                                        JsonObject toolCall = new JsonObject();
                                        JsonObject function = new JsonObject();
                                        function.add("name", funcObj.get("name"));
                                        function.add("arguments", funcObj.get("arguments"));
                                        toolCall.add("function", function);
                                        toolCalls.add(toolCall);
                                    }
                                }
                            }
                            if (toolCalls.size() > 0) {
                                return "{\"tool_calls\":" + toolCalls.toString() + "}";
                            }
                        }
                    } catch (JsonSyntaxException e) {
                        // Content is not valid JSON, fall through to return original content
                    }
                }
                
                // If we couldn't parse as tool calls, return the original content
                return "{\"tool_calls\":[]}";
            }

            // No valid tool calls found
            return "{\"tool_calls\":[]}";
        } catch (IOException e) {
            throw handleNetworkError(e, "createChatCompletionWithFunctions");
        }
    }

    @Override
    public List<String> getAvailableModels() throws APIProviderException {
        Request request = new Request.Builder()
            .url(super.getUrl() + OLLAMA_MODELS_ENDPOINT)
            .build();

        try (Response response = executeWithRetry(request, "getAvailableModels")) {
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
        } catch (IOException e) {
            throw handleNetworkError(e, "getAvailableModels");
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
                callback.onError(handleNetworkError(e, "getEmbeddingsAsync"));
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                try (ResponseBody responseBody = response.body()) {
                    if (!response.isSuccessful()) {
                        callback.onError(handleHttpError(response, "getEmbeddingsAsync"));
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
    
    /**
     * Parse tool calls from content and return in OpenAI format
     */
    private JsonArray parseToolCallsFromContent(String content) {
        if (content == null || content.trim().isEmpty()) {
            return null;
        }
        
        content = content.trim();
        
        // Try to parse content as JSON if it looks like JSON
        if (content.startsWith("{") || content.startsWith("[")) {
            try {
                JsonElement contentJson = JsonParser.parseString(content);
                
                // Case 1: Content is a single function call
                if (contentJson.isJsonObject()) {
                    JsonObject funcObj = contentJson.getAsJsonObject();
                    if (funcObj.has("name") && funcObj.has("arguments")) {
                        // Convert to tool_calls format
                        JsonArray toolCalls = new JsonArray();
                        JsonObject toolCall = new JsonObject();
                        toolCall.addProperty("id", "call_" + System.currentTimeMillis());
                        toolCall.addProperty("type", "function");
                        
                        JsonObject function = new JsonObject();
                        function.addProperty("name", funcObj.get("name").getAsString());
                        function.addProperty("arguments", gson.toJson(funcObj.get("arguments")));
                        toolCall.add("function", function);
                        
                        toolCalls.add(toolCall);
                        return toolCalls;
                    }
                }
                
                // Case 2: Content is array of function calls
                if (contentJson.isJsonArray()) {
                    JsonArray funcArray = contentJson.getAsJsonArray();
                    JsonArray toolCalls = new JsonArray();
                    
                    for (JsonElement funcElement : funcArray) {
                        if (funcElement.isJsonObject()) {
                            JsonObject funcObj = funcElement.getAsJsonObject();
                            if (funcObj.has("name") && funcObj.has("arguments")) {
                                JsonObject toolCall = new JsonObject();
                                toolCall.addProperty("id", "call_" + System.currentTimeMillis() + "_" + toolCalls.size());
                                toolCall.addProperty("type", "function");
                                
                                JsonObject function = new JsonObject();
                                function.addProperty("name", funcObj.get("name").getAsString());
                                function.addProperty("arguments", gson.toJson(funcObj.get("arguments")));
                                toolCall.add("function", function);
                                
                                toolCalls.add(toolCall);
                            }
                        }
                    }
                    
                    return toolCalls.size() > 0 ? toolCalls : null;
                }
                
                // Case 3: Content has tool_calls property
                if (contentJson.isJsonObject()) {
                    JsonObject obj = contentJson.getAsJsonObject();
                    if (obj.has("tool_calls")) {
                        JsonArray existingToolCalls = obj.getAsJsonArray("tool_calls");
                        // Convert to OpenAI format if needed
                        JsonArray toolCalls = new JsonArray();
                        for (JsonElement tcElement : existingToolCalls) {
                            if (tcElement.isJsonObject()) {
                                JsonObject tc = tcElement.getAsJsonObject();
                                if (!tc.has("id")) {
                                    tc.addProperty("id", "call_" + System.currentTimeMillis() + "_" + toolCalls.size());
                                }
                                if (!tc.has("type")) {
                                    tc.addProperty("type", "function");
                                }
                                toolCalls.add(tc);
                            }
                        }
                        return toolCalls.size() > 0 ? toolCalls : null;
                    }
                }
                
            } catch (Exception e) {
                // If parsing fails, return null
                return null;
            }
        }
        
        return null;
    }
    
    /**
     * Convert native Ollama tool calls to OpenAI format
     */
    private JsonArray convertNativeToolCallsToOpenAI(JsonArray nativeToolCalls) {
        JsonArray toolCalls = new JsonArray();
        
        for (JsonElement tcElement : nativeToolCalls) {
            if (tcElement.isJsonObject()) {
                JsonObject nativeToolCall = tcElement.getAsJsonObject();
                
                JsonObject toolCall = new JsonObject();
                toolCall.addProperty("id", "call_" + System.currentTimeMillis() + "_" + toolCalls.size());
                toolCall.addProperty("type", "function");
                
                // Extract function information
                if (nativeToolCall.has("function")) {
                    JsonObject nativeFunction = nativeToolCall.getAsJsonObject("function");
                    
                    JsonObject function = new JsonObject();
                    if (nativeFunction.has("name")) {
                        function.addProperty("name", nativeFunction.get("name").getAsString());
                    }
                    if (nativeFunction.has("arguments")) {
                        function.addProperty("arguments", gson.toJson(nativeFunction.get("arguments")));
                    }
                    
                    toolCall.add("function", function);
                    toolCalls.add(toolCall);
                }
            }
        }
        
        return toolCalls;
    }
}