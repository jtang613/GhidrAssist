package ghidrassist.apiprovider;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import com.google.gson.stream.JsonReader;

import ghidrassist.LlmApi;
import ghidrassist.apiprovider.exceptions.*;
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

public class OpenAIProvider extends APIProvider implements FunctionCallingProvider, ModelListProvider, EmbeddingProvider {
    private static final Gson gson = new Gson();
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    private static final String OPENAI_CHAT_ENDPOINT = "chat/completions";
    private static final String OPENAI_MODELS_ENDPOINT = "models";
    private static final String OPENAI_EMBEDDINGS_ENDPOINT = "embeddings";
    private static final String OPENAI_EMBEDDING_MODEL = "text-embedding-ada-002";
    private volatile boolean isCancelled = false;

    public OpenAIProvider(String name, String model, Integer maxTokens, String url, String key, boolean disableTlsVerification, Integer timeout) {
        super(name, ProviderType.OPENAI, model, maxTokens, url, key, disableTlsVerification, timeout);
    }

    public static OpenAIProvider fromConfig(APIProviderConfig config) {
        return new OpenAIProvider(
            config.getName(),
            config.getModel(),
            config.getMaxTokens(),
            config.getUrl(),
            config.getKey(),
            config.isDisableTlsVerification(),
            config.getTimeout()
        );
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
            throw new RuntimeException("Failed to build OpenAI HTTP client: " + e.getMessage(), e);
        }
    }

    @Override
    public String createChatCompletion(List<ChatMessage> messages) throws APIProviderException {
        JsonObject payload = buildChatCompletionPayload(messages, false);
        
        Request request = new Request.Builder()
            .url(url + OPENAI_CHAT_ENDPOINT)
            .post(RequestBody.create(JSON, gson.toJson(payload)))
            .build();

        try (Response response = executeWithRetry(request, "createChatCompletion")) {
            String responseBody = response.body().string();
            try {
                JsonObject responseObj = gson.fromJson(responseBody, JsonObject.class);
                return extractContentFromResponse(responseObj);
            } catch (JsonSyntaxException e) {
                throw new ResponseException(name, "createChatCompletion", 
                    ResponseException.ResponseErrorType.MALFORMED_JSON, e);
            }
        } catch (IOException e) {
            throw handleNetworkError(e, "createChatCompletion");
        }
    }

    @Override
    public void streamChatCompletion(List<ChatMessage> messages, LlmApi.LlmResponseHandler handler) throws APIProviderException {
        JsonObject payload = buildChatCompletionPayload(messages, true);

        Request request = new Request.Builder()
            .url(url + OPENAI_CHAT_ENDPOINT)
            .post(RequestBody.create(JSON, gson.toJson(payload)))
            .build();

        client.newCall(request).enqueue(new Callback() {
            private boolean isFirst = true;

            @Override
            public void onFailure(Call call, IOException e) {
                APIProviderException apiException;
                if (call.isCanceled()) {
                    apiException = new StreamCancelledException(name, "stream_chat_completion", 
                        StreamCancelledException.CancellationReason.USER_REQUESTED, e);
                } else {
                    apiException = handleNetworkError(e, "stream_chat_completion");
                }
                handler.onError(apiException);
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                try (ResponseBody responseBody = response.body()) {
                    if (!response.isSuccessful()) {
                        APIProviderException apiException = handleHttpError(response, "stream_chat_completion");
                        handler.onError(apiException);
                        return;
                    }

                    if (responseBody == null) {
                        handler.onError(new ResponseException(name, "stream_chat_completion", 
                            ResponseException.ResponseErrorType.EMPTY_RESPONSE));
                        return;
                    }

                    BufferedSource source = responseBody.source();
                    StringBuilder contentBuilder = new StringBuilder();

                    try {
                        while (!source.exhausted() && !isCancelled && handler.shouldContinue()) {
                            String line = source.readUtf8Line();
                            if (line == null || line.isEmpty()) continue;
                            
                            if (line.startsWith("data: ")) {
                                String data = line.substring(6).trim();
                                if (data.equals("[DONE]")) {
                                    handler.onComplete(contentBuilder.toString());
                                    return;
                                }

                                try {
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
                                } catch (JsonSyntaxException e) {
                                    handler.onError(new ResponseException(name, "stream_chat_completion", 
                                        ResponseException.ResponseErrorType.MALFORMED_JSON, e));
                                    return;
                                }
                            }
                        }

                        if (isCancelled) {
                            handler.onError(new StreamCancelledException(name, "stream_chat_completion", 
                                StreamCancelledException.CancellationReason.USER_REQUESTED));
                        } else if (!handler.shouldContinue()) {
                            handler.onError(new StreamCancelledException(name, "stream_chat_completion", 
                                StreamCancelledException.CancellationReason.USER_REQUESTED));
                        }
                    } catch (IOException e) {
                        handler.onError(new ResponseException(name, "stream_chat_completion", 
                            ResponseException.ResponseErrorType.STREAM_INTERRUPTED, e));
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
        
        Request request = new Request.Builder()
            .url(url + OPENAI_CHAT_ENDPOINT)
            .post(RequestBody.create(JSON, gson.toJson(payload)))
            .build();

        try (Response response = executeWithRetry(request, "createChatCompletionWithFunctionsFullResponse")) {
            String responseBody = response.body().string();
            
            // Return the full response body as-is, including finish_reason
            return responseBody;
            
        } catch (IOException e) {
            throw new NetworkException(name, "createChatCompletionWithFunctionsFullResponse", NetworkException.NetworkErrorType.CONNECTION_FAILED);
        }
    }

    @Override
    public String createChatCompletionWithFunctions(List<ChatMessage> messages, List<Map<String, Object>> functions) throws APIProviderException {
        JsonObject payload = buildChatCompletionPayload(messages, false);
        
        // Add tools (functions) to the payload
        payload.add("tools", gson.toJsonTree(functions));

        // Specify json output
        //payload.add("format", gson.toJsonTree("json"));
        
        Request request = new Request.Builder()
            .url(url + OPENAI_CHAT_ENDPOINT)
            .post(RequestBody.create(JSON, gson.toJson(payload)))
            .build();

        try (Response response = executeWithRetry(request, "createChatCompletionWithFunctions")) {
            String responseBody = response.body().string();
            StringReader responseStr = new StringReader(responseBody.replaceFirst("```json", "").replaceAll("```", ""));
            
            try {
                // Create a lenient JsonReader
                JsonReader jsonReader = new JsonReader(responseStr);
                jsonReader.setLenient(true);

                // Parse with lenient reader
                JsonObject responseObj = JsonParser.parseReader(jsonReader).getAsJsonObject();
            JsonObject message = new JsonObject();
            if ( responseObj.has("message") ) {
            	message = responseObj.getAsJsonObject("message");
            } else if ( responseObj.has("choices") ) {
            	JsonArray choices = responseObj.getAsJsonArray("choices");
            	message = choices.get(0).getAsJsonObject().getAsJsonObject("message");
            }

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
            
            } catch (JsonSyntaxException e) {
                throw new ResponseException(name, "createChatCompletionWithFunctions", 
                    ResponseException.ResponseErrorType.MALFORMED_JSON, e);
            }
        } catch (IOException e) {
            throw handleNetworkError(e, "createChatCompletionWithFunctions");
        }
    }


    @Override
    public List<String> getAvailableModels() throws APIProviderException {
        Request request = new Request.Builder()
            .url(url + OPENAI_MODELS_ENDPOINT)
            .build();

        try (Response response = executeWithRetry(request, "getAvailableModels")) {
            String responseBody = response.body().string();
            try {
                JsonObject responseObj = gson.fromJson(responseBody, JsonObject.class);
                List<String> modelIds = new ArrayList<>();
                
                if (!responseObj.has("data")) {
                    throw new ResponseException(name, "get_models", 
                        ResponseException.ResponseErrorType.MISSING_REQUIRED_FIELD);
                }
                
                JsonArray models = responseObj.getAsJsonArray("data");
                for (JsonElement model : models) {
                    if (model.isJsonObject() && model.getAsJsonObject().has("id")) {
                        modelIds.add(model.getAsJsonObject().get("id").getAsString());
                    }
                }
                
                return modelIds;
            } catch (JsonSyntaxException e) {
                throw new ResponseException(name, "getAvailableModels", 
                    ResponseException.ResponseErrorType.MALFORMED_JSON, e);
            }
        } catch (IOException e) {
            throw handleNetworkError(e, "getAvailableModels");
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
                APIProviderException apiException;
                if (call.isCanceled()) {
                    apiException = new StreamCancelledException(name, "get_embeddings", 
                        StreamCancelledException.CancellationReason.USER_REQUESTED, e);
                } else {
                    apiException = handleNetworkError(e, "get_embeddings");
                }
                callback.onError(apiException);
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                try (ResponseBody responseBody = response.body()) {
                    if (!response.isSuccessful()) {
                        APIProviderException apiException = handleHttpError(response, "get_embeddings");
                        callback.onError(apiException);
                        return;
                    }

                    if (responseBody == null) {
                        callback.onError(new ResponseException(name, "get_embeddings", 
                            ResponseException.ResponseErrorType.EMPTY_RESPONSE));
                        return;
                    }

                    try {
                        String responseBodyStr = responseBody.string();
                        JsonObject responseObj = gson.fromJson(responseBodyStr, JsonObject.class);
                        
                        if (!responseObj.has("data")) {
                            callback.onError(new ResponseException(name, "get_embeddings", 
                                ResponseException.ResponseErrorType.MISSING_REQUIRED_FIELD));
                            return;
                        }
                        
                        JsonArray dataArray = responseObj.getAsJsonArray("data");
                        if (dataArray.size() == 0) {
                            callback.onError(new ResponseException(name, "get_embeddings", 
                                "No embedding data in response"));
                            return;
                        }
                        
                        JsonObject firstElement = dataArray.get(0).getAsJsonObject();
                        if (!firstElement.has("embedding")) {
                            callback.onError(new ResponseException(name, "get_embeddings", 
                                ResponseException.ResponseErrorType.MISSING_REQUIRED_FIELD));
                            return;
                        }
                        
                        JsonArray embedding = firstElement.getAsJsonArray("embedding");

                        double[] embeddingArray = new double[embedding.size()];
                        for (int i = 0; i < embedding.size(); i++) {
                            embeddingArray[i] = embedding.get(i).getAsDouble();
                        }
                        
                        callback.onSuccess(embeddingArray);
                    } catch (JsonSyntaxException e) {
                        callback.onError(new ResponseException(name, "get_embeddings", 
                            ResponseException.ResponseErrorType.MALFORMED_JSON, e));
                    } catch (NumberFormatException e) {
                        callback.onError(new ResponseException(name, "get_embeddings", 
                            "Invalid embedding format: " + e.getMessage()));
                    }
                } catch (IOException e) {
                    callback.onError(new ResponseException(name, "get_embeddings", 
                        ResponseException.ResponseErrorType.STREAM_INTERRUPTED, e));
                }
            }
        });
    }

    private JsonObject buildChatCompletionPayload(List<ChatMessage> messages, boolean stream) {
        JsonObject payload = new JsonObject();
        payload.addProperty("model", super.getModel());

        // Handle different token field names based on model
        String modelName = super.getModel();
        if (modelName != null && (modelName.startsWith("o1-") || modelName.startsWith("o3-") || modelName.startsWith("o4-"))) {
            payload.addProperty("max_completion_tokens", super.getMaxTokens());
        } else {
            payload.addProperty("max_tokens", super.getMaxTokens());
        }
        
        payload.addProperty("stream", stream);

        JsonArray messagesArray = new JsonArray();
        for (ChatMessage message : messages) {
            JsonObject messageObj = new JsonObject();
            messageObj.addProperty("role", message.getRole());
            
            // Handle content (can be null for tool calling assistant messages)
            if (message.getContent() != null) {
                messageObj.addProperty("content", message.getContent());
            }
            
            // Handle tool calls for assistant messages
            if (message.getToolCalls() != null) {
                messageObj.add("tool_calls", message.getToolCalls());
            }
            
            // Handle tool call ID for tool response messages
            if (message.getToolCallId() != null) {
                messageObj.addProperty("tool_call_id", message.getToolCallId());
            }
            
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
    
    @Override
    protected String extractApiErrorCode(String responseBody) {
        if (responseBody == null || responseBody.isEmpty()) {
            return null;
        }
        
        try {
            JsonObject errorObj = gson.fromJson(responseBody, JsonObject.class);
            if (errorObj.has("error")) {
                JsonObject error = errorObj.getAsJsonObject("error");
                if (error.has("type")) {
                    return error.get("type").getAsString();
                } else if (error.has("code")) {
                    return error.get("code").getAsString();
                }
            }
        } catch (JsonSyntaxException e) {
            // Ignore parsing errors
        }
        
        return null;
    }
    
    @Override
    protected String extractErrorMessage(String responseBody, int statusCode) {
        if (responseBody == null || responseBody.isEmpty()) {
            return null;
        }
        
        try {
            JsonObject errorObj = gson.fromJson(responseBody, JsonObject.class);
            if (errorObj.has("error")) {
                JsonObject error = errorObj.getAsJsonObject("error");
                if (error.has("message")) {
                    return error.get("message").getAsString();
                }
            }
        } catch (JsonSyntaxException e) {
            // Ignore parsing errors and fall back to parent implementation
        }
        
        // Fallback to parent implementation
        return super.extractErrorMessage(responseBody, statusCode);
    }
    
    @Override
    protected Integer extractRetryAfter(Response response, String responseBody) {
        // First check the parent implementation for standard headers
        Integer retryAfter = super.extractRetryAfter(response, responseBody);
        if (retryAfter != null) {
            return retryAfter;
        }
        
        // Check OpenAI-specific retry information in response body
        if (responseBody != null) {
            try {
                JsonObject errorObj = gson.fromJson(responseBody, JsonObject.class);
                if (errorObj.has("error")) {
                    JsonObject error = errorObj.getAsJsonObject("error");
                    if (error.has("retry_after")) {
                        return error.get("retry_after").getAsInt();
                    }
                }
            } catch (Exception e) {
                // Ignore parsing errors
            }
        }
        
        return null;
    }
}