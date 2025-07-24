package ghidrassist.apiprovider;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

import ghidrassist.LlmApi;
import ghidrassist.apiprovider.exceptions.*;
import ghidrassist.apiprovider.capabilities.FunctionCallingProvider;
import ghidrassist.apiprovider.capabilities.ModelListProvider;
import ghidrassist.apiprovider.capabilities.EmbeddingProvider;
import okhttp3.*;
import okio.BufferedSource;
import javax.net.ssl.*;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class AzureOpenAIProvider extends APIProvider
        implements FunctionCallingProvider, ModelListProvider, EmbeddingProvider {
    private static final Gson gson = new Gson();
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    private static final String AZURE_API_VERSION = "2025-01-01-preview";
    private static final String AZURE_EMBEDDING_MODEL = "text-embedding-ada-002";
    private volatile boolean isCancelled = false;

    // Azure OpenAI requires a deployment name
    private String deploymentName;

    public AzureOpenAIProvider(String name, String model, Integer maxTokens, String url, String key,
            boolean disableTlsVerification, Integer timeout) {
        super(name, ProviderType.AZURE_OPENAI, model, maxTokens, url, key, disableTlsVerification, timeout);

        // Extract deployment name from model if it contains a deployment name
        // Format: deploymentName or deploymentName:modelName
        if (model != null && model.contains(":")) {
            String[] parts = model.split(":", 2);
            this.deploymentName = parts[0];
            this.model = parts[1]; // Use the actual model name
        } else {
            this.deploymentName = model; // Use model as deployment name
        }
    }

    public static AzureOpenAIProvider fromConfig(APIProviderConfig config) {
        return new AzureOpenAIProvider(
                config.getName(),
                config.getModel(),
                config.getMaxTokens(),
                config.getUrl(),
                config.getKey(),
                config.isDisableTlsVerification(),
                config.getTimeout());
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

                        // Add Azure OpenAI specific headers
                        Request.Builder requestBuilder = originalRequest.newBuilder()
                                .header("api-key", super.key)
                                .header("Content-Type", "application/json");

                        return chain.proceed(requestBuilder.build());
                    });

            if (disableTlsVerification) {
                // Create a trust manager that does not validate certificate chains
                final TrustManager[] trustAllCerts = new TrustManager[] {
                        new X509TrustManager() {
                            @Override
                            public void checkClientTrusted(java.security.cert.X509Certificate[] chain,
                                    String authType) {
                            }

                            @Override
                            public void checkServerTrusted(java.security.cert.X509Certificate[] chain,
                                    String authType) {
                            }

                            @Override
                            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                                return new java.security.cert.X509Certificate[] {};
                            }
                        }
                };

                // Install the all-trusting trust manager
                final SSLContext sslContext = SSLContext.getInstance("SSL");
                sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
                final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

                builder.sslSocketFactory(sslSocketFactory, (X509TrustManager) trustAllCerts[0]);
                builder.hostnameVerifier((hostname, session) -> true);
            }

            return builder.build();
        } catch (Exception e) {
            throw new RuntimeException("Failed to build Azure OpenAI HTTP client: " + e.getMessage(), e);
        }
    }

    @Override
    public String createChatCompletion(List<ChatMessage> messages) throws APIProviderException {
        JsonObject payload = buildChatCompletionPayload(messages, false);

        String endpoint = buildChatCompletionUrl();
        Request request = new Request.Builder()
                .url(endpoint)
                .post(RequestBody.create(gson.toJson(payload), JSON))
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
    public void streamChatCompletion(List<ChatMessage> messages, LlmApi.LlmResponseHandler handler)
            throws APIProviderException {
        JsonObject payload = buildChatCompletionPayload(messages, true);

        String endpoint = buildChatCompletionUrl();
        Request request = new Request.Builder()
                .url(endpoint)
                .post(RequestBody.create(gson.toJson(payload), JSON))
                .build();

        client.newCall(request).enqueue(new Callback() {
            private boolean isFirst = true;

            @Override
            public void onFailure(Call call, IOException e) {
                if (!isCancelled) {
                    handler.onError(handleNetworkError(e, "streamChatCompletion"));
                }
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                if (!response.isSuccessful()) {
                    handler.onError(handleHttpError(response, "streamChatCompletion"));
                    return;
                }

                try (BufferedSource source = response.body().source()) {
                    StringBuilder contentBuilder = new StringBuilder();

                    while (!source.exhausted() && !isCancelled && handler.shouldContinue()) {
                        String line = source.readUtf8Line();
                        if (line == null || line.isEmpty())
                            continue;

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
                                handler.onError(new ResponseException(name, "streamChatCompletion",
                                        ResponseException.ResponseErrorType.MALFORMED_JSON, e));
                                return;
                            }
                        }
                    }

                    if (isCancelled) {
                        handler.onError(new StreamCancelledException(name, "streamChatCompletion",
                                StreamCancelledException.CancellationReason.USER_REQUESTED));
                    } else if (!handler.shouldContinue()) {
                        handler.onError(new StreamCancelledException(name, "streamChatCompletion",
                                StreamCancelledException.CancellationReason.USER_REQUESTED));
                    } else {
                        handler.onComplete(contentBuilder.toString());
                    }
                } catch (IOException e) {
                    if (!isCancelled) {
                        handler.onError(handleNetworkError(e, "streamChatCompletion"));
                    }
                }
            }
        });
    }

    @Override
    public String createChatCompletionWithFunctionsFullResponse(List<ChatMessage> messages,
            List<Map<String, Object>> functions) throws APIProviderException {
        JsonObject payload = buildChatCompletionPayload(messages, false);

        // Add tools (functions) to the payload
        payload.add("tools", gson.toJsonTree(functions));

        String endpoint = buildChatCompletionUrl();
        Request request = new Request.Builder()
                .url(endpoint)
                .post(RequestBody.create(gson.toJson(payload), JSON))
                .build();

        try (Response response = executeWithRetry(request, "createChatCompletionWithFunctionsFullResponse")) {
            String responseBody = response.body().string();

            // Return the full response body as-is, including finish_reason
            return responseBody;

        } catch (IOException e) {
            throw new NetworkException(name, "createChatCompletionWithFunctionsFullResponse",
                    NetworkException.NetworkErrorType.CONNECTION_FAILED);
        }
    }

    @Override
    public String createChatCompletionWithFunctions(List<ChatMessage> messages, List<Map<String, Object>> functions)
            throws APIProviderException {
        JsonObject payload = buildChatCompletionPayload(messages, false);

        // Add tools (functions) to the payload
        payload.add("tools", gson.toJsonTree(functions));

        String endpoint = buildChatCompletionUrl();
        Request request = new Request.Builder()
                .url(endpoint)
                .post(RequestBody.create(gson.toJson(payload), JSON))
                .build();

        try (Response response = executeWithRetry(request, "createChatCompletionWithFunctions")) {
            String responseBody = response.body().string();

            try {
                JsonObject responseObj = gson.fromJson(responseBody, JsonObject.class);

                // Extract message from response (Azure OpenAI follows standard format)
                JsonObject message = responseObj.getAsJsonArray("choices")
                        .get(0).getAsJsonObject()
                        .getAsJsonObject("message");

                // Check if tool_calls exists directly
                if (message.has("tool_calls") && !message.get("tool_calls").isJsonNull()) {
                    return "{\"tool_calls\":" + message.get("tool_calls").toString() + "}";
                }

                // If no tool_calls, check if content contains a JSON object (fallback for edge
                // cases)
                if (message.has("content") && !message.get("content").isJsonNull()) {
                    String content = message.get("content").getAsString().trim();

                    // Try to parse content as JSON if it looks like JSON
                    if (content.startsWith("{") || content.startsWith("[")) {
                        try {
                            JsonElement contentJson = JsonParser.parseString(content);

                            // Case 1: Content is already a tool_calls object
                            if (contentJson.isJsonObject() && contentJson.getAsJsonObject().has("tool_calls")) {
                                return content;
                            }

                            // Case 2: Content is a single function call
                            if (contentJson.isJsonObject()) {
                                JsonObject funcObj = contentJson.getAsJsonObject();
                                if (funcObj.has("name") && funcObj.has("arguments")) {
                                    JsonArray toolCalls = new JsonArray();
                                    JsonObject toolCall = new JsonObject();
                                    toolCall.addProperty("id", "call_" + System.currentTimeMillis());
                                    toolCall.addProperty("type", "function");

                                    JsonObject function = new JsonObject();
                                    function.add("name", funcObj.get("name"));
                                    function.add("arguments", funcObj.get("arguments"));
                                    toolCall.add("function", function);
                                    toolCalls.add(toolCall);

                                    return "{\"tool_calls\":" + toolCalls.toString() + "}";
                                }
                            }
                        } catch (JsonSyntaxException e) {
                            // Content is not valid JSON, fall through
                        }
                    }
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
        String endpoint = buildModelsUrl();
        Request request = new Request.Builder()
                .url(endpoint)
                .build();

        try (Response response = executeWithRetry(request, "getAvailableModels")) {
            String responseBody = response.body().string();
            try {
                JsonObject responseObj = gson.fromJson(responseBody, JsonObject.class);
                JsonArray modelsArray = responseObj.getAsJsonArray("data");

                List<String> models = new ArrayList<>();
                for (JsonElement element : modelsArray) {
                    JsonObject modelObj = element.getAsJsonObject();
                    models.add(modelObj.get("id").getAsString());
                }
                return models;
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
        payload.addProperty("input", text);

        String endpoint = buildEmbeddingsUrl();
        Request request = new Request.Builder()
                .url(endpoint)
                .post(RequestBody.create(gson.toJson(payload), JSON))
                .build();

        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                callback.onError(handleNetworkError(e, "getEmbeddingsAsync"));
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                if (!response.isSuccessful()) {
                    callback.onError(handleHttpError(response, "getEmbeddingsAsync"));
                    return;
                }

                try {
                    String responseBody = response.body().string();
                    JsonObject responseObj = gson.fromJson(responseBody, JsonObject.class);
                    JsonArray dataArray = responseObj.getAsJsonArray("data");

                    if (dataArray.size() > 0) {
                        JsonArray embeddingArray = dataArray.get(0).getAsJsonObject().getAsJsonArray("embedding");
                        double[] embedding = new double[embeddingArray.size()];

                        for (int i = 0; i < embeddingArray.size(); i++) {
                            embedding[i] = embeddingArray.get(i).getAsDouble();
                        }

                        callback.onSuccess(embedding);
                    } else {
                        callback.onError(new ResponseException(name, "getEmbeddingsAsync",
                                ResponseException.ResponseErrorType.EMPTY_RESPONSE));
                    }
                } catch (JsonSyntaxException e) {
                    callback.onError(new ResponseException(name, "getEmbeddingsAsync",
                            ResponseException.ResponseErrorType.MALFORMED_JSON, e));
                }
            }
        });
    }

    private String buildChatCompletionUrl() {
        return String.format("%sopenai/deployments/%s/chat/completions?api-version=%s",
                url, deploymentName, AZURE_API_VERSION);
    }

    private String buildModelsUrl() {
        return String.format("%sopenai/models?api-version=%s", url, AZURE_API_VERSION);
    }

    private String buildEmbeddingsUrl() {
        return String.format("%sopenai/deployments/%s/embeddings?api-version=%s",
                url, AZURE_EMBEDDING_MODEL, AZURE_API_VERSION);
    }

    private JsonObject buildChatCompletionPayload(List<ChatMessage> messages, boolean stream) {
        JsonObject payload = new JsonObject();

        // Handle different token field names based on model
        String modelName = super.getModel();
        if (modelName != null
                && (modelName.startsWith("o1-") || modelName.startsWith("o3-") || modelName.startsWith("o4-"))) {
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
                messageObj.add("tool_calls", gson.toJsonTree(message.getToolCalls()));
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
        JsonObject message = responseObj.getAsJsonArray("choices")
                .get(0).getAsJsonObject()
                .getAsJsonObject("message");

        // Check if content exists and is not null
        if (message.has("content") && !message.get("content").isJsonNull()) {
            return message.get("content").getAsString();
        }

        // If no content, this might be a tool call response
        // Return empty string or handle tool calls appropriately
        return "";
    }

    private String extractDeltaContent(JsonObject chunk) {
        try {
            JsonObject delta = chunk.getAsJsonArray("choices")
                    .get(0).getAsJsonObject()
                    .getAsJsonObject("delta");

            if (delta.has("content") && !delta.get("content").isJsonNull()) {
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
                if (error.has("code")) {
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

        // Check Azure OpenAI-specific retry information in response body
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
