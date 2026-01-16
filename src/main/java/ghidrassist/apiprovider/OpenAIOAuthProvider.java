package ghidrassist.apiprovider;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.util.Msg;
import ghidrassist.LlmApi.LlmResponseHandler;
import ghidrassist.apiprovider.capabilities.FunctionCallingProvider;
import ghidrassist.apiprovider.capabilities.ModelListProvider;
import ghidrassist.apiprovider.exceptions.*;
import ghidrassist.apiprovider.oauth.OpenAIOAuthTokenManager;
import okhttp3.*;
import okio.BufferedSource;

import javax.net.ssl.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * OpenAI OAuth Provider - Uses OAuth authentication for ChatGPT Pro/Plus subscriptions.
 * 
 * This provider uses the Codex Responses API endpoint, implementing the same protocol
 * as the official Codex CLI (codex-cli-rs). Routes requests through the ChatGPT backend.
 * 
 * Key Features:
 * - OAuth PKCE authentication (no API key required)
 * - Automatic token refresh
 * - OpenAI Responses API format translation
 * - Streaming (required by Codex API)
 * - Function/tool calling support
 * 
 * CRITICAL Implementation Details:
 * - originator header MUST be "codex_cli_rs" (not "opencode")
 * - OpenAI-Beta header MUST include "responses=experimental"
 * - chatgpt-account-id header must be lowercase
 * - instructions MUST match the official Codex CLI prompt
 * - stream MUST be true (API requires streaming)
 * - store MUST be false
 */
public class OpenAIOAuthProvider extends APIProvider implements FunctionCallingProvider, ModelListProvider {
    
    private static final Gson gson = new Gson();
    private static final MediaType JSON = MediaType.get("application/json");
    
    // Codex API endpoint
    private static final String CODEX_API_ENDPOINT = "https://chatgpt.com/backend-api/codex/responses";
    
    // Default model
    private static final String DEFAULT_MODEL = "gpt-5.1-codex";
    
    private final OpenAIOAuthTokenManager tokenManager;
    private volatile boolean isCancelled = false;
    
    /**
     * Creates a new OpenAI OAuth provider.
     * 
     * @param name Provider name
     * @param model Model to use (user-specified, API will validate)
     * @param maxTokens Maximum tokens
     * @param url Ignored (uses fixed Codex endpoint)
     * @param key OAuth credentials as JSON, or empty for unauthenticated
     * @param disableTlsVerification TLS verification setting
     * @param timeout Timeout in seconds
     */
    public OpenAIOAuthProvider(String name, String model, Integer maxTokens, String url,
                               String key, boolean disableTlsVerification, Integer timeout) {
        super(name, ProviderType.OPENAI_OAUTH, 
              model != null && !model.isEmpty() ? model : DEFAULT_MODEL,
              maxTokens, CODEX_API_ENDPOINT, key, disableTlsVerification, timeout);
        
        // Initialize token manager with credentials from key field
        this.tokenManager = new OpenAIOAuthTokenManager(key);
        
        Msg.info(this, "OpenAI OAuth provider initialized with model: " + this.model);
    }
    
    /**
     * Gets the OAuth token manager for authentication operations.
     */
    public OpenAIOAuthTokenManager getTokenManager() {
        return tokenManager;
    }
    
    /**
     * Checks if the provider is authenticated.
     */
    public boolean isAuthenticated() {
        return tokenManager.isAuthenticated();
    }
    
    /**
     * Gets updated credentials JSON for storage.
     */
    public String getCredentialsJson() {
        return tokenManager.toJson();
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
    
    // =========================================================================
    // Request Headers
    // =========================================================================
    
    /**
     * Gets headers for Codex API requests.
     * CRITICAL: These headers must match what the official Codex CLI sends.
     */
    private Headers.Builder getCodexHeaders() throws IOException {
        String accessToken = tokenManager.getValidAccessToken();
        
        // Match Python client header names exactly (lowercase)
        Headers.Builder headers = new Headers.Builder()
            .add("Content-Type", "application/json")
            .add("Authorization", "Bearer " + accessToken)
            .add("originator", "codex_cli_rs")
            .add("OpenAI-Beta", "responses=experimental")
            .add("accept", "text/event-stream");  // lowercase to match Python
        
        // Add account ID header (lowercase)
        String accountId = tokenManager.getAccountId();
        if (accountId != null && !accountId.isEmpty()) {
            headers.add("chatgpt-account-id", accountId);
        }
        
        return headers;
    }
    
    // =========================================================================
    // Message Translation - OpenAI Responses API Format
    // =========================================================================
    
    /**
     * Translates ChatMessage list to OpenAI Responses API input format.
     * Matches the BinAssist Codex provider payload shape exactly.
     */
    private JsonArray translateMessagesToInput(List<ChatMessage> messages) {
        JsonArray inputItems = new JsonArray();

        if (messages == null) {
            return inputItems;
        }

        for (ChatMessage message : messages) {
            if (message == null || message.getRole() == null) {
                continue;
            }

            String role = message.getRole();
            String content = message.getContent();

            if (ChatMessage.ChatMessageRole.SYSTEM.equals(role)) {
                if (content == null || content.isEmpty()) {
                    continue;
                }
                JsonObject item = new JsonObject();
                item.addProperty("role", "developer");
                JsonArray contentArray = new JsonArray();
                JsonObject textContent = new JsonObject();
                textContent.addProperty("type", "input_text");
                textContent.addProperty("text", content);
                contentArray.add(textContent);
                item.add("content", contentArray);
                inputItems.add(item);
                continue;
            }

            if (ChatMessage.ChatMessageRole.USER.equals(role)) {
                if (content == null || content.isEmpty()) {
                    continue;
                }
                JsonObject item = new JsonObject();
                item.addProperty("role", "user");
                JsonArray contentArray = new JsonArray();
                JsonObject textContent = new JsonObject();
                textContent.addProperty("type", "input_text");
                textContent.addProperty("text", content);
                contentArray.add(textContent);
                item.add("content", contentArray);
                inputItems.add(item);
                continue;
            }

            if (ChatMessage.ChatMessageRole.ASSISTANT.equals(role)) {
                JsonArray toolCalls = message.getToolCalls();
                if (toolCalls != null && toolCalls.size() > 0) {
                    for (JsonElement toolCallElement : toolCalls) {
                        if (!toolCallElement.isJsonObject()) {
                            continue;
                        }
                        JsonObject toolCall = toolCallElement.getAsJsonObject();
                        JsonObject function = toolCall.has("function") && toolCall.get("function").isJsonObject()
                            ? toolCall.getAsJsonObject("function")
                            : null;

                        String callId = null;
                        if (toolCall.has("id")) {
                            callId = toolCall.get("id").getAsString();
                        } else if (toolCall.has("call_id")) {
                            callId = toolCall.get("call_id").getAsString();
                        }

                        String name = null;
                        if (function != null && function.has("name")) {
                            name = function.get("name").getAsString();
                        } else if (toolCall.has("name")) {
                            name = toolCall.get("name").getAsString();
                        }

                        String arguments = null;
                        JsonElement argumentsElement = null;
                        if (function != null && function.has("arguments")) {
                            argumentsElement = function.get("arguments");
                        } else if (toolCall.has("arguments")) {
                            argumentsElement = toolCall.get("arguments");
                        }
                        if (argumentsElement != null && !argumentsElement.isJsonNull()) {
                            if (argumentsElement.isJsonPrimitive()) {
                                arguments = argumentsElement.getAsString();
                            } else {
                                arguments = gson.toJson(argumentsElement);
                            }
                        }

                        JsonObject item = new JsonObject();
                        item.addProperty("type", "function_call");
                        if (callId != null && !callId.isEmpty()) {
                            item.addProperty("call_id", callId);
                        }
                        if (name != null && !name.isEmpty()) {
                            item.addProperty("name", name);
                        }
                        if (arguments != null && !arguments.isEmpty()) {
                            item.addProperty("arguments", arguments);
                        }
                        inputItems.add(item);
                    }
                }

                if (content != null && !content.isEmpty()) {
                    JsonObject item = new JsonObject();
                    item.addProperty("role", "assistant");
                    JsonArray contentArray = new JsonArray();
                    JsonObject textContent = new JsonObject();
                    textContent.addProperty("type", "output_text");
                    textContent.addProperty("text", content);
                    contentArray.add(textContent);
                    item.add("content", contentArray);
                    inputItems.add(item);
                }
                continue;
            }

            if (ChatMessage.ChatMessageRole.TOOL.equals(role) || ChatMessage.ChatMessageRole.FUNCTION.equals(role)) {
                if (content == null || content.isEmpty()) {
                    continue;
                }
                JsonObject item = new JsonObject();
                item.addProperty("type", "function_call_output");
                if (message.getToolCallId() != null && !message.getToolCallId().isEmpty()) {
                    item.addProperty("call_id", message.getToolCallId());
                }
                item.addProperty("output", content);
                inputItems.add(item);
            }
        }

        return inputItems;
    }
    
    /**
     * Translates tool definitions to Responses API format.
     */
    private JsonArray translateToolsToFormat(List<Map<String, Object>> tools) {
        JsonArray responsesTools = new JsonArray();
        
        if (tools == null || tools.isEmpty()) {
            return responsesTools;
        }
        
        for (Map<String, Object> tool : tools) {
            if (!"function".equals(tool.get("type"))) {
                continue;
            }
            
            @SuppressWarnings("unchecked")
            Map<String, Object> function = (Map<String, Object>) tool.get("function");
            if (function == null) continue;
            
            JsonObject responsesTool = new JsonObject();
            responsesTool.addProperty("type", "function");
            responsesTool.addProperty("name", (String) function.get("name"));
            responsesTool.addProperty("description", (String) function.get("description"));
            
            @SuppressWarnings("unchecked")
            Map<String, Object> parameters = (Map<String, Object>) function.get("parameters");
            if (parameters != null) {
                responsesTool.add("parameters", gson.toJsonTree(parameters));
            }
            
            if (function.containsKey("strict")) {
                responsesTool.addProperty("strict", (Boolean) function.get("strict"));
            }
            
            responsesTools.add(responsesTool);
        }
        
        return responsesTools;
    }
    
    // =========================================================================
    // Response Parsing
    // =========================================================================
    
    /**
     * Parses response content from Responses API format.
     * Returns a ParsedResponse containing text, tool calls, and finish reason.
     */
    private ParsedResponse parseResponseContent(JsonObject responseData) {
        StringBuilder textContent = new StringBuilder();
        JsonArray toolCalls = new JsonArray();
        String finishReason = "stop";
        
        JsonArray output = responseData.has("output") ? responseData.getAsJsonArray("output") : new JsonArray();
        
        for (JsonElement itemElement : output) {
            JsonObject item = itemElement.getAsJsonObject();
            String itemType = item.has("type") ? item.get("type").getAsString() : "";
            
            if ("message".equals(itemType)) {
                // Extract text content from message
                JsonArray content = item.has("content") ? item.getAsJsonArray("content") : new JsonArray();
                for (JsonElement partElement : content) {
                    JsonObject part = partElement.getAsJsonObject();
                    if ("output_text".equals(part.has("type") ? part.get("type").getAsString() : "")) {
                        if (part.has("text")) {
                            textContent.append(part.get("text").getAsString());
                        }
                    }
                }
            } else if ("function_call".equals(itemType)) {
                // Parse function call into OpenAI format
                JsonObject toolCall = new JsonObject();
                toolCall.addProperty("id", item.has("call_id") ? item.get("call_id").getAsString() 
                                                               : item.get("id").getAsString());
                toolCall.addProperty("type", "function");
                
                JsonObject function = new JsonObject();
                function.addProperty("name", item.get("name").getAsString());
                function.addProperty("arguments", item.get("arguments").getAsString());
                toolCall.add("function", function);
                
                toolCalls.add(toolCall);
                finishReason = "tool_calls";
            }
        }
        
        // Check status for finish reason
        if (responseData.has("status")) {
            String status = responseData.get("status").getAsString();
            if ("incomplete".equals(status)) {
                if (responseData.has("incomplete_details")) {
                    JsonObject details = responseData.getAsJsonObject("incomplete_details");
                    if (details.has("reason")) {
                        finishReason = details.get("reason").getAsString();
                    }
                } else {
                    finishReason = "length";
                }
            }
        }
        
        return new ParsedResponse(textContent.toString(), toolCalls, finishReason);
    }
    
    private record ParsedResponse(String textContent, JsonArray toolCalls, String finishReason) {}
    
    // =========================================================================
    // Chat Completion - Streaming Required
    // =========================================================================
    
    @Override
    public String createChatCompletion(List<ChatMessage> messages) throws APIProviderException {
        if (!isAuthenticated()) {
            throw new AuthenticationException(name, "createChatCompletion", 401, null,
                "Not authenticated. Please authenticate via Settings > Edit Provider > Authenticate.");
        }
        
        try {
            // Build payload - Codex requires stream=true, we collect the response
            JsonObject payload = buildRequestPayload(messages, null);
            Headers headers = getCodexHeaders().build();
            
            Request request = new Request.Builder()
                .url(CODEX_API_ENDPOINT)
                .post(buildJsonRequestBody(payload))
                .headers(headers)
                .build();
            
            try (Response response = client.newCall(request).execute()) {
                if (response.code() == 401) {
                    throw new AuthenticationException(name, "createChatCompletion", 401, 
                        response.body() != null ? response.body().string() : null,
                        "Authentication failed. Please re-authenticate.");
                }
                if (response.code() == 429) {
                    throw new RateLimitException(name, "createChatCompletion", null, null);
                }
                if (!response.isSuccessful()) {
                    String errorBody = response.body() != null ? response.body().string() : "";
                    throw new APIProviderException(APIProviderException.ErrorCategory.SERVICE_ERROR,
                        name, "createChatCompletion", 
                        "API error " + response.code() + ": " + errorBody);
                }
                
                // Collect streaming response (API requires stream=true)
                JsonObject responseData = collectStreamingResponse(response);
                ParsedResponse parsed = parseResponseContent(responseData);
                
                return parsed.textContent();
            }
        } catch (IOException e) {
            throw handleNetworkError(e, "createChatCompletion");
        }
    }
    
    @Override
    public void streamChatCompletion(List<ChatMessage> messages, LlmResponseHandler handler) 
            throws APIProviderException {
        if (!isAuthenticated()) {
            throw new AuthenticationException(name, "streamChatCompletion", 401, null,
                "Not authenticated. Please authenticate via Settings > Edit Provider > Authenticate.");
        }
        
        isCancelled = false;
        
        try {
            JsonObject payload = buildRequestPayload(messages, null);
            Headers headers = getCodexHeaders().build();
            
            Request request = new Request.Builder()
                .url(CODEX_API_ENDPOINT)
                .post(buildJsonRequestBody(payload))
                .headers(headers)
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
                        if (response.code() == 401) {
                            handler.onError(new AuthenticationException(name, "streamChatCompletion", 
                                401, null, "Authentication failed. Please re-authenticate."));
                            return;
                        }
                        if (response.code() == 429) {
                            handler.onError(new RateLimitException(name, "streamChatCompletion", null, null));
                            return;
                        }
                        if (!response.isSuccessful()) {
                            String errorBody = responseBody != null ? responseBody.string() : "";
                            handler.onError(new APIProviderException(APIProviderException.ErrorCategory.SERVICE_ERROR,
                                name, "streamChatCompletion", 
                                "API error " + response.code() + ": " + errorBody));
                            return;
                        }
                        
                        BufferedSource source = responseBody.source();
                        while (!source.exhausted() && !isCancelled && handler.shouldContinue()) {
                            String line = source.readUtf8Line();
                            if (line == null || line.isEmpty()) continue;
                            
                            if (line.startsWith("data: ")) {
                                String data = line.substring(6).trim();
                                
                                if ("[DONE]".equals(data)) {
                                    handler.onComplete(contentBuilder.toString());
                                    return;
                                }
                                
                                try {
                                    JsonObject event = gson.fromJson(data, JsonObject.class);
                                    String eventType = event.has("type") ? event.get("type").getAsString() : "";
                                    
                                    // Handle text delta
                                    if ("response.output_text.delta".equals(eventType)) {
                                        String deltaText = event.has("delta") ? event.get("delta").getAsString() : "";
                                        if (!deltaText.isEmpty()) {
                                            if (isFirst) {
                                                handler.onStart();
                                                isFirst = false;
                                            }
                                            contentBuilder.append(deltaText);
                                            handler.onUpdate(deltaText);
                                        }
                                    }
                                    // Handle completed response
                                    else if ("response.completed".equals(eventType) || "response.done".equals(eventType)) {
                                        handler.onComplete(contentBuilder.toString());
                                        return;
                                    }
                                } catch (Exception e) {
                                    // Skip malformed events
                                    Msg.debug(OpenAIOAuthProvider.this, "Skipping malformed SSE event: " + e.getMessage());
                                }
                            }
                        }
                        
                        if (isCancelled) {
                            handler.onError(new APIProviderException(APIProviderException.ErrorCategory.CANCELLED,
                                name, "streamChatCompletion", "Request cancelled"));
                        } else {
                            handler.onComplete(contentBuilder.toString());
                        }
                    }
                }
            });
        } catch (IOException e) {
            handler.onError(handleNetworkError(e, "streamChatCompletion"));
        }
    }
    
    /**
     * Collects a streaming SSE response into a complete response object.
     * The Codex API requires stream=true, so we must parse SSE events.
     */
    private JsonObject collectStreamingResponse(Response response) throws IOException {
        JsonObject finalResponse = new JsonObject();
        
        try (ResponseBody body = response.body()) {
            if (body == null) return finalResponse;
            
            BufferedSource source = body.source();
            while (!source.exhausted()) {
                String line = source.readUtf8Line();
                if (line == null || line.isEmpty()) continue;
                
                if (line.startsWith("data: ")) {
                    String data = line.substring(6).trim();
                    
                    if ("[DONE]".equals(data)) {
                        break;
                    }
                    
                    try {
                        JsonObject event = gson.fromJson(data, JsonObject.class);
                        String eventType = event.has("type") ? event.get("type").getAsString() : "";
                        
                        // Capture the final response
                        if ("response.completed".equals(eventType) || "response.done".equals(eventType)) {
                            if (event.has("response")) {
                                finalResponse = event.getAsJsonObject("response");
                            }
                        }
                    } catch (Exception e) {
                        // Skip malformed events
                    }
                }
            }
        }
        
        return finalResponse;
    }
    
    // =========================================================================
    // Function Calling
    // =========================================================================
    
    @Override
    public String createChatCompletionWithFunctions(List<ChatMessage> messages,
                                                    List<Map<String, Object>> functions) 
            throws APIProviderException {
        if (!isAuthenticated()) {
            throw new AuthenticationException(name, "createChatCompletionWithFunctions", 401, null,
                "Not authenticated. Please authenticate via Settings > Edit Provider > Authenticate.");
        }
        
        try {
            JsonObject payload = buildRequestPayload(messages, functions);
            Headers headers = getCodexHeaders().build();
            
            Request request = new Request.Builder()
                .url(CODEX_API_ENDPOINT)
                .post(buildJsonRequestBody(payload))
                .headers(headers)
                .build();
            
            try (Response response = client.newCall(request).execute()) {
                if (response.code() == 401) {
                    throw new AuthenticationException(name, "createChatCompletionWithFunctions", 401, 
                        response.body() != null ? response.body().string() : null,
                        "Authentication failed. Please re-authenticate.");
                }
                if (!response.isSuccessful()) {
                    String errorBody = response.body() != null ? response.body().string() : "";
                    throw new APIProviderException(APIProviderException.ErrorCategory.SERVICE_ERROR,
                        name, "createChatCompletionWithFunctions", 
                        "API error " + response.code() + ": " + errorBody);
                }
                
                JsonObject responseData = collectStreamingResponse(response);
                ParsedResponse parsed = parseResponseContent(responseData);
                
                // Return tool calls in OpenAI format
                JsonObject result = new JsonObject();
                result.add("tool_calls", parsed.toolCalls());
                return gson.toJson(result);
            }
        } catch (IOException e) {
            throw handleNetworkError(e, "createChatCompletionWithFunctions");
        }
    }
    
    @Override
    public String createChatCompletionWithFunctionsFullResponse(List<ChatMessage> messages,
                                                                List<Map<String, Object>> functions)
            throws APIProviderException {
        if (!isAuthenticated()) {
            throw new AuthenticationException(name, "createChatCompletionWithFunctionsFullResponse", 401, null,
                "Not authenticated. Please authenticate via Settings > Edit Provider > Authenticate.");
        }
        
        try {
            JsonObject payload = buildRequestPayload(messages, functions);
            Headers headers = getCodexHeaders().build();
            
            Request request = new Request.Builder()
                .url(CODEX_API_ENDPOINT)
                .post(buildJsonRequestBody(payload))
                .headers(headers)
                .build();
            
            try (Response response = client.newCall(request).execute()) {
                if (response.code() == 401) {
                    throw new AuthenticationException(name, "createChatCompletionWithFunctionsFullResponse", 401, 
                        response.body() != null ? response.body().string() : null,
                        "Authentication failed. Please re-authenticate.");
                }
                if (!response.isSuccessful()) {
                    String errorBody = response.body() != null ? response.body().string() : "";
                    throw new APIProviderException(APIProviderException.ErrorCategory.SERVICE_ERROR,
                        name, "createChatCompletionWithFunctionsFullResponse", 
                        "API error " + response.code() + ": " + errorBody);
                }
                
                JsonObject responseData = collectStreamingResponse(response);
                ParsedResponse parsed = parseResponseContent(responseData);
                
                // Convert to OpenAI Chat Completions format
                JsonObject fullResponse = new JsonObject();
                JsonArray choices = new JsonArray();
                JsonObject choice = new JsonObject();
                JsonObject message = new JsonObject();
                
                message.addProperty("role", "assistant");
                
                if (!parsed.toolCalls().isEmpty()) {
                    message.add("tool_calls", parsed.toolCalls());
                    if (!parsed.textContent().isEmpty()) {
                        message.addProperty("content", parsed.textContent());
                    }
                } else {
                    message.addProperty("content", parsed.textContent());
                }
                
                choice.add("message", message);
                choice.addProperty("finish_reason", parsed.finishReason());
                choice.addProperty("index", 0);
                choices.add(choice);
                
                fullResponse.add("choices", choices);
                fullResponse.addProperty("id", "chatcmpl-codex-" + System.currentTimeMillis());
                fullResponse.addProperty("object", "chat.completion");
                fullResponse.addProperty("created", System.currentTimeMillis() / 1000);
                fullResponse.addProperty("model", this.model);
                
                return gson.toJson(fullResponse);
            }
        } catch (IOException e) {
            throw handleNetworkError(e, "createChatCompletionWithFunctionsFullResponse");
        }
    }
    
    // =========================================================================
    // Request Building
    // =========================================================================
    
    /**
     * Builds request payload in OpenAI Responses API format.
     * CRITICAL: Codex API requires store=false AND stream=true.
     */
    private JsonObject buildRequestPayload(List<ChatMessage> messages, List<Map<String, Object>> tools) {
        JsonObject payload = new JsonObject();
        payload.addProperty("model", this.model);
        payload.add("input", translateMessagesToInput(messages));
        payload.addProperty("instructions", CodexInstructions.INSTRUCTIONS);
        payload.addProperty("store", false);
        payload.addProperty("stream", true);  // REQUIRED by Codex API
        
        // Add tools if present
        if (tools != null && !tools.isEmpty()) {
            payload.add("tools", translateToolsToFormat(tools));
        }
        
        return payload;
    }

    private RequestBody buildJsonRequestBody(JsonObject payload) {
        return RequestBody.create(gson.toJson(payload).getBytes(StandardCharsets.UTF_8), JSON);
    }
    
    
    // =========================================================================
    // Other Required Methods
    // =========================================================================
    
    @Override
    public List<String> getAvailableModels() throws APIProviderException {
        // Return commonly available Codex models
        // The API will reject invalid models for the user's subscription
        List<String> models = new ArrayList<>();
        models.add("gpt-5.1-codex");
        models.add("gpt-4.1-codex");
        models.add("o3");
        models.add("o4-mini");
        return models;
    }
    
    @Override
    public void getEmbeddingsAsync(String text, EmbeddingCallback callback) {
        callback.onError(new UnsupportedOperationException(
            "Embeddings are not supported by the OpenAI Codex OAuth API"));
    }
    
    public void cancelRequest() {
        isCancelled = true;
    }
}
