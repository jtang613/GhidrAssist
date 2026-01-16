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
import ghidrassist.apiprovider.oauth.OAuthTokenManager;
import okhttp3.*;
import okio.BufferedSource;

import javax.net.ssl.*;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Anthropic OAuth Provider - Uses OAuth authentication for Claude Pro/Max subscriptions.
 * 
 * This provider uses OAuth PKCE authentication to access the Anthropic API using
 * Claude Pro/Max subscriptions, replicating the authentication flow used by Claude Code.
 * 
 * Key Features:
 * - OAuth PKCE authentication (no API key required)
 * - Automatic token refresh
 * - Two-step warmup sequence (required by API)
 * - Claude Code-style request formatting
 * - Tool name prefixing (mcp_)
 * 
 * Based on the BinAssist Anthropic Experimental Provider implementation.
 */
public class AnthropicOAuthProvider extends APIProvider implements FunctionCallingProvider, ModelListProvider {
    
    private static final Gson gson = new Gson();
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    
    // Anthropic API
    private static final String ANTHROPIC_API_URL = "https://api.anthropic.com";
    private static final String MESSAGES_ENDPOINT = "/v1/messages";
    
    // Required system prompt prefix for Claude Code OAuth requests
    private static final String CLAUDE_CODE_SYSTEM_PREFIX = 
        "You are a Claude agent, built on Anthropic's Claude Agent SDK.";
    
    // Tool name prefix required by OAuth API
    private static final String TOOL_PREFIX = "mcp_";
    
    // Beta headers
    private static final String BETA_HEADERS_WARMUP = "oauth-2025-04-20,interleaved-thinking-2025-05-14";
    private static final String BETA_HEADERS_FULL = "claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14";
    
    // Retry settings
    private static final int MAX_STREAMING_RETRIES = 10;
    private static final int MIN_RETRY_BACKOFF_MS = 10000;
    private static final int MAX_RETRY_BACKOFF_MS = 30000;
    
    // Minimal stub tools required for OAuth API requests
    private static final JsonArray MINIMAL_STUB_TOOLS;
    static {
        MINIMAL_STUB_TOOLS = new JsonArray();
        
        JsonObject taskTool = new JsonObject();
        taskTool.addProperty("name", "mcp_Task");
        taskTool.addProperty("description", "Launch a task to perform work");
        JsonObject taskSchema = new JsonObject();
        taskSchema.addProperty("type", "object");
        JsonObject taskProps = new JsonObject();
        JsonObject promptProp = new JsonObject();
        promptProp.addProperty("type", "string");
        promptProp.addProperty("description", "The task prompt");
        taskProps.add("prompt", promptProp);
        taskSchema.add("properties", taskProps);
        JsonArray required = new JsonArray();
        required.add("prompt");
        taskSchema.add("required", required);
        taskTool.add("input_schema", taskSchema);
        MINIMAL_STUB_TOOLS.add(taskTool);
        
        JsonObject bashTool = new JsonObject();
        bashTool.addProperty("name", "mcp_Bash");
        bashTool.addProperty("description", "Execute bash commands");
        JsonObject bashSchema = new JsonObject();
        bashSchema.addProperty("type", "object");
        JsonObject bashProps = new JsonObject();
        JsonObject cmdProp = new JsonObject();
        cmdProp.addProperty("type", "string");
        cmdProp.addProperty("description", "The command to run");
        bashProps.add("command", cmdProp);
        bashSchema.add("properties", bashProps);
        JsonArray bashRequired = new JsonArray();
        bashRequired.add("command");
        bashSchema.add("required", bashRequired);
        bashTool.add("input_schema", bashSchema);
        MINIMAL_STUB_TOOLS.add(bashTool);
        
        JsonObject readTool = new JsonObject();
        readTool.addProperty("name", "mcp_Read");
        readTool.addProperty("description", "Read file contents");
        JsonObject readSchema = new JsonObject();
        readSchema.addProperty("type", "object");
        JsonObject readProps = new JsonObject();
        JsonObject pathProp = new JsonObject();
        pathProp.addProperty("type", "string");
        pathProp.addProperty("description", "File path to read");
        readProps.add("path", pathProp);
        readSchema.add("properties", readProps);
        JsonArray readRequired = new JsonArray();
        readRequired.add("path");
        readSchema.add("required", readRequired);
        readTool.add("input_schema", readSchema);
        MINIMAL_STUB_TOOLS.add(readTool);
    }
    
    private final OAuthTokenManager tokenManager;
    private volatile boolean warmedUp = false;
    private volatile boolean isCancelled = false;
    
    /**
     * Creates a new Anthropic OAuth provider.
     * 
     * @param name Provider name
     * @param model Model to use
     * @param maxTokens Maximum tokens
     * @param url Ignored (uses Anthropic API URL)
     * @param key OAuth credentials as JSON, or empty for unauthenticated
     * @param disableTlsVerification TLS verification setting
     * @param timeout Timeout in seconds
     */
    public AnthropicOAuthProvider(String name, String model, Integer maxTokens, String url, 
                               String key, boolean disableTlsVerification, Integer timeout) {
        super(name, ProviderType.ANTHROPIC_OAUTH, model, maxTokens, 
              ANTHROPIC_API_URL, key, disableTlsVerification, timeout);
        
        // Initialize token manager with credentials from key field
        this.tokenManager = new OAuthTokenManager(key);
        
        Msg.info(this, "Anthropic OAuth provider initialized with model: " + model);
    }
    
    /**
     * Gets the OAuth token manager for authentication operations.
     */
    public OAuthTokenManager getTokenManager() {
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
    // Warmup Sequence
    // =========================================================================
    
    /**
     * Ensures the warmup sequence has been performed.
     */
    private void ensureWarmedUp() throws APIProviderException {
        if (!warmedUp) {
            performWarmup();
        }
    }
    
    /**
     * Performs the two-step warmup sequence required for OAuth API calls.
     */
    private synchronized void performWarmup() throws APIProviderException {
        if (warmedUp) return;
        
        if (!isAuthenticated()) {
            throw new AuthenticationException(name, "warmup", 401, null,
                "Not authenticated. Please authenticate via Settings > Edit Provider > Authenticate.");
        }
        
        Msg.info(this, "Performing OAuth warmup sequence...");
        
        try {
            // Step 1: Quota check (no claude-code beta)
            Msg.debug(this, "Warmup step 1/2: quota check...");
            warmupQuotaCheck();
            
            // Step 2: Token counting with tools (includes claude-code beta)
            Msg.debug(this, "Warmup step 2/2: token count with tools...");
            warmupTokenCount();
            
            warmedUp = true;
            Msg.info(this, "OAuth warmup completed successfully");
            
        } catch (Exception e) {
            Msg.error(this, "OAuth warmup failed: " + e.getMessage());
            throw new APIProviderException(APIProviderException.ErrorCategory.SERVICE_ERROR,
                name, "warmup", "OAuth warmup failed: " + e.getMessage());
        }
    }
    
    /**
     * Step 1: Simple quota check request (no claude-code beta).
     */
    private void warmupQuotaCheck() throws IOException, APIProviderException {
        String accessToken = tokenManager.getValidAccessToken();
        
        JsonObject payload = new JsonObject();
        payload.addProperty("model", "claude-haiku-4-5-20251001");
        payload.addProperty("max_tokens", 1);
        JsonArray messages = new JsonArray();
        JsonObject msg = new JsonObject();
        msg.addProperty("role", "user");
        msg.addProperty("content", "quota");
        messages.add(msg);
        payload.add("messages", messages);
        
        JsonObject metadata = new JsonObject();
        metadata.addProperty("user_id", generateUserId());
        payload.add("metadata", metadata);
        
        Request request = new Request.Builder()
            .url(ANTHROPIC_API_URL + MESSAGES_ENDPOINT + "?beta=true")
            .post(RequestBody.create(gson.toJson(payload), JSON))
            .header("Authorization", "Bearer " + accessToken)
            .header("anthropic-version", "2023-06-01")
            .header("anthropic-beta", BETA_HEADERS_WARMUP)
            .header("anthropic-dangerous-direct-browser-access", "true")
            .header("Content-Type", "application/json")
            .header("user-agent", "claude-cli/2.1.6 (external, sdk-cli)")
            .header("x-app", "cli")
            .build();
        
        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                String body = response.body() != null ? response.body().string() : "";
                throw new IOException("Warmup quota check failed: " + response.code() + " - " + body);
            }
            Msg.debug(this, "Warmup step 1 succeeded");
        }
    }
    
    /**
     * Step 2: Token counting request with tools (includes claude-code beta).
     */
    private void warmupTokenCount() throws IOException, APIProviderException {
        String accessToken = tokenManager.getValidAccessToken();
        
        // Tools without mcp_ prefix for token counting
        JsonArray tools = new JsonArray();
        JsonObject tool = new JsonObject();
        tool.addProperty("name", "Task");
        tool.addProperty("description", "Launch a task");
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();
        JsonObject promptProp = new JsonObject();
        promptProp.addProperty("type", "string");
        props.add("prompt", promptProp);
        schema.add("properties", props);
        JsonArray required = new JsonArray();
        required.add("prompt");
        schema.add("required", required);
        tool.add("input_schema", schema);
        tools.add(tool);
        
        JsonObject payload = new JsonObject();
        payload.addProperty("model", "claude-opus-4-5-20251101");
        JsonArray messages = new JsonArray();
        JsonObject msg = new JsonObject();
        msg.addProperty("role", "user");
        msg.addProperty("content", "foo");
        messages.add(msg);
        payload.add("messages", messages);
        payload.add("tools", tools);
        
        Request request = new Request.Builder()
            .url(ANTHROPIC_API_URL + "/v1/messages/count_tokens?beta=true")
            .post(RequestBody.create(gson.toJson(payload), JSON))
            .header("Authorization", "Bearer " + accessToken)
            .header("anthropic-version", "2023-06-01")
            .header("anthropic-beta", BETA_HEADERS_FULL + ",token-counting-2024-11-01")
            .header("anthropic-dangerous-direct-browser-access", "true")
            .header("Content-Type", "application/json")
            .header("user-agent", "claude-cli/2.1.6 (external, sdk-cli)")
            .header("x-app", "cli")
            .build();
        
        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                String body = response.body() != null ? response.body().string() : "";
                throw new IOException("Warmup token count failed: " + response.code() + " - " + body);
            }
            Msg.debug(this, "Warmup step 2 succeeded");
        }
    }
    
    /**
     * Generates a user ID in Claude Code format.
     */
    private String generateUserId() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest("ghidrassist_oauth".getBytes());
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) {
                hex.append(String.format("%02x", b));
            }
            return "user_" + hex + "_account_00000000-0000-0000-0000-000000000000_session_00000000-0000-0000-0000-000000000000";
        } catch (Exception e) {
            return "user_ghidrassist";
        }
    }
    
    // =========================================================================
    // Request Helpers
    // =========================================================================
    
    /**
     * Gets headers for OAuth API requests.
     */
    private Headers.Builder getOAuthHeaders() throws IOException {
        String accessToken = tokenManager.getValidAccessToken();
        
        return new Headers.Builder()
            .add("Authorization", "Bearer " + accessToken)
            .add("anthropic-version", "2023-06-01")
            .add("anthropic-beta", BETA_HEADERS_FULL)
            .add("anthropic-dangerous-direct-browser-access", "true")
            .add("Content-Type", "application/json")
            .add("Accept", "application/json")
            .add("user-agent", "claude-cli/2.1.6 (external, sdk-cli)")
            .add("x-app", "cli");
    }
    
    /**
     * Prepares the system prompt with required Claude Code prefix.
     * Currently ignores custom system prompts due to OAuth restrictions.
     */
    private String prepareSystemPrompt(String originalSystem) {
        // WORKAROUND: Only use Claude Code prefix, ignore custom system prompt
        // The full system prompt causes OAuth rejection
        return CLAUDE_CODE_SYSTEM_PREFIX;
    }
    
    /**
     * Prepares tools array with mcp_ prefix.
     */
    private JsonArray prepareTools(List<Map<String, Object>> requestTools) {
        if (requestTools != null && !requestTools.isEmpty()) {
            JsonArray tools = new JsonArray();
            for (Map<String, Object> tool : requestTools) {
                @SuppressWarnings("unchecked")
                Map<String, Object> function = (Map<String, Object>) tool.get("function");
                
                JsonObject anthropicTool = new JsonObject();
                String name = (String) function.get("name");
                if (!name.startsWith(TOOL_PREFIX)) {
                    name = TOOL_PREFIX + name;
                }
                anthropicTool.addProperty("name", name);
                anthropicTool.addProperty("description", (String) function.get("description"));
                
                @SuppressWarnings("unchecked")
                Map<String, Object> parameters = (Map<String, Object>) function.get("parameters");
                if (parameters != null) {
                    anthropicTool.add("input_schema", gson.toJsonTree(parameters));
                }
                
                tools.add(anthropicTool);
            }
            return tools;
        }
        return MINIMAL_STUB_TOOLS.deepCopy();
    }
    
    /**
     * Removes mcp_ prefix from tool names in response.
     */
    private String removeToolPrefix(String name) {
        if (name != null && name.startsWith(TOOL_PREFIX)) {
            return name.substring(TOOL_PREFIX.length());
        }
        return name;
    }
    
    // =========================================================================
    // Chat Completion
    // =========================================================================
    
    @Override
    public String createChatCompletion(List<ChatMessage> messages) throws APIProviderException {
        if (!isAuthenticated()) {
            throw new AuthenticationException(name, "createChatCompletion", 401, null,
                "Not authenticated. Please authenticate via Settings > Edit Provider > Authenticate.");
        }
        
        ensureWarmedUp();
        
        try {
            JsonObject payload = buildMessagesPayload(messages, false);
            
            Request request = new Request.Builder()
                .url(ANTHROPIC_API_URL + MESSAGES_ENDPOINT + "?beta=true")
                .post(RequestBody.create(gson.toJson(payload), JSON))
                .headers(getOAuthHeaders().build())
                .build();
            
            try (Response response = executeWithRetry(request, "createChatCompletion")) {
                JsonObject responseObj = gson.fromJson(response.body().string(), JsonObject.class);
                
                StringBuilder textContent = new StringBuilder();
                if (responseObj.has("content")) {
                    JsonArray contentArray = responseObj.getAsJsonArray("content");
                    for (JsonElement contentElement : contentArray) {
                        JsonObject contentBlock = contentElement.getAsJsonObject();
                        String type = contentBlock.get("type").getAsString();
                        if ("text".equals(type) && contentBlock.has("text")) {
                            textContent.append(contentBlock.get("text").getAsString());
                        }
                    }
                }
                return textContent.toString();
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
        
        ensureWarmedUp();
        
        JsonObject payload = buildMessagesPayload(messages, true);
        executeStreamingWithRetry(payload, handler, "streamChatCompletion", 0);
    }
    
    /**
     * Execute streaming request with retry logic.
     */
    private void executeStreamingWithRetry(JsonObject payload, LlmResponseHandler handler,
                                           String operation, int attemptNumber) {
        if (isCancelled) {
            handler.onError(new APIProviderException(APIProviderException.ErrorCategory.CANCELLED,
                name, operation, "Request cancelled"));
            return;
        }
        
        try {
            Request request = new Request.Builder()
                .url(ANTHROPIC_API_URL + MESSAGES_ENDPOINT + "?beta=true")
                .post(RequestBody.create(gson.toJson(payload), JSON))
                .headers(getOAuthHeaders().add("Accept", "text/event-stream").build())
                .build();
            
            client.newCall(request).enqueue(new Callback() {
                private boolean isFirst = true;
                private StringBuilder contentBuilder = new StringBuilder();
                
                @Override
                public void onFailure(Call call, IOException e) {
                    APIProviderException error = handleNetworkError(e, operation);
                    if (shouldRetryStreaming(error, attemptNumber)) {
                        retryStreamingAfterDelay(payload, handler, operation, attemptNumber, error);
                    } else {
                        handler.onError(error);
                    }
                }
                
                @Override
                public void onResponse(Call call, Response response) throws IOException {
                    try (ResponseBody responseBody = response.body()) {
                        if (!response.isSuccessful()) {
                            String errorBody = responseBody != null ? responseBody.string() : null;
                            APIProviderException error = handleHttpError(response, errorBody, operation);
                            
                            if (shouldRetryStreaming(error, attemptNumber)) {
                                retryStreamingAfterDelay(payload, handler, operation, attemptNumber, error);
                            } else {
                                handler.onError(error);
                            }
                            return;
                        }
                        
                        BufferedSource source = responseBody.source();
                        while (!source.exhausted() && !isCancelled && handler.shouldContinue()) {
                            String line = source.readUtf8Line();
                            if (line == null || line.isEmpty()) continue;
                            
                            if (line.equals("event: ping")) {
                                source.readUtf8Line();
                                continue;
                            }
                            
                            if (line.startsWith("data: ")) {
                                String data = line.substring(6).trim();
                                if (data.equals("[DONE]")) {
                                    handler.onComplete(contentBuilder.toString());
                                    return;
                                }
                                
                                JsonObject event = gson.fromJson(data, JsonObject.class);
                                
                                if (event.has("type") && event.get("type").getAsString().equals("error")) {
                                    handler.onError(new APIProviderException(
                                        APIProviderException.ErrorCategory.SERVICE_ERROR,
                                        name, operation, event.get("error").getAsString()));
                                    return;
                                }
                                
                                if (event.has("type") && 
                                    event.get("type").getAsString().equals("content_block_delta")) {
                                    JsonObject delta = event.getAsJsonObject("delta");
                                    
                                    if (delta.has("text")) {
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
                        }
                        
                        if (isCancelled) {
                            handler.onError(new APIProviderException(
                                APIProviderException.ErrorCategory.CANCELLED,
                                name, operation, "Request cancelled"));
                        } else {
                            handler.onComplete(contentBuilder.toString());
                        }
                    }
                }
            });
        } catch (IOException e) {
            handler.onError(handleNetworkError(e, operation));
        }
    }
    
    private boolean shouldRetryStreaming(APIProviderException error, int attemptNumber) {
        if (attemptNumber >= MAX_STREAMING_RETRIES) return false;
        
        switch (error.getCategory()) {
            case RATE_LIMIT:
            case NETWORK:
            case TIMEOUT:
            case SERVICE_ERROR:
                return true;
            default:
                return false;
        }
    }
    
    private void retryStreamingAfterDelay(JsonObject payload, LlmResponseHandler handler,
                                          String operation, int attemptNumber, 
                                          APIProviderException error) {
        int nextAttempt = attemptNumber + 1;
        int waitTimeMs = calculateStreamingRetryWait(error);
        
        Msg.warn(this, String.format("Streaming retry %d/%d for %s: %s. Waiting %d seconds...",
            nextAttempt, MAX_STREAMING_RETRIES, operation,
            error.getCategory().getDisplayName(), waitTimeMs / 1000));
        
        new Thread(() -> {
            try {
                Thread.sleep(waitTimeMs);
                if (!isCancelled) {
                    executeStreamingWithRetry(payload, handler, operation, nextAttempt);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                handler.onError(new APIProviderException(APIProviderException.ErrorCategory.CANCELLED,
                    name, operation, "Retry interrupted"));
            }
        }, "AnthropicOAuthProvider-StreamRetry").start();
    }
    
    private int calculateStreamingRetryWait(APIProviderException error) {
        if (error.getCategory() == APIProviderException.ErrorCategory.RATE_LIMIT) {
            Integer retryAfter = error.getRetryAfterSeconds();
            if (retryAfter != null && retryAfter > 0) {
                return retryAfter * 1000;
            }
        }
        return MIN_RETRY_BACKOFF_MS + (int) (Math.random() * (MAX_RETRY_BACKOFF_MS - MIN_RETRY_BACKOFF_MS));
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
        
        ensureWarmedUp();
        
        try {
            JsonObject payload = buildMessagesPayload(messages, false);
            payload.add("tools", prepareTools(functions));
            
            JsonObject toolChoice = new JsonObject();
            toolChoice.addProperty("type", "any");
            payload.add("tool_choice", toolChoice);
            
            Request request = new Request.Builder()
                .url(ANTHROPIC_API_URL + MESSAGES_ENDPOINT + "?beta=true")
                .post(RequestBody.create(gson.toJson(payload), JSON))
                .headers(getOAuthHeaders().build())
                .build();
            
            try (Response response = executeWithRetry(request, "createChatCompletionWithFunctions")) {
                JsonObject responseObj = gson.fromJson(response.body().string(), JsonObject.class);
                
                JsonArray toolCallsArray = new JsonArray();
                
                if (responseObj.has("content")) {
                    JsonArray contentArray = responseObj.getAsJsonArray("content");
                    
                    for (JsonElement contentElement : contentArray) {
                        JsonObject contentBlock = contentElement.getAsJsonObject();
                        String type = contentBlock.get("type").getAsString();
                        
                        if ("tool_use".equals(type)) {
                            JsonObject toolCall = new JsonObject();
                            toolCall.addProperty("id", contentBlock.get("id").getAsString());
                            toolCall.addProperty("type", "function");
                            
                            JsonObject function = new JsonObject();
                            function.addProperty("name", 
                                removeToolPrefix(contentBlock.get("name").getAsString()));
                            function.addProperty("arguments", 
                                gson.toJson(contentBlock.get("input")));
                            toolCall.add("function", function);
                            
                            toolCallsArray.add(toolCall);
                        }
                    }
                }
                
                JsonObject result = new JsonObject();
                result.add("tool_calls", toolCallsArray);
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
        
        ensureWarmedUp();
        
        try {
            JsonObject payload = buildMessagesPayload(messages, false);
            payload.add("tools", prepareTools(functions));
            
            Request request = new Request.Builder()
                .url(ANTHROPIC_API_URL + MESSAGES_ENDPOINT + "?beta=true")
                .post(RequestBody.create(gson.toJson(payload), JSON))
                .headers(getOAuthHeaders().build())
                .build();
            
            try (Response response = executeWithRetry(request, "createChatCompletionWithFunctionsFullResponse")) {
                JsonObject responseObj = gson.fromJson(response.body().string(), JsonObject.class);
                
                // Convert to OpenAI format
                JsonObject fullResponse = new JsonObject();
                JsonArray choices = new JsonArray();
                JsonObject choice = new JsonObject();
                JsonObject message = new JsonObject();
                
                message.addProperty("role", "assistant");
                
                String finishReason = "stop";
                JsonArray toolCalls = null;
                StringBuilder textContent = new StringBuilder();
                
                if (responseObj.has("content")) {
                    JsonArray contentArray = responseObj.getAsJsonArray("content");
                    
                    for (JsonElement contentElement : contentArray) {
                        JsonObject contentBlock = contentElement.getAsJsonObject();
                        String type = contentBlock.get("type").getAsString();
                        
                        if ("tool_use".equals(type)) {
                            if (toolCalls == null) {
                                toolCalls = new JsonArray();
                                finishReason = "tool_calls";
                            }
                            
                            JsonObject toolCall = new JsonObject();
                            toolCall.addProperty("id", contentBlock.get("id").getAsString());
                            toolCall.addProperty("type", "function");
                            
                            JsonObject function = new JsonObject();
                            function.addProperty("name",
                                removeToolPrefix(contentBlock.get("name").getAsString()));
                            function.addProperty("arguments",
                                gson.toJson(contentBlock.get("input")));
                            toolCall.add("function", function);
                            
                            toolCalls.add(toolCall);
                            
                        } else if ("text".equals(type)) {
                            if (contentBlock.has("text")) {
                                textContent.append(contentBlock.get("text").getAsString());
                            }
                        }
                    }
                }
                
                if (toolCalls != null) {
                    message.add("tool_calls", toolCalls);
                    if (textContent.length() > 0) {
                        message.addProperty("content", textContent.toString());
                    }
                } else {
                    message.addProperty("content", textContent.toString());
                }
                
                if (responseObj.has("stop_reason")) {
                    String anthropicStopReason = responseObj.get("stop_reason").getAsString();
                    if ("tool_use".equals(anthropicStopReason)) {
                        finishReason = "tool_calls";
                    } else {
                        finishReason = "stop";
                    }
                }
                
                choice.add("message", message);
                choice.addProperty("finish_reason", finishReason);
                choice.addProperty("index", 0);
                choices.add(choice);
                
                fullResponse.add("choices", choices);
                fullResponse.addProperty("id", "chatcmpl-oauth-" + System.currentTimeMillis());
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
    // Message Building
    // =========================================================================
    
    private JsonObject buildMessagesPayload(List<ChatMessage> messages, boolean stream) {
        JsonObject payload = new JsonObject();
        payload.addProperty("model", super.getModel());
        payload.addProperty("max_tokens", super.getMaxTokens());
        payload.addProperty("stream", stream);
        
        // Add system prompt with Claude Code prefix
        String systemPrompt = prepareSystemPrompt(null);
        payload.addProperty("system", systemPrompt);
        
        // Add tools
        payload.add("tools", MINIMAL_STUB_TOOLS.deepCopy());
        
        // Add metadata
        JsonObject metadata = new JsonObject();
        metadata.addProperty("user_id", generateUserId());
        payload.add("metadata", metadata);
        
        // Convert messages
        JsonArray messagesArray = new JsonArray();
        for (ChatMessage message : messages) {
            if (message.getRole().equals(ChatMessage.ChatMessageRole.SYSTEM)) {
                // System messages handled separately
                continue;
            }
            
            JsonObject messageObj = new JsonObject();
            messageObj.addProperty("role", convertRole(message.getRole()));
            
            if (message.getRole().equals(ChatMessage.ChatMessageRole.TOOL)) {
                JsonArray contentArray = new JsonArray();
                JsonObject toolResultBlock = new JsonObject();
                toolResultBlock.addProperty("type", "tool_result");
                toolResultBlock.addProperty("tool_use_id", message.getToolCallId());
                toolResultBlock.addProperty("content", message.getContent());
                contentArray.add(toolResultBlock);
                messageObj.add("content", contentArray);
                
            } else if (message.getToolCalls() != null) {
                JsonArray contentArray = new JsonArray();
                
                if (message.getContent() != null && !message.getContent().isEmpty()) {
                    JsonObject textBlock = new JsonObject();
                    textBlock.addProperty("type", "text");
                    textBlock.addProperty("text", message.getContent());
                    contentArray.add(textBlock);
                }
                
                JsonArray toolCalls = message.getToolCalls();
                for (JsonElement toolCallElement : toolCalls) {
                    JsonObject toolCall = toolCallElement.getAsJsonObject();
                    JsonObject function = toolCall.getAsJsonObject("function");
                    
                    JsonObject toolUseBlock = new JsonObject();
                    toolUseBlock.addProperty("type", "tool_use");
                    toolUseBlock.addProperty("id", toolCall.get("id").getAsString());
                    
                    String toolName = function.get("name").getAsString();
                    if (!toolName.startsWith(TOOL_PREFIX)) {
                        toolName = TOOL_PREFIX + toolName;
                    }
                    toolUseBlock.addProperty("name", toolName);
                    
                    try {
                        JsonElement argumentsElement = function.get("arguments");
                        if (argumentsElement != null && !argumentsElement.isJsonNull()) {
                            String argumentsStr = argumentsElement.getAsString();
                            if (argumentsStr != null && !argumentsStr.trim().isEmpty()) {
                                JsonElement arguments = gson.fromJson(argumentsStr, JsonElement.class);
                                toolUseBlock.add("input", arguments);
                            } else {
                                toolUseBlock.add("input", new JsonObject());
                            }
                        } else {
                            toolUseBlock.add("input", new JsonObject());
                        }
                    } catch (Exception e) {
                        toolUseBlock.add("input", new JsonObject());
                    }
                    
                    contentArray.add(toolUseBlock);
                }
                
                messageObj.add("content", contentArray);
                
            } else {
                String content = message.getContent();
                if (content == null || content.trim().isEmpty()) {
                    continue;
                }
                messageObj.addProperty("content", content);
            }
            
            messagesArray.add(messageObj);
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
                return "assistant";
            case ChatMessage.ChatMessageRole.TOOL:
                return "user";
            default:
                return role;
        }
    }
    
    // =========================================================================
    // Other Required Methods
    // =========================================================================
    
    @Override
    public List<String> getAvailableModels() throws APIProviderException {
        List<String> models = new ArrayList<>();
        models.add("claude-sonnet-4-20250514");
        models.add("claude-haiku-4-5-20251001");
        models.add("claude-opus-4-5-20251101");
        return models;
    }
    
    @Override
    public void getEmbeddingsAsync(String text, EmbeddingCallback callback) {
        callback.onError(new UnsupportedOperationException(
            "Embeddings are not supported by the Anthropic OAuth API"));
    }
    
    public void cancelRequest() {
        isCancelled = true;
    }
    
    /**
     * Resets the warmup state (for re-authentication).
     */
    public void resetWarmup() {
        warmedUp = false;
    }
}
