package ghidrassist.apiprovider;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.util.Msg;
import ghidrassist.LlmApi;
import ghidrassist.apiprovider.exceptions.*;
import okhttp3.*;
import okio.BufferedSource;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * LiteLLM Provider - Implementation for LiteLLM proxy API.
 * Handles AWS Bedrock and other providers via LiteLLM proxy.
 *
 * LiteLLM provides an OpenAI-compatible API but does NOT perform payload
 * translation for provider-specific features like Anthropic's extended thinking.
 * This applies regardless of whether the backend is direct Anthropic or Bedrock.
 *
 * Known quirks handled:
 * 1. Anthropic models with extended thinking require specific message formats
 *    that LiteLLM doesn't translate - thinking blocks must be preserved
 * 2. Model family and Bedrock detection from model name AND URL patterns
 * 3. LiteLLM model aliases (e.g., "claude-sonnet-4-5") that route to Bedrock
 * 4. Message format translation for thinking blocks
 */
public class LiteLLMProvider extends OpenAIProvider {

    private static final Gson gson = new Gson();
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");

    private final String modelFamily;
    private final boolean isBedrock;
    private final boolean isAnthropicCompatible;
    private boolean warnedAboutThinking = false;

    public LiteLLMProvider(String name, String model, Integer maxTokens, String url,
                           String key, boolean disableTlsVerification, Integer timeout) {
        super(name, model, maxTokens, url, key, disableTlsVerification, timeout);

        // Override the type to LITELLM
        this.type = ProviderType.LITELLM;

        // Detect model characteristics from both model name AND URL
        this.isBedrock = detectIsBedrock(model, url);
        this.modelFamily = detectModelFamily(model);
        this.isAnthropicCompatible = "anthropic".equals(modelFamily);

        Msg.info(this, String.format(
                "LiteLLM provider initialized - Model: %s, Family: %s, Bedrock: %s, AnthropicCompatible: %s",
                model, modelFamily, isBedrock, isAnthropicCompatible));

        if (isAnthropicCompatible) {
            Msg.info(this, "LiteLLM: Anthropic-compatible model detected. " +
                    "Extended thinking will use proper message format translation.");
        }
    }

    public static LiteLLMProvider fromConfig(APIProviderConfig config) {
        return new LiteLLMProvider(
            config.getName(),
            config.getModel(),
            config.getMaxTokens(),
            config.getUrl(),
            config.getKey(),
            config.isDisableTlsVerification(),
            config.getTimeout()
        );
    }

    /**
     * Detect if this is a Bedrock model.
     * Checks both model name patterns AND URL patterns.
     *
     * Detection sources:
     * 1. Model name prefix "bedrock/" (LiteLLM standard format)
     * 2. Model name prefix "bedrock-" (alternative format like "bedrock-claude-opus-4-5")
     * 3. Model name contains "bedrock" anywhere
     * 4. URL contains AWS/Bedrock patterns (amazonaws.com, bedrock, etc.)
     * 5. Common Bedrock model aliases (claude-sonnet-4-5, claude-opus-4, etc.)
     */
    private boolean detectIsBedrock(String model, String url) {
        if (model == null) return false;
        String lowerModel = model.toLowerCase();
        String lowerUrl = url != null ? url.toLowerCase() : "";

        // Direct model name detection - both slash and hyphen prefixes
        if (lowerModel.startsWith("bedrock/") || lowerModel.startsWith("bedrock-") ||
            lowerModel.contains("bedrock")) {
            Msg.info(this, "LiteLLM: Detected Bedrock model from name: " + model);
            return true;
        }

        // URL-based detection for AWS/Bedrock
        if (lowerUrl.contains("amazonaws.com") ||
            lowerUrl.contains("bedrock") ||
            lowerUrl.contains(".aws.") ||
            lowerUrl.contains("aws-")) {
            Msg.info(this, "LiteLLM: Detected Bedrock from URL pattern: " + url);
            return true;
        }

        // Common LiteLLM model aliases that typically route to Bedrock
        // These are Anthropic model aliases that LiteLLM maps to Bedrock
        if (lowerModel.matches("claude-(sonnet|opus|haiku)-\\d.*") ||
            lowerModel.matches("anthropic[./].*") ||
            lowerModel.matches("claude-\\d.*-sonnet.*") ||
            lowerModel.matches("claude-\\d.*-opus.*") ||
            lowerModel.matches("claude-\\d.*-haiku.*")) {

            // These could be either direct Anthropic or Bedrock
            // Check if URL suggests direct Anthropic API
            if (lowerUrl.contains("anthropic.com") || lowerUrl.contains("api.anthropic")) {
                return false; // Direct Anthropic, not Bedrock
            }

            // If it's a Claude model alias and not direct Anthropic API,
            // it's likely Bedrock (common LiteLLM setup)
            Msg.info(this, "LiteLLM: Claude model alias '" + model +
                    "' detected - assuming Bedrock routing (use native Anthropic provider for direct API)");
            return true;
        }

        return false;
    }

    /**
     * Detect the underlying model family from the model name.
     *
     * Examples:
     * - bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0 -> anthropic
     * - bedrock-claude-opus-4-5 -> anthropic (hyphen prefix format)
     * - bedrock/amazon.nova-pro-v1:0 -> amazon
     * - bedrock/meta.llama3-70b-instruct-v1:0 -> meta
     * - claude-sonnet-4-5 -> anthropic (alias)
     * - claude-3-5-sonnet -> anthropic (non-Bedrock)
     * - gpt-4o -> openai (non-Bedrock)
     */
    private String detectModelFamily(String model) {
        if (model == null) return "unknown";
        String lowerModel = model.toLowerCase();

        // Bedrock models with slash format: bedrock/<provider>.<model-name>
        if (lowerModel.startsWith("bedrock/")) {
            if (lowerModel.contains("anthropic") || lowerModel.contains("claude")) {
                return "anthropic";
            } else if (lowerModel.contains("amazon") || lowerModel.contains("nova") || lowerModel.contains("titan")) {
                return "amazon";
            } else if (lowerModel.contains("meta") || lowerModel.contains("llama")) {
                return "meta";
            } else if (lowerModel.contains("cohere")) {
                return "cohere";
            } else if (lowerModel.contains("ai21")) {
                return "ai21";
            } else if (lowerModel.contains("mistral")) {
                return "mistral";
            }
        }

        // Bedrock models with hyphen format: bedrock-<model-name>
        if (lowerModel.startsWith("bedrock-")) {
            String modelPart = lowerModel.substring(8); // Remove "bedrock-" prefix
            if (modelPart.contains("claude") || modelPart.contains("anthropic")) {
                return "anthropic";
            } else if (modelPart.contains("nova") || modelPart.contains("titan") || modelPart.contains("amazon")) {
                return "amazon";
            } else if (modelPart.contains("llama") || modelPart.contains("meta")) {
                return "meta";
            } else if (modelPart.contains("mistral")) {
                return "mistral";
            }
        }

        // Non-Bedrock or alias models
        if (lowerModel.contains("claude") || lowerModel.contains("anthropic")) {
            return "anthropic";
        } else if (lowerModel.contains("gpt") || lowerModel.contains("openai") || lowerModel.startsWith("o1") || lowerModel.startsWith("o3")) {
            return "openai";
        } else if (lowerModel.contains("gemini") || lowerModel.contains("google")) {
            return "google";
        } else if (lowerModel.contains("llama") || lowerModel.contains("meta")) {
            return "meta";
        } else if (lowerModel.contains("mistral")) {
            return "mistral";
        }

        return "unknown";
    }

    /**
     * Build chat completion payload with LiteLLM/Bedrock quirks handled.
     *
     * LiteLLM Quirks (apply to ALL models):
     * 1. Skip reasoning_effort parameter (not supported via LiteLLM proxy)
     * 2. Always include tools array (even empty) for Bedrock compatibility
     *
     * Anthropic-specific quirks:
     * 3. Format messages with proper thinking block structure
     * 4. Temperature must be 1 when thinking is enabled
     */
    private JsonObject buildLiteLLMPayload(List<ChatMessage> messages, boolean stream,
                                            List<Map<String, Object>> functions) {
        JsonObject payload = new JsonObject();
        payload.addProperty("model", super.getModel());
        payload.addProperty("max_tokens", super.getMaxTokens());
        payload.addProperty("stream", stream);

        ReasoningConfig reasoning = super.getReasoningConfig();
        boolean thinkingEnabled = reasoning != null && reasoning.isEnabled();

        // LITELLM QUIRK #1: Skip reasoning_effort parameter for ALL LiteLLM providers
        // LiteLLM/Bedrock doesn't support this OpenAI-style parameter
        if (thinkingEnabled && !warnedAboutThinking) {
            Msg.warn(this, "LiteLLM: reasoning_effort parameter skipped (not supported via LiteLLM proxy). " +
                    "Extended thinking may still work if enabled in model/server config.");
            warnedAboutThinking = true;
        }

        // LITELLM QUIRK #2: Temperature must be 1 when thinking is enabled for Anthropic
        if (thinkingEnabled && isAnthropicCompatible) {
            payload.addProperty("temperature", 1);
        }

        // Build messages array - only use thinking block format for Anthropic models
        JsonArray messagesArray = new JsonArray();
        for (ChatMessage message : messages) {
            JsonObject messageObj = buildMessageObject(message, thinkingEnabled && isAnthropicCompatible);
            messagesArray.add(messageObj);
        }
        payload.add("messages", messagesArray);

        // LITELLM/BEDROCK QUIRK #3: Always include tools array for compatibility
        // Bedrock requires tools=[] even when not using tools
        if (functions != null && !functions.isEmpty()) {
            payload.add("tools", gson.toJsonTree(functions));
        } else {
            // Add empty tools array for Bedrock compatibility
            payload.add("tools", new JsonArray());
            Msg.debug(this, "LiteLLM: Added empty tools array for Bedrock compatibility");
        }

        return payload;
    }

    /**
     * Build a message object with proper format for the target model.
     *
     * @param message The chat message to format
     * @param useAnthropicThinkingFormat If true, format thinking blocks for Anthropic models.
     *                                    If false, use standard OpenAI format.
     */
    private JsonObject buildMessageObject(ChatMessage message, boolean useAnthropicThinkingFormat) {
        JsonObject messageObj = new JsonObject();
        messageObj.addProperty("role", message.getRole());

        // Check if this message has thinking data
        boolean hasThinking = message.getThinkingContent() != null ||
                              message.getThinkingSignature() != null;

        // For Anthropic models with thinking enabled AND assistant messages,
        // we MUST include thinking blocks (either real or redacted)
        if (useAnthropicThinkingFormat && "assistant".equals(message.getRole())) {
            JsonArray contentBlocks = new JsonArray();

            if (hasThinking && message.getThinkingContent() != null) {
                // Add actual thinking block first (Anthropic requirement)
                JsonObject thinkingBlock = new JsonObject();
                thinkingBlock.addProperty("type", "thinking");
                thinkingBlock.addProperty("thinking", message.getThinkingContent());
                if (message.getThinkingSignature() != null) {
                    thinkingBlock.addProperty("signature", message.getThinkingSignature());
                }
                contentBlocks.add(thinkingBlock);
            } else {
                // No thinking content stored - add redacted_thinking block
                // This is required by Bedrock when thinking is enabled globally
                // "When thinking is enabled, a final assistant message must start with a thinking block"
                JsonObject redactedBlock = new JsonObject();
                redactedBlock.addProperty("type", "redacted_thinking");
                redactedBlock.addProperty("data", ""); // Empty redacted block
                contentBlocks.add(redactedBlock);
                Msg.debug(this, "LiteLLM: Added redacted_thinking block for historical assistant message");
            }

            // Add text content block
            if (message.getContent() != null && !message.getContent().isEmpty()) {
                JsonObject textBlock = new JsonObject();
                textBlock.addProperty("type", "text");
                textBlock.addProperty("text", message.getContent());
                contentBlocks.add(textBlock);
            }

            messageObj.add("content", contentBlocks);
        } else {
            // Standard OpenAI format - simple string content
            // This is used for ALL non-Anthropic models and user/system messages
            if (message.getContent() != null) {
                messageObj.addProperty("content", message.getContent());
            }
        }

        // Handle tool calls for assistant messages
        if (message.getToolCalls() != null) {
            messageObj.add("tool_calls", message.getToolCalls());
        }

        // Handle tool call ID for tool response messages
        if (message.getToolCallId() != null) {
            messageObj.addProperty("tool_call_id", message.getToolCallId());
        }

        return messageObj;
    }

    /**
     * Override streaming with functions to use LiteLLM-specific payload building.
     */
    @Override
    public void streamChatCompletionWithFunctions(
            List<ChatMessage> messages,
            List<Map<String, Object>> functions,
            StreamingFunctionHandler handler
    ) throws APIProviderException {

        JsonObject payload = buildLiteLLMPayload(messages, true, functions);

        Msg.debug(this, "LiteLLM request payload: " + payload.toString());

        Request request = new Request.Builder()
                .url(url + "chat/completions")
                .post(RequestBody.create(JSON, gson.toJson(payload)))
                .build();

        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                APIProviderException apiException;
                if (call.isCanceled()) {
                    apiException = new StreamCancelledException(name, "stream_chat_completion_with_functions",
                            StreamCancelledException.CancellationReason.USER_REQUESTED, e);
                } else {
                    apiException = handleNetworkError(e, "stream_chat_completion_with_functions");
                }
                handler.onError(apiException);
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                try (ResponseBody responseBody = response.body()) {
                    if (!response.isSuccessful()) {
                        APIProviderException apiException = handleHttpError(response, "stream_chat_completion_with_functions");
                        handler.onError(apiException);
                        return;
                    }

                    if (responseBody == null) {
                        handler.onError(new ResponseException(name, "stream_chat_completion_with_functions",
                                ResponseException.ResponseErrorType.EMPTY_RESPONSE));
                        return;
                    }

                    BufferedSource source = responseBody.source();
                    StringBuilder textBuilder = new StringBuilder();
                    java.util.Map<Integer, ToolCallAccumulator> toolCallsMap = new java.util.HashMap<>();
                    String finishReason = "stop";

                    try {
                        while (!source.exhausted() && handler.shouldContinue()) {
                            String line = source.readUtf8Line();
                            if (line == null || line.isEmpty()) continue;

                            if (line.startsWith("data: ")) {
                                String data = line.substring(6).trim();
                                if (data.equals("[DONE]")) {
                                    // Process complete - convert accumulated tool calls
                                    java.util.List<ToolCall> toolCalls = new java.util.ArrayList<>();
                                    toolCallsMap.entrySet().stream()
                                            .sorted(java.util.Map.Entry.comparingByKey())
                                            .forEach(entry -> {
                                                ToolCallAccumulator acc = entry.getValue();
                                                String args = acc.argumentsBuffer.toString().trim();
                                                if (args.isEmpty()) {
                                                    args = "{}";
                                                }
                                                toolCalls.add(new ToolCall(acc.id, acc.name, args));
                                            });

                                    handler.onStreamComplete(finishReason, textBuilder.toString(), toolCalls);
                                    return;
                                }

                                try {
                                    JsonObject chunk = gson.fromJson(data, JsonObject.class);

                                    if (chunk.has("choices")) {
                                        com.google.gson.JsonArray choices = chunk.getAsJsonArray("choices");
                                        if (choices.size() > 0) {
                                            JsonObject choice = choices.get(0).getAsJsonObject();

                                            if (choice.has("delta")) {
                                                JsonObject delta = choice.getAsJsonObject("delta");

                                                // Stream text content immediately
                                                if (delta.has("content") && !delta.get("content").isJsonNull()) {
                                                    String content = delta.get("content").getAsString();
                                                    textBuilder.append(content);
                                                    handler.onTextUpdate(content);
                                                }

                                                // Buffer tool calls
                                                if (delta.has("tool_calls")) {
                                                    com.google.gson.JsonArray toolCallDeltas = delta.getAsJsonArray("tool_calls");
                                                    for (com.google.gson.JsonElement tcElement : toolCallDeltas) {
                                                        JsonObject toolCallDelta = tcElement.getAsJsonObject();
                                                        int index = toolCallDelta.has("index") ? toolCallDelta.get("index").getAsInt() : 0;

                                                        ToolCallAccumulator acc = toolCallsMap.computeIfAbsent(index, k -> new ToolCallAccumulator());

                                                        if (toolCallDelta.has("id")) {
                                                            acc.id = toolCallDelta.get("id").getAsString();
                                                        }

                                                        if (toolCallDelta.has("function")) {
                                                            JsonObject functionDelta = toolCallDelta.getAsJsonObject("function");
                                                            if (functionDelta.has("name")) {
                                                                acc.name = functionDelta.get("name").getAsString();
                                                            }
                                                            if (functionDelta.has("arguments")) {
                                                                acc.argumentsBuffer.append(functionDelta.get("arguments").getAsString());
                                                            }
                                                        }
                                                    }
                                                }
                                            }

                                            if (choice.has("finish_reason") && !choice.get("finish_reason").isJsonNull()) {
                                                finishReason = choice.get("finish_reason").getAsString();
                                            }
                                        }
                                    }
                                } catch (com.google.gson.JsonSyntaxException e) {
                                    handler.onError(new ResponseException(name, "stream_chat_completion_with_functions",
                                            ResponseException.ResponseErrorType.MALFORMED_JSON, e));
                                    return;
                                }
                            }
                        }

                        if (!handler.shouldContinue()) {
                            handler.onError(new StreamCancelledException(name, "stream_chat_completion_with_functions",
                                    StreamCancelledException.CancellationReason.USER_REQUESTED));
                        }
                    } catch (IOException e) {
                        handler.onError(new ResponseException(name, "stream_chat_completion_with_functions",
                                ResponseException.ResponseErrorType.STREAM_INTERRUPTED, e));
                    }
                }
            }
        });
    }

    /**
     * Override standard streaming to use LiteLLM-specific payload building.
     */
    @Override
    public void streamChatCompletion(List<ChatMessage> messages, LlmApi.LlmResponseHandler handler)
            throws APIProviderException {

        JsonObject payload = buildLiteLLMPayload(messages, true, null);

        Request request = new Request.Builder()
                .url(url + "chat/completions")
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
                        while (!source.exhausted() && handler.shouldContinue()) {
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
                                } catch (com.google.gson.JsonSyntaxException e) {
                                    handler.onError(new ResponseException(name, "stream_chat_completion",
                                            ResponseException.ResponseErrorType.MALFORMED_JSON, e));
                                    return;
                                }
                            }
                        }

                        if (!handler.shouldContinue()) {
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

    /**
     * Extract delta content from a streaming chunk.
     */
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

    /**
     * Helper class to accumulate tool call deltas during streaming.
     */
    private static class ToolCallAccumulator {
        String id;
        String name;
        final StringBuilder argumentsBuffer = new StringBuilder();
    }

    /**
     * Override non-streaming function call to handle Bedrock quirk:
     * "Thinking may not be enabled when tool_choice forces tool use."
     *
     * When tool_choice is "required", we must NOT include any thinking/reasoning
     * configuration for Anthropic models on Bedrock.
     */
    @Override
    public String createChatCompletionWithFunctions(List<ChatMessage> messages,
                                                     List<Map<String, Object>> functions) throws APIProviderException {
        // Build payload WITHOUT thinking enabled (tool_choice will be "required")
        JsonObject payload = buildToolCallPayload(messages, functions, true);

        Request request = new Request.Builder()
                .url(url + "chat/completions")
                .post(RequestBody.create(JSON, gson.toJson(payload)))
                .build();

        try (Response response = executeWithRetry(request, "createChatCompletionWithFunctions")) {
            String responseBody = response.body().string();
            return parseToolCallResponse(responseBody);
        } catch (IOException e) {
            throw handleNetworkError(e, "createChatCompletionWithFunctions");
        }
    }

    /**
     * Override non-streaming full response function call.
     */
    @Override
    public String createChatCompletionWithFunctionsFullResponse(List<ChatMessage> messages,
                                                                  List<Map<String, Object>> functions) throws APIProviderException {
        // Build payload WITHOUT thinking enabled
        JsonObject payload = buildToolCallPayload(messages, functions, false);

        Request request = new Request.Builder()
                .url(url + "chat/completions")
                .post(RequestBody.create(JSON, gson.toJson(payload)))
                .build();

        try (Response response = executeWithRetry(request, "createChatCompletionWithFunctionsFullResponse")) {
            return response.body().string();
        } catch (IOException e) {
            throw handleNetworkError(e, "createChatCompletionWithFunctionsFullResponse");
        }
    }

    /**
     * Build payload for tool/function calls.
     * CRITICAL: Thinking must be DISABLED when tool_choice forces tool use.
     *
     * @param messages Chat messages
     * @param functions Tool/function definitions
     * @param forceToolUse If true, set tool_choice to "required"
     */
    private JsonObject buildToolCallPayload(List<ChatMessage> messages,
                                             List<Map<String, Object>> functions,
                                             boolean forceToolUse) {
        JsonObject payload = new JsonObject();
        payload.addProperty("model", super.getModel());
        payload.addProperty("max_tokens", super.getMaxTokens());
        payload.addProperty("stream", false);

        // CRITICAL: Do NOT include reasoning/thinking when using tool_choice
        // Bedrock error: "Thinking may not be enabled when tool_choice forces tool use."
        // So we intentionally skip all thinking-related configuration here

        // Build messages array - use standard format (no thinking blocks)
        JsonArray messagesArray = new JsonArray();
        for (ChatMessage message : messages) {
            // Always use standard format for tool calls - no thinking block translation
            JsonObject messageObj = buildMessageObject(message, false);
            messagesArray.add(messageObj);
        }
        payload.add("messages", messagesArray);

        // Add tools
        if (functions != null && !functions.isEmpty()) {
            payload.add("tools", gson.toJsonTree(functions));
        } else {
            payload.add("tools", new JsonArray());
        }

        // Set tool_choice if forcing tool use
        if (forceToolUse) {
            payload.addProperty("tool_choice", "required");
        }

        Msg.debug(this, "LiteLLM tool call payload (thinking disabled): " + payload.toString());
        return payload;
    }

    /**
     * Parse tool call response and return in standard {"tool_calls":[...]} format.
     * Handles both OpenAI format and Anthropic/Bedrock format.
     *
     * OpenAI format:
     *   choices[0].message.tool_calls[0].function.arguments
     *
     * Anthropic/Bedrock format (via LiteLLM):
     *   choices[0].message.content[] with type="tool_use", input={...}
     *   OR direct content array with tool_use blocks
     *
     * Returns: {"tool_calls":[{"function":{"name":"...", "arguments":{...}}}]}
     */
    private String parseToolCallResponse(String responseBody) throws APIProviderException {
        try {
            Msg.debug(this, "LiteLLM parsing response: " + responseBody);
            JsonObject jsonResponse = gson.fromJson(responseBody, JsonObject.class);

            if (jsonResponse.has("choices")) {
                JsonArray choices = jsonResponse.getAsJsonArray("choices");
                if (choices.size() > 0) {
                    JsonObject choice = choices.get(0).getAsJsonObject();
                    if (choice.has("message")) {
                        JsonObject message = choice.getAsJsonObject("message");

                        // Format 1: OpenAI style - tool_calls array
                        if (message.has("tool_calls")) {
                            JsonArray toolCalls = message.getAsJsonArray("tool_calls");
                            String result = "{\"tool_calls\":" + toolCalls.toString() + "}";
                            Msg.debug(this, "LiteLLM parsed OpenAI tool_calls format: " + result);
                            return result;
                        }

                        // Format 2: Anthropic/Bedrock style - content array with tool_use blocks
                        if (message.has("content")) {
                            com.google.gson.JsonElement contentElement = message.get("content");

                            // Content could be an array (Anthropic format)
                            if (contentElement.isJsonArray()) {
                                JsonArray contentArray = contentElement.getAsJsonArray();
                                JsonArray convertedToolCalls = convertToolUseToToolCalls(contentArray);
                                if (convertedToolCalls.size() > 0) {
                                    String result = "{\"tool_calls\":" + convertedToolCalls.toString() + "}";
                                    Msg.debug(this, "LiteLLM parsed Anthropic tool_use format: " + result);
                                    return result;
                                }
                            }
                        }
                    }
                }
            }

            // Format 3: Direct Anthropic API response (content at top level)
            if (jsonResponse.has("content")) {
                com.google.gson.JsonElement contentElement = jsonResponse.get("content");
                if (contentElement.isJsonArray()) {
                    JsonArray contentArray = contentElement.getAsJsonArray();
                    JsonArray convertedToolCalls = convertToolUseToToolCalls(contentArray);
                    if (convertedToolCalls.size() > 0) {
                        String result = "{\"tool_calls\":" + convertedToolCalls.toString() + "}";
                        Msg.debug(this, "LiteLLM parsed direct Anthropic format: " + result);
                        return result;
                    }
                }
            }

            Msg.warn(this, "LiteLLM: Could not find tool call in response: " + responseBody);
            // Return empty tool_calls if nothing found
            return "{\"tool_calls\":[]}";
        } catch (Exception e) {
            throw new ResponseException(name, "createChatCompletionWithFunctions",
                    ResponseException.ResponseErrorType.MALFORMED_JSON, e);
        }
    }

    /**
     * Convert Anthropic tool_use content blocks to OpenAI-style tool_calls array.
     *
     * Anthropic format:
     *   { "type": "tool_use", "id": "...", "name": "func_name", "input": {...} }
     *
     * OpenAI format:
     *   { "function": { "name": "func_name", "arguments": {...} }, "id": "..." }
     */
    private JsonArray convertToolUseToToolCalls(JsonArray contentArray) {
        JsonArray toolCalls = new JsonArray();

        for (com.google.gson.JsonElement item : contentArray) {
            if (!item.isJsonObject()) continue;

            JsonObject contentBlock = item.getAsJsonObject();
            if (!contentBlock.has("type")) continue;

            String type = contentBlock.get("type").getAsString();
            if ("tool_use".equals(type)) {
                JsonObject toolCall = new JsonObject();
                JsonObject function = new JsonObject();

                // Get function name
                if (contentBlock.has("name")) {
                    function.addProperty("name", contentBlock.get("name").getAsString());
                }

                // Get arguments (called "input" in Anthropic format)
                if (contentBlock.has("input")) {
                    // Keep as object, not string
                    function.add("arguments", contentBlock.get("input"));
                }

                toolCall.add("function", function);

                // Preserve ID if present
                if (contentBlock.has("id")) {
                    toolCall.addProperty("id", contentBlock.get("id").getAsString());
                }

                toolCalls.add(toolCall);
            }
        }

        return toolCalls;
    }

    /**
     * Get the detected model family.
     */
    public String getModelFamily() {
        return modelFamily;
    }

    /**
     * Check if this is a Bedrock model.
     */
    public boolean isBedrock() {
        return isBedrock;
    }

    /**
     * Check if this model uses Anthropic-compatible API.
     */
    public boolean isAnthropicCompatible() {
        return isAnthropicCompatible;
    }
}
