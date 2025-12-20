package ghidrassist.context;

import ghidrassist.LlmApi;
import ghidrassist.apiprovider.ChatMessage;
import ghidra.util.Msg;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Manages context window to prevent token overflow.
 * Provides token-based thresholds, LLM-based summarization, tool result truncation,
 * and orphaned tool call cleanup.
 *
 * Design: Standalone, reusable component with no ReAct dependencies.
 * Can be used by any feature requiring context management.
 */
public class ContextWindowManager {

    private final ContextWindowConfig config;
    private final TokenCounter tokenCounter;
    private final LlmApi llmApi; // For LLM-based summarization (optional)

    public ContextWindowManager(ContextWindowConfig config, TokenCounter tokenCounter) {
        this(config, tokenCounter, null);
    }

    public ContextWindowManager(ContextWindowConfig config, TokenCounter tokenCounter, LlmApi llmApi) {
        this.config = config;
        this.tokenCounter = tokenCounter;
        this.llmApi = llmApi;
    }

    /**
     * Main entry point: Check and manage conversation history before LLM request.
     * Compresses history if threshold exceeded, otherwise returns original.
     *
     * @param conversationHistory Current conversation messages
     * @param tools Tool definitions (for token estimation)
     * @return Managed conversation history (compressed if needed)
     */
    public CompletableFuture<List<ChatMessage>> checkAndManage(
        List<ChatMessage> conversationHistory,
        List<Map<String, Object>> tools
    ) {
        CompletableFuture<List<ChatMessage>> future = new CompletableFuture<>();

        try {
            // Get current status
            ContextStatus status = getStatus(conversationHistory, tools).join();

            // If within limits, return original history
            if (!status.needsCompression()) {
                Msg.debug(this, "Context within limits: " + status);
                future.complete(conversationHistory);
                return future;
            }

            // Compression needed
            Msg.info(this, "Context compression needed: " + status);

            // Perform compression
            compressHistory(conversationHistory)
                .thenAccept(compressedHistory -> {
                    Msg.info(this, String.format(
                        "Context compressed: %d → %d messages",
                        conversationHistory.size(), compressedHistory.size()
                    ));
                    future.complete(compressedHistory);
                })
                .exceptionally(throwable -> {
                    Msg.error(this, "Context compression failed: " + throwable.getMessage(), throwable);
                    // Fall back to original history on error
                    future.complete(conversationHistory);
                    return null;
                });

        } catch (Exception e) {
            Msg.error(this, "Context management failed: " + e.getMessage(), e);
            future.complete(conversationHistory); // Fall back to original
        }

        return future;
    }

    /**
     * Get context status without modification.
     *
     * @param conversationHistory Current conversation messages
     * @param tools Tool definitions (for token estimation)
     * @return Context status
     */
    public CompletableFuture<ContextStatus> getStatus(
        List<ChatMessage> conversationHistory,
        List<Map<String, Object>> tools
    ) {
        return CompletableFuture.supplyAsync(() -> {
            // Count tokens in conversation
            int conversationTokens = tokenCounter.countTokens(conversationHistory);

            // Estimate tokens for tools (if present)
            int toolTokens = 0;
            if (tools != null && !tools.isEmpty()) {
                toolTokens = tokenCounter.estimateTokensForTools(tools);
            }

            // Total tokens
            int totalTokens = conversationTokens + toolTokens;

            // Check if compression needed
            boolean needsCompression = totalTokens > config.getCompressionThresholdTokens();

            if (needsCompression) {
                return ContextStatus.needsCompression(
                    totalTokens,
                    config.getMaxContextTokens(),
                    config.getCompressionThresholdTokens(),
                    conversationHistory.size()
                );
            } else {
                return ContextStatus.withinLimits(
                    totalTokens,
                    config.getMaxContextTokens(),
                    config.getCompressionThresholdTokens(),
                    conversationHistory.size()
                );
            }
        });
    }

    /**
     * Truncate individual tool result to max tokens.
     * Preserves start and end with ellipsis marker.
     *
     * @param result Tool result text
     * @param maxTokens Maximum tokens (default: config.getMaxToolResultTokens())
     * @return Truncated result
     */
    public String truncateToolResult(String result, int maxTokens) {
        if (result == null || result.isEmpty()) {
            return result;
        }

        int actualMaxTokens = maxTokens > 0 ? maxTokens : config.getMaxToolResultTokens();

        // Count tokens in result
        int resultTokens = tokenCounter.countTokens(result);

        if (resultTokens <= actualMaxTokens) {
            return result; // No truncation needed
        }

        // Calculate how much to keep
        double keepRatio = (double) actualMaxTokens / resultTokens;
        int charsToKeep = (int) (result.length() * keepRatio);

        // Keep first 70% of allowed space, last 30%
        int startChars = (int) (charsToKeep * 0.7);
        int endChars = (int) (charsToKeep * 0.3);

        String truncated = result.substring(0, Math.min(startChars, result.length())) +
            "\n\n[... truncated for context management ...]\n\n" +
            result.substring(Math.max(0, result.length() - endChars));

        return truncated;
    }

    /**
     * Truncate with default max tokens from config.
     */
    public String truncateToolResult(String result) {
        return truncateToolResult(result, config.getMaxToolResultTokens());
    }

    /**
     * Cleanup orphaned tool calls (for cancellation handling).
     * Removes assistant messages with tool_calls that don't have corresponding tool results.
     *
     * @param messages Conversation messages
     * @return Cleaned messages
     */
    public List<ChatMessage> removeOrphanedToolCalls(List<ChatMessage> messages) {
        List<ChatMessage> cleaned = new ArrayList<>();
        Set<String> toolCallIdsWithResults = new HashSet<>();

        // First pass: identify tool call IDs that have results
        for (ChatMessage message : messages) {
            if (ChatMessage.ChatMessageRole.TOOL.equals(message.getRole()) &&
                message.getToolCallId() != null) {
                toolCallIdsWithResults.add(message.getToolCallId());
            }
        }

        // Second pass: remove assistant messages with orphaned tool calls
        for (int i = 0; i < messages.size(); i++) {
            ChatMessage message = messages.get(i);

            // Check if this is an assistant message with tool calls
            if (ChatMessage.ChatMessageRole.ASSISTANT.equals(message.getRole()) &&
                message.getToolCalls() != null &&
                !message.getToolCalls().isEmpty()) {

                // Check if all tool calls have results
                boolean allHaveResults = true;
                for (Object toolCall : message.getToolCalls()) {
                    // Extract tool call ID (implementation depends on toolCall structure)
                    String toolCallId = extractToolCallId(toolCall);
                    if (toolCallId != null && !toolCallIdsWithResults.contains(toolCallId)) {
                        allHaveResults = false;
                        break;
                    }
                }

                if (allHaveResults) {
                    cleaned.add(message);
                } else {
                    Msg.debug(this, "Removed orphaned tool call message at index " + i);
                }
            } else {
                cleaned.add(message);
            }
        }

        return cleaned;
    }

    /**
     * Compress conversation history when threshold exceeded.
     * Preserves system messages, recent messages, and complete tool pairs.
     * Summarizes older messages using LLM.
     *
     * @param messages Current conversation messages
     * @return Compressed messages
     */
    private CompletableFuture<List<ChatMessage>> compressHistory(List<ChatMessage> messages) {
        CompletableFuture<List<ChatMessage>> future = new CompletableFuture<>();

        try {
            List<ChatMessage> result = new ArrayList<>();

            // 1. Extract and preserve system messages
            List<ChatMessage> systemMessages = new ArrayList<>();
            List<ChatMessage> nonSystemMessages = new ArrayList<>();

            for (ChatMessage message : messages) {
                if (ChatMessage.ChatMessageRole.SYSTEM.equals(message.getRole())) {
                    systemMessages.add(message);
                } else {
                    nonSystemMessages.add(message);
                }
            }

            // 2. Preserve recent messages
            int preserveCount = config.getPreserveRecentMessages();
            int startIndexForRecent = Math.max(0, nonSystemMessages.size() - preserveCount);
            List<ChatMessage> recentMessages = nonSystemMessages.subList(startIndexForRecent, nonSystemMessages.size());

            // 3. Extract complete tool pairs from recent messages
            List<ToolPair> recentToolPairs = extractToolPairs(recentMessages);
            int preserveToolPairCount = Math.min(config.getPreserveToolPairs(), recentToolPairs.size());

            // 4. Identify messages to summarize (older messages not in recent/tool pairs)
            Set<ChatMessage> preservedMessages = new HashSet<>(recentMessages);

            // Add tool pair messages to preserved set
            for (int i = recentToolPairs.size() - preserveToolPairCount; i < recentToolPairs.size(); i++) {
                preservedMessages.addAll(recentToolPairs.get(i).getAllMessages());
            }

            List<ChatMessage> toSummarize = new ArrayList<>();
            for (ChatMessage message : nonSystemMessages) {
                if (!preservedMessages.contains(message)) {
                    toSummarize.add(message);
                }
            }

            // 5. Summarize older messages
            if (!toSummarize.isEmpty() && config.isEnableLlmSummarization() && llmApi != null) {
                summarizeMessages(toSummarize)
                    .thenAccept(summaryText -> {
                        // Build result: system + summary + recent
                        result.addAll(systemMessages);

                        // Add summary as user message
                        ChatMessage summaryMessage = new ChatMessage(
                            ChatMessage.ChatMessageRole.USER,
                            "## Conversation Summary (Older Messages)\n\n" + summaryText
                        );
                        result.add(summaryMessage);

                        // Add recent messages
                        result.addAll(recentMessages);

                        future.complete(result);
                    })
                    .exceptionally(throwable -> {
                        Msg.error(this, "Summarization failed: " + throwable.getMessage(), throwable);
                        // Fall back to keeping only system + recent
                        result.addAll(systemMessages);
                        result.addAll(recentMessages);
                        future.complete(result);
                        return null;
                    });
            } else {
                // No LLM summarization - just keep system + recent
                result.addAll(systemMessages);
                result.addAll(recentMessages);
                future.complete(result);
            }

        } catch (Exception e) {
            Msg.error(this, "History compression failed: " + e.getMessage(), e);
            future.completeExceptionally(e);
        }

        return future;
    }

    /**
     * Extract complete tool pairs from messages.
     */
    private List<ToolPair> extractToolPairs(List<ChatMessage> messages) {
        List<ToolPair> pairs = new ArrayList<>();
        ToolPair currentPair = null;

        for (ChatMessage message : messages) {
            // Check for assistant message with tool calls
            if (ChatMessage.ChatMessageRole.ASSISTANT.equals(message.getRole()) &&
                message.getToolCalls() != null &&
                !message.getToolCalls().isEmpty()) {

                // Start new pair
                currentPair = new ToolPair(message);
                pairs.add(currentPair);

            } else if (ChatMessage.ChatMessageRole.TOOL.equals(message.getRole()) &&
                       currentPair != null) {

                // Add tool result to current pair
                currentPair.addToolResult(message);
            }
        }

        return pairs;
    }

    /**
     * Use LLM to summarize older messages into compact form.
     */
    private CompletableFuture<String> summarizeMessages(List<ChatMessage> messages) {
        CompletableFuture<String> future = new CompletableFuture<>();

        if (messages.isEmpty()) {
            future.complete("");
            return future;
        }

        // Build summarization prompt
        StringBuilder prompt = new StringBuilder();
        prompt.append("Summarize the following conversation messages concisely, ");
        prompt.append("preserving key information, discoveries, and context:\n\n");

        for (ChatMessage message : messages) {
            prompt.append(String.format("**%s**: %s\n\n",
                message.getRole(),
                message.getContent() != null ? message.getContent() : "(no content)"));
        }

        prompt.append("\nProvide a compact summary (2-3 paragraphs) that captures the essential information.");

        // Use LLM to generate summary
        AtomicBoolean completed = new AtomicBoolean(false);
        StringBuilder summaryBuilder = new StringBuilder();

        llmApi.sendRequestAsync(prompt.toString(), new LlmApi.LlmResponseHandler() {
            @Override
            public void onStart() {
                summaryBuilder.setLength(0);
            }

            @Override
            public void onUpdate(String partialResponse) {
                summaryBuilder.append(partialResponse);
            }

            @Override
            public void onComplete(String fullResponse) {
                if (!completed.getAndSet(true)) {
                    future.complete(summaryBuilder.toString());
                }
            }

            @Override
            public void onError(Throwable error) {
                if (!completed.getAndSet(true)) {
                    future.completeExceptionally(error);
                }
            }
        });

        return future;
    }

    /**
     * Extract tool call ID from tool call object.
     * Handles different tool call formats from different providers.
     */
    private String extractToolCallId(Object toolCall) {
        if (toolCall == null) {
            return null;
        }

        // Try to extract ID from Map structure (most common)
        if (toolCall instanceof Map) {
            Map<?, ?> toolCallMap = (Map<?, ?>) toolCall;
            Object id = toolCallMap.get("id");
            return id != null ? id.toString() : null;
        }

        // Could add more extraction logic for other formats if needed

        return null;
    }

    // Getters
    public ContextWindowConfig getConfig() {
        return config;
    }
}
