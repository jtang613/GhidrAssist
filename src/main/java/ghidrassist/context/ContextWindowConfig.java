package ghidrassist.context;

/**
 * Configuration for context window management.
 * Defines limits, thresholds, and preservation rules for managing conversation history.
 */
public class ContextWindowConfig {

    // Token limits
    private final int maxContextTokens;           // Maximum tokens allowed in context window
    private final int compressionThresholdPercent; // Trigger compression at this % of max
    private final int maxToolResultTokens;         // Max tokens per individual tool result

    // Preservation rules
    private final int preserveRecentMessages;      // Always keep last N messages
    private final int preserveToolPairs;           // Always keep last N complete tool pairs

    // Summarization
    private final boolean enableLlmSummarization;  // Use LLM to summarize old messages

    /**
     * Create context window config with default values.
     */
    public ContextWindowConfig() {
        this(200000, 75, 10000, 10, 2, true);
    }

    /**
     * Create context window config with custom values.
     *
     * @param maxContextTokens Maximum tokens in context window
     * @param compressionThresholdPercent Percentage of max to trigger compression (0-100)
     * @param maxToolResultTokens Maximum tokens per tool result
     * @param preserveRecentMessages Always keep last N messages
     * @param preserveToolPairs Always keep last N complete tool pairs
     * @param enableLlmSummarization Use LLM for summarization
     */
    public ContextWindowConfig(
        int maxContextTokens,
        int compressionThresholdPercent,
        int maxToolResultTokens,
        int preserveRecentMessages,
        int preserveToolPairs,
        boolean enableLlmSummarization
    ) {
        this.maxContextTokens = maxContextTokens;
        this.compressionThresholdPercent = Math.max(1, Math.min(100, compressionThresholdPercent));
        this.maxToolResultTokens = maxToolResultTokens;
        this.preserveRecentMessages = preserveRecentMessages;
        this.preserveToolPairs = preserveToolPairs;
        this.enableLlmSummarization = enableLlmSummarization;
    }

    // Getters
    public int getMaxContextTokens() {
        return maxContextTokens;
    }

    public int getCompressionThresholdPercent() {
        return compressionThresholdPercent;
    }

    public int getCompressionThresholdTokens() {
        return (maxContextTokens * compressionThresholdPercent) / 100;
    }

    public int getMaxToolResultTokens() {
        return maxToolResultTokens;
    }

    public int getPreserveRecentMessages() {
        return preserveRecentMessages;
    }

    public int getPreserveToolPairs() {
        return preserveToolPairs;
    }

    public boolean isEnableLlmSummarization() {
        return enableLlmSummarization;
    }

    @Override
    public String toString() {
        return String.format(
            "ContextWindowConfig{max=%d, threshold=%d%%, toolResult=%d, recent=%d, toolPairs=%d, llmSumm=%s}",
            maxContextTokens, compressionThresholdPercent, maxToolResultTokens,
            preserveRecentMessages, preserveToolPairs, enableLlmSummarization
        );
    }
}
