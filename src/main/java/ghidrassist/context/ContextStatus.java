package ghidrassist.context;

/**
 * Represents the current status of context window usage.
 * Provides information about token counts, percentages, and whether compression is needed.
 */
public class ContextStatus {

    private final int currentTokens;
    private final int maxTokens;
    private final int compressionThresholdTokens;
    private final int messageCount;
    private final boolean needsCompression;
    private final String statusMessage;

    public ContextStatus(
        int currentTokens,
        int maxTokens,
        int compressionThresholdTokens,
        int messageCount,
        boolean needsCompression,
        String statusMessage
    ) {
        this.currentTokens = currentTokens;
        this.maxTokens = maxTokens;
        this.compressionThresholdTokens = compressionThresholdTokens;
        this.messageCount = messageCount;
        this.needsCompression = needsCompression;
        this.statusMessage = statusMessage;
    }

    /**
     * Calculate percentage of context window used.
     */
    public int getPercentageUsed() {
        if (maxTokens <= 0) {
            return 0;
        }
        return (currentTokens * 100) / maxTokens;
    }

    /**
     * Get percentage of threshold reached.
     */
    public int getThresholdPercentage() {
        if (compressionThresholdTokens <= 0) {
            return 0;
        }
        return (currentTokens * 100) / compressionThresholdTokens;
    }

    /**
     * Get tokens remaining before hitting max.
     */
    public int getTokensRemaining() {
        return Math.max(0, maxTokens - currentTokens);
    }

    // Getters
    public int getCurrentTokens() {
        return currentTokens;
    }

    public int getMaxTokens() {
        return maxTokens;
    }

    public int getCompressionThresholdTokens() {
        return compressionThresholdTokens;
    }

    public int getMessageCount() {
        return messageCount;
    }

    public boolean needsCompression() {
        return needsCompression;
    }

    public String getStatusMessage() {
        return statusMessage;
    }

    @Override
    public String toString() {
        return String.format(
            "ContextStatus{%d/%d tokens (%d%%), %d messages, compression:%s - %s}",
            currentTokens, maxTokens, getPercentageUsed(), messageCount,
            needsCompression ? "NEEDED" : "not needed", statusMessage
        );
    }

    /**
     * Create status indicating compression is needed.
     */
    public static ContextStatus needsCompression(
        int currentTokens,
        int maxTokens,
        int compressionThresholdTokens,
        int messageCount
    ) {
        return new ContextStatus(
            currentTokens,
            maxTokens,
            compressionThresholdTokens,
            messageCount,
            true,
            String.format("Exceeded threshold: %d > %d tokens", currentTokens, compressionThresholdTokens)
        );
    }

    /**
     * Create status indicating context is within limits.
     */
    public static ContextStatus withinLimits(
        int currentTokens,
        int maxTokens,
        int compressionThresholdTokens,
        int messageCount
    ) {
        return new ContextStatus(
            currentTokens,
            maxTokens,
            compressionThresholdTokens,
            messageCount,
            false,
            String.format("Within limits: %d/%d tokens", currentTokens, maxTokens)
        );
    }
}
