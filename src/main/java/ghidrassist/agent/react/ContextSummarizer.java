package ghidrassist.agent.react;

/**
 * Manages context summarization to stay within token limits.
 * Compresses conversation history while retaining key information.
 */
public class ContextSummarizer {

    private final int summaryThreshold;  // Trigger summarization after this many chars

    public ContextSummarizer() {
        this(8000);  // Default threshold
    }

    public ContextSummarizer(int summaryThreshold) {
        this.summaryThreshold = summaryThreshold;
    }

    /**
     * Check if summarization is needed based on context size.
     */
    public boolean needsSummarization(int currentSize) {
        return currentSize > summaryThreshold;
    }

    /**
     * Create a compact summary of current progress.
     */
    public String createSummary(
        String objective,
        TodoListManager todoManager,
        FindingsCache findings
    ) {
        StringBuilder sb = new StringBuilder();

        sb.append("## Investigation Summary\n\n");
        sb.append("**Objective**: ").append(objective).append("\n\n");

        // Progress
        sb.append("**Progress**: ").append(todoManager.toCompactString()).append("\n\n");

        // Completed todos with evidence
        String completed = todoManager.getCompletedSummary();
        if (!completed.isEmpty()) {
            sb.append("**Completed**:\n");
            sb.append(completed).append("\n\n");
        }

        // Pending todos
        String pending = todoManager.formatForPrompt();
        if (!pending.isEmpty() && !todoManager.allComplete()) {
            sb.append("**Still To Do**:\n");
            sb.append(pending).append("\n\n");
        }

        // Key findings
        sb.append("**Key Findings** (").append(findings.getCount()).append(" total):\n");
        sb.append(findings.formatForPrompt(15)).append("\n\n");

        return sb.toString();
    }

    /**
     * Create a continuation prompt after summarization.
     * This replaces the long conversation history.
     */
    public String createContinuationPrompt(String summary) {
        return String.format("""
            You are continuing a reverse engineering investigation.
            Here's what has been done so far:

            %s

            Continue the investigation based on the pending todos and what you've learned.
            Use tools to gather any additional information needed.
            """,
            summary
        );
    }

    /**
     * Estimate context size in characters (rough approximation).
     */
    public int estimateContextSize(
        String objective,
        TodoListManager todoManager,
        FindingsCache findings,
        int conversationSize
    ) {
        return objective.length() +
               todoManager.formatForPrompt().length() +
               findings.formatForPrompt().length() +
               conversationSize;
    }

    public int getSummaryThreshold() {
        return summaryThreshold;
    }
}
