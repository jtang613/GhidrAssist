package ghidrassist.agent.react;

import com.google.gson.JsonObject;

/**
 * Callback interface for tracking ReAct agent progress.
 * Much simpler than AgentProgressHandler - no hypothesis/reflection callbacks.
 */
public interface ReActProgressHandler {

    /**
     * Called when analysis starts.
     * @param objective The user's query/question
     */
    void onStart(String objective);

    /**
     * Called when the agent generates a thought.
     * @param thought The agent's reasoning about what to do next
     * @param iteration Current iteration number (1-based)
     */
    void onThought(String thought, int iteration);

    /**
     * Called when the agent decides to execute a tool.
     * @param toolName Name of the tool being called
     * @param args Arguments for the tool call
     */
    void onAction(String toolName, JsonObject args);

    /**
     * Called when a tool execution completes.
     * @param toolName Name of the tool that was called
     * @param result Result from the tool execution
     */
    void onObservation(String toolName, String result);

    /**
     * Called when the agent adds a key finding.
     * @param finding A significant discovery worth highlighting
     */
    void onFinding(String finding);

    /**
     * Called when analysis completes (successfully or otherwise).
     * @param result The final analysis result
     */
    void onComplete(ReActResult result);

    /**
     * Called when an error occurs during analysis.
     * @param error The error that occurred
     */
    void onError(Throwable error);

    /**
     * Called periodically to check if analysis should continue.
     * @return true to continue, false to cancel
     */
    boolean shouldContinue();

    /**
     * Called when approaching iteration limit.
     * @param remaining Number of iterations remaining
     */
    default void onIterationWarning(int remaining) {
        // Default implementation does nothing - can be overridden
    }

    /**
     * Called when approaching tool call limit.
     * @param remaining Number of tool calls remaining
     */
    default void onToolCallWarning(int remaining) {
        // Default implementation does nothing - can be overridden
    }

    /**
     * Called when todos are updated.
     * @param todosFormatted Current todo list formatted for display
     */
    default void onTodosUpdated(String todosFormatted) {
        // Default implementation does nothing - can be overridden
    }

    /**
     * Called when context is being summarized.
     * @param summary The summary being created
     */
    default void onSummarizing(String summary) {
        // Default implementation does nothing - can be overridden
    }
}
