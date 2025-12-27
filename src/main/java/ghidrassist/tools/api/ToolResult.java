package ghidrassist.tools.api;

/**
 * Unified result type for tool execution.
 * Encapsulates success/error state and content.
 */
public class ToolResult {

    private final boolean success;
    private final String content;
    private final String errorMessage;

    private ToolResult(boolean success, String content, String errorMessage) {
        this.success = success;
        this.content = content;
        this.errorMessage = errorMessage;
    }

    /**
     * Create a successful result with content.
     */
    public static ToolResult success(String content) {
        return new ToolResult(true, content, null);
    }

    /**
     * Create an error result with a message.
     */
    public static ToolResult error(String errorMessage) {
        return new ToolResult(false, null, errorMessage);
    }

    /**
     * Check if this result represents success.
     */
    public boolean isSuccess() {
        return success;
    }

    /**
     * Check if this result represents an error.
     */
    public boolean isError() {
        return !success;
    }

    /**
     * Get the content (for successful results).
     */
    public String getContent() {
        return content;
    }

    /**
     * Get the error message (for error results).
     */
    public String getErrorMessage() {
        return errorMessage;
    }

    /**
     * Get the content or error message, whichever is applicable.
     */
    public String getContentOrError() {
        return success ? content : errorMessage;
    }

    @Override
    public String toString() {
        if (success) {
            return "ToolResult[success, content=" +
                   (content != null ? content.substring(0, Math.min(100, content.length())) + "..." : "null") + "]";
        } else {
            return "ToolResult[error, message=" + errorMessage + "]";
        }
    }
}
