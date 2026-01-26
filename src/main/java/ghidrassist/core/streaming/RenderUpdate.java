package ghidrassist.core.streaming;

/**
 * Represents an update to be applied to the streaming markdown display.
 * Supports both incremental updates (append to committed, replace pending)
 * and full document replacements.
 */
public class RenderUpdate {

    public enum UpdateType {
        /** Append to committed div, replace pending div */
        INCREMENTAL,
        /** Replace entire document content */
        FULL_REPLACE
    }

    private final UpdateType type;
    private final String committedHtmlToAppend;
    private final String pendingHtml;
    private final String fullHtml;

    private RenderUpdate(UpdateType type, String committedHtmlToAppend, String pendingHtml, String fullHtml) {
        this.type = type;
        this.committedHtmlToAppend = committedHtmlToAppend;
        this.pendingHtml = pendingHtml;
        this.fullHtml = fullHtml;
    }

    /**
     * Create an incremental update that appends to committed content
     * and replaces pending content.
     *
     * @param committedHtmlToAppend HTML to append to the committed div (may be empty)
     * @param pendingHtml HTML to replace in the pending div
     * @return A new RenderUpdate for incremental application
     */
    public static RenderUpdate incremental(String committedHtmlToAppend, String pendingHtml) {
        return new RenderUpdate(UpdateType.INCREMENTAL, committedHtmlToAppend, pendingHtml, null);
    }

    /**
     * Create a full replacement update that replaces the entire document body.
     * Used at stream completion for final render.
     *
     * @param fullHtml The complete HTML content
     * @return A new RenderUpdate for full replacement
     */
    public static RenderUpdate fullReplace(String fullHtml) {
        return new RenderUpdate(UpdateType.FULL_REPLACE, null, null, fullHtml);
    }

    public UpdateType getType() {
        return type;
    }

    public String getCommittedHtmlToAppend() {
        return committedHtmlToAppend;
    }

    public String getPendingHtml() {
        return pendingHtml;
    }

    public String getFullHtml() {
        return fullHtml;
    }
}
