package ghidrassist.core.streaming;

import ghidrassist.core.MarkdownHelper;

import javax.swing.SwingUtilities;
import java.util.function.Consumer;

/**
 * Handles incremental markdown rendering during LLM streaming.
 * Uses a committed/pending model where stable blocks are promoted
 * to committed status for efficient DOM updates.
 */
public class StreamingMarkdownRenderer {

    private final StringBuilder committedMarkdown = new StringBuilder();
    private final StringBuilder pendingMarkdown = new StringBuilder();
    private final Consumer<RenderUpdate> updateCallback;
    private final MarkdownHelper markdownHelper;
    private String conversationPrefix = "";  // HTML for prior conversation history

    /**
     * Create a new streaming renderer.
     *
     * @param updateCallback Callback to receive render updates (called on EDT)
     * @param markdownHelper Helper for markdown-to-HTML conversion
     */
    public StreamingMarkdownRenderer(Consumer<RenderUpdate> updateCallback, MarkdownHelper markdownHelper) {
        this.updateCallback = updateCallback;
        this.markdownHelper = markdownHelper;
    }

    /**
     * Set the conversation prefix HTML that appears before streaming content.
     * This is the rendered HTML of prior conversation history.
     *
     * @param prefixHtml Pre-rendered HTML for conversation history
     */
    public void setConversationPrefix(String prefixHtml) {
        this.conversationPrefix = prefixHtml != null ? prefixHtml : "";
    }

    /**
     * Get the conversation prefix HTML.
     *
     * @return The prefix HTML
     */
    public String getConversationPrefix() {
        return conversationPrefix;
    }

    /**
     * Process a new chunk of streaming text.
     * Detects block boundaries and issues incremental or pending updates.
     *
     * @param chunk The new text chunk to process
     */
    public void onChunkReceived(String chunk) {
        if (chunk == null || chunk.isEmpty()) {
            return;
        }

        pendingMarkdown.append(chunk);

        int boundary = BlockBoundaryDetector.findLastStableBoundary(pendingMarkdown.toString());

        String committedHtmlToAppend = "";
        if (boundary > 0) {
            String stablePrefix = pendingMarkdown.substring(0, boundary);
            committedMarkdown.append(stablePrefix);
            pendingMarkdown.delete(0, boundary);

            // Parse the newly committed portion to HTML
            committedHtmlToAppend = parseMarkdownFragment(stablePrefix);
        }

        // Parse the remaining pending portion
        String pendingText = pendingMarkdown.toString();
        String pendingHtml;
        if (pendingText.isEmpty()) {
            pendingHtml = "<span></span>";
        } else {
            pendingHtml = parseMarkdownFragment(pendingText);
        }

        RenderUpdate update = RenderUpdate.incremental(committedHtmlToAppend, pendingHtml);
        SwingUtilities.invokeLater(() -> updateCallback.accept(update));
    }

    /**
     * Signal that the stream is complete.
     * Promotes all pending content and issues a full replace update.
     */
    public void onStreamComplete() {
        // Promote all remaining pending content
        committedMarkdown.append(pendingMarkdown);
        pendingMarkdown.setLength(0);

        // Do a full parse of the complete document
        String fullHtml = parseMarkdownFragment(committedMarkdown.toString());

        RenderUpdate update = RenderUpdate.fullReplace(fullHtml);
        SwingUtilities.invokeLater(() -> updateCallback.accept(update));
    }

    /**
     * Reset the renderer state for a new stream.
     */
    public void reset() {
        committedMarkdown.setLength(0);
        pendingMarkdown.setLength(0);
        conversationPrefix = "";
    }

    /**
     * Get the current accumulated markdown content (committed + pending).
     *
     * @return The full markdown text received so far
     */
    public String getCurrentMarkdown() {
        return committedMarkdown.toString() + pendingMarkdown.toString();
    }

    /**
     * Get only the committed markdown content.
     *
     * @return The committed (stable) markdown text
     */
    public String getCommittedMarkdown() {
        return committedMarkdown.toString();
    }

    /**
     * Parse a markdown fragment to HTML using the MarkdownHelper.
     * Applies table attribute post-processing for Swing compatibility.
     *
     * @param markdown The markdown to convert
     * @return The resulting HTML fragment
     */
    private String parseMarkdownFragment(String markdown) {
        if (markdown == null || markdown.isEmpty()) {
            return "";
        }

        // Use markdownHelper's parsing - get raw HTML without wrapper
        String html = markdownHelper.markdownToHtmlFragment(markdown);

        // Post-process: add HTML attributes for table rendering in Swing
        // (Swing's HTMLDocument doesn't support CSS border on td/th,
        //  but does support border/cellpadding/cellspacing attributes)
        html = html.replace("<table>", "<table border=\"1\" cellpadding=\"4\" cellspacing=\"0\">");

        return html;
    }
}
