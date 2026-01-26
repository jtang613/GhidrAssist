package ghidrassist.core.streaming;

import java.util.regex.Pattern;

/**
 * Detects stable block boundaries in markdown text during streaming.
 * This allows us to identify content that is "complete" and won't be
 * reinterpreted as more text arrives.
 */
public class BlockBoundaryDetector {

    private static final Pattern ATX_HEADING = Pattern.compile("^#{1,6}\\s");
    private static final Pattern THEMATIC_BREAK = Pattern.compile("^(\\*{3,}|-{3,}|_{3,})\\s*$");
    private static final Pattern FENCE_OPEN = Pattern.compile("^(`{3,}|~{3,})");
    private static final Pattern LIST_ITEM = Pattern.compile("^(\\s*([-*+]|\\d+[.)]))\\s");
    private static final Pattern BLOCK_QUOTE = Pattern.compile("^>\\s?");
    private static final Pattern TABLE_ROW = Pattern.compile("^\\|.*\\|\\s*$");

    /**
     * Finds the last position in the pending markdown where all preceding content
     * is considered "stable" (i.e., complete blocks that won't be reinterpreted).
     *
     * @param pendingMarkdown the current pending markdown text
     * @return the index into pendingMarkdown up to which content is stable,
     *         or 0 if nothing is stable yet
     */
    public static int findLastStableBoundary(String pendingMarkdown) {
        if (pendingMarkdown.isEmpty()) {
            return 0;
        }

        String[] lines = pendingMarkdown.split("\n", -1);
        int lastStableBoundary = 0;
        int currentOffset = 0;
        boolean inFence = false;
        String fenceMarker = null;

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            int lineEnd = currentOffset + line.length();
            // Account for the \n that was consumed by split (except possibly the last element)
            boolean hasNewline = (lineEnd < pendingMarkdown.length());

            if (!hasNewline && i == lines.length - 1) {
                // Last line without trailing newline - potentially incomplete, never promote
                break;
            }

            if (inFence) {
                // Check if this line closes the fence
                if (isClosingFence(line, fenceMarker)) {
                    inFence = false;
                    fenceMarker = null;
                    // The fence block is now complete; boundary is after this line
                    lastStableBoundary = lineEnd + 1; // +1 for the \n
                }
                // Lines inside an unclosed fence are not stable
            } else {
                // Check for fence opening
                var fenceMatcher = FENCE_OPEN.matcher(line);
                if (fenceMatcher.find()) {
                    fenceMarker = fenceMatcher.group(1);
                    inFence = true;
                } else if (isBlockBoundary(line, i, lines)) {
                    // This line starts a new block, meaning everything before it is stable
                    // But we need the *previous* block to be complete.
                    // A blank line or block-start means the preceding block is done.
                    lastStableBoundary = lineEnd + 1; // +1 for the \n
                }
            }

            currentOffset = lineEnd + 1; // +1 for the \n
        }

        return Math.min(lastStableBoundary, pendingMarkdown.length());
    }

    private static boolean isClosingFence(String line, String fenceMarker) {
        if (fenceMarker == null) return false;
        String trimmed = line.trim();
        char fenceChar = fenceMarker.charAt(0);
        if (trimmed.isEmpty()) return false;
        // Closing fence must use same character, at least as many, and nothing else
        for (char c : trimmed.toCharArray()) {
            if (c != fenceChar) return false;
        }
        return trimmed.length() >= fenceMarker.length();
    }

    private static boolean isBlockBoundary(String line, int lineIndex, String[] lines) {
        // Table rows are never boundaries - the table stays in pending
        // until a non-table line (blank, heading, etc.) terminates it
        if (TABLE_ROW.matcher(line).matches()) {
            return false;
        }

        // Blank line is always a block boundary
        if (line.trim().isEmpty()) {
            return true;
        }

        // ATX heading
        if (ATX_HEADING.matcher(line).find()) {
            return true;
        }

        // Thematic break
        if (THEMATIC_BREAK.matcher(line).matches()) {
            return true;
        }

        // List item start
        if (LIST_ITEM.matcher(line).find()) {
            return true;
        }

        // Block quote
        if (BLOCK_QUOTE.matcher(line).find()) {
            return true;
        }

        return false;
    }
}
