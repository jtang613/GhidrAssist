package ghidrassist.core.streaming;

import javax.swing.JScrollBar;
import javax.swing.JScrollPane;

/**
 * Manages scroll position during streaming updates.
 * Auto-scrolls to bottom when user is already at bottom,
 * but preserves scroll position when user has scrolled up.
 *
 * Based on working reference implementation from java-text-widget-test.
 */
public class StreamingScrollManager {

    private static final int BOTTOM_THRESHOLD = 50;
    private final JScrollPane scrollPane;

    public StreamingScrollManager(JScrollPane scrollPane) {
        this.scrollPane = scrollPane;
    }

    /**
     * Check if the viewport is currently at the bottom (within threshold).
     *
     * @return true if scrolled to bottom
     */
    public boolean isAtBottom() {
        JScrollBar verticalBar = scrollPane.getVerticalScrollBar();
        int extent = verticalBar.getModel().getExtent();
        int maximum = verticalBar.getMaximum();
        int value = verticalBar.getValue();
        return (maximum - (value + extent)) <= BOTTOM_THRESHOLD;
    }

    /**
     * Scroll to the bottom of the content.
     */
    public void scrollToBottom() {
        JScrollBar verticalBar = scrollPane.getVerticalScrollBar();
        verticalBar.setValue(verticalBar.getMaximum());
    }

    /**
     * Get the current scroll position value.
     *
     * @return The vertical scrollbar value
     */
    public int getScrollPosition() {
        return scrollPane.getVerticalScrollBar().getValue();
    }

    /**
     * Set the scroll position value.
     *
     * @param position The position to scroll to
     */
    public void setScrollPosition(int position) {
        scrollPane.getVerticalScrollBar().setValue(position);
    }

    /**
     * Get the scroll pane for direct access.
     *
     * @return The scroll pane
     */
    public JScrollPane getScrollPane() {
        return scrollPane;
    }
}
