package ghidrassist.workers;

/**
 * Progress update data for background workers.
 */
public class ProgressUpdate {
    public final int current;
    public final int total;
    public final String message;

    public ProgressUpdate(int current, int total, String message) {
        this.current = current;
        this.total = total;
        this.message = message;
    }

    /**
     * Get progress as a percentage (0-100).
     */
    public int getPercentage() {
        if (total <= 0) return 0;
        return (int) ((current * 100L) / total);
    }
}
