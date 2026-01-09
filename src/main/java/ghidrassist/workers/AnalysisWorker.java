package ghidrassist.workers;

import javax.swing.SwingWorker;
import java.util.function.Consumer;

/**
 * Base class for background analysis workers.
 * Uses SwingWorker to run tasks in the background without blocking the UI.
 *
 * @param <R> Result type returned by doInBackground
 */
public abstract class AnalysisWorker<R> extends SwingWorker<R, ProgressUpdate> {

    protected volatile boolean cancelled = false;

    // Callbacks
    private Consumer<ProgressUpdate> progressCallback;
    private Consumer<R> completedCallback;
    private Runnable cancelledCallback;
    private Consumer<String> failedCallback;

    /**
     * Set progress callback - called on EDT with progress updates.
     */
    public void setProgressCallback(Consumer<ProgressUpdate> callback) {
        this.progressCallback = callback;
    }

    /**
     * Set completed callback - called on EDT when work completes successfully.
     */
    public void setCompletedCallback(Consumer<R> callback) {
        this.completedCallback = callback;
    }

    /**
     * Set cancelled callback - called on EDT when work is cancelled.
     */
    public void setCancelledCallback(Runnable callback) {
        this.cancelledCallback = callback;
    }

    /**
     * Set failed callback - called on EDT when work fails with an error.
     */
    public void setFailedCallback(Consumer<String> callback) {
        this.failedCallback = callback;
    }

    /**
     * Cancel the worker. Subclasses should check isCancelRequested() periodically.
     */
    public void requestCancel() {
        this.cancelled = true;
        cancel(false); // Don't interrupt - let worker check flag
    }

    /**
     * Check if cancellation has been requested.
     */
    public boolean isCancelRequested() {
        return cancelled || isCancelled();
    }

    /**
     * Publish a progress update to the EDT.
     */
    protected void publishProgress(int current, int total, String message) {
        publish(new ProgressUpdate(current, total, message));
    }

    @Override
    protected void process(java.util.List<ProgressUpdate> chunks) {
        // Get the latest progress update
        if (progressCallback != null && !chunks.isEmpty()) {
            progressCallback.accept(chunks.get(chunks.size() - 1));
        }
    }

    @Override
    protected void done() {
        if (cancelled || isCancelled()) {
            if (cancelledCallback != null) {
                cancelledCallback.run();
            }
            return;
        }

        try {
            R result = get();
            if (completedCallback != null) {
                completedCallback.accept(result);
            }
        } catch (Exception e) {
            String message = e.getCause() != null ? e.getCause().getMessage() : e.getMessage();
            if (failedCallback != null) {
                failedCallback.accept(message);
            }
        }
    }
}
