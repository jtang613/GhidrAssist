package ghidrassist.workers;

import ghidra.util.task.TaskMonitor;
import java.util.function.Supplier;

/**
 * A TaskMonitor implementation that bridges to SwingWorker.
 * Delegates progress updates to a callback and checks a cancellation supplier.
 */
public class SwingWorkerTaskMonitor implements TaskMonitor {

    private final ProgressCallback progressCallback;
    private final Supplier<Boolean> cancelledSupplier;

    private String message = "";
    private long progress = 0;
    private long maximum = 100;
    private boolean indeterminate = false;

    /**
     * Callback for progress updates.
     */
    public interface ProgressCallback {
        void onProgress(int current, int total, String message);
    }

    /**
     * Create a TaskMonitor that bridges to SwingWorker.
     *
     * @param progressCallback  Called when progress changes
     * @param cancelledSupplier Returns true if cancellation requested
     */
    public SwingWorkerTaskMonitor(ProgressCallback progressCallback, Supplier<Boolean> cancelledSupplier) {
        this.progressCallback = progressCallback;
        this.cancelledSupplier = cancelledSupplier;
    }

    @Override
    public boolean isCancelled() {
        return cancelledSupplier != null && cancelledSupplier.get();
    }

    @Override
    public void setShowProgressValue(boolean showProgressValue) {
        // Not used in SwingWorker context
    }

    @Override
    public void setMessage(String message) {
        this.message = message;
        fireProgress();
    }

    @Override
    public String getMessage() {
        return message;
    }

    @Override
    public void setProgress(long value) {
        this.progress = value;
        fireProgress();
    }

    @Override
    public void initialize(long max) {
        this.maximum = max;
        this.progress = 0;
        fireProgress();
    }

    @Override
    public void setMaximum(long max) {
        this.maximum = max;
        fireProgress();
    }

    @Override
    public long getMaximum() {
        return maximum;
    }

    @Override
    public void setIndeterminate(boolean indeterminate) {
        this.indeterminate = indeterminate;
        fireProgress();
    }

    @Override
    public boolean isIndeterminate() {
        return indeterminate;
    }

    @Override
    public void checkCancelled() throws ghidra.util.exception.CancelledException {
        if (isCancelled()) {
            throw new ghidra.util.exception.CancelledException();
        }
    }

    @Override
    public void checkCanceled() throws ghidra.util.exception.CancelledException {
        checkCancelled();
    }

    @Override
    public void incrementProgress(long incrementAmount) {
        this.progress += incrementAmount;
        fireProgress();
    }

    @Override
    public long getProgress() {
        return progress;
    }

    @Override
    public void cancel() {
        // Can't cancel from here - cancellation is controlled by SwingWorker
    }

    @Override
    public void addCancelledListener(ghidra.util.task.CancelledListener listener) {
        // Not implemented for SwingWorker context
    }

    @Override
    public void removeCancelledListener(ghidra.util.task.CancelledListener listener) {
        // Not implemented for SwingWorker context
    }

    @Override
    public void setCancelEnabled(boolean enable) {
        // Not used in SwingWorker context
    }

    @Override
    public boolean isCancelEnabled() {
        return true;
    }

    @Override
    public void clearCancelled() {
        // Not used in SwingWorker context
    }

    @Override
    public void clearCanceled() {
        // Not used in SwingWorker context (alternate spelling)
    }

    private void fireProgress() {
        if (progressCallback != null) {
            int current = (int) Math.min(progress, Integer.MAX_VALUE);
            int total = (int) Math.min(maximum, Integer.MAX_VALUE);
            progressCallback.onProgress(current, total, message);
        }
    }
}
