package ghidrassist.core;

import ghidra.util.Msg;
import ghidrassist.workers.AnalysisWorker;
import ghidrassist.workers.ProgressUpdate;

import javax.swing.*;
import java.util.function.Consumer;

/**
 * Utility class for executing AnalysisWorker instances with standardized callback patterns.
 * Eliminates code duplication across worker setup in controllers.
 *
 * Extracted from TabController as part of decomposition refactoring.
 */
public class WorkerExecutor {

    /**
     * Interface for UI components that can show progress.
     * Controllers pass implementations to WorkerExecutor for progress feedback.
     */
    public interface ProgressUI {
        /**
         * Show progress bar with percentage and message.
         */
        void showProgress(int percentage, String message);

        /**
         * Show indeterminate progress (spinner) with message.
         */
        default void showIndeterminateProgress(String message) {
            showProgress(-1, message);
        }

        /**
         * Hide the progress indicator.
         */
        void hideProgress();

        /**
         * Set the running state for this operation.
         * @param running true if operation is starting, false if ending
         */
        void setRunning(boolean running);

        /**
         * Refresh the view after operation completes.
         */
        default void refreshView() {
            // Optional - override if needed
        }
    }

    /**
     * Configuration for worker execution.
     * Uses builder pattern for optional callbacks.
     */
    public static class ExecutionConfig<R> {
        private final AnalysisWorker<R> worker;
        private final ProgressUI ui;
        private String progressPrefix = "";
        private Consumer<R> onComplete;
        private Runnable onNextStep;
        private Consumer<String> onFailed;
        private Runnable onCancelled;
        private String operationName = "Operation";
        private String successMessage;
        private boolean showSuccessDialog = false;

        public ExecutionConfig(AnalysisWorker<R> worker, ProgressUI ui) {
            this.worker = worker;
            this.ui = ui;
        }

        /**
         * Set prefix for progress messages (e.g., "Security: ").
         */
        public ExecutionConfig<R> progressPrefix(String prefix) {
            this.progressPrefix = prefix;
            return this;
        }

        /**
         * Set callback when work completes successfully.
         */
        public ExecutionConfig<R> onComplete(Consumer<R> callback) {
            this.onComplete = callback;
            return this;
        }

        /**
         * Set callback to run next step in a chain after completion.
         */
        public ExecutionConfig<R> onNextStep(Runnable nextStep) {
            this.onNextStep = nextStep;
            return this;
        }

        /**
         * Set callback when work fails.
         */
        public ExecutionConfig<R> onFailed(Consumer<String> callback) {
            this.onFailed = callback;
            return this;
        }

        /**
         * Set callback when work is cancelled.
         */
        public ExecutionConfig<R> onCancelled(Runnable callback) {
            this.onCancelled = callback;
            return this;
        }

        /**
         * Set operation name for logging and error messages.
         */
        public ExecutionConfig<R> operationName(String name) {
            this.operationName = name;
            return this;
        }

        /**
         * Set success message to show when operation completes.
         * If set with showSuccessDialog(true), shows a dialog.
         */
        public ExecutionConfig<R> successMessage(String message) {
            this.successMessage = message;
            return this;
        }

        /**
         * Whether to show success dialog on completion.
         */
        public ExecutionConfig<R> showSuccessDialog(boolean show) {
            this.showSuccessDialog = show;
            return this;
        }
    }

    /**
     * Execute a worker with the given configuration.
     * If the worker is already running, cancels it instead.
     *
     * @param config Execution configuration
     * @return true if execution started, false if cancelled existing execution
     */
    public static <R> boolean execute(ExecutionConfig<R> config) {
        AnalysisWorker<R> worker = config.worker;
        ProgressUI ui = config.ui;

        // If already running, cancel
        if (!worker.isDone()) {
            worker.requestCancel();
            return false;
        }

        // Configure callbacks
        worker.setProgressCallback(progress -> {
            String message = config.progressPrefix.isEmpty()
                ? progress.message
                : config.progressPrefix + progress.message;
            ui.showProgress(progress.getPercentage(), message);
        });

        worker.setCompletedCallback(result -> {
            ui.hideProgress();
            ui.setRunning(false);
            ui.refreshView();

            if (config.onComplete != null) {
                config.onComplete.accept(result);
            }

            if (config.successMessage != null && config.showSuccessDialog) {
                Msg.showInfo(WorkerExecutor.class, null, config.operationName + " Complete",
                    config.successMessage);
            }

            if (config.onNextStep != null) {
                config.onNextStep.run();
            }
        });

        worker.setCancelledCallback(() -> {
            ui.hideProgress();
            ui.setRunning(false);
            ui.refreshView();

            if (config.onCancelled != null) {
                config.onCancelled.run();
            }
        });

        worker.setFailedCallback(error -> {
            ui.hideProgress();
            ui.setRunning(false);

            if (config.onFailed != null) {
                config.onFailed.accept(error);
            } else {
                Msg.showError(WorkerExecutor.class, null, "Error",
                    "Failed to run " + config.operationName.toLowerCase() + ": " + error);
            }
        });

        // Start the worker
        ui.setRunning(true);
        ui.showProgress(0, "Starting " + config.operationName.toLowerCase() + "...");
        worker.execute();
        return true;
    }

    /**
     * Simple execution with standard callbacks.
     * Convenience method for common use cases.
     *
     * @param worker Worker to execute
     * @param ui Progress UI implementation
     * @param operationName Name for logging
     * @param onComplete Callback on completion
     */
    public static <R> void executeSimple(
            AnalysisWorker<R> worker,
            ProgressUI ui,
            String operationName,
            Consumer<R> onComplete) {

        ExecutionConfig<R> config = new ExecutionConfig<>(worker, ui)
            .operationName(operationName)
            .onComplete(onComplete);

        execute(config);
    }

    /**
     * Execute a worker as part of a chain.
     * On completion, runs the next step. On failure, optionally continues the chain.
     *
     * @param worker Worker to execute
     * @param ui Progress UI implementation
     * @param operationName Name for logging
     * @param progressPrefix Prefix for progress messages
     * @param onComplete Callback on completion
     * @param nextStep Next step to run on completion
     * @param continueOnFailure Whether to run nextStep even on failure
     */
    public static <R> void executeInChain(
            AnalysisWorker<R> worker,
            ProgressUI ui,
            String operationName,
            String progressPrefix,
            Consumer<R> onComplete,
            Runnable nextStep,
            boolean continueOnFailure) {

        ExecutionConfig<R> config = new ExecutionConfig<>(worker, ui)
            .operationName(operationName)
            .progressPrefix(progressPrefix)
            .onComplete(onComplete)
            .onNextStep(nextStep);

        if (continueOnFailure && nextStep != null) {
            config.onFailed(error -> {
                Msg.warn(WorkerExecutor.class,
                    operationName + " failed: " + error + ". Continuing with next step...");
                nextStep.run();
            });
        }

        execute(config);
    }

    /**
     * Check if a worker can be started (not currently running).
     *
     * @param worker Worker to check
     * @return true if worker can be started
     */
    public static <R> boolean canStart(AnalysisWorker<R> worker) {
        return worker == null || worker.isDone();
    }

    /**
     * Cancel a worker if it's running.
     *
     * @param worker Worker to cancel
     * @return true if worker was cancelled, false if not running
     */
    public static <R> boolean cancelIfRunning(AnalysisWorker<R> worker) {
        if (worker != null && !worker.isDone()) {
            worker.requestCancel();
            return true;
        }
        return false;
    }
}
