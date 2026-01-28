package ghidrassist.core;

import ghidra.util.Msg;
import ghidrassist.LlmApi;
import ghidrassist.agent.react.ReActOrchestrator;
import ghidrassist.services.ActionAnalysisService;
import ghidrassist.ui.tabs.ActionsTab;
import ghidrassist.ui.tabs.ExplainTab;
import ghidrassist.ui.tabs.QueryTab;

import javax.swing.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Manages operation state and cancellation for LLM interactions.
 * Handles UI state transitions and safety timeouts.
 *
 * Extracted from TabController as part of decomposition refactoring.
 */
public class OperationStateManager {

    // UI state flags - volatile for thread safety
    private volatile boolean isQueryRunning = false;
    private volatile boolean isLineQueryRunning = false;
    private volatile boolean isCancelling = false;

    // Current operation references
    private volatile LlmApi currentLlmApi;
    private volatile LlmApi currentLineExplainLlmApi;
    private volatile ReActOrchestrator currentOrchestrator;

    // Safety scheduler for timeout-based reset
    private final ScheduledExecutorService safetyScheduler = Executors.newSingleThreadScheduledExecutor();

    // Tab references for UI updates
    private ExplainTab explainTab;
    private QueryTab queryTab;
    private ActionsTab actionsTab;

    // External services
    private ActionAnalysisService actionAnalysisService;
    private StreamingResponseManager streamingManager;

    // ==== Configuration ====

    public void setExplainTab(ExplainTab tab) {
        this.explainTab = tab;
    }

    public void setQueryTab(QueryTab tab) {
        this.queryTab = tab;
    }

    public void setActionsTab(ActionsTab tab) {
        this.actionsTab = tab;
    }

    public void setActionAnalysisService(ActionAnalysisService service) {
        this.actionAnalysisService = service;
    }

    public void setStreamingManager(StreamingResponseManager manager) {
        this.streamingManager = manager;
    }

    // ==== State Accessors ====

    public boolean isQueryRunning() {
        return isQueryRunning;
    }

    public void setQueryRunning(boolean running) {
        this.isQueryRunning = running;
    }

    public boolean isLineQueryRunning() {
        return isLineQueryRunning;
    }

    public void setLineQueryRunning(boolean running) {
        this.isLineQueryRunning = running;
    }

    public boolean isCancelling() {
        return isCancelling;
    }

    // ==== LLM API Management ====

    public LlmApi getCurrentLlmApi() {
        return currentLlmApi;
    }

    public void setCurrentLlmApi(LlmApi api) {
        this.currentLlmApi = api;
    }

    public LlmApi getCurrentLineExplainLlmApi() {
        return currentLineExplainLlmApi;
    }

    public void setCurrentLineExplainLlmApi(LlmApi api) {
        this.currentLineExplainLlmApi = api;
    }

    public ReActOrchestrator getCurrentOrchestrator() {
        return currentOrchestrator;
    }

    public void setCurrentOrchestrator(ReActOrchestrator orchestrator) {
        this.currentOrchestrator = orchestrator;
    }

    // ==== Cancellation Operations ====

    /**
     * Cancel the current main operation (query, explain, agentic analysis).
     * Cleans up streaming renderers and schedules safety timeout.
     */
    public void cancelCurrentOperation() {
        // Mark that we're cancelling to prevent concurrent operations
        isCancelling = true;

        // Clean up streaming renderers FIRST to stop stale UI updates
        if (streamingManager != null) {
            streamingManager.cancelAllRenderers();
        }

        // Cancel the ReAct orchestrator if it exists
        if (currentOrchestrator != null) {
            currentOrchestrator.cancel();
            // Don't set to null here - let the completion handler do it
        }

        // Cancel the current LLM API instance if it exists
        if (currentLlmApi != null) {
            currentLlmApi.cancelCurrentRequest();
            // Don't set to null here - let the completion handler do it
        }

        // Cancel action analysis if running
        if (actionAnalysisService != null) {
            actionAnalysisService.cancelAnalysis();
        }

        // Update button text immediately to show cancellation is in progress
        SwingUtilities.invokeLater(() -> {
            if (queryTab != null) {
                queryTab.setSubmitButtonText("Cancelling...");
            }
        });

        // Schedule a safety reset in case the completion handlers don't fire
        scheduleSafetyReset();
    }

    /**
     * Cancel the current line explanation operation.
     */
    public void cancelLineExplainOperation() {
        if (currentLineExplainLlmApi != null) {
            currentLineExplainLlmApi.cancelCurrentRequest();
            currentLineExplainLlmApi = null;
        }

        // Clean up line explanation streaming renderer
        if (streamingManager != null) {
            streamingManager.setCurrentLineExplainStreamingRenderer(null);
        }

        setLineExplainUIState(false, "Explain Line");
    }

    /**
     * Schedule a safety reset in case completion handlers don't fire.
     * Prevents the UI from getting stuck.
     */
    private void scheduleSafetyReset() {
        safetyScheduler.schedule(() -> {
            if (isCancelling) {
                Msg.warn(this, "Cancellation safety timeout - forcing UI reset");
                SwingUtilities.invokeLater(() -> {
                    forceReset();
                });
            }
        }, 5, TimeUnit.SECONDS);
    }

    /**
     * Force reset all state. Used by safety timeout.
     */
    private void forceReset() {
        isCancelling = false;
        isQueryRunning = false;
        currentOrchestrator = null;
        currentLlmApi = null;

        if (streamingManager != null) {
            streamingManager.cancelAllRenderers();
        }

        setUIState(false, "Submit", null);
    }

    // ==== UI State Management ====

    /**
     * Set the main UI state (query running/not running).
     */
    public void setUIState(boolean running, String buttonText, String statusText) {
        isQueryRunning = running;
        // Reset cancellation flag when transitioning to non-running state
        if (!running) {
            isCancelling = false;
        }

        SwingUtilities.invokeLater(() -> {
            if (buttonText != null && explainTab != null) {
                explainTab.setFunctionButtonText(buttonText);
                explainTab.setLineButtonText(buttonText.equals("Stop") ? "Stop" : "Explain Line");
            }
            if (buttonText != null && queryTab != null) {
                queryTab.setSubmitButtonText(buttonText.equals("Stop") ? "Stop" : "Submit");
            }
            if (buttonText != null && actionsTab != null) {
                actionsTab.setAnalyzeFunctionButtonText(buttonText.equals("Stop") ? "Stop" : "Analyze Function");
            }
            if (statusText != null && explainTab != null) {
                explainTab.setExplanationText(statusText);
            }
        });
    }

    /**
     * Set the line explanation UI state.
     */
    public void setLineExplainUIState(boolean running, String buttonText) {
        isLineQueryRunning = running;
        SwingUtilities.invokeLater(() -> {
            if (explainTab != null) {
                explainTab.setLineButtonText(buttonText);
            }
        });
    }

    /**
     * Check if the UI should block a new operation.
     * Returns true if already running or cancelling.
     */
    public boolean shouldBlockOperation() {
        return isCancelling || isQueryRunning;
    }

    /**
     * Check if the UI should block a new line explain operation.
     */
    public boolean shouldBlockLineOperation() {
        return isLineQueryRunning;
    }

    // ==== Cleanup ====

    /**
     * Clean up resources when disposing.
     */
    public void dispose() {
        if (safetyScheduler != null) {
            safetyScheduler.shutdown();
        }
    }

    /**
     * Complete cleanup after an operation finishes.
     * Clears the LLM API reference and resets state.
     */
    public void completeOperation() {
        currentLlmApi = null;
        currentOrchestrator = null;
        setUIState(false, "Submit", null);
    }

    /**
     * Complete cleanup after a line explain operation finishes.
     */
    public void completeLineOperation() {
        currentLineExplainLlmApi = null;
        setLineExplainUIState(false, "Explain Line");
    }
}
