package ghidrassist.core;

import ghidra.util.Msg;
import ghidrassist.GhidrAssistPlugin;
import ghidrassist.apiprovider.APIProviderLogger;
import ghidrassist.apiprovider.ErrorAction;
import ghidrassist.apiprovider.exceptions.APIProviderException;
import ghidrassist.apiprovider.exceptions.StreamCancelledException;
import ghidrassist.ui.EnhancedErrorDialog;

import java.util.ArrayList;
import java.util.List;

/**
 * Handles error processing, logging, and user interaction for LLM operations.
 * Focused solely on error handling logic and user feedback.
 */
public class LlmErrorHandler {
    
    private final GhidrAssistPlugin plugin;
    private final Object source;
    
    public LlmErrorHandler(GhidrAssistPlugin plugin, Object source) {
        this.plugin = plugin;
        this.source = source;
    }
    
    /**
     * Handle an error with enhanced error dialogs and logging
     */
    public void handleError(Throwable error, String operation, Runnable retryAction) {
        if (error instanceof APIProviderException) {
            APIProviderException ape = (APIProviderException) error;
            
            // Log the error with structured information
            APIProviderLogger.logError(source, ape);
            
            // Skip showing error dialog for cancellations unless it's unexpected
            if (shouldSkipErrorDialog(ape)) {
                return;
            }
            
            // Create appropriate error actions
            List<ErrorAction> actions = createErrorActions(ape, retryAction);
            
            // Show enhanced error dialog
            java.awt.Window parentWindow = getParentWindow();
            EnhancedErrorDialog.showError(parentWindow, ape, actions);
            
        } else {
            // Handle non-API provider exceptions (fallback)
            handleGenericError(error, operation);
        }
    }
    
    /**
     * Handle generic (non-API provider) errors
     */
    private void handleGenericError(Throwable error, String operation) {
        String message = error.getMessage() != null ? error.getMessage() : error.getClass().getSimpleName();
        Msg.showError(source, null, "Unexpected Error", 
            "An unexpected error occurred during " + operation + ": " + message);
        
        // Log the error
        Msg.error(source, "Unexpected error during " + operation, error);
    }
    
    /**
     * Determine if error dialog should be skipped for certain cancellation types
     */
    private boolean shouldSkipErrorDialog(APIProviderException ape) {
        if (ape.getCategory() == APIProviderException.ErrorCategory.CANCELLED) {
            if (ape instanceof StreamCancelledException) {
                StreamCancelledException sce = (StreamCancelledException) ape;
                if (sce.getCancellationReason() == StreamCancelledException.CancellationReason.USER_REQUESTED) {
                    return true; // Don't show dialog for user-requested cancellations
                }
            }
        }
        return false;
    }
    
    /**
     * Create appropriate error actions based on the exception type
     */
    private List<ErrorAction> createErrorActions(APIProviderException ape, Runnable retryAction) {
        List<ErrorAction> actions = new ArrayList<>();
        
        // Add retry action for retryable errors
        if (ape.isRetryable() && retryAction != null) {
            actions.add(ErrorAction.createRetryAction(retryAction));
        }
        
        // Add settings action for configuration-related errors
        if (isConfigurationError(ape)) {
            actions.add(ErrorAction.createSettingsAction(() -> openSettings()));
        }
        
        // Add provider switching action for persistent errors
        APIProviderLogger.ErrorStats stats = APIProviderLogger.getErrorStats(ape.getProviderName());
        if (stats != null && stats.isFrequentErrorsDetected()) {
            actions.add(ErrorAction.createSwitchProviderAction(() -> suggestProviderSwitch()));
        }
        
        // Add copy error details action
        actions.add(ErrorAction.createCopyErrorAction(ape.getTechnicalDetails()));
        
        // Add dismiss action
        actions.add(ErrorAction.createDismissAction());
        
        return actions;
    }
    
    /**
     * Check if error is configuration-related
     */
    private boolean isConfigurationError(APIProviderException ape) {
        return ape.getCategory() == APIProviderException.ErrorCategory.AUTHENTICATION ||
               ape.getCategory() == APIProviderException.ErrorCategory.CONFIGURATION ||
               ape.getCategory() == APIProviderException.ErrorCategory.MODEL_ERROR;
    }
    
    /**
     * Get the parent window for error dialogs
     */
    private java.awt.Window getParentWindow() {
        try {
            // Try to get the main Ghidra window
            if (plugin != null && plugin.getTool() != null) {
                return plugin.getTool().getToolFrame();
            }
        } catch (Exception e) {
            // Ignore errors getting parent window
        }
        return null;
    }
    
    /**
     * Open the settings dialog
     */
    private void openSettings() {
        try {
            if (plugin != null) {
                // This would typically call the plugin's settings dialog
                // The actual implementation depends on how settings are accessed
                Msg.showInfo(source, null, "Settings", 
                    "Please go to Tools -> GhidrAssist Settings to configure API providers.");
            }
        } catch (Exception e) {
            Msg.showError(source, null, "Error", "Could not open settings: " + e.getMessage());
        }
    }
    
    /**
     * Suggest switching to a different provider
     */
    private void suggestProviderSwitch() {
        try {
            // Generate a simple suggestion message
            StringBuilder suggestion = new StringBuilder();
            suggestion.append("Current provider is experiencing frequent errors.\n\n");
            suggestion.append("Consider switching to a different provider in Settings.\n\n");
            suggestion.append("Provider Error Statistics:\n");
            suggestion.append(APIProviderLogger.generateDiagnosticsReport());
            
            Msg.showInfo(source, null, "Provider Reliability", suggestion.toString());
        } catch (Exception e) {
            Msg.showError(source, null, "Error", "Could not generate provider statistics: " + e.getMessage());
        }
    }
}