package ghidrassist.apiprovider;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

/**
 * Represents an action that can be taken in response to an error
 */
public class ErrorAction {
    private final String actionText;
    private final String description;
    private final Runnable action;
    private final boolean isPrimary;
    
    public ErrorAction(String actionText, String description, Runnable action, boolean isPrimary) {
        this.actionText = actionText;
        this.description = description;
        this.action = action;
        this.isPrimary = isPrimary;
    }
    
    public ErrorAction(String actionText, Runnable action) {
        this(actionText, null, action, false);
    }
    
    // Getters
    public String getActionText() { return actionText; }
    public String getDescription() { return description; }
    public Runnable getAction() { return action; }
    public boolean isPrimary() { return isPrimary; }
    
    /**
     * Create a button for this action
     */
    public JButton createButton() {
        JButton button = new JButton(actionText);
        if (description != null) {
            button.setToolTipText(description);
        }
        button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (action != null) {
                    try {
                        action.run();
                    } catch (Exception ex) {
                        // Log error but don't propagate to avoid cascading errors
                        System.err.println("Error executing action: " + ex.getMessage());
                    }
                }
            }
        });
        return button;
    }
    
    // Common action factory methods
    public static ErrorAction createSettingsAction(Runnable openSettingsAction) {
        return new ErrorAction(
            "Open Settings", 
            "Open the settings dialog to configure API providers",
            openSettingsAction, 
            true
        );
    }
    
    public static ErrorAction createRetryAction(Runnable retryAction) {
        return new ErrorAction(
            "Retry", 
            "Try the operation again",
            retryAction, 
            true
        );
    }
    
    public static ErrorAction createCopyErrorAction(String errorDetails) {
        return new ErrorAction(
            "Copy Details", 
            "Copy error details to clipboard",
            () -> copyToClipboard(errorDetails), 
            false
        );
    }
    
    public static ErrorAction createSwitchProviderAction(Runnable switchAction) {
        return new ErrorAction(
            "Switch Provider", 
            "Try using a different API provider",
            switchAction, 
            false
        );
    }
    
    public static ErrorAction createDismissAction() {
        return new ErrorAction(
            "Dismiss", 
            "Close this error dialog",
            () -> {}, // No-op, dialog will handle dismissal
            false
        );
    }
    
    private static void copyToClipboard(String text) {
        try {
            java.awt.datatransfer.StringSelection stringSelection = 
                new java.awt.datatransfer.StringSelection(text);
            java.awt.datatransfer.Clipboard clipboard = 
                java.awt.Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(stringSelection, null);
        } catch (Exception e) {
            // Silently fail if clipboard is not available
        }
    }
}