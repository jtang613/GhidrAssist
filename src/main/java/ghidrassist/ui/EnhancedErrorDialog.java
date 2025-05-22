package ghidrassist.ui;

import ghidrassist.apiprovider.ErrorAction;
import ghidrassist.apiprovider.ErrorMessageBuilder;
import ghidrassist.apiprovider.exceptions.APIProviderException;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;

/**
 * Enhanced error dialog that provides better error reporting and action options
 */
public class EnhancedErrorDialog extends JDialog {
    private final APIProviderException exception;
    private final List<ErrorAction> actions;
    private boolean detailsVisible = false;
    
    public EnhancedErrorDialog(Window parent, APIProviderException exception, List<ErrorAction> actions) {
        super(parent, "Error", ModalityType.APPLICATION_MODAL);
        this.exception = exception;
        this.actions = actions;
        
        initializeDialog();
        buildComponents();
        pack();
        setLocationRelativeTo(parent);
    }
    
    private void initializeDialog() {
        setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
        setResizable(true);
        
        // Set appropriate icon based on error category
        ImageIcon icon = getErrorIcon();
        if (icon != null) {
            setIconImage(icon.getImage());
        }
    }
    
    private void buildComponents() {
        setLayout(new BorderLayout());
        
        // Main content panel
        JPanel contentPanel = new JPanel(new BorderLayout());
        contentPanel.setBorder(new EmptyBorder(16, 16, 16, 16));
        
        // Header with icon and title
        JPanel headerPanel = createHeaderPanel();
        contentPanel.add(headerPanel, BorderLayout.NORTH);
        
        // Message panel
        JPanel messagePanel = createMessagePanel();
        contentPanel.add(messagePanel, BorderLayout.CENTER);
        
        // Details panel (initially hidden)
        JPanel detailsPanel = createDetailsPanel();
        contentPanel.add(detailsPanel, BorderLayout.SOUTH);
        
        add(contentPanel, BorderLayout.CENTER);
        
        // Button panel
        JPanel buttonPanel = createButtonPanel();
        add(buttonPanel, BorderLayout.SOUTH);
    }
    
    private JPanel createHeaderPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new EmptyBorder(0, 0, 16, 0));
        
        // Error icon
        JLabel iconLabel = new JLabel(getErrorIcon());
        iconLabel.setBorder(new EmptyBorder(0, 0, 0, 16));
        panel.add(iconLabel, BorderLayout.WEST);
        
        // Title and category
        JPanel titlePanel = new JPanel(new BorderLayout());
        
        JLabel titleLabel = new JLabel(exception.getCategory().getDisplayName());
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 16f));
        titlePanel.add(titleLabel, BorderLayout.NORTH);
        
        JLabel categoryLabel = new JLabel(exception.getCategory().getDescription());
        categoryLabel.setFont(categoryLabel.getFont().deriveFont(Font.ITALIC, 12f));
        categoryLabel.setForeground(Color.GRAY);
        titlePanel.add(categoryLabel, BorderLayout.SOUTH);
        
        panel.add(titlePanel, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createMessagePanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // User-friendly message
        String userMessage = ErrorMessageBuilder.buildUserMessage(exception);
        JTextArea messageArea = new JTextArea(userMessage);
        messageArea.setEditable(false);
        messageArea.setOpaque(false);
        messageArea.setWrapStyleWord(true);
        messageArea.setLineWrap(true);
        messageArea.setFont(messageArea.getFont().deriveFont(13f));
        
        // Set preferred size based on content
        messageArea.setColumns(50);
        messageArea.setRows(Math.min(6, userMessage.split("\n").length + 1));
        
        panel.add(messageArea, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createDetailsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new EmptyBorder(16, 0, 0, 0));
        
        // Details toggle button
        JButton toggleButton = new JButton("Show Details");
        toggleButton.addActionListener(e -> toggleDetails(toggleButton, panel));
        
        JPanel togglePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        togglePanel.add(toggleButton);
        panel.add(togglePanel, BorderLayout.NORTH);
        
        return panel;
    }
    
    private void toggleDetails(JButton toggleButton, JPanel detailsPanel) {
        detailsVisible = !detailsVisible;
        
        if (detailsVisible) {
            // Show details
            toggleButton.setText("Hide Details");
            
            JTextArea detailsArea = new JTextArea(exception.getTechnicalDetails());
            detailsArea.setEditable(false);
            detailsArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
            detailsArea.setBackground(getBackground());
            detailsArea.setBorder(new EmptyBorder(8, 0, 0, 0));
            
            JScrollPane scrollPane = new JScrollPane(detailsArea);
            scrollPane.setPreferredSize(new Dimension(500, 150));
            scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
            scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
            
            detailsPanel.add(scrollPane, BorderLayout.CENTER);
        } else {
            // Hide details
            toggleButton.setText("Show Details");
            
            // Remove details component
            Component[] components = detailsPanel.getComponents();
            for (Component comp : components) {
                if (comp instanceof JScrollPane) {
                    detailsPanel.remove(comp);
                }
            }
        }
        
        pack();
        repaint();
    }
    
    private JPanel createButtonPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        panel.setBorder(new EmptyBorder(16, 16, 16, 16));
        
        // Add action buttons
        if (actions != null && !actions.isEmpty()) {
            // Add primary actions first
            for (ErrorAction action : actions) {
                if (action.isPrimary()) {
                    JButton button = action.createButton();
                    button.addActionListener(e -> dispose()); // Close dialog after action
                    panel.add(button);
                }
            }
            
            // Add secondary actions
            for (ErrorAction action : actions) {
                if (!action.isPrimary()) {
                    JButton button = action.createButton();
                    if (!action.getActionText().equals("Dismiss")) {
                        button.addActionListener(e -> dispose()); // Close dialog after action
                    } else {
                        button.addActionListener(e -> dispose()); // Just close for dismiss
                    }
                    panel.add(button);
                }
            }
        } else {
            // Default close button
            JButton closeButton = new JButton("Close");
            closeButton.addActionListener(e -> dispose());
            panel.add(closeButton);
        }
        
        return panel;
    }
    
    private ImageIcon getErrorIcon() {
        switch (exception.getCategory()) {
            case AUTHENTICATION:
                return createColoredIcon(Color.RED);
            case NETWORK:
                return createColoredIcon(Color.ORANGE);
            case RATE_LIMIT:
                return createColoredIcon(Color.YELLOW);
            case MODEL_ERROR:
                return createColoredIcon(Color.MAGENTA);
            case CONFIGURATION:
                return createColoredIcon(Color.BLUE);
            case RESPONSE_ERROR:
                return createColoredIcon(Color.CYAN);
            case SERVICE_ERROR:
                return createColoredIcon(Color.RED);
            case TIMEOUT:
                return createColoredIcon(Color.ORANGE);
            case CANCELLED:
                return createColoredIcon(Color.GRAY);
            default:
                return createColoredIcon(Color.RED);
        }
    }
    
    private ImageIcon createColoredIcon(Color color) {
        // Create a simple colored circle icon
        int size = 32;
        java.awt.image.BufferedImage image = new java.awt.image.BufferedImage(
            size, size, java.awt.image.BufferedImage.TYPE_INT_ARGB);
        Graphics2D g2 = image.createGraphics();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setColor(color);
        g2.fillOval(2, 2, size - 4, size - 4);
        g2.setColor(Color.WHITE);
        g2.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 18));
        FontMetrics fm = g2.getFontMetrics();
        String text = "!";
        int x = (size - fm.stringWidth(text)) / 2;
        int y = (size - fm.getHeight()) / 2 + fm.getAscent();
        g2.drawString(text, x, y);
        g2.dispose();
        
        return new ImageIcon(image);
    }
    
    /**
     * Show an enhanced error dialog for an API provider exception
     */
    public static void showError(Window parent, APIProviderException exception, List<ErrorAction> actions) {
        SwingUtilities.invokeLater(() -> {
            EnhancedErrorDialog dialog = new EnhancedErrorDialog(parent, exception, actions);
            dialog.setVisible(true);
        });
    }
}