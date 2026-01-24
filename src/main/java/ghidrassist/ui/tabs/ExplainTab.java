package ghidrassist.ui.tabs;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.util.List;
import ghidra.util.Msg;
import ghidrassist.core.MarkdownHelper;
import ghidrassist.core.TabController;

public class ExplainTab extends JPanel {
    private static final long serialVersionUID = 1L;
    private final TabController controller;
    private final MarkdownHelper markdownHelper;
    private JLabel offsetLabel;
    private JTextField offsetField;
    private JEditorPane explainTextPane;
    private JTextArea markdownTextArea;
    private JButton explainFunctionButton;
    private JButton explainLineButton;
    private JButton clearExplainButton;
    private JButton editSaveButton;
    private JPanel contentPanel;
    private CardLayout contentLayout;
    private boolean isEditMode = false;
    private String currentMarkdown = "";

    // Security info panel components
    private JPanel securityInfoPanel;
    private JLabel riskLevelLabel;
    private JLabel activityProfileLabel;
    private JLabel securityFlagsLabel;
    private JTextArea networkAPIsTextArea;
    private JTextArea fileIOAPIsTextArea;

    // Line explanation panel components
    private JPanel lineExplanationPanel;
    private JEditorPane lineExplanationTextPane;
    private String lineExplanationMarkdown = "";
    private JSplitPane mainSplitPane;
    private JButton lineExplanationCloseButton;

    public ExplainTab(TabController controller) {
        super(new BorderLayout());
        this.controller = controller;
        this.markdownHelper = new MarkdownHelper();
        initializeComponents();
        layoutComponents();
        setupListeners();
        setupContextMenu();
    }

    private void initializeComponents() {
        // Initialize offset field
        offsetLabel = new JLabel("Offset: ");
        offsetField = new JTextField(16);
        offsetField.setEditable(false);

        // Initialize text pane for HTML viewing
        explainTextPane = new JEditorPane();
        explainTextPane.setEditable(false);
        explainTextPane.setContentType("text/html");
        explainTextPane.addHyperlinkListener(controller::handleHyperlinkEvent);

        // Initialize text area for Markdown editing
        markdownTextArea = new JTextArea();
        markdownTextArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        markdownTextArea.setLineWrap(true);
        markdownTextArea.setWrapStyleWord(true);

        // Initialize buttons
        explainFunctionButton = new JButton("Explain Function");
        explainLineButton = new JButton("Explain Line");
        explainLineButton.setEnabled(true);
        explainLineButton.setToolTipText("Explain the current line at cursor position");
        clearExplainButton = new JButton("Clear");
        editSaveButton = new JButton("Edit");

        // Setup card layout for switching between view and edit modes
        contentLayout = new CardLayout();
        contentPanel = new JPanel(contentLayout);
        contentPanel.add(new JScrollPane(explainTextPane), "view");
        contentPanel.add(new JScrollPane(markdownTextArea), "edit");

        // Initialize security info panel
        securityInfoPanel = new JPanel();
        securityInfoPanel.setLayout(new BoxLayout(securityInfoPanel, BoxLayout.Y_AXIS));
        securityInfoPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Security Analysis",
                TitledBorder.LEFT, TitledBorder.TOP));

        // Risk level and activity profile row
        JPanel topRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        riskLevelLabel = new JLabel("Risk: —");
        riskLevelLabel.setFont(riskLevelLabel.getFont().deriveFont(Font.BOLD));
        activityProfileLabel = new JLabel("Activity: —");
        topRow.add(riskLevelLabel);
        topRow.add(activityProfileLabel);
        securityInfoPanel.add(topRow);

        // Security flags row
        JPanel flagsRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        securityFlagsLabel = new JLabel("Flags: None");
        flagsRow.add(securityFlagsLabel);
        securityInfoPanel.add(flagsRow);

        // API lists in a horizontal panel
        JPanel apiPanel = new JPanel(new GridLayout(1, 2, 10, 0));

        // Network APIs
        JPanel networkPanel = new JPanel(new BorderLayout());
        networkPanel.setBorder(BorderFactory.createTitledBorder("Network APIs"));
        networkAPIsTextArea = new JTextArea(3, 20);
        networkAPIsTextArea.setEditable(false);
        networkAPIsTextArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        networkPanel.add(new JScrollPane(networkAPIsTextArea), BorderLayout.CENTER);
        apiPanel.add(networkPanel);

        // File I/O APIs
        JPanel filePanel = new JPanel(new BorderLayout());
        filePanel.setBorder(BorderFactory.createTitledBorder("File I/O APIs"));
        fileIOAPIsTextArea = new JTextArea(3, 20);
        fileIOAPIsTextArea.setEditable(false);
        fileIOAPIsTextArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        filePanel.add(new JScrollPane(fileIOAPIsTextArea), BorderLayout.CENTER);
        apiPanel.add(filePanel);

        securityInfoPanel.add(apiPanel);

        // Initially hide the security panel until we have data
        securityInfoPanel.setVisible(false);

        // Initialize line explanation panel with header containing close button
        lineExplanationPanel = new JPanel(new BorderLayout());
        lineExplanationPanel.setBorder(BorderFactory.createEtchedBorder());

        // Create header panel with title and close button
        JPanel lineHeaderPanel = new JPanel(new BorderLayout());
        lineHeaderPanel.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 2));
        JLabel lineHeaderLabel = new JLabel("Line Explanation");
        lineHeaderLabel.setFont(lineHeaderLabel.getFont().deriveFont(Font.BOLD));
        lineHeaderPanel.add(lineHeaderLabel, BorderLayout.WEST);

        // Close button (small X)
        lineExplanationCloseButton = new JButton("\u00D7"); // Unicode multiplication sign as X
        lineExplanationCloseButton.setMargin(new Insets(0, 4, 0, 4));
        lineExplanationCloseButton.setFont(lineExplanationCloseButton.getFont().deriveFont(Font.BOLD, 14f));
        lineExplanationCloseButton.setFocusPainted(false);
        lineExplanationCloseButton.setBorderPainted(false);
        lineExplanationCloseButton.setContentAreaFilled(false);
        lineExplanationCloseButton.setToolTipText("Hide line explanation");
        lineExplanationCloseButton.addActionListener(e -> clearLineExplanation());
        lineHeaderPanel.add(lineExplanationCloseButton, BorderLayout.EAST);

        lineExplanationPanel.add(lineHeaderPanel, BorderLayout.NORTH);

        lineExplanationTextPane = new JEditorPane();
        lineExplanationTextPane.setEditable(false);
        lineExplanationTextPane.setContentType("text/html");
        lineExplanationTextPane.addHyperlinkListener(controller::handleHyperlinkEvent);

        JScrollPane lineScrollPane = new JScrollPane(lineExplanationTextPane);
        lineScrollPane.setPreferredSize(new Dimension(0, 150));
        lineScrollPane.setMinimumSize(new Dimension(0, 80));
        lineExplanationPanel.add(lineScrollPane, BorderLayout.CENTER);

        // Set preferred/minimum sizes for the panel
        lineExplanationPanel.setPreferredSize(new Dimension(0, 180));
        lineExplanationPanel.setMinimumSize(new Dimension(0, 100));

        // Initially hide the line explanation panel
        lineExplanationPanel.setVisible(false);
    }

    private void layoutComponents() {
        // Offset and Edit/Save panel
        JPanel topPanel = new JPanel(new BorderLayout());

        JPanel offsetPanel = new JPanel();
        offsetPanel.add(offsetLabel);
        offsetPanel.add(offsetField);
        topPanel.add(offsetPanel, BorderLayout.WEST);

        JPanel editPanel = new JPanel();
        editPanel.add(editSaveButton);
        topPanel.add(editPanel, BorderLayout.EAST);

        add(topPanel, BorderLayout.NORTH);

        // Create split pane with function explanation (top) and line explanation (bottom)
        mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainSplitPane.setTopComponent(contentPanel);
        mainSplitPane.setBottomComponent(lineExplanationPanel);
        mainSplitPane.setResizeWeight(1.0); // Give all extra space to top component
        mainSplitPane.setOneTouchExpandable(true);
        mainSplitPane.setContinuousLayout(true);

        // Initially hide bottom component (line explanation)
        mainSplitPane.setDividerSize(0);
        mainSplitPane.setBottomComponent(null);

        add(mainSplitPane, BorderLayout.CENTER);

        // Bottom panel containing security info + buttons
        JPanel bottomPanel = new JPanel();
        bottomPanel.setLayout(new BoxLayout(bottomPanel, BoxLayout.Y_AXIS));

        // Security info panel
        bottomPanel.add(securityInfoPanel);

        // Button panel
        JPanel buttonPanel = new JPanel();
        buttonPanel.add(explainFunctionButton);
        buttonPanel.add(explainLineButton);
        buttonPanel.add(clearExplainButton);
        bottomPanel.add(buttonPanel);

        add(bottomPanel, BorderLayout.SOUTH);
    }

    private void setupListeners() {
        explainFunctionButton.addActionListener(e -> controller.handleExplainFunction());
        explainLineButton.addActionListener(e -> controller.handleExplainLine());
        clearExplainButton.addActionListener(e -> {
            // Clear the UI
            explainTextPane.setText("");
            markdownTextArea.setText("");
            currentMarkdown = "";
            
            // Also clear from database
            controller.handleClearAnalysisData();
        });
        
        editSaveButton.addActionListener(e -> {
            if (isEditMode) {
                // Save mode - save the markdown and switch to view mode
                currentMarkdown = markdownTextArea.getText();
                String html = markdownHelper.markdownToHtml(currentMarkdown);
                explainTextPane.setText(html);
                
                // Save to database
                controller.handleUpdateAnalysis(currentMarkdown);
                
                // Switch to view mode
                contentLayout.show(contentPanel, "view");
                editSaveButton.setText("Edit");
                isEditMode = false;
            } else {
                // Edit mode - switch to the markdown editor
                markdownTextArea.setText(currentMarkdown);
                
                // Switch to edit mode
                contentLayout.show(contentPanel, "edit");
                editSaveButton.setText("Save");
                isEditMode = true;
            }
        });
    }

    public void updateOffset(String offset) {
        offsetField.setText(offset);
    }

    public void setExplanationText(String text) {
        explainTextPane.setText(text);
        explainTextPane.setCaretPosition(0);
        
        // Store the markdown equivalent
        currentMarkdown = markdownHelper.extractMarkdownFromLlmResponse(text);
        
        // If we're in edit mode, update the markdown text area too
        if (isEditMode) {
            markdownTextArea.setText(currentMarkdown);
        }
        
        // Switch to view mode if we're setting new content
        if (isEditMode) {
            contentLayout.show(contentPanel, "view");
            editSaveButton.setText("Edit");
            isEditMode = false;
        }
    }

    public void setFunctionButtonText(String text) {
        explainFunctionButton.setText(text);
    }

    public void setLineButtonText(String text) {
        explainLineButton.setText(text);
    }

    /**
     * Setup context menu for clipboard operations
     */
    private void setupContextMenu() {
        JPopupMenu contextMenu = new JPopupMenu();

        JMenuItem copyMarkdown = new JMenuItem("Copy as Markdown");
        copyMarkdown.addActionListener(e -> {
            String selectedText = isEditMode ?
                    markdownTextArea.getSelectedText() :
                    getSelectedMarkdownText();
            if (selectedText != null && !selectedText.isEmpty()) {
                copyToClipboard(selectedText);
            }
        });

        JMenuItem copyHtml = new JMenuItem("Copy as HTML");
        copyHtml.addActionListener(e -> {
            String selectedText = explainTextPane.getSelectedText();
            if (selectedText != null && !selectedText.isEmpty()) {
                copyToClipboard(selectedText);
            }
        });

        JMenuItem copyPlainText = new JMenuItem("Copy as Plain Text");
        copyPlainText.addActionListener(e -> {
            String selectedText = isEditMode ?
                    markdownTextArea.getSelectedText() :
                    explainTextPane.getSelectedText();
            if (selectedText != null && !selectedText.isEmpty()) {
                // Strip markdown formatting for plain text
                String plainText = selectedText.replaceAll("\\*\\*|__|`|#+ |\\[|\\]\\([^)]*\\)", "");
                copyToClipboard(plainText);
            }
        });

        JMenuItem copyAll = new JMenuItem("Copy All as Markdown");
        copyAll.addActionListener(e -> {
            copyToClipboard(currentMarkdown);
        });

        JMenuItem selectAll = new JMenuItem("Select All");
        selectAll.addActionListener(e -> {
            if (isEditMode) {
                markdownTextArea.selectAll();
            } else {
                explainTextPane.selectAll();
            }
        });

        JMenuItem paste = new JMenuItem("Paste");
        paste.addActionListener(e -> {
            if (isEditMode) {
                markdownTextArea.paste();
            }
        });

        contextMenu.add(copyMarkdown);
        contextMenu.add(copyHtml);
        contextMenu.add(copyPlainText);
        contextMenu.addSeparator();
        contextMenu.add(copyAll);
        contextMenu.add(selectAll);
        contextMenu.addSeparator();
        contextMenu.add(paste);

        // Show paste only in edit mode
        contextMenu.addPopupMenuListener(new javax.swing.event.PopupMenuListener() {
            @Override
            public void popupMenuWillBecomeVisible(javax.swing.event.PopupMenuEvent e) {
                paste.setEnabled(isEditMode);
            }
            @Override
            public void popupMenuWillBecomeInvisible(javax.swing.event.PopupMenuEvent e) {}
            @Override
            public void popupMenuCanceled(javax.swing.event.PopupMenuEvent e) {}
        });

        explainTextPane.setComponentPopupMenu(contextMenu);
        markdownTextArea.setComponentPopupMenu(contextMenu);
    }

    /**
     * Get selected markdown text based on selection in view mode
     */
    private String getSelectedMarkdownText() {
        String selectedText = explainTextPane.getSelectedText();
        if (selectedText != null && !selectedText.isEmpty()) {
            return selectedText;
        }
        return currentMarkdown;
    }

    /**
     * Copy text to system clipboard
     */
    private void copyToClipboard(String text) {
        if (text != null && !text.isEmpty()) {
            try {
                Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                clipboard.setContents(new StringSelection(text), null);
            } catch (Exception e) {
                Msg.error(this, "Failed to copy to clipboard: " + e.getMessage());
            }
        }
    }

    /**
     * Get the current markdown content
     */
    public String getCurrentMarkdown() {
        return currentMarkdown;
    }

    /**
     * Update the security info panel with analysis results.
     *
     * @param riskLevel Risk level (LOW, MEDIUM, HIGH) or null
     * @param activityProfile Activity profile string or null
     * @param securityFlags List of security flags or null
     * @param networkAPIs List of network API calls or null
     * @param fileIOAPIs List of file I/O API calls or null
     */
    public void updateSecurityInfo(String riskLevel, String activityProfile,
                                   List<String> securityFlags,
                                   List<String> networkAPIs, List<String> fileIOAPIs) {
        // Update risk level with color coding
        if (riskLevel != null && !riskLevel.isEmpty()) {
            riskLevelLabel.setText("Risk: " + riskLevel);
            switch (riskLevel.toUpperCase()) {
                case "HIGH":
                    riskLevelLabel.setForeground(new Color(180, 0, 0)); // Red
                    break;
                case "MEDIUM":
                    riskLevelLabel.setForeground(new Color(180, 120, 0)); // Orange
                    break;
                case "LOW":
                    riskLevelLabel.setForeground(new Color(0, 120, 0)); // Green
                    break;
                default:
                    riskLevelLabel.setForeground(UIManager.getColor("Label.foreground"));
            }
        } else {
            riskLevelLabel.setText("Risk: —");
            riskLevelLabel.setForeground(UIManager.getColor("Label.foreground"));
        }

        // Update activity profile
        if (activityProfile != null && !activityProfile.isEmpty()) {
            activityProfileLabel.setText("Activity: " + activityProfile);
        } else {
            activityProfileLabel.setText("Activity: —");
        }

        // Update security flags
        if (securityFlags != null && !securityFlags.isEmpty()) {
            securityFlagsLabel.setText("Flags: " + String.join(", ", securityFlags));
        } else {
            securityFlagsLabel.setText("Flags: None");
        }

        // Update network APIs
        if (networkAPIs != null && !networkAPIs.isEmpty()) {
            networkAPIsTextArea.setText(String.join("\n", networkAPIs));
        } else {
            networkAPIsTextArea.setText("(none detected)");
        }

        // Update file I/O APIs
        if (fileIOAPIs != null && !fileIOAPIs.isEmpty()) {
            fileIOAPIsTextArea.setText(String.join("\n", fileIOAPIs));
        } else {
            fileIOAPIsTextArea.setText("(none detected)");
        }

        // Show the panel if we have any data
        boolean hasData = (riskLevel != null && !riskLevel.isEmpty()) ||
                         (activityProfile != null && !activityProfile.isEmpty()) ||
                         (securityFlags != null && !securityFlags.isEmpty()) ||
                         (networkAPIs != null && !networkAPIs.isEmpty()) ||
                         (fileIOAPIs != null && !fileIOAPIs.isEmpty());
        securityInfoPanel.setVisible(hasData);
    }

    /**
     * Clear the security info panel.
     */
    public void clearSecurityInfo() {
        riskLevelLabel.setText("Risk: —");
        riskLevelLabel.setForeground(UIManager.getColor("Label.foreground"));
        activityProfileLabel.setText("Activity: —");
        securityFlagsLabel.setText("Flags: None");
        networkAPIsTextArea.setText("");
        fileIOAPIsTextArea.setText("");
        securityInfoPanel.setVisible(false);
    }

    /**
     * Set the line explanation text and make panel visible.
     *
     * @param text The explanation text (can be HTML or plain text)
     */
    public void setLineExplanationText(String text) {
        if (text == null || text.trim().isEmpty()) {
            clearLineExplanation();
            return;
        }

        lineExplanationMarkdown = text;
        lineExplanationTextPane.setText(text);
        lineExplanationTextPane.setCaretPosition(0);

        // Show the line explanation panel in the split pane
        if (mainSplitPane.getBottomComponent() == null) {
            lineExplanationPanel.setVisible(true);
            mainSplitPane.setBottomComponent(lineExplanationPanel);
            mainSplitPane.setDividerSize(8);

            // Set initial divider location to show ~180px for line explanation
            SwingUtilities.invokeLater(() -> {
                int totalHeight = mainSplitPane.getHeight();
                if (totalHeight > 250) {
                    mainSplitPane.setDividerLocation(totalHeight - 180);
                } else {
                    mainSplitPane.setDividerLocation(0.7);
                }
            });
        }

        // Revalidate layout
        revalidate();
        repaint();
    }

    /**
     * Clear the line explanation panel and hide it.
     */
    public void clearLineExplanation() {
        lineExplanationMarkdown = "";
        lineExplanationTextPane.setText("");

        // Hide the line explanation panel by removing from split pane
        mainSplitPane.setBottomComponent(null);
        mainSplitPane.setDividerSize(0);
        lineExplanationPanel.setVisible(false);

        // Revalidate layout
        revalidate();
        repaint();
    }

    /**
     * Set the Explain Line button enabled state.
     *
     * @param enabled true to enable, false to disable
     */
    public void setLineButtonEnabled(boolean enabled) {
        explainLineButton.setEnabled(enabled);
    }

    /**
     * Get the current line explanation markdown.
     *
     * @return The markdown text
     */
    public String getLineExplanationMarkdown() {
        return lineExplanationMarkdown;
    }

    /**
     * Check if the line explanation panel is currently visible.
     *
     * @return true if visible
     */
    public boolean isLineExplanationVisible() {
        return lineExplanationPanel.isVisible();
    }
}