package ghidrassist.ui.tabs;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
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
        clearExplainButton = new JButton("Clear");
        editSaveButton = new JButton("Edit");
        
        // Setup card layout for switching between view and edit modes
        contentLayout = new CardLayout();
        contentPanel = new JPanel(contentLayout);
        contentPanel.add(new JScrollPane(explainTextPane), "view");
        contentPanel.add(new JScrollPane(markdownTextArea), "edit");
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

        // Text content panel with card layout
        add(contentPanel, BorderLayout.CENTER);

        // Button panel
        JPanel buttonPanel = new JPanel();
        buttonPanel.add(explainFunctionButton);
        buttonPanel.add(explainLineButton);
        buttonPanel.add(clearExplainButton);
        add(buttonPanel, BorderLayout.SOUTH);
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
}