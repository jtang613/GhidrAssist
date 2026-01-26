package ghidrassist.ui.tabs;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.text.*;
import javax.swing.text.html.HTML;
import javax.swing.text.html.HTMLDocument;
import javax.swing.text.html.HTMLEditorKit;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.text.SimpleDateFormat;
import java.util.TimeZone;
import java.util.Date;
import ghidra.util.Msg;
import ghidrassist.core.MarkdownHelper;
import ghidrassist.core.TabController;
import ghidrassist.core.streaming.RenderUpdate;
import ghidrassist.core.streaming.StreamingScrollManager;
import ghidrassist.mcp2.server.MCPServerRegistry;
import ghidrassist.AnalysisDB;

public class QueryTab extends JPanel {
    private static final long serialVersionUID = 1L;
    private final TabController controller;
    private final MarkdownHelper markdownHelper;
    private JTextPane responseTextPane;  // Changed from JEditorPane for better performance
    private StyledDocument responseDocument;
    private JTextArea queryTextArea;
    private JCheckBox useRAGCheckBox;
    private JCheckBox useMCPCheckBox;
    private JCheckBox useAgenticCheckBox;
    private JButton submitButton;
    private JButton newButton;
    private JButton deleteButton;
    private JTable chatHistoryTable;
    private DefaultTableModel chatHistoryModel;
    private SimpleDateFormat dateFormat;

    // Edit mode components
    private JButton editSaveButton;
    private JTextArea markdownEditArea;
    private JPanel contentPanel;
    private CardLayout contentLayout;
    private boolean isEditMode = false;
    private String currentMarkdownSource = "";
    private static final String QUERY_HINT_TEXT =
        "#line to include the current disassembly line.\n" +
        "#func to include current function disassembly.\n" +
        "#addr to include the current hex address.\n" +
        "#range(start, end) to include the view data in a given range.";

    // Streaming markdown rendering CSS
    private static final String STREAMING_CSS =
        "body { font-family: sans-serif; font-size: 14px; margin: 8px; }" +
        "pre { background-color: #f4f4f4; padding: 8px; border: 1px solid #ddd; overflow-x: auto; }" +
        "code { background-color: #f4f4f4; padding: 2px 4px; }" +
        "table { border-collapse: collapse; margin: 8px 0; }" +
        "th, td { border: 1px solid #ddd; padding: 4px 8px; }" +
        "th { background-color: #f0f0f0; }" +
        "blockquote { border-left: 3px solid #ccc; margin-left: 0; padding-left: 12px; color: #555; }";

    // Streaming state fields
    private StringBuilder accumulatedCommittedHtml = new StringBuilder();
    private String lastPendingHtml = "<span></span>";
    private boolean documentCorrupted = false;
    private StreamingScrollManager scrollManager;
    private JScrollPane responseScrollPane;

    public QueryTab(TabController controller) {
        super(new BorderLayout());
        this.controller = controller;
        this.markdownHelper = new MarkdownHelper();
        this.dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        this.dateFormat.setTimeZone(TimeZone.getDefault()); // Use local timezone

        // Initialize JTextPane with StyledDocument for incremental updates
        responseTextPane = new JTextPane();
        responseTextPane.setEditable(false);
        responseDocument = responseTextPane.getStyledDocument();

        // Enable double buffering for smoother updates
        responseTextPane.setDoubleBuffered(true);

        initializeComponents();
        layoutComponents();
        setupListeners();
        setupMCPDetection();
        setupChatHistoryRefresh();
        setupContextMenu();
    }

    private void initializeComponents() {
        useRAGCheckBox = new JCheckBox("Use RAG");
        useRAGCheckBox.setSelected(false);

        useMCPCheckBox = new JCheckBox("Use MCP Tools");
        useMCPCheckBox.setSelected(false);
        useMCPCheckBox.setEnabled(false); // Disabled by default, enabled when MCP is detected

        useAgenticCheckBox = new JCheckBox("Agentic Mode (ReAct)");
        useAgenticCheckBox.setSelected(false);
        useAgenticCheckBox.setEnabled(false); // Enabled only when MCP is available
        useAgenticCheckBox.setToolTipText("Enable autonomous ReAct-style analysis with systematic tool use");

        // responseTextPane already initialized in constructor

        queryTextArea = new JTextArea();
        queryTextArea.setRows(4);
        queryTextArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        queryTextArea.setLineWrap(true);
        queryTextArea.setWrapStyleWord(true);
        addHintTextToQueryTextArea();

        submitButton = new JButton("Submit");
        newButton = new JButton("New");
        deleteButton = new JButton("Delete");
        editSaveButton = new JButton("Edit");

        // Initialize markdown edit area for edit mode
        markdownEditArea = new JTextArea();
        markdownEditArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        markdownEditArea.setLineWrap(true);
        markdownEditArea.setWrapStyleWord(true);

        // Setup card layout for switching between view and edit modes
        contentLayout = new CardLayout();
        contentPanel = new JPanel(contentLayout);

        // Initialize chat history table
        chatHistoryModel = new DefaultTableModel(new Object[]{"Description", "Date"}, 0) {
            private static final long serialVersionUID = 1L;
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 0; // Only description column is editable
            }
        };
        
        chatHistoryTable = new JTable(chatHistoryModel);
        chatHistoryTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        chatHistoryTable.setRowHeight(20);
        chatHistoryTable.setTableHeader(null); // Completely remove header row
        
        // Set column widths
        chatHistoryTable.getColumnModel().getColumn(0).setPreferredWidth(150); // Description
        chatHistoryTable.getColumnModel().getColumn(1).setPreferredWidth(150); // Date
    }

    private void layoutComponents() {
        // Create top panel with checkboxes and edit button
        JPanel topPanel = new JPanel(new BorderLayout());

        JPanel checkboxPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        checkboxPanel.add(useRAGCheckBox);
        checkboxPanel.add(useMCPCheckBox);
        checkboxPanel.add(useAgenticCheckBox);
        topPanel.add(checkboxPanel, BorderLayout.CENTER);

        JPanel editPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        editPanel.add(editSaveButton);
        topPanel.add(editPanel, BorderLayout.EAST);

        add(topPanel, BorderLayout.NORTH);

        // Setup content panel with CardLayout (view mode + edit mode)
        responseScrollPane = new JScrollPane(responseTextPane);
        responseScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        scrollManager = new StreamingScrollManager(responseScrollPane);
        JScrollPane editScrollPane = new JScrollPane(markdownEditArea);
        contentPanel.add(responseScrollPane, "view");
        contentPanel.add(editScrollPane, "edit");

        JScrollPane queryScrollPane = new JScrollPane(queryTextArea);

        // Create chat history scroll pane with default height of 2 rows
        JScrollPane chatHistoryScrollPane = new JScrollPane(chatHistoryTable);
        chatHistoryScrollPane.setPreferredSize(new Dimension(0, 50)); // About 2 rows height
        chatHistoryScrollPane.setMinimumSize(new Dimension(0, 40));

        // Create a panel for chat history and query area
        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.add(chatHistoryScrollPane, BorderLayout.NORTH);
        bottomPanel.add(queryScrollPane, BorderLayout.CENTER);

        // Create main split pane between response and (chat history + query)
        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
            contentPanel, bottomPanel);
        mainSplitPane.setResizeWeight(0.7); // Give more space to response area

        // Create inner split pane for chat history and query area
        JSplitPane bottomSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
            chatHistoryScrollPane, queryScrollPane);
        bottomSplitPane.setResizeWeight(0.3); // Chat history takes less space than query

        // Replace the bottom panel with the split pane
        bottomPanel.removeAll();
        bottomPanel.add(bottomSplitPane, BorderLayout.CENTER);

        add(mainSplitPane, BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel();
        buttonPanel.add(submitButton);
        buttonPanel.add(newButton);
        buttonPanel.add(deleteButton);
        add(buttonPanel, BorderLayout.SOUTH);
    }

    private void setupListeners() {
        // Add hyperlink listener for RLHF feedback buttons
        responseTextPane.addHyperlinkListener(controller::handleHyperlinkEvent);

        submitButton.addActionListener(e -> controller.handleQuerySubmit(
            queryTextArea.getText(),
            useRAGCheckBox.isSelected(),
            useMCPCheckBox.isSelected(),
            useAgenticCheckBox.isSelected()
        ));

        newButton.addActionListener(e -> controller.handleNewChatSession());

        deleteButton.addActionListener(e -> controller.handleDeleteCurrentSession());

        // Edit/Save button handler
        editSaveButton.addActionListener(e -> {
            if (isEditMode) {
                // Save mode - capture content and notify controller
                currentMarkdownSource = markdownEditArea.getText();
                controller.handleChatEditSave(currentMarkdownSource);

                // Switch to view mode
                contentLayout.show(contentPanel, "view");
                editSaveButton.setText("Edit");
                isEditMode = false;
            } else {
                // Edit mode - notify controller to prepare content
                controller.handleChatEditStart();

                // Switch to edit mode
                contentLayout.show(contentPanel, "edit");
                editSaveButton.setText("Save");
                isEditMode = true;
            }
        });
        
        // Chat history table selection listener
        chatHistoryTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = chatHistoryTable.getSelectedRow();
                if (selectedRow >= 0) {
                    controller.handleChatSessionSelection(selectedRow);
                }
            }
        });
        
        // Chat history table double-click for inline editing
        chatHistoryTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int row = chatHistoryTable.rowAtPoint(e.getPoint());
                    int col = chatHistoryTable.columnAtPoint(e.getPoint());
                    if (row >= 0 && col == 0) { // Only description column is editable
                        chatHistoryTable.editCellAt(row, col);
                    }
                }
            }
        });
        
        // Auto-save when focus changes from description field
        chatHistoryModel.addTableModelListener(e -> {
            if (e.getColumn() == 0) { // Description column changed
                int row = e.getFirstRow();
                if (row >= 0) {
                    String newDescription = (String) chatHistoryModel.getValueAt(row, 0);
                    controller.handleChatDescriptionUpdate(row, newDescription);
                }
            }
        });
    }

    private void addHintTextToQueryTextArea() {
        Color fgColor = queryTextArea.getForeground();
        queryTextArea.setText(QUERY_HINT_TEXT);
        queryTextArea.setForeground(Color.GRAY);
        
        queryTextArea.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override
            public void focusGained(java.awt.event.FocusEvent e) {
                if (queryTextArea.getText().equals(QUERY_HINT_TEXT)) {
                    queryTextArea.setText("");
                    queryTextArea.setForeground(fgColor);
                }
            }

            @Override
            public void focusLost(java.awt.event.FocusEvent e) {
                if (queryTextArea.getText().isEmpty()) {
                    queryTextArea.setForeground(Color.GRAY);
                    queryTextArea.setText(QUERY_HINT_TEXT);
                }
            }
        });
    }

    /**
     * Set response text - switches to HTML mode and renders full content.
     * PERFORMANCE: This is used at completion for full markdown rendering.
     * Preserves scroll position if user has scrolled up from bottom.
     */
    public void setResponseText(String htmlText) {
        SwingUtilities.invokeLater(() -> {
            try {
                // Capture scroll state BEFORE any modifications
                boolean wasAtBottom = scrollManager.isAtBottom();
                int savedScrollValue = scrollManager.getScrollPane().getVerticalScrollBar().getValue();

                // Switch to HTML mode for final markdown rendering
                responseTextPane.setContentType("text/html");
                responseTextPane.setText(htmlText);

                // Restore scroll position - only auto-scroll if user was at bottom
                SwingUtilities.invokeLater(() -> {
                    if (wasAtBottom) {
                        scrollManager.scrollToBottom();
                    } else {
                        scrollManager.getScrollPane().getVerticalScrollBar().setValue(savedScrollValue);
                    }
                });
            } catch (Exception e) {
                Msg.error(this, "Error setting response text", e);
            }
        });
    }

    /**
     * Initialize the response pane for streaming with a two-div DOM structure.
     * Optionally includes conversation history as a prefix.
     *
     * @param prefixHtml Pre-rendered HTML for conversation history (may be empty)
     */
    public void initializeForStreaming(String prefixHtml) {
        SwingUtilities.invokeLater(() -> {
            // Capture scroll state BEFORE any modifications
            boolean wasAtBottom = scrollManager.isAtBottom();
            int savedScrollValue = scrollManager.getScrollPane().getVerticalScrollBar().getValue();

            // Reset streaming state
            accumulatedCommittedHtml.setLength(0);
            lastPendingHtml = "<span></span>";
            documentCorrupted = false;

            // Switch to HTML mode
            responseTextPane.setContentType("text/html");
            HTMLEditorKit kit = new HTMLEditorKit();
            responseTextPane.setEditorKit(kit);

            // Build initial HTML with two-div structure
            String prefix = (prefixHtml != null && !prefixHtml.isEmpty()) ? prefixHtml : "";
            String initialHtml = String.format(
                "<html><head><style>%s</style></head><body>%s" +
                "<div id=\"committed\"></div>" +
                "<div id=\"pending\"><span></span></div>" +
                "</body></html>",
                STREAMING_CSS, prefix);

            responseTextPane.setText(initialHtml);
            responseDocument = responseTextPane.getStyledDocument();

            // Restore scroll position
            if (wasAtBottom) {
                SwingUtilities.invokeLater(() -> scrollManager.scrollToBottom());
            } else {
                SwingUtilities.invokeLater(() ->
                        scrollManager.getScrollPane().getVerticalScrollBar().setValue(savedScrollValue));
            }
        });
    }

    /**
     * Apply a render update to the streaming display.
     * Handles both incremental (append/replace) and full document replacement.
     * Note: This method is called from EDT (via StreamingMarkdownRenderer's invokeLater).
     *
     * @param update The render update to apply
     */
    public void applyRenderUpdate(RenderUpdate update) {
        if (update == null) {
            return;
        }

        // Capture scroll state BEFORE any DOM modification
        boolean wasAtBottom = scrollManager.isAtBottom();
        int savedScrollValue = scrollManager.getScrollPane().getVerticalScrollBar().getValue();

        // Apply the update
        switch (update.getType()) {
            case INCREMENTAL -> applyIncrementalUpdate(update);
            case FULL_REPLACE -> applyFullReplaceUpdate(update);
        }

        // Restore scroll position or auto-scroll (matching reference implementation)
        if (wasAtBottom) {
            SwingUtilities.invokeLater(() -> scrollManager.scrollToBottom());
        } else {
            // Restore the user's scroll position exactly
            SwingUtilities.invokeLater(() ->
                    scrollManager.getScrollPane().getVerticalScrollBar().setValue(savedScrollValue));
        }
    }

    private void applyIncrementalUpdate(RenderUpdate update) {
        // Track content for fallback rebuilds
        String committedHtml = update.getCommittedHtmlToAppend();
        if (committedHtml != null && !committedHtml.isEmpty()) {
            accumulatedCommittedHtml.append(committedHtml);
        }
        String pendingHtml = update.getPendingHtml();
        if (pendingHtml != null) {
            lastPendingHtml = pendingHtml;
        }

        // If document was previously corrupted, use full rebuild strategy
        if (documentCorrupted) {
            rebuildDocument();
            return;
        }

        HTMLDocument doc = (HTMLDocument) responseTextPane.getDocument();

        try {
            // Append committed HTML
            if (committedHtml != null && !committedHtml.isEmpty()) {
                Element committedDiv = findElement(doc, "committed");
                if (committedDiv != null) {
                    doc.insertBeforeEnd(committedDiv, committedHtml);
                }
            }

            // Replace pending div atomically using setOuterHTML
            // (avoids the BiDi corruption bug in setInnerHTML)
            if (pendingHtml != null) {
                Element pendingDiv = findElement(doc, "pending");
                if (pendingDiv != null) {
                    String wrappedPending = "<div id=\"pending\">" + pendingHtml + "</div>";
                    doc.setOuterHTML(pendingDiv, wrappedPending);
                }
            }
        } catch (Exception e) {
            Msg.warn(this, "DOM update failed, switching to rebuild strategy: " + e.getMessage());
            documentCorrupted = true;
            rebuildDocument();
        }
    }

    private void applyFullReplaceUpdate(RenderUpdate update) {
        String fullHtml = update.getFullHtml();
        if (fullHtml != null) {
            String wrapped = "<html><head><style>" + STREAMING_CSS + "</style></head><body>" +
                    fullHtml + "</body></html>";
            responseTextPane.setText(wrapped);
            documentCorrupted = false;
        }
    }

    private void rebuildDocument() {
        String html = "<html><head><style>" + STREAMING_CSS + "</style></head><body>" +
                accumulatedCommittedHtml.toString() +
                lastPendingHtml +
                "</body></html>";
        responseTextPane.setText(html);
    }

    private Element findElement(HTMLDocument doc, String id) {
        return findElementById(doc.getDefaultRootElement(), id);
    }

    private Element findElementById(Element element, String id) {
        // Check this element's attributes for an id
        Object idAttr = element.getAttributes().getAttribute(HTML.Attribute.ID);
        if (id.equals(idAttr)) {
            return element;
        }

        // Recursively search children
        for (int i = 0; i < element.getElementCount(); i++) {
            Element found = findElementById(element.getElement(i), id);
            if (found != null) {
                return found;
            }
        }
        return null;
    }

    /**
     * Clear the response and prepare for streaming.
     */
    public void clearResponse() {
        initializeForStreaming("");
    }

    public void appendToResponse(String html) {
        // For backward compatibility - now just sets text
        setResponseText(html);
    }
    
    public void setSubmitButtonText(String text) {
        submitButton.setText(text);
    }
    
    public void setMCPEnabled(boolean enabled) {
        useMCPCheckBox.setEnabled(enabled);
        // Agentic mode requires MCP tools, so enable/disable together
        useAgenticCheckBox.setEnabled(enabled);
    }

    public boolean isMCPEnabled() {
        return useMCPCheckBox.isEnabled();
    }

    public boolean isMCPSelected() {
        return useMCPCheckBox.isSelected();
    }

    public boolean isAgenticSelected() {
        return useAgenticCheckBox.isSelected();
    }
    
    /**
     * Setup chat history refresh when tab receives focus
     */
    private void setupChatHistoryRefresh() {
        // Refresh chat history when tab receives focus
        this.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override
            public void focusGained(java.awt.event.FocusEvent e) {
                controller.refreshChatHistory();
            }
        });
        
        // Also refresh when component becomes visible
        this.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentShown(ComponentEvent e) {
                controller.refreshChatHistory();
            }
        });
    }
    
    /**
     * Setup MCP detection that checks for availability when tab becomes visible
     */
    private void setupMCPDetection() {
        // Check MCP availability when component becomes visible
        this.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentShown(ComponentEvent e) {
                updateMCPCheckboxState();
            }
        });
        
        // Also check when gaining focus
        this.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override
            public void focusGained(java.awt.event.FocusEvent e) {
                updateMCPCheckboxState();
            }
        });
        
        // Initial check
        SwingUtilities.invokeLater(this::updateMCPCheckboxState);
    }
    
    /**
     * Update MCP checkbox state based on enabled server configuration
     * Checks if any MCP servers are configured and enabled
     */
    private void updateMCPCheckboxState() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::updateMCPCheckboxState);
            return;
        }

        // Check if any MCP servers are enabled in configuration
        MCPServerRegistry registry = MCPServerRegistry.getInstance();
        boolean hasEnabledServers = !registry.getEnabledServers().isEmpty();

        boolean wasEnabled = useMCPCheckBox.isEnabled();
        useMCPCheckBox.setEnabled(hasEnabledServers);

        // Agentic mode requires MCP, so enable/disable together
        useAgenticCheckBox.setEnabled(hasEnabledServers);

        // If no servers enabled, also uncheck both boxes
        if (!hasEnabledServers) {
            useMCPCheckBox.setSelected(false);
            useAgenticCheckBox.setSelected(false);
        }
        
        // Log state change for debugging
        if (wasEnabled != hasEnabledServers) {
            String state = hasEnabledServers ? "enabled" : "disabled";
            int enabledCount = registry.getEnabledServers().size();
            Msg.info(this, "MCP Tools checkbox " + state + " - enabled servers: " + enabledCount);
        }
    }
    
    /**
     * Public method to update MCP checkbox state
     * Called by controller when actions are triggered
     */
    public void refreshMCPState() {
        updateMCPCheckboxState();
    }
    
    /**
     * Update the chat history table with sessions
     */
    public void updateChatHistory(java.util.List<AnalysisDB.ChatSession> sessions) {
        chatHistoryModel.setRowCount(0); // Clear existing rows
        
        for (AnalysisDB.ChatSession session : sessions) {
            // Convert SQL Timestamp to Date and format in local timezone
            Date localDate = new Date(session.getLastUpdate().getTime());
            String formattedDate = dateFormat.format(localDate);
            chatHistoryModel.addRow(new Object[]{session.getDescription(), formattedDate});
        }
    }
    
    /**
     * Select a specific chat session row
     */
    public void selectChatSession(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < chatHistoryTable.getRowCount()) {
            chatHistoryTable.setRowSelectionInterval(rowIndex, rowIndex);
        }
    }
    
    /**
     * Clear chat history selection
     */
    public void clearChatSelection() {
        chatHistoryTable.clearSelection();
    }
    
    /**
     * Get the currently selected chat session row (first selected if multiple)
     */
    public int getSelectedChatSession() {
        return chatHistoryTable.getSelectedRow();
    }

    /**
     * Get all selected chat session rows (for bulk operations like delete)
     */
    public int[] getSelectedChatSessions() {
        return chatHistoryTable.getSelectedRows();
    }

    /**
     * Setup context menu for clipboard operations
     */
    private void setupContextMenu() {
        JPopupMenu contextMenu = new JPopupMenu();

        JMenuItem copyMarkdown = new JMenuItem("Copy as Markdown");
        copyMarkdown.addActionListener(e -> {
            String selectedText = isEditMode ?
                    markdownEditArea.getSelectedText() :
                    getSelectedMarkdownText();
            if (selectedText != null && !selectedText.isEmpty()) {
                copyToClipboard(selectedText);
            }
        });

        JMenuItem copyHtml = new JMenuItem("Copy as HTML");
        copyHtml.addActionListener(e -> {
            String selectedText = responseTextPane.getSelectedText();
            if (selectedText != null && !selectedText.isEmpty()) {
                // For HTML, get from the rendered content
                copyToClipboard(selectedText);
            }
        });

        JMenuItem copyPlainText = new JMenuItem("Copy as Plain Text");
        copyPlainText.addActionListener(e -> {
            String selectedText = isEditMode ?
                    markdownEditArea.getSelectedText() :
                    responseTextPane.getSelectedText();
            if (selectedText != null && !selectedText.isEmpty()) {
                // Strip markdown formatting for plain text
                String plainText = selectedText.replaceAll("\\*\\*|__|`|#+ |\\[|\\]\\([^)]*\\)", "");
                copyToClipboard(plainText);
            }
        });

        JMenuItem copyAll = new JMenuItem("Copy All as Markdown");
        copyAll.addActionListener(e -> {
            copyToClipboard(currentMarkdownSource);
        });

        JMenuItem selectAll = new JMenuItem("Select All");
        selectAll.addActionListener(e -> {
            if (isEditMode) {
                markdownEditArea.selectAll();
            } else {
                responseTextPane.selectAll();
            }
        });

        JMenuItem paste = new JMenuItem("Paste");
        paste.addActionListener(e -> {
            if (isEditMode) {
                markdownEditArea.paste();
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

        responseTextPane.setComponentPopupMenu(contextMenu);
        markdownEditArea.setComponentPopupMenu(contextMenu);
    }

    /**
     * Get selected markdown text based on selection in view mode
     */
    private String getSelectedMarkdownText() {
        // If there's selected text in the response pane, try to map to markdown
        String selectedText = responseTextPane.getSelectedText();
        if (selectedText != null && !selectedText.isEmpty()) {
            // For now, return the selected text - could be enhanced to map to actual markdown
            return selectedText;
        }
        return currentMarkdownSource;
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

    // Edit mode public methods

    /**
     * Set editable content for edit mode
     */
    public void setEditableContent(String markdown) {
        currentMarkdownSource = markdown;
        markdownEditArea.setText(markdown);
    }

    /**
     * Get the current editable content
     */
    public String getEditableContent() {
        return isEditMode ? markdownEditArea.getText() : currentMarkdownSource;
    }

    /**
     * Set the markdown source (for view mode)
     */
    public void setMarkdownSource(String markdown) {
        currentMarkdownSource = markdown;
    }

    /**
     * Get the current markdown source
     */
    public String getMarkdownSource() {
        return currentMarkdownSource;
    }

    /**
     * Check if currently in edit mode
     */
    public boolean isInEditMode() {
        return isEditMode;
    }

    /**
     * Exit edit mode without saving
     */
    public void exitEditMode() {
        if (isEditMode) {
            contentLayout.show(contentPanel, "view");
            editSaveButton.setText("Edit");
            isEditMode = false;
        }
    }

    /**
     * Get the MarkdownHelper instance
     */
    public MarkdownHelper getMarkdownHelper() {
        return markdownHelper;
    }

}
