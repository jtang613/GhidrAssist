package ghidrassist.ui.tabs;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.text.SimpleDateFormat;
import java.util.TimeZone;
import java.util.Date;
import ghidra.util.Msg;
import ghidrassist.core.TabController;
import ghidrassist.mcp2.tools.MCPToolManager;
import ghidrassist.mcp2.server.MCPServerRegistry;
import ghidrassist.AnalysisDB;

public class QueryTab extends JPanel {
    private static final long serialVersionUID = 1L;
	private final TabController controller;
    private JEditorPane responseTextPane;
    private JTextArea queryTextArea;
    private JCheckBox useRAGCheckBox;
    private JCheckBox useMCPCheckBox;
    private JButton submitButton;
    private JButton newButton;
    private JButton deleteButton;
    private JTable chatHistoryTable;
    private DefaultTableModel chatHistoryModel;
    private SimpleDateFormat dateFormat;
    private static final String QUERY_HINT_TEXT = 
        "#line to include the current disassembly line.\n" +
        "#func to include current function disassembly.\n" +
        "#addr to include the current hex address.\n" +
        "#range(start, end) to include the view data in a given range.";

    public QueryTab(TabController controller) {
        super(new BorderLayout());
        this.controller = controller;
        this.dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        this.dateFormat.setTimeZone(TimeZone.getDefault()); // Use local timezone
        
        // Initialize components with optimized settings
        responseTextPane = new JEditorPane();
        responseTextPane.setEditable(false);
        responseTextPane.setContentType("text/html");
        responseTextPane.addHyperlinkListener(controller::handleHyperlinkEvent);
        responseTextPane.putClientProperty("JEditorPane.w3cLengthUnits", Boolean.TRUE);
        responseTextPane.putClientProperty("JEditorPane.honorDisplayProperties", Boolean.TRUE);
        
        // Enable double buffering for smoother updates
        responseTextPane.setDoubleBuffered(true);
        
        initializeComponents();
        layoutComponents();
        setupListeners();
        setupMCPDetection();
        setupChatHistoryRefresh();
    }

    private void initializeComponents() {
        useRAGCheckBox = new JCheckBox("Use RAG");
        useRAGCheckBox.setSelected(false);
        
        useMCPCheckBox = new JCheckBox("Use MCP Tools");
        useMCPCheckBox.setSelected(false);
        useMCPCheckBox.setEnabled(false); // Disabled by default, enabled when MCP is detected

        responseTextPane = new JEditorPane();
        responseTextPane.setEditable(false);
        responseTextPane.setContentType("text/html");
        responseTextPane.addHyperlinkListener(controller::handleHyperlinkEvent);

        queryTextArea = new JTextArea();
        queryTextArea.setRows(4);
        addHintTextToQueryTextArea();

        submitButton = new JButton("Submit");
        newButton = new JButton("New");
        deleteButton = new JButton("Delete");
        
        // Initialize chat history table
        chatHistoryModel = new DefaultTableModel(new Object[]{"Description", "Date"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 0; // Only description column is editable
            }
        };
        
        chatHistoryTable = new JTable(chatHistoryModel);
        chatHistoryTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        chatHistoryTable.setRowHeight(20);
        chatHistoryTable.setTableHeader(null); // Completely remove header row
        
        // Set column widths
        chatHistoryTable.getColumnModel().getColumn(0).setPreferredWidth(150); // Description
        chatHistoryTable.getColumnModel().getColumn(1).setPreferredWidth(150); // Date
    }

    private void layoutComponents() {
        // Create panel for checkboxes
        JPanel checkboxPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        checkboxPanel.add(useRAGCheckBox);
        checkboxPanel.add(useMCPCheckBox);
        add(checkboxPanel, BorderLayout.NORTH);

        // Create scroll panes
        JScrollPane responseScrollPane = new JScrollPane(responseTextPane);
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
            responseScrollPane, bottomPanel);
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
        submitButton.addActionListener(e -> controller.handleQuerySubmit(
            queryTextArea.getText(),
            useRAGCheckBox.isSelected(),
            useMCPCheckBox.isSelected()
        ));

        newButton.addActionListener(e -> controller.handleNewChatSession());
        
        deleteButton.addActionListener(e -> controller.handleDeleteCurrentSession());
        
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

    public void setResponseText(String text) {
        responseTextPane.setText(text);
        responseTextPane.setCaretPosition(responseTextPane.getDocument().getLength());
    }

    public void appendToResponse(String html) {
        // Only scroll if we're already at the bottom
        JScrollPane scrollPane = (JScrollPane) responseTextPane.getParent().getParent();
        JScrollBar vertical = scrollPane.getVerticalScrollBar();
        boolean shouldScroll = (vertical.getValue() + vertical.getVisibleAmount() == vertical.getMaximum());
        
        responseTextPane.setText(html);
        
        // Maintain scroll position if we were at the bottom
        if (shouldScroll) {
            SwingUtilities.invokeLater(() -> {
                vertical.setValue(vertical.getMaximum());
            });
        }
    }
    
    public void setSubmitButtonText(String text) {
        submitButton.setText(text);
    }
    
    public void setMCPEnabled(boolean enabled) {
        useMCPCheckBox.setEnabled(enabled);
    }
    
    public boolean isMCPEnabled() {
        return useMCPCheckBox.isEnabled();
    }
    
    public boolean isMCPSelected() {
        return useMCPCheckBox.isSelected();
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
        
        // If no servers enabled, also uncheck the box
        if (!hasEnabledServers) {
            useMCPCheckBox.setSelected(false);
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
     * Get the currently selected chat session row
     */
    public int getSelectedChatSession() {
        return chatHistoryTable.getSelectedRow();
    }
    
}
