package ghidrassist.ui.tabs;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import ghidra.util.Msg;
import ghidrassist.core.TabController;
import ghidrassist.mcp2.tools.MCPToolManager;

public class QueryTab extends JPanel {
    private static final long serialVersionUID = 1L;
	private final TabController controller;
    private JEditorPane responseTextPane;
    private JTextArea queryTextArea;
    private JCheckBox useRAGCheckBox;
    private JCheckBox useMCPCheckBox;
    private JButton submitButton;
    private JButton clearButton;
    private static final String QUERY_HINT_TEXT = 
        "#line to include the current disassembly line.\n" +
        "#func to include current function disassembly.\n" +
        "#addr to include the current hex address.\n" +
        "#range(start, end) to include the view data in a given range.";

    public QueryTab(TabController controller) {
        super(new BorderLayout());
        this.controller = controller;
        
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
        clearButton = new JButton("Clear");
    }

    private void layoutComponents() {
        // Create panel for checkboxes
        JPanel checkboxPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        checkboxPanel.add(useRAGCheckBox);
        checkboxPanel.add(useMCPCheckBox);
        add(checkboxPanel, BorderLayout.NORTH);

        JScrollPane responseScrollPane = new JScrollPane(responseTextPane);
        JScrollPane queryScrollPane = new JScrollPane(queryTextArea);
        
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, 
            responseScrollPane, queryScrollPane);
        splitPane.setResizeWeight(0.9);
        add(splitPane, BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel();
        buttonPanel.add(submitButton);
        buttonPanel.add(clearButton);
        add(buttonPanel, BorderLayout.SOUTH);
    }

    private void setupListeners() {
        submitButton.addActionListener(e -> controller.handleQuerySubmit(
            queryTextArea.getText(),
            useRAGCheckBox.isSelected(),
            useMCPCheckBox.isSelected()
        ));

        clearButton.addActionListener(e -> {
            responseTextPane.setText("");
            queryTextArea.setText("");
            addHintTextToQueryTextArea();
            controller.clearConversationHistory();
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
     * Setup MCP detection that checks for availability when tab becomes visible
     */
    private void setupMCPDetection() {
        // Check MCP availability when component becomes visible
        this.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentShown(ComponentEvent e) {
                checkMCPAvailability();
            }
        });
        
        // Also check when gaining focus
        this.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override
            public void focusGained(java.awt.event.FocusEvent e) {
                checkMCPAvailability();
            }
        });
        
        // Initial check
        SwingUtilities.invokeLater(this::checkMCPAvailability);
    }
    
    /**
     * Check if MCP is available and update checkbox state
     * This method is completely non-blocking and runs asynchronously
     */
    private void checkMCPAvailability() {
        MCPToolManager toolManager = MCPToolManager.getInstance();
        
        // Check current state immediately (non-blocking)
        boolean currentlyAvailable = toolManager.hasConnectedServers();
        
        // Update UI with current state
        SwingUtilities.invokeLater(() -> {
            boolean wasEnabled = useMCPCheckBox.isEnabled();
            useMCPCheckBox.setEnabled(currentlyAvailable);
            
            if (currentlyAvailable && !wasEnabled) {
            }
        });
        
        // If not initialized yet, start initialization asynchronously
        if (!currentlyAvailable && !toolManager.isInitialized()) {
            // Initialize in background - this is completely asynchronous
            toolManager.initializeServers()
                .thenRun(() -> {
                    // Update UI when initialization completes
                    SwingUtilities.invokeLater(() -> {
                        boolean nowAvailable = toolManager.hasConnectedServers();
                        boolean wasEnabled = useMCPCheckBox.isEnabled();
                        
                        useMCPCheckBox.setEnabled(nowAvailable);
                        
                        if (nowAvailable && !wasEnabled) {
                        }
                    });
                })
                .exceptionally(throwable -> {
                    // Log initialization failure but don't block UI
                    SwingUtilities.invokeLater(() -> {
                        Msg.error(this, "MCP initialization failed: " + throwable.getMessage());
                        useMCPCheckBox.setEnabled(false);
                    });
                    return null;
                });
        }
    }
}
