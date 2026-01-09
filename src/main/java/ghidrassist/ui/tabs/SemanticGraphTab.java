package ghidrassist.ui.tabs;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import ghidrassist.core.TabController;
import ghidrassist.ui.tabs.semanticgraph.ListViewPanel;
import ghidrassist.ui.tabs.semanticgraph.GraphViewPanel;
import ghidrassist.ui.tabs.semanticgraph.SearchViewPanel;

/**
 * Semantic Graph tab for viewing and editing knowledge graph data.
 * Provides three sub-views:
 * - List View: Table/list-based display of callers, callees, edges, and security flags
 * - Visual Graph: Interactive node-edge diagram with configurable N-hop depth
 * - Search: Query interface for testing semantic search and graph queries
 */
public class SemanticGraphTab extends JPanel {
    private static final long serialVersionUID = 1L;

    private final TabController controller;

    // Header components
    private JTextField currentFunctionField;
    private JButton goButton;
    private JLabel statusLabel;

    // Sub-tab pane
    private JTabbedPane subTabbedPane;
    private ListViewPanel listViewPanel;
    private GraphViewPanel graphViewPanel;
    private SearchViewPanel searchViewPanel;

    // Bottom panel components
    private JButton resetGraphButton;
    private JButton reindexButton;
    private JButton semanticAnalysisButton;
    private JButton securityAnalysisButton;
    private JButton networkFlowButton;
    private JButton refreshNamesButton;
    private JLabel statsLabel;
    private JProgressBar progressBar;

    // State
    private String currentNodeId;
    private long currentAddress;

    public SemanticGraphTab(TabController controller) {
        super(new BorderLayout());
        this.controller = controller;
        initializeComponents();
        layoutComponents();
        setupListeners();
    }

    private void initializeComponents() {
        // Header components
        currentFunctionField = new JTextField(40);
        currentFunctionField.setEditable(true);
        currentFunctionField.setToolTipText("Current function or address (editable for navigation)");

        goButton = new JButton("Go");
        goButton.setToolTipText("Navigate to the entered function or address");

        statusLabel = new JLabel("Status: No program loaded");

        // Sub-tab pane for List View and Visual Graph
        subTabbedPane = new JTabbedPane();

        // Create sub-panels
        listViewPanel = new ListViewPanel(controller, this);
        graphViewPanel = new GraphViewPanel(controller, this);
        searchViewPanel = new SearchViewPanel(controller, this);

        // Bottom action buttons
        resetGraphButton = new JButton("Reset Graph");
        resetGraphButton.setToolTipText("Clear all graph data for this binary (requires confirmation)");

        reindexButton = new JButton("ReIndex Binary");
        reindexButton.setToolTipText("Rebuild the knowledge graph from Ghidra analysis");

        semanticAnalysisButton = new JButton("Semantic Analysis");
        semanticAnalysisButton.setToolTipText("Use LLM to generate summaries for all stale/unsummarized nodes");

        securityAnalysisButton = new JButton("Security Analysis");
        securityAnalysisButton.setToolTipText("Run taint analysis and create vulnerability edges (source→sink paths)");

        networkFlowButton = new JButton("Network Flow Analysis");
        networkFlowButton.setToolTipText("Trace network data flow paths (send/recv API calls)");

        refreshNamesButton = new JButton("Refresh Names");
        refreshNamesButton.setToolTipText("Update function names in graph to match current Ghidra names");

        statsLabel = new JLabel("Graph Stats: Not loaded");

        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setVisible(false);
    }

    private void layoutComponents() {
        // ===== Header Panel =====
        JPanel headerPanel = new JPanel(new BorderLayout(5, 5));
        headerPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // Current function row
        JPanel functionRow = new JPanel(new BorderLayout(5, 0));
        JLabel currentLabel = new JLabel("Current:");
        functionRow.add(currentLabel, BorderLayout.WEST);
        functionRow.add(currentFunctionField, BorderLayout.CENTER);
        functionRow.add(goButton, BorderLayout.EAST);

        headerPanel.add(functionRow, BorderLayout.NORTH);
        headerPanel.add(statusLabel, BorderLayout.SOUTH);

        add(headerPanel, BorderLayout.NORTH);

        // ===== Sub-tabbed pane (List View / Visual Graph / Search) =====
        subTabbedPane.addTab("List View", listViewPanel);
        subTabbedPane.addTab("Visual Graph", graphViewPanel);
        subTabbedPane.addTab("Search", searchViewPanel);

        add(subTabbedPane, BorderLayout.CENTER);

        // ===== Bottom Panel =====
        JPanel bottomPanel = new JPanel(new BorderLayout(5, 5));
        bottomPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // Button row
        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        buttonRow.add(resetGraphButton);
        buttonRow.add(reindexButton);
        buttonRow.add(semanticAnalysisButton);
        buttonRow.add(securityAnalysisButton);
        buttonRow.add(networkFlowButton);
        buttonRow.add(refreshNamesButton);

        // Stats and progress row
        JPanel statusRow = new JPanel(new BorderLayout(5, 0));
        statusRow.add(statsLabel, BorderLayout.WEST);
        statusRow.add(progressBar, BorderLayout.CENTER);

        bottomPanel.add(buttonRow, BorderLayout.NORTH);
        bottomPanel.add(statusRow, BorderLayout.SOUTH);

        add(bottomPanel, BorderLayout.SOUTH);
    }

    private void setupListeners() {
        // Go button - navigate to function
        goButton.addActionListener(e -> handleGoButton());

        // Enter key in function field
        currentFunctionField.addActionListener(e -> handleGoButton());

        // Reset graph button
        resetGraphButton.addActionListener(e -> handleResetGraph());

        // ReIndex button
        reindexButton.addActionListener(e -> handleReindex());

        // Semantic Analysis button
        semanticAnalysisButton.addActionListener(e -> handleSemanticAnalysis());

        // Security Analysis button
        securityAnalysisButton.addActionListener(e -> handleSecurityAnalysis());

        // Network Flow Analysis button
        networkFlowButton.addActionListener(e -> handleNetworkFlowAnalysis());

        // Refresh names button
        refreshNamesButton.addActionListener(e -> handleRefreshNames());

        // Sub-tab change listener
        subTabbedPane.addChangeListener(e -> {
            // Refresh the selected view when switching tabs
            Component selected = subTabbedPane.getSelectedComponent();
            if (selected == graphViewPanel) {
                graphViewPanel.refresh();
            } else if (selected == searchViewPanel) {
                searchViewPanel.refresh();
            }
        });
    }

    // ===== Public Methods for External Updates =====

    /**
     * Update the displayed function/address when Ghidra cursor changes.
     * Called from TabController when location changes.
     *
     * @param address The new address
     * @param functionName The function name at that address (may be null)
     */
    public void updateLocation(long address, String functionName) {
        this.currentAddress = address;

        // Update the header field
        String displayText = functionName != null ?
                String.format("%s @ 0x%x", functionName, address) :
                String.format("0x%x", address);
        currentFunctionField.setText(displayText);

        // Refresh the current view
        refreshCurrentView();
    }

    /**
     * Update the status line with node information.
     *
     * @param indexed Whether the node is indexed
     * @param callerCount Number of callers
     * @param calleeCount Number of callees
     * @param flagCount Number of security flags
     */
    public void updateStatus(boolean indexed, int callerCount, int calleeCount, int flagCount) {
        if (indexed) {
            statusLabel.setText(String.format("Status: Indexed | %d callers | %d callees | %d security flags",
                    callerCount, calleeCount, flagCount));
        } else {
            statusLabel.setText("Status: Not Indexed");
        }
    }

    /**
     * Update the graph statistics display.
     *
     * @param nodeCount Total nodes in graph
     * @param edgeCount Total edges in graph
     * @param staleCount Number of stale nodes
     * @param lastIndexed Last indexing timestamp (may be null)
     */
    public void updateStats(int nodeCount, int edgeCount, int staleCount, String lastIndexed) {
        if (nodeCount == 0) {
            statsLabel.setText("Graph Stats: Not indexed");
        } else {
            String timestamp = lastIndexed != null ? lastIndexed : "unknown";
            statsLabel.setText(String.format("Graph Stats: %d nodes | %d edges | %d stale | Last indexed: %s",
                    nodeCount, edgeCount, staleCount, timestamp));
        }
    }

    /**
     * Get the current address being displayed.
     */
    public long getCurrentAddress() {
        return currentAddress;
    }

    /**
     * Get the current node ID (may be null if not indexed).
     */
    public String getCurrentNodeId() {
        return currentNodeId;
    }

    /**
     * Set the current node ID.
     */
    public void setCurrentNodeId(String nodeId) {
        this.currentNodeId = nodeId;
    }

    /**
     * Navigate to a different function (called from sub-panels).
     */
    public void navigateToFunction(long address) {
        controller.handleSemanticGraphNavigate(address);
    }

    /**
     * Refresh the currently visible sub-view.
     */
    public void refreshCurrentView() {
        if (subTabbedPane.getSelectedComponent() == listViewPanel) {
            listViewPanel.refresh();
        } else {
            graphViewPanel.refresh();
        }
    }

    // ===== Private Handler Methods =====

    private void handleGoButton() {
        String text = currentFunctionField.getText().trim();
        if (text.isEmpty()) {
            return;
        }

        // Try to parse as address or function name
        controller.handleSemanticGraphGo(text);
    }

    private void handleResetGraph() {
        int result = JOptionPane.showConfirmDialog(this,
                "Are you sure you want to reset the knowledge graph?\n" +
                "This will delete all indexed data for this binary.",
                "Reset Graph",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE);

        if (result == JOptionPane.YES_OPTION) {
            controller.handleSemanticGraphReset();
        }
    }

    private void handleReindex() {
        // If running, just stop (no confirmation needed)
        if (isReindexRunning()) {
            controller.handleSemanticGraphReindex();
            return;
        }

        // Otherwise confirm before starting
        int result = JOptionPane.showConfirmDialog(this,
                "ReIndex the entire binary?\n" +
                "This may take a while for large binaries.",
                "ReIndex Binary",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE);

        if (result == JOptionPane.YES_OPTION) {
            controller.handleSemanticGraphReindex();
        }
    }

    private void handleRefreshNames() {
        controller.handleSemanticGraphRefreshNames();
    }

    private void handleSemanticAnalysis() {
        // If running, just stop (no confirmation needed)
        if (isSemanticAnalysisRunning()) {
            controller.handleSemanticGraphSemanticAnalysis();
            return;
        }

        // Otherwise confirm before starting
        int result = JOptionPane.showConfirmDialog(this,
                "Run Semantic Analysis on all stale nodes?\n" +
                "This will use the LLM to generate summaries for unsummarized functions.\n" +
                "This may take a while and consume API credits.",
                "Semantic Analysis",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE);

        if (result == JOptionPane.YES_OPTION) {
            controller.handleSemanticGraphSemanticAnalysis();
        }
    }

    private void handleSecurityAnalysis() {
        // If running, just stop (no confirmation needed)
        if (isSecurityAnalysisRunning()) {
            controller.handleSemanticGraphSecurityAnalysis();
            return;
        }

        // Otherwise confirm before starting
        int result = JOptionPane.showConfirmDialog(this,
                "Run Security Analysis?\n" +
                "This will:\n" +
                "• Find taint paths from sources (input) to sinks (dangerous functions)\n" +
                "• Create TAINT_FLOWS_TO edges along discovered paths\n" +
                "• Create VULNERABLE_VIA edges from entry points to vulnerable sinks\n\n" +
                "This requires an indexed binary.",
                "Security Analysis",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE);

        if (result == JOptionPane.YES_OPTION) {
            controller.handleSemanticGraphSecurityAnalysis();
        }
    }

    private void handleNetworkFlowAnalysis() {
        // If running, just stop (no confirmation needed)
        if (isNetworkFlowRunning()) {
            controller.handleSemanticGraphNetworkFlowAnalysis();
            return;
        }

        // Otherwise confirm before starting
        int result = JOptionPane.showConfirmDialog(this,
                "Run Network Flow Analysis?\n" +
                "This will:\n" +
                "• Find functions that call send/recv APIs (WSASend, recv, etc.)\n" +
                "• Create NETWORK_SEND_PATH edges from entry points to send functions\n" +
                "• Create NETWORK_RECV_PATH edges from recv functions to their callers\n\n" +
                "This requires an indexed binary.",
                "Network Flow Analysis",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE);

        if (result == JOptionPane.YES_OPTION) {
            controller.handleSemanticGraphNetworkFlowAnalysis();
        }
    }

    /**
     * Show a "not indexed" placeholder in the content area.
     */
    public void showNotIndexedPlaceholder() {
        // This is handled by the sub-panels themselves
        listViewPanel.showNotIndexed();
        graphViewPanel.showNotIndexed();
    }

    /**
     * Get the TabController for sub-panels to use.
     */
    public TabController getController() {
        return controller;
    }

    // ===== Progress and Button State Management =====

    /**
     * Show progress bar with given percentage and message.
     */
    public void showProgress(int percent, String message) {
        progressBar.setVisible(true);
        progressBar.setValue(percent);
        progressBar.setString(message);
        progressBar.setIndeterminate(false);
    }

    /**
     * Show indeterminate progress bar with message.
     */
    public void showIndeterminateProgress(String message) {
        progressBar.setVisible(true);
        progressBar.setIndeterminate(true);
        progressBar.setString(message);
    }

    /**
     * Hide the progress bar.
     */
    public void hideProgress() {
        progressBar.setVisible(false);
        progressBar.setValue(0);
        progressBar.setString("");
        progressBar.setIndeterminate(false);
    }

    /**
     * Set reindex button to running state (shows "Stop" text).
     */
    public void setReindexRunning(boolean running) {
        reindexButton.setText(running ? "Stop" : "ReIndex Binary");
    }

    /**
     * Set semantic analysis button to running state (shows "Stop" text).
     */
    public void setSemanticAnalysisRunning(boolean running) {
        semanticAnalysisButton.setText(running ? "Stop" : "Semantic Analysis");
    }

    /**
     * Set security analysis button to running state (shows "Stop" text).
     */
    public void setSecurityAnalysisRunning(boolean running) {
        securityAnalysisButton.setText(running ? "Stop" : "Security Analysis");
    }

    /**
     * Set refresh names button to running state (shows "Stop" text).
     */
    public void setRefreshNamesRunning(boolean running) {
        refreshNamesButton.setText(running ? "Stop" : "Refresh Names");
    }

    /**
     * Check if reindex is currently running.
     */
    public boolean isReindexRunning() {
        return "Stop".equals(reindexButton.getText());
    }

    /**
     * Check if semantic analysis is currently running.
     */
    public boolean isSemanticAnalysisRunning() {
        return "Stop".equals(semanticAnalysisButton.getText());
    }

    /**
     * Check if security analysis is currently running.
     */
    public boolean isSecurityAnalysisRunning() {
        return "Stop".equals(securityAnalysisButton.getText());
    }

    /**
     * Check if refresh names is currently running.
     */
    public boolean isRefreshNamesRunning() {
        return "Stop".equals(refreshNamesButton.getText());
    }

    /**
     * Set network flow analysis button to running state (shows "Stop" text).
     */
    public void setNetworkFlowRunning(boolean running) {
        networkFlowButton.setText(running ? "Stop" : "Network Flow Analysis");
    }

    /**
     * Check if network flow analysis is currently running.
     */
    public boolean isNetworkFlowRunning() {
        return "Stop".equals(networkFlowButton.getText());
    }
}
