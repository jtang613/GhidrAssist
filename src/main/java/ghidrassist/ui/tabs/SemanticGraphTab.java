package ghidrassist.ui.tabs;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import ghidrassist.core.TabController;
import ghidrassist.ui.tabs.semanticgraph.ListViewPanel;
import ghidrassist.ui.tabs.semanticgraph.GraphViewPanel;
import ghidrassist.ui.tabs.semanticgraph.SearchViewPanel;
import ghidrassist.ui.tabs.semanticgraph.ManualAnalysisPanel;

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
    private ManualAnalysisPanel manualAnalysisPanel;

    // Bottom panel components
    private JButton resetGraphButton;
    private JButton reindexButton;
    private JButton semanticAnalysisButton;
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
        manualAnalysisPanel = new ManualAnalysisPanel(this);

        // Bottom action buttons
        resetGraphButton = new JButton("Reset Graph");
        resetGraphButton.setToolTipText("Clear all graph data for this binary (requires confirmation)");

        reindexButton = new JButton("ReIndex Binary");
        reindexButton.setToolTipText("Rebuild the knowledge graph: Structure + Semantic + Security + Network analysis");

        semanticAnalysisButton = new JButton("Semantic Analysis");
        semanticAnalysisButton.setToolTipText("Use LLM to generate summaries for all stale/unsummarized nodes");

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

        // ===== Sub-tabbed pane (List View / Visual Graph / Search / Manual Analysis) =====
        subTabbedPane.addTab("List View", listViewPanel);
        subTabbedPane.addTab("Visual Graph", graphViewPanel);
        subTabbedPane.addTab("Search", searchViewPanel);
        subTabbedPane.addTab("Manual Analysis", manualAnalysisPanel);

        add(subTabbedPane, BorderLayout.CENTER);

        // ===== Bottom Panel =====
        JPanel bottomPanel = new JPanel(new BorderLayout(5, 5));
        bottomPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // Button row - main operations only
        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        buttonRow.add(resetGraphButton);
        buttonRow.add(reindexButton);
        buttonRow.add(semanticAnalysisButton);

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

        // Sub-tab change listener
        subTabbedPane.addChangeListener(e -> {
            // Refresh the selected view when switching tabs
            Component selected = subTabbedPane.getSelectedComponent();
            if (selected == graphViewPanel) {
                graphViewPanel.refresh();
            } else if (selected == searchViewPanel) {
                searchViewPanel.refresh();
            } else if (selected == manualAnalysisPanel) {
                manualAnalysisPanel.refresh();
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

    // ===== Manual Analysis Panel Handlers =====

    /**
     * Handle ReIndex from Manual Analysis panel.
     */
    public void handleReindexFromManual() {
        // If running, just stop (no confirmation needed)
        if (manualAnalysisPanel.isReindexRunning()) {
            controller.handleSemanticGraphReindex();
            return;
        }

        // Otherwise confirm before starting
        int result = JOptionPane.showConfirmDialog(this,
                "ReIndex the entire binary?\n" +
                "This will:\n" +
                "• Extract structure from Ghidra analysis\n" +
                "• Run Security Analysis (taint paths)\n" +
                "• Run Network Flow Analysis (send/recv tracing)\n\n" +
                "This may take a while for large binaries.",
                "ReIndex Binary",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE);

        if (result == JOptionPane.YES_OPTION) {
            controller.handleSemanticGraphReindex();
        }
    }

    /**
     * Handle Semantic Analysis from Manual Analysis panel.
     */
    public void handleSemanticAnalysisFromManual() {
        // If running, just stop (no confirmation needed)
        if (manualAnalysisPanel.isSemanticAnalysisRunning()) {
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

    /**
     * Handle Security Analysis from Manual Analysis panel.
     */
    public void handleSecurityAnalysisFromManual() {
        // If running, just stop (no confirmation needed)
        if (manualAnalysisPanel.isSecurityAnalysisRunning()) {
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

    /**
     * Handle Network Flow Analysis from Manual Analysis panel.
     */
    public void handleNetworkFlowFromManual() {
        // If running, just stop (no confirmation needed)
        if (manualAnalysisPanel.isNetworkFlowRunning()) {
            controller.handleSemanticGraphNetworkFlowAnalysis();
            return;
        }

        // Otherwise confirm before starting
        int result = JOptionPane.showConfirmDialog(this,
                "Run Network Flow Analysis?\n" +
                "This will:\n" +
                "• Find functions that call send/recv APIs (WSASend, recv, etc.)\n" +
                "• Create NETWORK_SEND edges from entry points to send functions\n" +
                "• Create NETWORK_RECV edges from recv functions to their callers\n\n" +
                "This requires an indexed binary.",
                "Network Flow Analysis",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE);

        if (result == JOptionPane.YES_OPTION) {
            controller.handleSemanticGraphNetworkFlowAnalysis();
        }
    }

    /**
     * Handle Community Detection from Manual Analysis panel.
     */
    public void handleCommunityDetectionFromManual() {
        // If running, just stop (no confirmation needed)
        if (manualAnalysisPanel.isCommunityDetectionRunning()) {
            controller.handleSemanticGraphCommunityDetection();
            return;
        }

        // Otherwise confirm before starting
        int result = JOptionPane.showConfirmDialog(this,
                "Run Community Detection?\n" +
                "This will:\n" +
                "• Group related functions into communities using Label Propagation\n" +
                "• Create BELONGS_TO_COMMUNITY edges\n" +
                "• Generate summaries for each detected community\n\n" +
                "This requires an indexed binary.",
                "Community Detection",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE);

        if (result == JOptionPane.YES_OPTION) {
            controller.handleSemanticGraphCommunityDetection();
        }
    }

    /**
     * Handle Refresh Names from Manual Analysis panel.
     */
    public void handleRefreshNamesFromManual() {
        controller.handleSemanticGraphRefreshNames();
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
     * Updates both bottom panel button and ManualAnalysisPanel button.
     */
    public void setReindexRunning(boolean running) {
        reindexButton.setText(running ? "Stop" : "ReIndex Binary");
        manualAnalysisPanel.setReindexRunning(running);
    }

    /**
     * Set semantic analysis button to running state (shows "Stop" text).
     * Updates both bottom panel button and ManualAnalysisPanel button.
     */
    public void setSemanticAnalysisRunning(boolean running) {
        semanticAnalysisButton.setText(running ? "Stop" : "Semantic Analysis");
        manualAnalysisPanel.setSemanticAnalysisRunning(running);
    }

    /**
     * Set security analysis button to running state (shows "Stop" text).
     * Delegates to ManualAnalysisPanel.
     */
    public void setSecurityAnalysisRunning(boolean running) {
        manualAnalysisPanel.setSecurityAnalysisRunning(running);
    }

    /**
     * Set refresh names button to running state (shows "Stop" text).
     * Delegates to ManualAnalysisPanel.
     */
    public void setRefreshNamesRunning(boolean running) {
        manualAnalysisPanel.setRefreshNamesRunning(running);
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
     * Delegates to ManualAnalysisPanel.
     */
    public boolean isSecurityAnalysisRunning() {
        return manualAnalysisPanel.isSecurityAnalysisRunning();
    }

    /**
     * Check if refresh names is currently running.
     * Delegates to ManualAnalysisPanel.
     */
    public boolean isRefreshNamesRunning() {
        return manualAnalysisPanel.isRefreshNamesRunning();
    }

    /**
     * Set network flow analysis button to running state (shows "Stop" text).
     * Delegates to ManualAnalysisPanel.
     */
    public void setNetworkFlowRunning(boolean running) {
        manualAnalysisPanel.setNetworkFlowRunning(running);
    }

    /**
     * Check if network flow analysis is currently running.
     * Delegates to ManualAnalysisPanel.
     */
    public boolean isNetworkFlowRunning() {
        return manualAnalysisPanel.isNetworkFlowRunning();
    }

    /**
     * Set community detection button to running state (shows "Stop" text).
     * Delegates to ManualAnalysisPanel.
     */
    public void setCommunityDetectionRunning(boolean running) {
        manualAnalysisPanel.setCommunityDetectionRunning(running);
    }

    /**
     * Check if community detection is currently running.
     * Delegates to ManualAnalysisPanel.
     */
    public boolean isCommunityDetectionRunning() {
        return manualAnalysisPanel.isCommunityDetectionRunning();
    }
}
