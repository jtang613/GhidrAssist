package ghidrassist.ui.tabs.semanticgraph;

import javax.swing.*;
import java.awt.*;
import ghidrassist.ui.tabs.SemanticGraphTab;

/**
 * Panel for manual analysis operations on the knowledge graph.
 * Provides buttons with descriptions for various analysis tasks
 * that can be run independently or as part of the full ReIndex workflow.
 */
public class ManualAnalysisPanel extends JPanel {
    private static final long serialVersionUID = 1L;

    private static final int BUTTON_WIDTH = 240;
    private static final int BUTTON_HEIGHT = 28;

    private final SemanticGraphTab parentTab;

    // Primary operations
    private JButton reindexButton;
    private JButton semanticAnalysisButton;

    // Secondary operations
    private JButton securityAnalysisButton;
    private JButton networkFlowButton;
    private JButton communityDetectionButton;
    private JButton refreshNamesButton;

    public ManualAnalysisPanel(SemanticGraphTab parentTab) {
        super(new BorderLayout());
        this.parentTab = parentTab;
        initializeComponents();
        layoutComponents();
        setupListeners();
    }

    private void initializeComponents() {
        reindexButton = new JButton("ReIndex Binary");
        semanticAnalysisButton = new JButton("Semantic Analysis");
        securityAnalysisButton = new JButton("Security Analysis");
        networkFlowButton = new JButton("Network Flow Analysis");
        communityDetectionButton = new JButton("Community Detection");
        refreshNamesButton = new JButton("Refresh Names");
    }

    private void layoutComponents() {
        JPanel contentPanel = new JPanel();
        contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.Y_AXIS));
        contentPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // ===== Primary Operations Section =====
        JLabel primaryHeader = new JLabel("Primary Operations");
        primaryHeader.setFont(primaryHeader.getFont().deriveFont(Font.BOLD, 14f));
        primaryHeader.setAlignmentX(Component.LEFT_ALIGNMENT);
        contentPanel.add(primaryHeader);
        contentPanel.add(Box.createVerticalStrut(5));

        JLabel primaryDesc = new JLabel("<html><i>Full analysis workflows for the binary.</i></html>");
        primaryDesc.setAlignmentX(Component.LEFT_ALIGNMENT);
        contentPanel.add(primaryDesc);
        contentPanel.add(Box.createVerticalStrut(10));

        // ReIndex Binary
        contentPanel.add(createAnalysisRow(
            reindexButton,
            "Full Pipeline",
            "Extract structure from Ghidra analysis, then automatically run Security " +
            "and Network Flow analysis. Creates function nodes and call edges."
        ));
        contentPanel.add(Box.createVerticalStrut(8));

        // Semantic Analysis
        contentPanel.add(createAnalysisRow(
            semanticAnalysisButton,
            "LLM Summarization",
            "Use the configured LLM to generate summaries for all functions that " +
            "don't have summaries yet. Requires API credits."
        ));
        contentPanel.add(Box.createVerticalStrut(20));

        // ===== Secondary Operations Section =====
        JLabel secondaryHeader = new JLabel("Individual Analysis Operations");
        secondaryHeader.setFont(secondaryHeader.getFont().deriveFont(Font.BOLD, 14f));
        secondaryHeader.setAlignmentX(Component.LEFT_ALIGNMENT);
        contentPanel.add(secondaryHeader);
        contentPanel.add(Box.createVerticalStrut(5));

        JLabel secondaryDesc = new JLabel("<html><i>Run these analyses independently after indexing.</i></html>");
        secondaryDesc.setAlignmentX(Component.LEFT_ALIGNMENT);
        contentPanel.add(secondaryDesc);
        contentPanel.add(Box.createVerticalStrut(10));

        // Security Analysis
        contentPanel.add(createAnalysisRow(
            securityAnalysisButton,
            "Taint Analysis",
            "Find paths from input sources (user input, network) to dangerous sinks " +
            "(strcpy, system, SQL). Creates TAINT_FLOWS_TO and VULNERABLE_VIA edges."
        ));
        contentPanel.add(Box.createVerticalStrut(8));

        // Network Flow Analysis
        contentPanel.add(createAnalysisRow(
            networkFlowButton,
            "Network API Tracing",
            "Trace data flow through network send/recv APIs (WSASend, recv, send). " +
            "Creates NETWORK_SEND and NETWORK_RECV edges from entry points."
        ));
        contentPanel.add(Box.createVerticalStrut(8));

        // Community Detection
        contentPanel.add(createAnalysisRow(
            communityDetectionButton,
            "Function Clustering",
            "Group related functions into communities using Label Propagation algorithm. " +
            "Helps identify modules and subsystems in the binary."
        ));
        contentPanel.add(Box.createVerticalStrut(8));

        // Refresh Names
        contentPanel.add(createAnalysisRow(
            refreshNamesButton,
            "Sync Names",
            "Update function names in the graph to match current Ghidra names. " +
            "Use after renaming functions in Ghidra."
        ));

        // Add glue to push content to top
        contentPanel.add(Box.createVerticalGlue());

        // Wrap in scroll pane
        JScrollPane scrollPane = new JScrollPane(contentPanel);
        scrollPane.setBorder(null);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);

        add(scrollPane, BorderLayout.CENTER);
    }

    /**
     * Create a row with a button and description panel.
     */
    private JPanel createAnalysisRow(JButton button, String title, String description) {
        JPanel row = new JPanel(new BorderLayout(10, 0));
        row.setAlignmentX(Component.LEFT_ALIGNMENT);
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, 70));

        // Button panel (fixed width)
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        button.setPreferredSize(new Dimension(BUTTON_WIDTH, BUTTON_HEIGHT));
        buttonPanel.add(button);
        buttonPanel.setPreferredSize(new Dimension(BUTTON_WIDTH + 10, 40));

        // Description panel
        JPanel descPanel = new JPanel();
        descPanel.setLayout(new BoxLayout(descPanel, BoxLayout.Y_AXIS));

        JLabel titleLabel = new JLabel(title);
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD));
        titleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel descLabel = new JLabel("<html><body style='width: 350px'>" + description + "</body></html>");
        descLabel.setForeground(Color.GRAY);
        descLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        descPanel.add(titleLabel);
        descPanel.add(descLabel);

        row.add(buttonPanel, BorderLayout.WEST);
        row.add(descPanel, BorderLayout.CENTER);

        return row;
    }

    private void setupListeners() {
        reindexButton.addActionListener(e -> parentTab.handleReindexFromManual());
        semanticAnalysisButton.addActionListener(e -> parentTab.handleSemanticAnalysisFromManual());
        securityAnalysisButton.addActionListener(e -> parentTab.handleSecurityAnalysisFromManual());
        networkFlowButton.addActionListener(e -> parentTab.handleNetworkFlowFromManual());
        communityDetectionButton.addActionListener(e -> parentTab.handleCommunityDetectionFromManual());
        refreshNamesButton.addActionListener(e -> parentTab.handleRefreshNamesFromManual());
    }

    // ===== Button State Management =====

    public void setReindexRunning(boolean running) {
        reindexButton.setText(running ? "Stop" : "ReIndex Binary");
    }

    public void setSemanticAnalysisRunning(boolean running) {
        semanticAnalysisButton.setText(running ? "Stop" : "Semantic Analysis");
    }

    public void setSecurityAnalysisRunning(boolean running) {
        securityAnalysisButton.setText(running ? "Stop" : "Security Analysis");
    }

    public void setNetworkFlowRunning(boolean running) {
        networkFlowButton.setText(running ? "Stop" : "Network Flow Analysis");
    }

    public void setCommunityDetectionRunning(boolean running) {
        communityDetectionButton.setText(running ? "Stop" : "Community Detection");
    }

    public void setRefreshNamesRunning(boolean running) {
        refreshNamesButton.setText(running ? "Stop" : "Refresh Names");
    }

    public boolean isReindexRunning() {
        return "Stop".equals(reindexButton.getText());
    }

    public boolean isSemanticAnalysisRunning() {
        return "Stop".equals(semanticAnalysisButton.getText());
    }

    public boolean isSecurityAnalysisRunning() {
        return "Stop".equals(securityAnalysisButton.getText());
    }

    public boolean isNetworkFlowRunning() {
        return "Stop".equals(networkFlowButton.getText());
    }

    public boolean isCommunityDetectionRunning() {
        return "Stop".equals(communityDetectionButton.getText());
    }

    public boolean isRefreshNamesRunning() {
        return "Stop".equals(refreshNamesButton.getText());
    }

    /**
     * Refresh the panel (placeholder for future use).
     */
    public void refresh() {
        // Nothing to refresh currently
    }
}
