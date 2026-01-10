package ghidrassist.ui.tabs.semanticgraph;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;
import java.util.ArrayList;

import ghidrassist.core.TabController;
import ghidrassist.ui.tabs.SemanticGraphTab;
import ghidrassist.graphrag.nodes.KnowledgeNode;
import ghidrassist.graphrag.BinaryKnowledgeGraph.GraphEdge;
import ghidrassist.graphrag.nodes.EdgeType;

/**
 * List/table view sub-panel for the Semantic Graph tab.
 * Displays callers, callees, edges, security flags, and LLM summary.
 */
public class ListViewPanel extends JPanel {
    private static final long serialVersionUID = 1L;

    private final TabController controller;
    private final SemanticGraphTab parentTab;

    // Left column - relationships
    private JList<FunctionEntry> callersList;
    private DefaultListModel<FunctionEntry> callersModel;
    private JList<FunctionEntry> calleesList;
    private DefaultListModel<FunctionEntry> calleesModel;
    private JTable edgesTable;
    private DefaultTableModel edgesTableModel;
    private JComboBox<String> edgeTypeFilter;

    // Right column - node details
    private JPanel securityFlagsPanel;
    private JTextArea summaryTextArea;
    private JButton editSummaryButton;
    private JButton addFlagButton;
    private boolean isEditingSummary = false;

    // Not-indexed placeholder
    private JPanel notIndexedPanel;
    private JPanel contentPanel;
    private CardLayout cardLayout;

    // Known security flags
    private static final String[] KNOWN_FLAGS = {
            "BUFFER_OVERFLOW_RISK",
            "COMMAND_INJECTION_RISK",
            "FORMAT_STRING_RISK",
            "USE_AFTER_FREE_RISK",
            "PATH_TRAVERSAL_RISK",
            "INTEGER_OVERFLOW_RISK",
            "NULL_DEREF_RISK",
            "MEMORY_LEAK_RISK",
            "RACE_CONDITION_RISK",
            "HANDLES_USER_INPUT",
            "PARSES_NETWORK_DATA",
            "CRYPTO_OPERATION",
            "AUTHENTICATION"
    };

    public ListViewPanel(TabController controller, SemanticGraphTab parentTab) {
        super(new BorderLayout());
        this.controller = controller;
        this.parentTab = parentTab;
        initializeComponents();
        layoutComponents();
        setupListeners();
    }

    private void initializeComponents() {
        // Callers list
        callersModel = new DefaultListModel<>();
        callersList = new JList<>(callersModel);
        callersList.setCellRenderer(new FunctionEntryCellRenderer());
        callersList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        // Callees list
        calleesModel = new DefaultListModel<>();
        calleesList = new JList<>(calleesModel);
        calleesList.setCellRenderer(new FunctionEntryCellRenderer());
        calleesList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        // Edges table
        String[] edgeColumns = {"Type", "Target", "Weight", "Actions"};
        edgesTableModel = new DefaultTableModel(edgeColumns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 3; // Only Actions column is "editable" (for button clicks)
            }
        };
        edgesTable = new JTable(edgesTableModel);
        edgesTable.getColumnModel().getColumn(0).setPreferredWidth(120);
        edgesTable.getColumnModel().getColumn(1).setPreferredWidth(150);
        edgesTable.getColumnModel().getColumn(2).setPreferredWidth(60);
        edgesTable.getColumnModel().getColumn(3).setPreferredWidth(100);

        // Edge type filter
        String[] filterOptions = {"All Types", "CALLS", "REFERENCES", "CALLS_VULNERABLE", "SIMILAR_PURPOSE",
                                  "TAINT_FLOWS_TO", "VULNERABLE_VIA", "NETWORK_SEND", "NETWORK_RECV"};
        edgeTypeFilter = new JComboBox<>(filterOptions);

        // Security flags panel (will be populated dynamically)
        securityFlagsPanel = new JPanel();
        securityFlagsPanel.setLayout(new BoxLayout(securityFlagsPanel, BoxLayout.Y_AXIS));

        // Summary text area
        summaryTextArea = new JTextArea();
        summaryTextArea.setLineWrap(true);
        summaryTextArea.setWrapStyleWord(true);
        summaryTextArea.setEditable(false);
        summaryTextArea.setFont(new Font("SansSerif", Font.PLAIN, 12));

        // Buttons
        editSummaryButton = new JButton("Edit");
        addFlagButton = new JButton("+ Add Custom Flag...");

        // Not indexed placeholder
        notIndexedPanel = createNotIndexedPanel();

        // Card layout to switch between content and placeholder
        cardLayout = new CardLayout();
        contentPanel = new JPanel(cardLayout);
    }

    private JPanel createNotIndexedPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.insets = new Insets(10, 10, 10, 10);

        JLabel messageLabel = new JLabel("<html><center>Function not yet indexed in<br>the knowledge graph.</center></html>");
        messageLabel.setHorizontalAlignment(SwingConstants.CENTER);
        panel.add(messageLabel, gbc);

        gbc.gridy = 1;
        JButton indexButton = new JButton("Index This Function");
        indexButton.addActionListener(e -> controller.handleSemanticGraphIndexFunction(parentTab.getCurrentAddress()));
        panel.add(indexButton, gbc);

        gbc.gridy = 2;
        JLabel orLabel = new JLabel("Or index the entire binary:");
        panel.add(orLabel, gbc);

        gbc.gridy = 3;
        JButton reindexButton = new JButton("ReIndex Binary");
        reindexButton.addActionListener(e -> controller.handleSemanticGraphReindex());
        panel.add(reindexButton, gbc);

        return panel;
    }

    private void layoutComponents() {
        // ===== Main content panel =====
        JPanel mainContent = new JPanel(new BorderLayout(5, 5));
        mainContent.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // Create split pane for left/right columns
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setResizeWeight(0.6); // Left panel gets 60%

        // ===== Left Column (Relationships) =====
        JPanel leftColumn = new JPanel();
        leftColumn.setLayout(new BoxLayout(leftColumn, BoxLayout.Y_AXIS));

        // Callers panel
        JPanel callersPanel = new JPanel(new BorderLayout());
        callersPanel.setBorder(BorderFactory.createTitledBorder("CALLERS"));
        callersPanel.add(new JScrollPane(callersList), BorderLayout.CENTER);
        callersPanel.setPreferredSize(new Dimension(300, 150));
        leftColumn.add(callersPanel);

        leftColumn.add(Box.createVerticalStrut(5));

        // Callees panel
        JPanel calleesPanel = new JPanel(new BorderLayout());
        calleesPanel.setBorder(BorderFactory.createTitledBorder("CALLEES"));
        calleesPanel.add(new JScrollPane(calleesList), BorderLayout.CENTER);
        calleesPanel.setPreferredSize(new Dimension(300, 150));
        leftColumn.add(calleesPanel);

        leftColumn.add(Box.createVerticalStrut(5));

        // Edges panel
        JPanel edgesPanel = new JPanel(new BorderLayout(5, 5));
        edgesPanel.setBorder(BorderFactory.createTitledBorder("EDGES"));

        JPanel filterRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        filterRow.add(new JLabel("Filter:"));
        filterRow.add(edgeTypeFilter);
        edgesPanel.add(filterRow, BorderLayout.NORTH);
        edgesPanel.add(new JScrollPane(edgesTable), BorderLayout.CENTER);

        leftColumn.add(edgesPanel);

        splitPane.setLeftComponent(new JScrollPane(leftColumn));

        // ===== Right Column (Node Details) =====
        JPanel rightColumn = new JPanel();
        rightColumn.setLayout(new BoxLayout(rightColumn, BoxLayout.Y_AXIS));

        // Security flags panel
        JPanel flagsWrapper = new JPanel(new BorderLayout());
        flagsWrapper.setBorder(BorderFactory.createTitledBorder("SECURITY FLAGS"));

        JScrollPane flagsScroll = new JScrollPane(securityFlagsPanel);
        flagsScroll.setPreferredSize(new Dimension(200, 200));
        flagsWrapper.add(flagsScroll, BorderLayout.CENTER);

        JPanel addFlagRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        addFlagRow.add(addFlagButton);
        flagsWrapper.add(addFlagRow, BorderLayout.SOUTH);

        rightColumn.add(flagsWrapper);

        rightColumn.add(Box.createVerticalStrut(5));

        // LLM Summary panel
        JPanel summaryPanel = new JPanel(new BorderLayout());
        summaryPanel.setBorder(BorderFactory.createTitledBorder("LLM SUMMARY"));

        JScrollPane summaryScroll = new JScrollPane(summaryTextArea);
        summaryScroll.setPreferredSize(new Dimension(200, 150));
        summaryPanel.add(summaryScroll, BorderLayout.CENTER);

        JPanel editRow = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        editRow.add(editSummaryButton);
        summaryPanel.add(editRow, BorderLayout.SOUTH);

        rightColumn.add(summaryPanel);

        splitPane.setRightComponent(rightColumn);

        mainContent.add(splitPane, BorderLayout.CENTER);

        // ===== Card layout setup =====
        contentPanel.add(mainContent, "content");
        contentPanel.add(notIndexedPanel, "notIndexed");

        add(contentPanel, BorderLayout.CENTER);

        // Default to not indexed
        cardLayout.show(contentPanel, "notIndexed");
    }

    private void setupListeners() {
        // Double-click on callers list to navigate
        callersList.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    FunctionEntry selected = callersList.getSelectedValue();
                    if (selected != null) {
                        parentTab.navigateToFunction(selected.address);
                    }
                }
            }
        });

        // Double-click on callees list to navigate
        calleesList.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    FunctionEntry selected = calleesList.getSelectedValue();
                    if (selected != null) {
                        parentTab.navigateToFunction(selected.address);
                    }
                }
            }
        });

        // Edge type filter
        edgeTypeFilter.addActionListener(e -> refreshEdgesTable());

        // Edit summary button
        editSummaryButton.addActionListener(e -> toggleSummaryEdit());

        // Add custom flag button
        addFlagButton.addActionListener(e -> showAddFlagDialog());

        // Edges table click handler
        edgesTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int row = edgesTable.rowAtPoint(e.getPoint());
                int col = edgesTable.columnAtPoint(e.getPoint());
                if (row >= 0 && col == 3) {
                    // Actions column clicked - could add View/Delete buttons here
                    handleEdgeAction(row);
                }
            }
        });
    }

    // ===== Public Methods =====

    /**
     * Refresh the panel with data for the current function.
     */
    public void refresh() {
        controller.handleSemanticGraphListViewRefresh(this, parentTab.getCurrentAddress());
    }

    /**
     * Show the "not indexed" placeholder.
     */
    public void showNotIndexed() {
        cardLayout.show(contentPanel, "notIndexed");
    }

    /**
     * Show the main content (when node is indexed).
     */
    public void showContent() {
        cardLayout.show(contentPanel, "content");
    }

    /**
     * Update the callers list.
     */
    public void setCallers(List<KnowledgeNode> callers) {
        callersModel.clear();
        for (KnowledgeNode node : callers) {
            boolean hasVuln = node.hasSecurityFlags();
            String summary = node.getLlmSummary();
            if (summary == null || summary.isEmpty()) {
                summary = "";
            } else if (summary.length() > 50) {
                summary = summary.substring(0, 47) + "...";
            }
            callersModel.addElement(new FunctionEntry(
                    node.getName(),
                    node.getAddress(),
                    summary,
                    hasVuln
            ));
        }
        updateCallersBorder(callers.size());
    }

    /**
     * Update the callees list.
     */
    public void setCallees(List<KnowledgeNode> callees) {
        calleesModel.clear();
        for (KnowledgeNode node : callees) {
            boolean hasVuln = node.hasSecurityFlags();
            String summary = node.getLlmSummary();
            if (summary == null || summary.isEmpty()) {
                summary = "";
            } else if (summary.length() > 50) {
                summary = summary.substring(0, 47) + "...";
            }
            calleesModel.addElement(new FunctionEntry(
                    node.getName(),
                    node.getAddress(),
                    summary,
                    hasVuln
            ));
        }
        updateCalleesBorder(callees.size());
    }

    /**
     * Update the edges table.
     */
    public void setEdges(List<GraphEdge> edges) {
        // Store all edges for filtering
        this.allEdges = edges;
        refreshEdgesTable();
    }

    private List<GraphEdge> allEdges = new ArrayList<>();

    private void refreshEdgesTable() {
        edgesTableModel.setRowCount(0);
        String filter = (String) edgeTypeFilter.getSelectedItem();

        for (GraphEdge edge : allEdges) {
            if (filter.equals("All Types") || edge.getType().name().equals(filter)) {
                edgesTableModel.addRow(new Object[]{
                        edge.getType().getDisplayName(),
                        edge.getTargetId(), // Should be resolved to name
                        String.format("%.2f", edge.getWeight()),
                        "[View]"
                });
            }
        }

        updateEdgesBorder(edgesTableModel.getRowCount());
    }

    /**
     * Update security flags panel.
     */
    public void setSecurityFlags(List<String> flags) {
        securityFlagsPanel.removeAll();

        for (String knownFlag : KNOWN_FLAGS) {
            JCheckBox checkbox = new JCheckBox(knownFlag);
            checkbox.setSelected(flags.contains(knownFlag));
            checkbox.addActionListener(e -> handleFlagChange(knownFlag, checkbox.isSelected()));
            securityFlagsPanel.add(checkbox);
        }

        // Add any custom flags not in the known list
        for (String flag : flags) {
            boolean isKnown = false;
            for (String known : KNOWN_FLAGS) {
                if (known.equals(flag)) {
                    isKnown = true;
                    break;
                }
            }
            if (!isKnown) {
                JCheckBox checkbox = new JCheckBox(flag);
                checkbox.setSelected(true);
                checkbox.addActionListener(e -> handleFlagChange(flag, checkbox.isSelected()));
                securityFlagsPanel.add(checkbox);
            }
        }

        securityFlagsPanel.revalidate();
        securityFlagsPanel.repaint();
    }

    /**
     * Update LLM summary.
     */
    public void setSummary(String summary) {
        summaryTextArea.setText(summary != null ? summary : "");
        summaryTextArea.setCaretPosition(0);
    }

    // ===== Private Helper Methods =====

    private void updateCallersBorder(int count) {
        JPanel panel = (JPanel) callersList.getParent().getParent().getParent();
        panel.setBorder(BorderFactory.createTitledBorder("CALLERS (" + count + ")"));
    }

    private void updateCalleesBorder(int count) {
        JPanel panel = (JPanel) calleesList.getParent().getParent().getParent();
        panel.setBorder(BorderFactory.createTitledBorder("CALLEES (" + count + ")"));
    }

    private void updateEdgesBorder(int count) {
        JPanel panel = (JPanel) edgesTable.getParent().getParent().getParent();
        panel.setBorder(BorderFactory.createTitledBorder("EDGES (" + count + ")"));
    }

    private void toggleSummaryEdit() {
        if (isEditingSummary) {
            // Save changes
            String newSummary = summaryTextArea.getText();
            controller.handleSemanticGraphSaveSummary(parentTab.getCurrentAddress(), newSummary);
            summaryTextArea.setEditable(false);
            editSummaryButton.setText("Edit");
            isEditingSummary = false;
        } else {
            // Enter edit mode
            summaryTextArea.setEditable(true);
            editSummaryButton.setText("Save");
            isEditingSummary = true;
        }
    }

    private void showAddFlagDialog() {
        String flag = JOptionPane.showInputDialog(this,
                "Enter custom security flag:",
                "Add Security Flag",
                JOptionPane.PLAIN_MESSAGE);

        if (flag != null && !flag.trim().isEmpty()) {
            flag = flag.trim().toUpperCase().replace(" ", "_");
            controller.handleSemanticGraphAddFlag(parentTab.getCurrentAddress(), flag);
            refresh(); // Refresh to show new flag
        }
    }

    private void handleFlagChange(String flag, boolean selected) {
        if (selected) {
            controller.handleSemanticGraphAddFlag(parentTab.getCurrentAddress(), flag);
        } else {
            controller.handleSemanticGraphRemoveFlag(parentTab.getCurrentAddress(), flag);
        }
    }

    private void handleEdgeAction(int row) {
        // For now, just navigate to the target
        String targetId = (String) edgesTableModel.getValueAt(row, 1);
        // The targetId should be resolved to an address - controller will handle this
        controller.handleSemanticGraphEdgeClick(targetId);
    }

    // ===== Inner Classes =====

    /**
     * Entry for function lists (callers/callees).
     */
    static class FunctionEntry {
        final String name;
        final long address;
        final String summary;
        final boolean hasVulnerability;

        FunctionEntry(String name, long address, String summary, boolean hasVulnerability) {
            this.name = name;
            this.address = address;
            this.summary = summary;
            this.hasVulnerability = hasVulnerability;
        }

        @Override
        public String toString() {
            return name;
        }
    }

    /**
     * Cell renderer for function entries showing name, address, and vulnerability badge.
     */
    static class FunctionEntryCellRenderer extends DefaultListCellRenderer {
        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value,
                int index, boolean isSelected, boolean cellHasFocus) {

            JPanel panel = new JPanel(new BorderLayout(5, 2));
            panel.setOpaque(true);

            if (isSelected) {
                panel.setBackground(list.getSelectionBackground());
                panel.setForeground(list.getSelectionForeground());
            } else {
                panel.setBackground(list.getBackground());
                panel.setForeground(list.getForeground());
            }

            if (value instanceof FunctionEntry) {
                FunctionEntry entry = (FunctionEntry) value;

                // Top row: name and address
                JPanel topRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 0));
                topRow.setOpaque(false);

                JLabel nameLabel = new JLabel(entry.name);
                nameLabel.setFont(nameLabel.getFont().deriveFont(Font.BOLD));
                topRow.add(nameLabel);

                JLabel addrLabel = new JLabel("@ 0x" + Long.toHexString(entry.address));
                addrLabel.setForeground(Color.GRAY);
                topRow.add(addrLabel);

                if (entry.hasVulnerability) {
                    JLabel vulnLabel = new JLabel("[VULN]");
                    vulnLabel.setForeground(Color.RED);
                    vulnLabel.setFont(vulnLabel.getFont().deriveFont(Font.BOLD));
                    topRow.add(vulnLabel);
                }

                panel.add(topRow, BorderLayout.NORTH);

                // Bottom row: summary (if present)
                if (entry.summary != null && !entry.summary.isEmpty()) {
                    JLabel summaryLabel = new JLabel("  " + entry.summary);
                    summaryLabel.setForeground(Color.DARK_GRAY);
                    summaryLabel.setFont(summaryLabel.getFont().deriveFont(Font.ITALIC, 11f));
                    panel.add(summaryLabel, BorderLayout.SOUTH);
                }
            }

            panel.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 5));
            return panel;
        }
    }
}
