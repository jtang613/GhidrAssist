package ghidrassist.ui.tabs;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;
import java.awt.*;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

import ghidrassist.core.TabController;
import ghidrassist.services.symgraph.SymGraphModels.*;

/**
 * Tab for SymGraph integration - query, push, and pull symbols/graph data.
 */
public class SymGraphTab extends JPanel {
    private static final long serialVersionUID = 1L;
    private final TabController controller;

    // Binary info section
    private JLabel binaryNameLabel;
    private JLabel sha256Label;

    // Query section
    private JButton queryButton;
    private JLabel statusLabel;
    private JPanel statsPanel;
    private JLabel symbolsStatLabel;
    private JLabel functionsStatLabel;
    private JLabel nodesStatLabel;
    private JLabel updatedStatLabel;

    // Push section
    private JRadioButton fullBinaryRadio;
    private JRadioButton currentFunctionRadio;
    private JCheckBox pushSymbolsCheck;
    private JCheckBox pushGraphCheck;
    private JButton pushButton;
    private JLabel pushStatusLabel;
    private JProgressBar pushProgressBar;
    private JButton cancelPushButton;

    // Pull section
    private JButton pullPreviewButton;
    private JTable conflictTable;
    private DefaultTableModel conflictTableModel;
    private JButton selectAllButton;
    private JButton deselectAllButton;
    private JButton invertSelectionButton;
    private JButton applyButton;
    private JButton cancelButton;
    private JLabel pullStatusLabel;

    // Pull configuration
    private JCheckBox pullFunctionsCheck;
    private JCheckBox pullVariablesCheck;
    private JCheckBox pullTypesCheck;
    private JCheckBox pullCommentsCheck;
    private JCheckBox pullGraphCheck;
    private JSlider confidenceSlider;
    private JLabel confidenceValueLabel;

    // Wizard components
    private static final String PAGE_INITIAL = "initial";
    private static final String PAGE_SUMMARY = "summary";
    private static final String PAGE_DETAILS = "details";
    private static final String PAGE_APPLYING = "applying";
    private static final String PAGE_COMPLETE = "complete";

    private static final String MERGE_POLICY_UPSERT = "upsert";
    private static final String MERGE_POLICY_PREFER_LOCAL = "prefer_local";
    private static final String MERGE_POLICY_REPLACE = "replace";

    private CardLayout wizardLayout;
    private JPanel wizardPanel;

    // Summary page
    private JLabel summaryNewCount;
    private JLabel summaryConflictCount;
    private JLabel summarySameCount;
    private JLabel summaryGraphLabel;
    private JLabel summaryGraphNodesLabel;
    private JLabel summaryGraphEdgesLabel;
    private JLabel summaryGraphCommunitiesLabel;
    private ButtonGroup summaryMergeGroup;
    private JButton applyAllNewButton;
    private JButton reviewConflictsButton;
    private JButton showAllButton;
    private JButton summaryBackButton;

    // Details page
    private JTabbedPane detailsTabs;
    private JLabel detailsGraphLabel;
    private JLabel detailsGraphNodesLabel;
    private JLabel detailsGraphEdgesLabel;
    private JLabel detailsGraphCommunitiesLabel;
    private JLabel detailsGraphPolicyLabel;
    private ButtonGroup detailsMergeGroup;
    private JButton backToSummaryButton;

    // Applying page
    private JProgressBar applyProgressBar;
    private JLabel applyProgressLabel;
    private JButton applyCancelButton;

    // Complete page
    private JLabel completeIcon;
    private JLabel completeMessage;
    private JButton doneButton;

    // Stored conflict data
    private List<ConflictEntry> currentConflicts = new ArrayList<>();
    private List<ConflictEntry> displayedConflicts = new ArrayList<>();

    private GraphExport graphPreviewData;
    private int graphPreviewNodes;
    private int graphPreviewEdges;
    private int graphPreviewCommunities;
    private String graphMergePolicy = MERGE_POLICY_UPSERT;

    // Push cancellation callback
    private Runnable pushCancelCallback;

    public SymGraphTab(TabController controller) {
        super(new BorderLayout());
        this.controller = controller;
        initializeComponents();
        layoutComponents();
        setupListeners();
    }

    private void initializeComponents() {
        // Binary info
        binaryNameLabel = new JLabel("<no binary loaded>");
        binaryNameLabel.setFont(binaryNameLabel.getFont().deriveFont(Font.BOLD));
        sha256Label = new JLabel("<none>");
        sha256Label.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));

        // Query section
        queryButton = new JButton("Check SymGraph");
        statusLabel = new JLabel("Not checked");
        statusLabel.setForeground(Color.GRAY);

        symbolsStatLabel = new JLabel("Symbols: -");
        functionsStatLabel = new JLabel("Functions: -");
        nodesStatLabel = new JLabel("Graph Nodes: -");
        updatedStatLabel = new JLabel("Last Updated: -");

        statsPanel = new JPanel(new GridLayout(2, 2, 10, 5));
        statsPanel.add(symbolsStatLabel);
        statsPanel.add(functionsStatLabel);
        statsPanel.add(nodesStatLabel);
        statsPanel.add(updatedStatLabel);
        statsPanel.setVisible(false);

        // Push section
        fullBinaryRadio = new JRadioButton("Full Binary");
        currentFunctionRadio = new JRadioButton("Current Function", true);
        ButtonGroup scopeGroup = new ButtonGroup();
        scopeGroup.add(fullBinaryRadio);
        scopeGroup.add(currentFunctionRadio);

        pushSymbolsCheck = new JCheckBox("Symbols (function names, variables, types)", true);
        pushGraphCheck = new JCheckBox("Graph (nodes, edges, summaries)", true);

        pushButton = new JButton("Push to SymGraph");
        pushStatusLabel = new JLabel("Status: Ready");
        pushStatusLabel.setForeground(Color.GRAY);

        pushProgressBar = new JProgressBar(0, 100);
        pushProgressBar.setStringPainted(true);
        pushProgressBar.setVisible(false);

        cancelPushButton = new JButton("Cancel");
        cancelPushButton.setVisible(false);

        // Pull section
        pullPreviewButton = new JButton("Pull & Preview");

        // Pull configuration - Symbol type checkboxes
        pullFunctionsCheck = new JCheckBox("Functions", true);
        pullVariablesCheck = new JCheckBox("Variables", true);
        pullTypesCheck = new JCheckBox("Types", true);
        pullCommentsCheck = new JCheckBox("Comments", true);
        pullGraphCheck = new JCheckBox("Include Graph Data", true);
        pullGraphCheck.setToolTipText("Download graph nodes and edges for semantic analysis");

        // Confidence slider (0-100, displayed as 0.0-1.0)
        confidenceSlider = new JSlider(JSlider.HORIZONTAL, 0, 100, 0);
        confidenceSlider.setPreferredSize(new Dimension(100, 20));
        confidenceSlider.setToolTipText("Only show symbols with confidence >= this threshold");
        confidenceValueLabel = new JLabel("0.0");

        confidenceSlider.addChangeListener(e -> {
            double value = confidenceSlider.getValue() / 100.0;
            confidenceValueLabel.setText(String.format("%.1f", value));
        });

        conflictTableModel = new DefaultTableModel(
                new Object[]{"Select", "Address", "Type/Storage", "Local Name", "Remote Name", "Action"}, 0) {
            private static final long serialVersionUID = 1L;

            @Override
            public Class<?> getColumnClass(int column) {
                return column == 0 ? Boolean.class : String.class;
            }

            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 0; // Only checkbox is editable
            }
        };
        conflictTable = new JTable(conflictTableModel);
        conflictTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        conflictTable.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        conflictTable.setFillsViewportHeight(true);

        // Set column widths - Select narrow, Type/Storage, Action narrow, others flexible
        conflictTable.getColumnModel().getColumn(0).setMinWidth(50);
        conflictTable.getColumnModel().getColumn(0).setMaxWidth(60);
        conflictTable.getColumnModel().getColumn(0).setPreferredWidth(50);

        conflictTable.getColumnModel().getColumn(1).setMinWidth(80);
        conflictTable.getColumnModel().getColumn(1).setPreferredWidth(100);

        conflictTable.getColumnModel().getColumn(2).setMinWidth(90);
        conflictTable.getColumnModel().getColumn(2).setPreferredWidth(120);

        conflictTable.getColumnModel().getColumn(3).setMinWidth(100);
        conflictTable.getColumnModel().getColumn(3).setPreferredWidth(150);

        conflictTable.getColumnModel().getColumn(4).setMinWidth(100);
        conflictTable.getColumnModel().getColumn(4).setPreferredWidth(150);

        conflictTable.getColumnModel().getColumn(5).setMinWidth(70);
        conflictTable.getColumnModel().getColumn(5).setMaxWidth(90);
        conflictTable.getColumnModel().getColumn(5).setPreferredWidth(80);

        // Custom renderer for action column (color-coded)
        conflictTable.getColumnModel().getColumn(5).setCellRenderer(new ActionCellRenderer());

        selectAllButton = new JButton("Select All");
        deselectAllButton = new JButton("Deselect All");
        invertSelectionButton = new JButton("Invert Selection");
        applyButton = new JButton("Apply Selected");
        cancelButton = new JButton("Cancel");
        pullStatusLabel = new JLabel("");
    }

    private void layoutComponents() {
        // Main container with padding
        JPanel mainPanel = new JPanel(new BorderLayout(5, 5));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // Binary Info Section at top
        JPanel binaryInfoPanel = createBinaryInfoPanel();
        mainPanel.add(binaryInfoPanel, BorderLayout.NORTH);

        // Create split pane for query/push and pull sections
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setResizeWeight(0.35);
        splitPane.setContinuousLayout(true);

        // Top panel: Query + Push stacked vertically, full width
        JPanel topPanel = new JPanel(new BorderLayout(5, 5));

        JPanel queryPushPanel = new JPanel();
        queryPushPanel.setLayout(new BoxLayout(queryPushPanel, BoxLayout.Y_AXIS));

        JPanel querySection = createQuerySection();
        querySection.setAlignmentX(Component.LEFT_ALIGNMENT);
        queryPushPanel.add(querySection);
        queryPushPanel.add(Box.createVerticalStrut(5));

        JPanel pushSection = createPushSection();
        pushSection.setAlignmentX(Component.LEFT_ALIGNMENT);
        queryPushPanel.add(pushSection);

        topPanel.add(queryPushPanel, BorderLayout.CENTER);
        splitPane.setTopComponent(topPanel);

        // Bottom panel: Pull
        splitPane.setBottomComponent(createPullSection());

        mainPanel.add(splitPane, BorderLayout.CENTER);

        add(mainPanel, BorderLayout.CENTER);
        syncMergePolicySelections();
        updateGraphLabels();
    }

    private JPanel createBinaryInfoPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder("Binary Information"),
                BorderFactory.createEmptyBorder(5, 5, 5, 5)));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(2, 5, 2, 5);

        // Binary name row
        gbc.gridx = 0; gbc.gridy = 0;
        panel.add(new JLabel("Binary:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0; gbc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(binaryNameLabel, gbc);

        // SHA256 row
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0; gbc.fill = GridBagConstraints.NONE;
        panel.add(new JLabel("SHA256:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0; gbc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(sha256Label, gbc);

        return panel;
    }

    private JPanel createQuerySection() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder("Query Status"),
                BorderFactory.createEmptyBorder(5, 5, 5, 5)));

        // Button row
        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        buttonRow.add(queryButton);

        // Status row
        JPanel statusRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        statusRow.add(new JLabel("Status:"));
        statusRow.add(statusLabel);

        JPanel topPanel = new JPanel();
        topPanel.setLayout(new BoxLayout(topPanel, BoxLayout.Y_AXIS));
        topPanel.add(buttonRow);
        topPanel.add(statusRow);

        panel.add(topPanel, BorderLayout.NORTH);
        panel.add(statsPanel, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createPushSection() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder("Push to SymGraph"),
                BorderFactory.createEmptyBorder(5, 5, 5, 5)));

        JPanel contentPanel = new JPanel();
        contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.Y_AXIS));

        // Scope row
        JPanel scopeRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        scopeRow.add(new JLabel("Scope:"));
        scopeRow.add(fullBinaryRadio);
        scopeRow.add(currentFunctionRadio);
        contentPanel.add(scopeRow);

        // Data checkboxes row
        JPanel dataRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        dataRow.add(new JLabel("Data to Push:"));
        dataRow.add(pushSymbolsCheck);
        dataRow.add(pushGraphCheck);
        contentPanel.add(dataRow);

        // Button and status row
        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        buttonRow.add(pushButton);
        buttonRow.add(cancelPushButton);
        buttonRow.add(pushStatusLabel);
        contentPanel.add(buttonRow);

        // Progress bar row
        JPanel progressRow = new JPanel(new BorderLayout(5, 0));
        progressRow.add(pushProgressBar, BorderLayout.CENTER);
        contentPanel.add(progressRow);

        panel.add(contentPanel, BorderLayout.CENTER);
        return panel;
    }

    private JPanel createPullSection() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder("Pull from SymGraph"),
                BorderFactory.createEmptyBorder(5, 5, 5, 5)));

        // Config panel at top (always visible, like BinAssist)
        JPanel configPanel = new JPanel();
        configPanel.setLayout(new BoxLayout(configPanel, BoxLayout.Y_AXIS));

        // Symbol Types label on its own row
        JPanel typeLabelRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        typeLabelRow.add(new JLabel("Symbol Types:"));
        configPanel.add(typeLabelRow);

        // Checkboxes on next row
        JPanel typeCheckRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        typeCheckRow.add(pullFunctionsCheck);
        typeCheckRow.add(pullVariablesCheck);
        typeCheckRow.add(pullTypesCheck);
        typeCheckRow.add(pullCommentsCheck);
        configPanel.add(typeCheckRow);

        // Options row: Graph checkbox and confidence slider
        JPanel optionsRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        optionsRow.add(pullGraphCheck);
        optionsRow.add(Box.createHorizontalStrut(15));
        optionsRow.add(new JLabel("Min Confidence:"));
        optionsRow.add(confidenceSlider);
        optionsRow.add(confidenceValueLabel);
        configPanel.add(optionsRow);

        // Button row
        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        buttonRow.add(pullPreviewButton);
        configPanel.add(buttonRow);

        panel.add(configPanel, BorderLayout.NORTH);

        // Create wizard panel with CardLayout (below config)
        wizardLayout = new CardLayout();
        wizardPanel = new JPanel(wizardLayout);

        // Create and add wizard pages (no initial page needed - config is always visible)
        wizardPanel.add(createEmptyPage(), PAGE_INITIAL);
        wizardPanel.add(createSummaryPage(), PAGE_SUMMARY);
        wizardPanel.add(createDetailsPage(), PAGE_DETAILS);
        wizardPanel.add(createApplyingPage(), PAGE_APPLYING);
        wizardPanel.add(createCompletePage(), PAGE_COMPLETE);

        panel.add(wizardPanel, BorderLayout.CENTER);
        return panel;
    }

    private JPanel createEmptyPage() {
        // Empty placeholder for initial state (config is shown above)
        JPanel page = new JPanel(new BorderLayout());
        JLabel infoLabel = new JLabel("<html><i>Configure options above and click 'Pull & Preview' to fetch symbols from SymGraph.</i></html>");
        infoLabel.setForeground(Color.GRAY);
        JPanel infoPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        infoPanel.add(infoLabel);
        page.add(infoPanel, BorderLayout.NORTH);
        return page;
    }

    private JPanel createSummaryPage() {
        JPanel page = new JPanel(new BorderLayout(10, 10));
        page.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Title
        JLabel titleLabel = new JLabel("Preview Summary");
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 14f));
        page.add(titleLabel, BorderLayout.NORTH);

        // Summary cards panel
        JPanel cardsPanel = new JPanel(new GridLayout(1, 3, 15, 0));

        // NEW card (green)
        JPanel newCard = createSummaryCard("NEW", new Color(0, 128, 0), new Color(230, 255, 230));
        summaryNewCount = (JLabel) ((JPanel) newCard.getComponent(0)).getComponent(0);
        JLabel newSubLabel = new JLabel("(safe)");
        newSubLabel.setForeground(Color.GRAY);
        newSubLabel.setFont(newSubLabel.getFont().deriveFont(10f));
        JPanel newSubPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 0, 0));
        newSubPanel.setOpaque(false);
        newSubPanel.add(newSubLabel);
        newCard.add(newSubPanel);
        cardsPanel.add(newCard);

        // CONFLICTS card (orange)
        JPanel conflictCard = createSummaryCard("CONFLICTS", new Color(255, 140, 0), new Color(255, 245, 230));
        summaryConflictCount = (JLabel) ((JPanel) conflictCard.getComponent(0)).getComponent(0);
        JLabel conflictSubLabel = new JLabel("(review)");
        conflictSubLabel.setForeground(Color.GRAY);
        conflictSubLabel.setFont(conflictSubLabel.getFont().deriveFont(10f));
        JPanel conflictSubPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 0, 0));
        conflictSubPanel.setOpaque(false);
        conflictSubPanel.add(conflictSubLabel);
        conflictCard.add(conflictSubPanel);
        cardsPanel.add(conflictCard);

        // UNCHANGED card (gray)
        JPanel sameCard = createSummaryCard("UNCHANGED", Color.GRAY, new Color(245, 245, 245));
        summarySameCount = (JLabel) ((JPanel) sameCard.getComponent(0)).getComponent(0);
        JLabel sameSubLabel = new JLabel("(skip)");
        sameSubLabel.setForeground(Color.GRAY);
        sameSubLabel.setFont(sameSubLabel.getFont().deriveFont(10f));
        JPanel sameSubPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 0, 0));
        sameSubPanel.setOpaque(false);
        sameSubPanel.add(sameSubLabel);
        sameCard.add(sameSubPanel);
        cardsPanel.add(sameCard);

        JPanel centerPanel = new JPanel(new BorderLayout(5, 15));
        centerPanel.add(cardsPanel, BorderLayout.NORTH);

        // Graph info panel
        summaryGraphLabel = new JLabel("No graph data selected");
        summaryGraphLabel.setForeground(Color.GRAY);

        summaryGraphNodesLabel = new JLabel("Nodes: 0");
        summaryGraphEdgesLabel = new JLabel("Edges: 0");
        summaryGraphCommunitiesLabel = new JLabel("Communities: 0");

        JPanel graphStatsRow = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 0));
        graphStatsRow.add(summaryGraphNodesLabel);
        graphStatsRow.add(summaryGraphEdgesLabel);
        graphStatsRow.add(summaryGraphCommunitiesLabel);

        summaryMergeGroup = new ButtonGroup();
        JPanel mergePanel = createMergePolicyPanel(summaryMergeGroup);

        JPanel graphPanel = new JPanel();
        graphPanel.setLayout(new BoxLayout(graphPanel, BoxLayout.Y_AXIS));
        graphPanel.add(summaryGraphLabel);
        graphPanel.add(graphStatsRow);
        graphPanel.add(mergePanel);
        centerPanel.add(graphPanel, BorderLayout.CENTER);

        page.add(centerPanel, BorderLayout.CENTER);

        // Button panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 5));

        applyAllNewButton = new JButton("Apply All New");
        applyAllNewButton.setToolTipText("Apply all NEW symbols without reviewing conflicts");

        reviewConflictsButton = new JButton("Review Conflicts");
        reviewConflictsButton.setToolTipText("Show only conflicting symbols for review");

        showAllButton = new JButton("Show All Details");
        showAllButton.setToolTipText("Show full details table with all symbols");

        summaryBackButton = new JButton("Back");
        summaryBackButton.setToolTipText("Return to configuration");

        buttonPanel.add(applyAllNewButton);
        buttonPanel.add(reviewConflictsButton);
        buttonPanel.add(showAllButton);
        buttonPanel.add(summaryBackButton);

        page.add(buttonPanel, BorderLayout.SOUTH);

        return page;
    }

    private JPanel createSummaryCard(String title, Color titleColor, Color bgColor) {
        JPanel card = new JPanel();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(titleColor, 2),
                BorderFactory.createEmptyBorder(15, 20, 15, 20)));
        card.setBackground(bgColor);

        // Count label (large) - centered in its own panel
        JLabel countLabel = new JLabel("0", SwingConstants.CENTER);
        countLabel.setFont(countLabel.getFont().deriveFont(Font.BOLD, 28f));
        countLabel.setForeground(titleColor);
        countLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        countLabel.setHorizontalAlignment(SwingConstants.CENTER);

        JPanel countPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 0, 0));
        countPanel.setOpaque(false);
        countPanel.add(countLabel);

        // Title label - centered
        JLabel titleLabel = new JLabel(title, SwingConstants.CENTER);
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 12f));
        titleLabel.setForeground(titleColor);
        titleLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        titleLabel.setHorizontalAlignment(SwingConstants.CENTER);

        JPanel titlePanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 0, 0));
        titlePanel.setOpaque(false);
        titlePanel.add(titleLabel);

        card.add(countPanel);
        card.add(Box.createVerticalStrut(5));
        card.add(titlePanel);

        return card;
    }

    private JPanel createMergePolicyPanel(ButtonGroup group) {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

        JLabel label = new JLabel("Graph Merge Policy:");
        label.setFont(label.getFont().deriveFont(Font.BOLD));
        panel.add(label);

        JRadioButton upsert = new JRadioButton("Upsert (merge and overwrite)");
        upsert.setActionCommand(MERGE_POLICY_UPSERT);
        JRadioButton preferLocal = new JRadioButton("Prefer Local (skip existing)");
        preferLocal.setActionCommand(MERGE_POLICY_PREFER_LOCAL);
        JRadioButton replace = new JRadioButton("Replace (clear graph tables)");
        replace.setActionCommand(MERGE_POLICY_REPLACE);

        group.add(upsert);
        group.add(preferLocal);
        group.add(replace);

        ActionListener listener = e -> setGraphMergePolicy(e.getActionCommand());
        upsert.addActionListener(listener);
        preferLocal.addActionListener(listener);
        replace.addActionListener(listener);

        upsert.setSelected(true);

        panel.add(upsert);
        panel.add(preferLocal);
        panel.add(replace);

        return panel;
    }

    private void setGraphMergePolicy(String policy) {
        if (policy == null) {
            return;
        }
        graphMergePolicy = policy;
        syncMergePolicySelections();
        updateGraphLabels();
    }

    private void syncMergePolicySelections() {
        syncMergePolicyGroup(summaryMergeGroup);
        syncMergePolicyGroup(detailsMergeGroup);
    }

    private void syncMergePolicyGroup(ButtonGroup group) {
        if (group == null) {
            return;
        }
        for (java.util.Enumeration<AbstractButton> e = group.getElements(); e.hasMoreElements();) {
            AbstractButton button = e.nextElement();
            if (graphMergePolicy.equals(button.getActionCommand())) {
                button.setSelected(true);
            }
        }
    }

    private String getMergePolicyLabel() {
        switch (graphMergePolicy) {
            case MERGE_POLICY_PREFER_LOCAL:
                return "Prefer Local";
            case MERGE_POLICY_REPLACE:
                return "Replace";
            default:
                return "Upsert";
        }
    }

    private JPanel createDetailsPage() {
        JPanel page = new JPanel(new BorderLayout(5, 5));

        JPanel titleRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        JLabel titleLabel = new JLabel("Details");
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 14f));
        titleRow.add(titleLabel);
        page.add(titleRow, BorderLayout.NORTH);

        detailsTabs = new JTabbedPane();

        // Symbols tab
        JPanel symbolsTab = new JPanel(new BorderLayout(5, 5));
        JScrollPane tableScrollPane = new JScrollPane(conflictTable);
        tableScrollPane.setMinimumSize(new Dimension(500, 150));
        tableScrollPane.setPreferredSize(new Dimension(600, 200));
        symbolsTab.add(tableScrollPane, BorderLayout.CENTER);

        JPanel selectionRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        selectionRow.add(selectAllButton);
        selectionRow.add(deselectAllButton);
        selectionRow.add(invertSelectionButton);
        symbolsTab.add(selectionRow, BorderLayout.SOUTH);

        // Graph tab
        JPanel graphTab = new JPanel();
        graphTab.setLayout(new BoxLayout(graphTab, BoxLayout.Y_AXIS));
        detailsGraphLabel = new JLabel("No graph data available");
        detailsGraphLabel.setForeground(Color.GRAY);
        detailsGraphNodesLabel = new JLabel("Nodes: 0");
        detailsGraphEdgesLabel = new JLabel("Edges: 0");
        detailsGraphCommunitiesLabel = new JLabel("Communities: 0");
        detailsGraphPolicyLabel = new JLabel("Selected policy: Upsert");
        detailsGraphPolicyLabel.setForeground(Color.DARK_GRAY);

        JPanel graphStatsRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        graphStatsRow.add(detailsGraphNodesLabel);
        graphStatsRow.add(detailsGraphEdgesLabel);
        graphStatsRow.add(detailsGraphCommunitiesLabel);

        detailsMergeGroup = new ButtonGroup();
        JPanel mergePanel = createMergePolicyPanel(detailsMergeGroup);

        graphTab.add(detailsGraphLabel);
        graphTab.add(Box.createVerticalStrut(5));
        graphTab.add(graphStatsRow);
        graphTab.add(Box.createVerticalStrut(10));
        graphTab.add(detailsGraphPolicyLabel);
        graphTab.add(Box.createVerticalStrut(5));
        graphTab.add(mergePanel);
        graphTab.add(Box.createVerticalGlue());

        detailsTabs.addTab("Symbols", symbolsTab);
        detailsTabs.addTab("Graph", graphTab);

        page.add(detailsTabs, BorderLayout.CENTER);

        // Bottom buttons (including Back to Summary)
        JPanel bottomPanel = new JPanel();
        bottomPanel.setLayout(new BoxLayout(bottomPanel, BoxLayout.Y_AXIS));

        JPanel actionRow = new JPanel(new BorderLayout(5, 0));
        JPanel leftButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        leftButtons.add(applyButton);
        actionRow.add(leftButtons, BorderLayout.WEST);

        backToSummaryButton = new JButton("Back to Summary");
        JPanel rightButtons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
        rightButtons.add(backToSummaryButton);
        actionRow.add(rightButtons, BorderLayout.EAST);

        JPanel statusRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        statusRow.add(pullStatusLabel);

        bottomPanel.add(actionRow);
        bottomPanel.add(statusRow);

        page.add(bottomPanel, BorderLayout.SOUTH);
        return page;
    }

    private JPanel createApplyingPage() {
        JPanel page = new JPanel(new BorderLayout(10, 10));
        page.setBorder(BorderFactory.createEmptyBorder(30, 30, 30, 30));

        JPanel centerPanel = new JPanel();
        centerPanel.setLayout(new BoxLayout(centerPanel, BoxLayout.Y_AXIS));

        // Title
        JLabel titleLabel = new JLabel("Applying Changes");
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 16f));
        titleLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        centerPanel.add(titleLabel);
        centerPanel.add(Box.createVerticalStrut(20));

        // Progress bar
        applyProgressBar = new JProgressBar(0, 100);
        applyProgressBar.setStringPainted(true);
        applyProgressBar.setPreferredSize(new Dimension(400, 25));
        applyProgressBar.setMaximumSize(new Dimension(400, 25));
        applyProgressBar.setAlignmentX(Component.CENTER_ALIGNMENT);
        centerPanel.add(applyProgressBar);
        centerPanel.add(Box.createVerticalStrut(10));

        // Progress label
        applyProgressLabel = new JLabel("Starting...");
        applyProgressLabel.setForeground(Color.GRAY);
        applyProgressLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        centerPanel.add(applyProgressLabel);
        centerPanel.add(Box.createVerticalStrut(20));

        // Cancel button
        applyCancelButton = new JButton("Cancel");
        applyCancelButton.setAlignmentX(Component.CENTER_ALIGNMENT);
        centerPanel.add(applyCancelButton);

        page.add(centerPanel, BorderLayout.CENTER);
        return page;
    }

    private JPanel createCompletePage() {
        JPanel page = new JPanel(new BorderLayout(10, 10));
        page.setBorder(BorderFactory.createEmptyBorder(30, 30, 30, 30));

        JPanel centerPanel = new JPanel();
        centerPanel.setLayout(new BoxLayout(centerPanel, BoxLayout.Y_AXIS));

        // Success icon (checkmark)
        completeIcon = new JLabel("✓");
        completeIcon.setFont(completeIcon.getFont().deriveFont(Font.BOLD, 48f));
        completeIcon.setForeground(new Color(0, 128, 0));
        completeIcon.setAlignmentX(Component.CENTER_ALIGNMENT);
        centerPanel.add(completeIcon);
        centerPanel.add(Box.createVerticalStrut(15));

        // Complete message
        completeMessage = new JLabel("Operation Complete");
        completeMessage.setFont(completeMessage.getFont().deriveFont(Font.BOLD, 16f));
        completeMessage.setAlignmentX(Component.CENTER_ALIGNMENT);
        centerPanel.add(completeMessage);
        centerPanel.add(Box.createVerticalStrut(30));

        // Done button
        doneButton = new JButton("Done");
        doneButton.setAlignmentX(Component.CENTER_ALIGNMENT);
        centerPanel.add(doneButton);

        page.add(centerPanel, BorderLayout.CENTER);
        return page;
    }

    private void setupListeners() {
        queryButton.addActionListener(e -> controller.handleSymGraphQuery());
        pushButton.addActionListener(e -> handlePushClicked());
        pullPreviewButton.addActionListener(e -> controller.handleSymGraphPullPreview());
        applyButton.addActionListener(e -> handleApplyClicked());
        cancelButton.addActionListener(e -> resetWizard());

        cancelPushButton.addActionListener(e -> {
            if (pushCancelCallback != null) {
                pushCancelCallback.run();
            }
        });

        selectAllButton.addActionListener(e -> setAllSelected(true));
        deselectAllButton.addActionListener(e -> setAllSelected(false));
        invertSelectionButton.addActionListener(e -> invertSelection());

        // Wizard navigation listeners
        applyAllNewButton.addActionListener(e -> controller.handleSymGraphApplyAllNew());
        reviewConflictsButton.addActionListener(e -> showConflictsOnly());
        showAllButton.addActionListener(e -> showDetailsPage());
        summaryBackButton.addActionListener(e -> resetWizard());
        backToSummaryButton.addActionListener(e -> showSummaryPage());
        doneButton.addActionListener(e -> resetWizard());
        applyCancelButton.addActionListener(e -> {
            // Cancel is handled by the controller - just reset
            resetWizard();
        });
    }

    private void handlePushClicked() {
        String scope = fullBinaryRadio.isSelected() ?
                PushScope.FULL_BINARY.getValue() : PushScope.CURRENT_FUNCTION.getValue();
        boolean pushSymbols = pushSymbolsCheck.isSelected();
        boolean pushGraph = pushGraphCheck.isSelected();

        if (!pushSymbols && !pushGraph) {
            setPushStatus("Select at least one data type", false);
            return;
        }

        controller.handleSymGraphPush(scope, pushSymbols, pushGraph);
    }

    private void handleApplyClicked() {
        List<Long> selectedAddresses = getSelectedAddresses();
        if (selectedAddresses.isEmpty() && graphPreviewData == null) {
            setPullStatus("No items selected", false);
            return;
        }
        controller.handleSymGraphApplySelected(getSelectedConflicts());
    }

    private void setAllSelected(boolean selected) {
        for (int i = 0; i < conflictTableModel.getRowCount(); i++) {
            conflictTableModel.setValueAt(selected, i, 0);
        }
    }

    private void invertSelection() {
        for (int i = 0; i < conflictTableModel.getRowCount(); i++) {
            Boolean current = (Boolean) conflictTableModel.getValueAt(i, 0);
            conflictTableModel.setValueAt(!current, i, 0);
        }
    }

    // === Public methods for controller ===

    public void setBinaryInfo(String name, String sha256) {
        binaryNameLabel.setText(name != null ? name : "<no binary loaded>");
        sha256Label.setText(sha256 != null ? sha256 : "<none>");
    }

    public void setQueryStatus(String status, boolean found) {
        statusLabel.setText(status);
        if (found) {
            statusLabel.setForeground(new Color(0, 128, 0)); // Green
        } else if (status.toLowerCase().contains("error") || status.toLowerCase().contains("not found")) {
            statusLabel.setForeground(Color.RED);
        } else {
            statusLabel.setForeground(Color.GRAY);
        }
    }

    public void setStats(int symbols, int functions, int nodes, String lastUpdated) {
        symbolsStatLabel.setText(String.format("Symbols: %,d", symbols));
        functionsStatLabel.setText(String.format("Functions: %,d", functions));
        nodesStatLabel.setText(String.format("Graph Nodes: %,d", nodes));
        updatedStatLabel.setText("Last Updated: " + (lastUpdated != null ? lastUpdated : "Unknown"));
        statsPanel.setVisible(true);
    }

    public void hideStats() {
        statsPanel.setVisible(false);
    }

    public void setPushStatus(String status, Boolean success) {
        pushStatusLabel.setText("Status: " + status);
        if (success == null) {
            pushStatusLabel.setForeground(Color.GRAY);
        } else if (success) {
            pushStatusLabel.setForeground(new Color(0, 128, 0));
        } else {
            pushStatusLabel.setForeground(Color.RED);
        }
    }

    /**
     * Show the push progress bar and set the cancel callback.
     */
    public void showPushProgress(Runnable cancelCallback) {
        this.pushCancelCallback = cancelCallback;
        pushProgressBar.setValue(0);
        pushProgressBar.setString("Starting...");
        pushProgressBar.setVisible(true);
        cancelPushButton.setVisible(true);
        pushButton.setEnabled(false);
    }

    /**
     * Update the push progress bar.
     */
    public void updatePushProgress(int current, int total, String message) {
        int percent = total > 0 ? (int) ((current * 100L) / total) : 0;
        pushProgressBar.setValue(percent);
        pushProgressBar.setString(message != null ? message : String.format("%d/%d (%d%%)", current, total, percent));
    }

    /**
     * Hide the push progress bar.
     */
    public void hidePushProgress() {
        pushProgressBar.setVisible(false);
        cancelPushButton.setVisible(false);
        pushButton.setEnabled(true);
        pushCancelCallback = null;
    }

    public void setPullStatus(String status, Boolean success) {
        pullStatusLabel.setText(status);
        if (success == null) {
            pullStatusLabel.setForeground(Color.GRAY);
        } else if (success) {
            pullStatusLabel.setForeground(new Color(0, 128, 0));
        } else {
            pullStatusLabel.setForeground(Color.RED);
        }
    }

    public void populateConflicts(List<ConflictEntry> conflicts) {
        currentConflicts.clear();

        // Calculate counts for summary
        int newCount = 0;
        int conflictCount = 0;
        int sameCount = 0;

        for (ConflictEntry conflict : conflicts) {
            switch (conflict.getAction()) {
                case NEW:
                    newCount++;
                    break;
                case CONFLICT:
                    conflictCount++;
                    break;
                case SAME:
                    sameCount++;
                    break;
            }
        }

        // Update summary labels
        summaryNewCount.setText(String.valueOf(newCount));
        summaryConflictCount.setText(String.valueOf(conflictCount));
        summarySameCount.setText(String.valueOf(sameCount));

        // Enable/disable buttons based on counts
        applyAllNewButton.setEnabled(newCount > 0);
        reviewConflictsButton.setEnabled(conflictCount > 0);

        // Sort: CONFLICT first, then by address
        List<ConflictEntry> sortedConflicts = new ArrayList<>(conflicts);
        sortedConflicts.sort((a, b) -> {
            if (a.getAction() == ConflictAction.CONFLICT && b.getAction() != ConflictAction.CONFLICT) {
                return -1;
            }
            if (a.getAction() != ConflictAction.CONFLICT && b.getAction() == ConflictAction.CONFLICT) {
                return 1;
            }
            return Long.compare(a.getAddress(), b.getAddress());
        });

        currentConflicts.addAll(sortedConflicts);
        refreshConflictTable(currentConflicts);

        // Show summary page
        showSummaryPage();
    }

    private String formatStorageInfo(Symbol symbol) {
        if (symbol == null) {
            return "";
        }

        String symType = symbol.getSymbolType();
        if (!"variable".equals(symType)) {
            return "func";
        }

        java.util.Map<String, Object> metadata = symbol.getMetadata();
        if (metadata == null) {
            return "variable";
        }

        String storageClass = (String) metadata.get("storage_class");
        String scope = (String) metadata.get("scope");

        if ("parameter".equals(storageClass)) {
            Object idx = metadata.get("parameter_index");
            String reg = (String) metadata.get("register");
            String idxStr = idx != null ? idx.toString() : "?";
            if (reg != null) {
                return String.format("param[%s] (%s)", idxStr, reg);
            }
            return String.format("param[%s]", idxStr);
        } else if ("stack".equals(storageClass)) {
            Object offsetObj = metadata.get("stack_offset");
            if (offsetObj != null) {
                int offset = ((Number) offsetObj).intValue();
                String sign = offset >= 0 ? "+" : "";
                return String.format("local [%s0x%x]", sign, Math.abs(offset));
            }
            return "local [stack]";
        } else if ("register".equals(storageClass)) {
            String reg = (String) metadata.get("register");
            return reg != null ? String.format("local (%s)", reg) : "local (reg)";
        } else if ("local".equals(scope)) {
            return "local";
        }

        return "global";
    }

    private void refreshConflictTable(List<ConflictEntry> conflicts) {
        conflictTableModel.setRowCount(0);
        displayedConflicts = new ArrayList<>(conflicts);
        for (ConflictEntry conflict : displayedConflicts) {
            String storageInfo = formatStorageInfo(conflict.getRemoteSymbol());
            conflictTableModel.addRow(new Object[]{
                    conflict.isSelected(),
                    conflict.getAddressHex(),
                    storageInfo,
                    conflict.getLocalNameDisplay(),
                    conflict.getRemoteNameDisplay(),
                    conflict.getAction().getValue().toUpperCase()
            });
        }
    }

    public void setGraphPreviewData(GraphExport export, int nodes, int edges, int communities) {
        graphPreviewData = export;
        graphPreviewNodes = nodes;
        graphPreviewEdges = edges;
        graphPreviewCommunities = communities;
        updateGraphLabels();
    }

    public GraphExport getGraphPreviewData() {
        return graphPreviewData;
    }

    public boolean hasGraphPreviewData() {
        return graphPreviewData != null;
    }

    public String getGraphMergePolicy() {
        return graphMergePolicy;
    }

    private void updateGraphLabels() {
        boolean hasGraph = graphPreviewData != null;
        summaryGraphLabel.setText(hasGraph ? "Graph data available for merge" : "No graph data selected");
        summaryGraphNodesLabel.setText("Nodes: " + graphPreviewNodes);
        summaryGraphEdgesLabel.setText("Edges: " + graphPreviewEdges);
        summaryGraphCommunitiesLabel.setText("Communities: " + graphPreviewCommunities);

        if (detailsGraphLabel != null) {
            detailsGraphLabel.setText(hasGraph ? "Graph data available for merge" : "No graph data available");
            detailsGraphNodesLabel.setText("Nodes: " + graphPreviewNodes);
            detailsGraphEdgesLabel.setText("Edges: " + graphPreviewEdges);
            detailsGraphCommunitiesLabel.setText("Communities: " + graphPreviewCommunities);
            if (detailsGraphPolicyLabel != null) {
                detailsGraphPolicyLabel.setText("Selected policy: " + getMergePolicyLabel());
            }
        }
    }

    public void clearConflicts() {
        resetWizard();
    }

    // === Wizard navigation methods ===

    private void resetWizard() {
        conflictTableModel.setRowCount(0);
        currentConflicts.clear();
        displayedConflicts.clear();
        pullStatusLabel.setText("");
        summaryNewCount.setText("0");
        summaryConflictCount.setText("0");
        summarySameCount.setText("0");
        summaryGraphLabel.setText("No graph data selected");
        graphPreviewData = null;
        graphPreviewNodes = 0;
        graphPreviewEdges = 0;
        graphPreviewCommunities = 0;
        graphMergePolicy = MERGE_POLICY_UPSERT;
        syncMergePolicySelections();
        updateGraphLabels();
        if (detailsTabs != null) {
            detailsTabs.setSelectedIndex(0);
        }
        wizardLayout.show(wizardPanel, PAGE_INITIAL);
    }

    private void showSummaryPage() {
        wizardLayout.show(wizardPanel, PAGE_SUMMARY);
    }

    private void showDetailsPage() {
        refreshConflictTable(currentConflicts);
        // Show all conflicts in the table
        if (detailsTabs != null) {
            detailsTabs.setSelectedIndex(0);
        }
        wizardLayout.show(wizardPanel, PAGE_DETAILS);
    }

    private void showConflictsOnly() {
        List<ConflictEntry> conflictOnly = new ArrayList<>();
        for (ConflictEntry conflict : currentConflicts) {
            if (conflict.getAction() == ConflictAction.CONFLICT) {
                conflictOnly.add(conflict);
            }
        }
        refreshConflictTable(conflictOnly);
        if (detailsTabs != null) {
            detailsTabs.setSelectedIndex(0);
        }
        wizardLayout.show(wizardPanel, PAGE_DETAILS);
    }

    /**
     * Show the applying page with a status message.
     */
    public void showApplyingPage(String message) {
        applyProgressBar.setValue(0);
        applyProgressLabel.setText(message != null ? message : "Starting...");
        wizardLayout.show(wizardPanel, PAGE_APPLYING);
    }

    /**
     * Update the apply progress bar.
     */
    public void updateApplyProgress(int current, int total, String message) {
        int percent = total > 0 ? (int) ((current * 100L) / total) : 0;
        applyProgressBar.setValue(percent);
        applyProgressBar.setString(String.format("%d/%d (%d%%)", current, total, percent));
        if (message != null) {
            applyProgressLabel.setText(message);
        }
    }

    /**
     * Show the complete page with results.
     */
    public void showCompletePage(String message, boolean success) {
        if (success) {
            completeIcon.setText("✓");
            completeIcon.setForeground(new Color(0, 128, 0));
        } else {
            completeIcon.setText("✗");
            completeIcon.setForeground(Color.RED);
        }
        completeMessage.setText(message != null ? message : "Operation Complete");
        wizardLayout.show(wizardPanel, PAGE_COMPLETE);
    }

    /**
     * Get all conflicts with NEW action (for "Apply All New" button).
     */
    public List<ConflictEntry> getAllNewConflicts() {
        List<ConflictEntry> newItems = new ArrayList<>();
        for (ConflictEntry conflict : currentConflicts) {
            if (conflict.getAction() == ConflictAction.NEW) {
                newItems.add(conflict);
            }
        }
        return newItems;
    }

    /**
     * Set graph info in the summary page.
     */
    public void setSummaryGraphInfo(int nodes, int edges, int communities) {
        graphPreviewNodes = nodes;
        graphPreviewEdges = edges;
        graphPreviewCommunities = communities;
        updateGraphLabels();
    }

    public List<Long> getSelectedAddresses() {
        List<Long> selected = new ArrayList<>();
        for (int i = 0; i < conflictTableModel.getRowCount(); i++) {
            Boolean isSelected = (Boolean) conflictTableModel.getValueAt(i, 0);
            if (isSelected != null && isSelected && i < displayedConflicts.size()) {
                selected.add(displayedConflicts.get(i).getAddress());
            }
        }
        return selected;
    }

    public List<ConflictEntry> getSelectedConflicts() {
        List<ConflictEntry> selected = new ArrayList<>();
        for (int i = 0; i < conflictTableModel.getRowCount(); i++) {
            Boolean isSelected = (Boolean) conflictTableModel.getValueAt(i, 0);
            if (isSelected != null && isSelected && i < displayedConflicts.size()) {
                selected.add(displayedConflicts.get(i));
            }
        }
        return selected;
    }

    /**
     * Get the current pull configuration settings.
     *
     * @return PullConfig with symbol types, min confidence, and graph option
     */
    public PullConfig getPullConfig() {
        List<String> types = new ArrayList<>();
        if (pullFunctionsCheck.isSelected()) types.add("function");
        if (pullVariablesCheck.isSelected()) types.add("variable");
        if (pullTypesCheck.isSelected()) types.add("type");
        if (pullCommentsCheck.isSelected()) types.add("comment");

        double minConfidence = confidenceSlider.getValue() / 100.0;
        boolean includeGraph = pullGraphCheck.isSelected();

        return new PullConfig(types, minConfidence, includeGraph);
    }

    /**
     * Configuration for pull preview operation.
     */
    public static class PullConfig {
        private final List<String> symbolTypes;
        private final double minConfidence;
        private final boolean includeGraph;

        public PullConfig(List<String> symbolTypes, double minConfidence, boolean includeGraph) {
            this.symbolTypes = symbolTypes;
            this.minConfidence = minConfidence;
            this.includeGraph = includeGraph;
        }

        public List<String> getSymbolTypes() { return symbolTypes; }
        public double getMinConfidence() { return minConfidence; }
        public boolean isIncludeGraph() { return includeGraph; }
    }

    public void setButtonsEnabled(boolean enabled) {
        queryButton.setEnabled(enabled);
        pushButton.setEnabled(enabled);
        pullPreviewButton.setEnabled(enabled);
        applyButton.setEnabled(enabled);
    }

    /**
     * Custom cell renderer for the Action column.
     */
    private static class ActionCellRenderer extends JLabel implements TableCellRenderer {
        private static final long serialVersionUID = 1L;

        public ActionCellRenderer() {
            setOpaque(true);
            setHorizontalAlignment(CENTER);
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean isSelected, boolean hasFocus, int row, int column) {

            String action = value != null ? value.toString() : "";
            setText(action);

            if (isSelected) {
                setBackground(table.getSelectionBackground());
                setForeground(table.getSelectionForeground());
            } else {
                setBackground(table.getBackground());
                switch (action) {
                    case "CONFLICT":
                        setForeground(Color.RED);
                        break;
                    case "NEW":
                        setForeground(new Color(0, 128, 0));
                        break;
                    case "SAME":
                        setForeground(Color.GRAY);
                        break;
                    default:
                        setForeground(table.getForeground());
                }
            }

            return this;
        }
    }
}
