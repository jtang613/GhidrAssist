package ghidrassist.ui.tabs.semanticgraph;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;

import com.mxgraph.layout.hierarchical.mxHierarchicalLayout;
import com.mxgraph.model.mxCell;
import com.mxgraph.swing.mxGraphComponent;
import com.mxgraph.util.mxConstants;
import com.mxgraph.view.mxGraph;
import com.mxgraph.view.mxStylesheet;

import ghidrassist.core.TabController;
import ghidrassist.ui.tabs.SemanticGraphTab;
import ghidrassist.graphrag.nodes.KnowledgeNode;
import ghidrassist.graphrag.BinaryKnowledgeGraph.GraphEdge;
import ghidrassist.graphrag.nodes.EdgeType;

/**
 * Visual graph sub-panel for the Semantic Graph tab.
 * Uses JGraphX to render an interactive node-edge diagram.
 */
public class GraphViewPanel extends JPanel {
    private static final long serialVersionUID = 1L;

    private final TabController controller;
    private final SemanticGraphTab parentTab;

    // JGraphX components
    private mxGraph graph;
    private mxGraphComponent graphComponent;

    // Controls
    private JSpinner nHopsSpinner;
    private JCheckBox showCallsCheckbox;
    private JCheckBox showRefsCheckbox;
    private JCheckBox showDataDepCheckbox;
    private JCheckBox showVulnCheckbox;

    // Selected node info panel
    private JLabel selectedNodeLabel;
    private JLabel selectedSummaryLabel;
    private JButton goToButton;
    private JButton detailsButton;

    // Not-indexed placeholder
    private JPanel notIndexedPanel;
    private JPanel contentPanel;
    private CardLayout cardLayout;

    // Node mapping for click handling
    private Map<Object, KnowledgeNode> cellToNodeMap = new HashMap<>();
    private KnowledgeNode selectedNode = null;

    // Styles
    private static final String STYLE_CENTER = "centerNode";
    private static final String STYLE_NORMAL = "normalNode";
    private static final String STYLE_VULN = "vulnNode";
    private static final String STYLE_EDGE_CALLS = "edgeCalls";
    private static final String STYLE_EDGE_REFS = "edgeRefs";
    private static final String STYLE_EDGE_DATA = "edgeData";
    private static final String STYLE_EDGE_VULN = "edgeVuln";

    public GraphViewPanel(TabController controller, SemanticGraphTab parentTab) {
        super(new BorderLayout());
        this.controller = controller;
        this.parentTab = parentTab;
        initializeGraph();
        initializeComponents();
        layoutComponents();
        setupListeners();
    }

    private void initializeGraph() {
        graph = new mxGraph() {
            // Disable edge editing
            @Override
            public boolean isCellEditable(Object cell) {
                return false;
            }

            // Disable cell moving (optional - can enable for user arrangement)
            @Override
            public boolean isCellMovable(Object cell) {
                return true;
            }
        };

        // Configure graph
        graph.setAllowDanglingEdges(false);
        graph.setEdgeLabelsMovable(false);
        graph.setCellsResizable(false);

        // Setup styles
        setupStyles();

        // Create graph component
        graphComponent = new mxGraphComponent(graph);
        graphComponent.setConnectable(false);
        graphComponent.getViewport().setOpaque(true);
        graphComponent.getViewport().setBackground(Color.WHITE);
        graphComponent.setWheelScrollingEnabled(true);

        // Enable zoom with mouse wheel
        graphComponent.setZoomPolicy(mxGraphComponent.ZOOM_POLICY_WIDTH);
    }

    private void setupStyles() {
        mxStylesheet stylesheet = graph.getStylesheet();

        // Center node style (highlighted)
        Map<String, Object> centerStyle = new HashMap<>();
        centerStyle.put(mxConstants.STYLE_SHAPE, mxConstants.SHAPE_RECTANGLE);
        centerStyle.put(mxConstants.STYLE_ROUNDED, true);
        centerStyle.put(mxConstants.STYLE_FILLCOLOR, "#4A90D9");
        centerStyle.put(mxConstants.STYLE_STROKECOLOR, "#2060A0");
        centerStyle.put(mxConstants.STYLE_STROKEWIDTH, 3);
        centerStyle.put(mxConstants.STYLE_FONTCOLOR, "#FFFFFF");
        centerStyle.put(mxConstants.STYLE_FONTSIZE, 11);
        centerStyle.put(mxConstants.STYLE_FONTSTYLE, mxConstants.FONT_BOLD);
        centerStyle.put(mxConstants.STYLE_VERTICAL_ALIGN, mxConstants.ALIGN_MIDDLE);
        stylesheet.putCellStyle(STYLE_CENTER, centerStyle);

        // Normal node style
        Map<String, Object> normalStyle = new HashMap<>();
        normalStyle.put(mxConstants.STYLE_SHAPE, mxConstants.SHAPE_RECTANGLE);
        normalStyle.put(mxConstants.STYLE_ROUNDED, true);
        normalStyle.put(mxConstants.STYLE_FILLCOLOR, "#E8E8E8");
        normalStyle.put(mxConstants.STYLE_STROKECOLOR, "#808080");
        normalStyle.put(mxConstants.STYLE_STROKEWIDTH, 1);
        normalStyle.put(mxConstants.STYLE_FONTCOLOR, "#000000");
        normalStyle.put(mxConstants.STYLE_FONTSIZE, 10);
        normalStyle.put(mxConstants.STYLE_VERTICAL_ALIGN, mxConstants.ALIGN_MIDDLE);
        stylesheet.putCellStyle(STYLE_NORMAL, normalStyle);

        // Vulnerable node style
        Map<String, Object> vulnStyle = new HashMap<>();
        vulnStyle.put(mxConstants.STYLE_SHAPE, mxConstants.SHAPE_RECTANGLE);
        vulnStyle.put(mxConstants.STYLE_ROUNDED, true);
        vulnStyle.put(mxConstants.STYLE_FILLCOLOR, "#FFCCCC");
        vulnStyle.put(mxConstants.STYLE_STROKECOLOR, "#CC0000");
        vulnStyle.put(mxConstants.STYLE_STROKEWIDTH, 2);
        vulnStyle.put(mxConstants.STYLE_FONTCOLOR, "#CC0000");
        vulnStyle.put(mxConstants.STYLE_FONTSIZE, 10);
        vulnStyle.put(mxConstants.STYLE_FONTSTYLE, mxConstants.FONT_BOLD);
        vulnStyle.put(mxConstants.STYLE_VERTICAL_ALIGN, mxConstants.ALIGN_MIDDLE);
        stylesheet.putCellStyle(STYLE_VULN, vulnStyle);

        // Edge styles
        Map<String, Object> callsEdgeStyle = new HashMap<>();
        callsEdgeStyle.put(mxConstants.STYLE_STROKECOLOR, "#4A90D9");
        callsEdgeStyle.put(mxConstants.STYLE_STROKEWIDTH, 2);
        callsEdgeStyle.put(mxConstants.STYLE_ENDARROW, mxConstants.ARROW_CLASSIC);
        callsEdgeStyle.put(mxConstants.STYLE_FONTSIZE, 9);
        stylesheet.putCellStyle(STYLE_EDGE_CALLS, callsEdgeStyle);

        Map<String, Object> refsEdgeStyle = new HashMap<>();
        refsEdgeStyle.put(mxConstants.STYLE_STROKECOLOR, "#808080");
        refsEdgeStyle.put(mxConstants.STYLE_STROKEWIDTH, 1);
        refsEdgeStyle.put(mxConstants.STYLE_DASHED, true);
        refsEdgeStyle.put(mxConstants.STYLE_ENDARROW, mxConstants.ARROW_CLASSIC);
        refsEdgeStyle.put(mxConstants.STYLE_FONTSIZE, 9);
        stylesheet.putCellStyle(STYLE_EDGE_REFS, refsEdgeStyle);

        Map<String, Object> dataEdgeStyle = new HashMap<>();
        dataEdgeStyle.put(mxConstants.STYLE_STROKECOLOR, "#009900");
        dataEdgeStyle.put(mxConstants.STYLE_STROKEWIDTH, 1);
        dataEdgeStyle.put(mxConstants.STYLE_DASHED, true);
        dataEdgeStyle.put(mxConstants.STYLE_ENDARROW, mxConstants.ARROW_OVAL);
        dataEdgeStyle.put(mxConstants.STYLE_FONTSIZE, 9);
        stylesheet.putCellStyle(STYLE_EDGE_DATA, dataEdgeStyle);

        Map<String, Object> vulnEdgeStyle = new HashMap<>();
        vulnEdgeStyle.put(mxConstants.STYLE_STROKECOLOR, "#CC0000");
        vulnEdgeStyle.put(mxConstants.STYLE_STROKEWIDTH, 2);
        vulnEdgeStyle.put(mxConstants.STYLE_ENDARROW, mxConstants.ARROW_CLASSIC);
        vulnEdgeStyle.put(mxConstants.STYLE_FONTSIZE, 9);
        stylesheet.putCellStyle(STYLE_EDGE_VULN, vulnEdgeStyle);
    }

    private void initializeComponents() {
        // N-Hops spinner
        SpinnerNumberModel spinnerModel = new SpinnerNumberModel(2, 1, 5, 1);
        nHopsSpinner = new JSpinner(spinnerModel);
        nHopsSpinner.setPreferredSize(new Dimension(50, 25));

        // Edge type checkboxes
        showCallsCheckbox = new JCheckBox("CALLS", true);
        showRefsCheckbox = new JCheckBox("REFS", true);
        showDataDepCheckbox = new JCheckBox("DATA_DEP", false);
        showVulnCheckbox = new JCheckBox("VULN", true);

        // Selected node info
        selectedNodeLabel = new JLabel("Selected: None");
        selectedSummaryLabel = new JLabel("");
        selectedSummaryLabel.setForeground(Color.GRAY);

        goToButton = new JButton("Go To");
        goToButton.setEnabled(false);

        detailsButton = new JButton("Details");
        detailsButton.setEnabled(false);

        // Not indexed placeholder
        notIndexedPanel = createNotIndexedPanel();

        // Card layout
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

        // ===== Top controls =====
        JPanel controlsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));

        controlsPanel.add(new JLabel("N-Hops:"));
        controlsPanel.add(nHopsSpinner);

        controlsPanel.add(Box.createHorizontalStrut(20));
        controlsPanel.add(new JLabel("Edge Types:"));
        controlsPanel.add(showCallsCheckbox);
        controlsPanel.add(showRefsCheckbox);
        controlsPanel.add(showDataDepCheckbox);
        controlsPanel.add(showVulnCheckbox);

        mainContent.add(controlsPanel, BorderLayout.NORTH);

        // ===== Graph component (center) =====
        mainContent.add(graphComponent, BorderLayout.CENTER);

        // ===== Selected node info (bottom) =====
        JPanel infoPanel = new JPanel(new BorderLayout(5, 5));
        infoPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        JPanel labelPanel = new JPanel(new GridLayout(2, 1));
        labelPanel.add(selectedNodeLabel);
        labelPanel.add(selectedSummaryLabel);
        infoPanel.add(labelPanel, BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
        buttonPanel.add(goToButton);
        buttonPanel.add(detailsButton);
        infoPanel.add(buttonPanel, BorderLayout.EAST);

        mainContent.add(infoPanel, BorderLayout.SOUTH);

        // ===== Card layout setup =====
        contentPanel.add(mainContent, "content");
        contentPanel.add(notIndexedPanel, "notIndexed");

        add(contentPanel, BorderLayout.CENTER);

        // Default to not indexed
        cardLayout.show(contentPanel, "notIndexed");
    }

    private void setupListeners() {
        // N-Hops change
        nHopsSpinner.addChangeListener(e -> refresh());

        // Edge type filters
        showCallsCheckbox.addActionListener(e -> refresh());
        showRefsCheckbox.addActionListener(e -> refresh());
        showDataDepCheckbox.addActionListener(e -> refresh());
        showVulnCheckbox.addActionListener(e -> refresh());

        // Graph click handler
        graphComponent.getGraphControl().addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                Object cell = graphComponent.getCellAt(e.getX(), e.getY());
                if (cell != null && cell instanceof mxCell) {
                    mxCell mxc = (mxCell) cell;
                    if (mxc.isVertex()) {
                        handleNodeClick(mxc);
                    }
                } else {
                    clearSelection();
                }

                // Double-click to navigate
                if (e.getClickCount() == 2 && selectedNode != null) {
                    parentTab.navigateToFunction(selectedNode.getAddress());
                }
            }
        });

        // Go To button
        goToButton.addActionListener(e -> {
            if (selectedNode != null) {
                parentTab.navigateToFunction(selectedNode.getAddress());
            }
        });

        // Details button - switch to list view
        detailsButton.addActionListener(e -> {
            if (selectedNode != null) {
                // Navigate and switch to list view
                parentTab.navigateToFunction(selectedNode.getAddress());
            }
        });
    }

    // ===== Public Methods =====

    /**
     * Refresh the graph view.
     */
    public void refresh() {
        int nHops = (Integer) nHopsSpinner.getValue();
        Set<EdgeType> edgeTypes = getSelectedEdgeTypes();
        controller.handleSemanticGraphVisualRefresh(this, parentTab.getCurrentAddress(), nHops, edgeTypes);
    }

    /**
     * Show the "not indexed" placeholder.
     */
    public void showNotIndexed() {
        cardLayout.show(contentPanel, "notIndexed");
    }

    /**
     * Show the main content.
     */
    public void showContent() {
        cardLayout.show(contentPanel, "content");
    }

    /**
     * Build and display the graph with the given nodes and edges.
     *
     * @param centerNode The center node (current function)
     * @param nodes All nodes to display
     * @param edges All edges to display
     */
    public void buildGraph(KnowledgeNode centerNode, List<KnowledgeNode> nodes, List<GraphEdge> edges) {
        graph.getModel().beginUpdate();
        try {
            // Clear existing graph
            graph.removeCells(graph.getChildVertices(graph.getDefaultParent()));
            cellToNodeMap.clear();

            Object parent = graph.getDefaultParent();
            Map<String, Object> nodeIdToCellMap = new HashMap<>();

            // Create node cells
            for (KnowledgeNode node : nodes) {
                String label = formatNodeLabel(node);
                String style = getNodeStyle(node, centerNode);

                Object cell = graph.insertVertex(parent, node.getId(), label,
                        0, 0, 120, 50, style);

                nodeIdToCellMap.put(node.getId(), cell);
                cellToNodeMap.put(cell, node);
            }

            // Create edge cells
            for (GraphEdge edge : edges) {
                Object sourceCell = nodeIdToCellMap.get(edge.getSourceId());
                Object targetCell = nodeIdToCellMap.get(edge.getTargetId());

                if (sourceCell != null && targetCell != null) {
                    String edgeStyle = getEdgeStyle(edge.getType());
                    String label = edge.getType().getDisplayName();
                    graph.insertEdge(parent, edge.getId(), label, sourceCell, targetCell, edgeStyle);
                }
            }

            // Apply layout
            mxHierarchicalLayout layout = new mxHierarchicalLayout(graph);
            layout.setInterRankCellSpacing(80);
            layout.setIntraCellSpacing(40);
            layout.execute(parent);

        } finally {
            graph.getModel().endUpdate();
        }

        // Fit to view
        graphComponent.zoomAndCenter();
    }

    // ===== Private Helper Methods =====

    private Set<EdgeType> getSelectedEdgeTypes() {
        Set<EdgeType> types = new HashSet<>();
        if (showCallsCheckbox.isSelected()) {
            types.add(EdgeType.CALLS);
        }
        if (showRefsCheckbox.isSelected()) {
            types.add(EdgeType.REFERENCES);
        }
        if (showDataDepCheckbox.isSelected()) {
            types.add(EdgeType.DATA_DEPENDS);
        }
        if (showVulnCheckbox.isSelected()) {
            types.add(EdgeType.CALLS_VULNERABLE);
        }
        return types;
    }

    private String formatNodeLabel(KnowledgeNode node) {
        String name = node.getName();
        if (name == null || name.isEmpty()) {
            name = "0x" + Long.toHexString(node.getAddress());
        }
        if (name.length() > 20) {
            name = name.substring(0, 17) + "...";
        }

        String addr = "0x" + Long.toHexString(node.getAddress());

        StringBuilder label = new StringBuilder();
        label.append(name).append("\n").append(addr);

        if (node.hasSecurityFlags()) {
            label.append("\n[VULN]");
        }

        return label.toString();
    }

    private String getNodeStyle(KnowledgeNode node, KnowledgeNode centerNode) {
        if (node.getId().equals(centerNode.getId())) {
            return STYLE_CENTER;
        } else if (node.hasSecurityFlags()) {
            return STYLE_VULN;
        } else {
            return STYLE_NORMAL;
        }
    }

    private String getEdgeStyle(EdgeType type) {
        switch (type) {
            case CALLS:
                return STYLE_EDGE_CALLS;
            case REFERENCES:
                return STYLE_EDGE_REFS;
            case DATA_DEPENDS:
                return STYLE_EDGE_DATA;
            case CALLS_VULNERABLE:
                return STYLE_EDGE_VULN;
            default:
                return STYLE_EDGE_CALLS;
        }
    }

    private void handleNodeClick(mxCell cell) {
        KnowledgeNode node = cellToNodeMap.get(cell);
        if (node != null) {
            selectedNode = node;
            selectedNodeLabel.setText("Selected: " + node.getName() + " @ 0x" + Long.toHexString(node.getAddress()));

            String summary = node.getLlmSummary();
            if (summary != null && !summary.isEmpty()) {
                if (summary.length() > 100) {
                    summary = summary.substring(0, 97) + "...";
                }
                selectedSummaryLabel.setText("Summary: " + summary);
            } else {
                selectedSummaryLabel.setText("");
            }

            goToButton.setEnabled(true);
            detailsButton.setEnabled(true);

            // Highlight the selected cell
            graph.setSelectionCell(cell);
        }
    }

    private void clearSelection() {
        selectedNode = null;
        selectedNodeLabel.setText("Selected: None");
        selectedSummaryLabel.setText("");
        goToButton.setEnabled(false);
        detailsButton.setEnabled(false);
        graph.clearSelection();
    }
}
