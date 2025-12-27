package ghidrassist.ui.tabs.semanticgraph;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseWheelEvent;
import java.awt.event.MouseWheelListener;
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

    // Zoom controls
    private JButton zoomInButton;
    private JButton zoomOutButton;
    private JButton zoomFitButton;
    private JLabel zoomLabel;

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

        // Setup styles with theme colors
        setupStyles();

        // Create graph component
        graphComponent = new mxGraphComponent(graph);
        graphComponent.setConnectable(false);
        graphComponent.getViewport().setOpaque(true);

        // Use theme-aware background color
        Color bgColor = UIManager.getColor("Panel.background");
        if (bgColor == null) {
            bgColor = getBackground();
        }
        graphComponent.getViewport().setBackground(bgColor);
        graphComponent.setBackground(bgColor);

        // Disable default wheel scrolling so we can use CTRL+Wheel for zoom
        graphComponent.setWheelScrollingEnabled(false);

        // Add CTRL+Wheel zoom support
        graphComponent.addMouseWheelListener(new MouseWheelListener() {
            @Override
            public void mouseWheelMoved(MouseWheelEvent e) {
                if (e.isControlDown()) {
                    // CTRL+Wheel = zoom
                    if (e.getWheelRotation() < 0) {
                        graphComponent.zoomIn();
                    } else {
                        graphComponent.zoomOut();
                    }
                    updateZoomLabel();
                } else {
                    // Normal wheel = scroll
                    JScrollBar vBar = graphComponent.getVerticalScrollBar();
                    if (vBar != null) {
                        int amount = e.getWheelRotation() * vBar.getUnitIncrement();
                        vBar.setValue(vBar.getValue() + amount);
                    }
                }
            }
        });
    }

    private void setupStyles() {
        mxStylesheet stylesheet = graph.getStylesheet();

        // Get theme colors from UIManager for light/dark mode support
        Color selectionBg = UIManager.getColor("List.selectionBackground");
        Color selectionFg = UIManager.getColor("List.selectionForeground");
        Color panelBg = UIManager.getColor("Panel.background");
        Color textColor = UIManager.getColor("Label.foreground");
        Color borderColor = UIManager.getColor("Component.borderColor");

        // Determine if we're in dark mode by checking text brightness
        boolean isDarkMode = isColorDark(panelBg);

        // Fallback colors if UIManager doesn't provide them
        if (selectionBg == null) selectionBg = new Color(74, 144, 217);
        if (selectionFg == null) selectionFg = Color.WHITE;
        if (textColor == null) textColor = isDarkMode ? Color.WHITE : Color.BLACK;
        if (borderColor == null) borderColor = isDarkMode ? new Color(100, 100, 100) : new Color(128, 128, 128);

        // Normal node colors based on theme
        Color normalNodeBg = isDarkMode ? new Color(60, 63, 65) : new Color(232, 232, 232);
        Color normalNodeBorder = borderColor;
        Color normalNodeText = textColor;

        // Vulnerable node colors - red tint that works in both modes
        Color vulnNodeBg = isDarkMode ? new Color(80, 40, 40) : new Color(255, 204, 204);
        Color vulnNodeBorder = isDarkMode ? new Color(200, 80, 80) : new Color(204, 0, 0);
        Color vulnNodeText = isDarkMode ? new Color(255, 120, 120) : new Color(204, 0, 0);

        // Edge colors
        Color callsEdgeColor = selectionBg;
        Color refsEdgeColor = borderColor;
        Color dataEdgeColor = isDarkMode ? new Color(80, 180, 80) : new Color(0, 153, 0);
        Color vulnEdgeColor = vulnNodeBorder;

        // Center node style (highlighted with selection color)
        Map<String, Object> centerStyle = new HashMap<>();
        centerStyle.put(mxConstants.STYLE_SHAPE, mxConstants.SHAPE_RECTANGLE);
        centerStyle.put(mxConstants.STYLE_ROUNDED, true);
        centerStyle.put(mxConstants.STYLE_FILLCOLOR, colorToHex(selectionBg));
        centerStyle.put(mxConstants.STYLE_STROKECOLOR, colorToHex(selectionBg.darker()));
        centerStyle.put(mxConstants.STYLE_STROKEWIDTH, 3);
        centerStyle.put(mxConstants.STYLE_FONTCOLOR, colorToHex(selectionFg));
        centerStyle.put(mxConstants.STYLE_FONTSIZE, 11);
        centerStyle.put(mxConstants.STYLE_FONTSTYLE, mxConstants.FONT_BOLD);
        centerStyle.put(mxConstants.STYLE_VERTICAL_ALIGN, mxConstants.ALIGN_MIDDLE);
        stylesheet.putCellStyle(STYLE_CENTER, centerStyle);

        // Normal node style
        Map<String, Object> normalStyle = new HashMap<>();
        normalStyle.put(mxConstants.STYLE_SHAPE, mxConstants.SHAPE_RECTANGLE);
        normalStyle.put(mxConstants.STYLE_ROUNDED, true);
        normalStyle.put(mxConstants.STYLE_FILLCOLOR, colorToHex(normalNodeBg));
        normalStyle.put(mxConstants.STYLE_STROKECOLOR, colorToHex(normalNodeBorder));
        normalStyle.put(mxConstants.STYLE_STROKEWIDTH, 1);
        normalStyle.put(mxConstants.STYLE_FONTCOLOR, colorToHex(normalNodeText));
        normalStyle.put(mxConstants.STYLE_FONTSIZE, 10);
        normalStyle.put(mxConstants.STYLE_VERTICAL_ALIGN, mxConstants.ALIGN_MIDDLE);
        stylesheet.putCellStyle(STYLE_NORMAL, normalStyle);

        // Vulnerable node style
        Map<String, Object> vulnStyle = new HashMap<>();
        vulnStyle.put(mxConstants.STYLE_SHAPE, mxConstants.SHAPE_RECTANGLE);
        vulnStyle.put(mxConstants.STYLE_ROUNDED, true);
        vulnStyle.put(mxConstants.STYLE_FILLCOLOR, colorToHex(vulnNodeBg));
        vulnStyle.put(mxConstants.STYLE_STROKECOLOR, colorToHex(vulnNodeBorder));
        vulnStyle.put(mxConstants.STYLE_STROKEWIDTH, 2);
        vulnStyle.put(mxConstants.STYLE_FONTCOLOR, colorToHex(vulnNodeText));
        vulnStyle.put(mxConstants.STYLE_FONTSIZE, 10);
        vulnStyle.put(mxConstants.STYLE_FONTSTYLE, mxConstants.FONT_BOLD);
        vulnStyle.put(mxConstants.STYLE_VERTICAL_ALIGN, mxConstants.ALIGN_MIDDLE);
        stylesheet.putCellStyle(STYLE_VULN, vulnStyle);

        // Edge styles
        Map<String, Object> callsEdgeStyle = new HashMap<>();
        callsEdgeStyle.put(mxConstants.STYLE_STROKECOLOR, colorToHex(callsEdgeColor));
        callsEdgeStyle.put(mxConstants.STYLE_STROKEWIDTH, 2);
        callsEdgeStyle.put(mxConstants.STYLE_ENDARROW, mxConstants.ARROW_CLASSIC);
        callsEdgeStyle.put(mxConstants.STYLE_FONTSIZE, 9);
        callsEdgeStyle.put(mxConstants.STYLE_FONTCOLOR, colorToHex(textColor));
        stylesheet.putCellStyle(STYLE_EDGE_CALLS, callsEdgeStyle);

        Map<String, Object> refsEdgeStyle = new HashMap<>();
        refsEdgeStyle.put(mxConstants.STYLE_STROKECOLOR, colorToHex(refsEdgeColor));
        refsEdgeStyle.put(mxConstants.STYLE_STROKEWIDTH, 1);
        refsEdgeStyle.put(mxConstants.STYLE_DASHED, true);
        refsEdgeStyle.put(mxConstants.STYLE_ENDARROW, mxConstants.ARROW_CLASSIC);
        refsEdgeStyle.put(mxConstants.STYLE_FONTSIZE, 9);
        refsEdgeStyle.put(mxConstants.STYLE_FONTCOLOR, colorToHex(textColor));
        stylesheet.putCellStyle(STYLE_EDGE_REFS, refsEdgeStyle);

        Map<String, Object> dataEdgeStyle = new HashMap<>();
        dataEdgeStyle.put(mxConstants.STYLE_STROKECOLOR, colorToHex(dataEdgeColor));
        dataEdgeStyle.put(mxConstants.STYLE_STROKEWIDTH, 1);
        dataEdgeStyle.put(mxConstants.STYLE_DASHED, true);
        dataEdgeStyle.put(mxConstants.STYLE_ENDARROW, mxConstants.ARROW_OVAL);
        dataEdgeStyle.put(mxConstants.STYLE_FONTSIZE, 9);
        dataEdgeStyle.put(mxConstants.STYLE_FONTCOLOR, colorToHex(textColor));
        stylesheet.putCellStyle(STYLE_EDGE_DATA, dataEdgeStyle);

        Map<String, Object> vulnEdgeStyle = new HashMap<>();
        vulnEdgeStyle.put(mxConstants.STYLE_STROKECOLOR, colorToHex(vulnEdgeColor));
        vulnEdgeStyle.put(mxConstants.STYLE_STROKEWIDTH, 2);
        vulnEdgeStyle.put(mxConstants.STYLE_ENDARROW, mxConstants.ARROW_CLASSIC);
        vulnEdgeStyle.put(mxConstants.STYLE_FONTSIZE, 9);
        vulnEdgeStyle.put(mxConstants.STYLE_FONTCOLOR, colorToHex(textColor));
        stylesheet.putCellStyle(STYLE_EDGE_VULN, vulnEdgeStyle);
    }

    /**
     * Check if a color is dark (for determining light vs dark mode).
     */
    private boolean isColorDark(Color color) {
        if (color == null) return false;
        // Use perceived brightness formula
        double brightness = (color.getRed() * 299 + color.getGreen() * 587 + color.getBlue() * 114) / 1000.0;
        return brightness < 128;
    }

    /**
     * Convert Color to hex string for JGraphX styles.
     */
    private String colorToHex(Color color) {
        return String.format("#%02X%02X%02X", color.getRed(), color.getGreen(), color.getBlue());
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

        // Zoom controls
        zoomInButton = new JButton("+");
        zoomInButton.setToolTipText("Zoom In");
        zoomInButton.setMargin(new Insets(2, 6, 2, 6));

        zoomOutButton = new JButton("-");
        zoomOutButton.setToolTipText("Zoom Out");
        zoomOutButton.setMargin(new Insets(2, 6, 2, 6));

        zoomFitButton = new JButton("Fit");
        zoomFitButton.setToolTipText("Fit to View (1:1)");
        zoomFitButton.setMargin(new Insets(2, 6, 2, 6));

        zoomLabel = new JLabel("100%");
        zoomLabel.setToolTipText("Current zoom level (CTRL+Wheel to zoom)");

        // Selected node info
        selectedNodeLabel = new JLabel("Selected: None");
        selectedSummaryLabel = new JLabel("");
        selectedSummaryLabel.setForeground(UIManager.getColor("Label.disabledForeground"));

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
        JPanel controlsPanel = new JPanel(new BorderLayout());

        // Left side: N-Hops and Edge Types
        JPanel leftControls = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        leftControls.add(new JLabel("N-Hops:"));
        leftControls.add(nHopsSpinner);
        leftControls.add(Box.createHorizontalStrut(10));
        leftControls.add(new JLabel("Edge Types:"));
        leftControls.add(showCallsCheckbox);
        leftControls.add(showRefsCheckbox);
        leftControls.add(showDataDepCheckbox);
        leftControls.add(showVulnCheckbox);

        // Right side: Zoom controls
        JPanel zoomControls = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 5));
        zoomControls.add(new JLabel("Zoom:"));
        zoomControls.add(zoomOutButton);
        zoomControls.add(zoomLabel);
        zoomControls.add(zoomInButton);
        zoomControls.add(zoomFitButton);

        controlsPanel.add(leftControls, BorderLayout.WEST);
        controlsPanel.add(zoomControls, BorderLayout.EAST);

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

        // Zoom button handlers
        zoomInButton.addActionListener(e -> {
            graphComponent.zoomIn();
            updateZoomLabel();
        });

        zoomOutButton.addActionListener(e -> {
            graphComponent.zoomOut();
            updateZoomLabel();
        });

        zoomFitButton.addActionListener(e -> {
            graphComponent.zoomActual();
            graphComponent.zoomAndCenter();
            updateZoomLabel();
        });

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

    /**
     * Update the zoom label to show current zoom percentage.
     */
    private void updateZoomLabel() {
        double scale = graphComponent.getGraph().getView().getScale();
        int percentage = (int) Math.round(scale * 100);
        zoomLabel.setText(percentage + "%");
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
