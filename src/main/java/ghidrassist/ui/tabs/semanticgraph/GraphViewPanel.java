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
import com.mxgraph.layout.mxOrganicLayout;
import com.mxgraph.model.mxCell;
import com.mxgraph.swing.mxGraphComponent;
import com.mxgraph.util.mxConstants;
import com.mxgraph.view.mxGraph;
import com.mxgraph.view.mxStylesheet;

import ghidra.util.Msg;

import ghidrassist.core.MarkdownHelper;
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
    private JCheckBox showVulnCheckbox;
    private JCheckBox showNetworkCheckbox;

    // Zoom controls
    private JButton zoomInButton;
    private JButton zoomOutButton;
    private JButton zoomFitButton;
    private JLabel zoomLabel;

    // Selected node info panel
    private JLabel selectedNodeLabel;
    private JEditorPane summaryPane;
    private JScrollPane summaryScrollPane;
    private MarkdownHelper markdownHelper;

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
    private static final String STYLE_EDGE_VULN = "edgeVuln";
    private static final String STYLE_EDGE_NETWORK = "edgeNetwork";

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
        Color vulnEdgeColor = vulnNodeBorder;
        Color networkEdgeColor = new Color(6, 182, 212);  // cyan-500

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

        Map<String, Object> vulnEdgeStyle = new HashMap<>();
        vulnEdgeStyle.put(mxConstants.STYLE_STROKECOLOR, colorToHex(vulnEdgeColor));
        vulnEdgeStyle.put(mxConstants.STYLE_STROKEWIDTH, 2);
        vulnEdgeStyle.put(mxConstants.STYLE_ENDARROW, mxConstants.ARROW_CLASSIC);
        vulnEdgeStyle.put(mxConstants.STYLE_FONTSIZE, 9);
        vulnEdgeStyle.put(mxConstants.STYLE_FONTCOLOR, colorToHex(textColor));
        stylesheet.putCellStyle(STYLE_EDGE_VULN, vulnEdgeStyle);

        Map<String, Object> networkEdgeStyle = new HashMap<>();
        networkEdgeStyle.put(mxConstants.STYLE_STROKECOLOR, colorToHex(networkEdgeColor));
        networkEdgeStyle.put(mxConstants.STYLE_STROKEWIDTH, 2);
        networkEdgeStyle.put(mxConstants.STYLE_ENDARROW, mxConstants.ARROW_CLASSIC);
        networkEdgeStyle.put(mxConstants.STYLE_FONTSIZE, 9);
        networkEdgeStyle.put(mxConstants.STYLE_FONTCOLOR, colorToHex(textColor));
        stylesheet.putCellStyle(STYLE_EDGE_NETWORK, networkEdgeStyle);
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
        nHopsSpinner.setPreferredSize(new Dimension(75, 25));

        // Edge type checkboxes
        showCallsCheckbox = new JCheckBox("CALLS", true);
        showVulnCheckbox = new JCheckBox("VULN", true);
        showNetworkCheckbox = new JCheckBox("NETWORK", true);

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

        // Markdown helper for rendering summaries
        markdownHelper = new MarkdownHelper();

        // Selected node info
        selectedNodeLabel = new JLabel("Double-click a node to navigate");
        selectedNodeLabel.setForeground(UIManager.getColor("Label.disabledForeground"));

        // Summary pane for rendering markdown
        summaryPane = new JEditorPane();
        summaryPane.setContentType("text/html");
        summaryPane.setEditable(false);
        summaryPane.setOpaque(false);
        summaryPane.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        summaryPane.setFont(UIManager.getFont("Label.font"));

        summaryScrollPane = new JScrollPane(summaryPane);
        summaryScrollPane.setBorder(BorderFactory.createEmptyBorder());
        summaryScrollPane.setPreferredSize(new Dimension(400, 120));
        summaryScrollPane.getVerticalScrollBar().setUnitIncrement(16);

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
        leftControls.add(showVulnCheckbox);
        leftControls.add(showNetworkCheckbox);

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

        // ===== Selected node info and summary (bottom) =====
        JPanel infoPanel = new JPanel(new BorderLayout(5, 5));
        infoPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        infoPanel.add(selectedNodeLabel, BorderLayout.NORTH);
        infoPanel.add(summaryScrollPane, BorderLayout.CENTER);

        // ===== Resizable split between graph and summary =====
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, graphComponent, infoPanel);
        splitPane.setResizeWeight(0.8);
        splitPane.setContinuousLayout(true);
        splitPane.setBorder(BorderFactory.createEmptyBorder());

        mainContent.add(splitPane, BorderLayout.CENTER);

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
        showVulnCheckbox.addActionListener(e -> refresh());
        showNetworkCheckbox.addActionListener(e -> refresh());

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

                        // Double-click to navigate (skip external functions with null address)
                        if (e.getClickCount() == 2 && selectedNode != null && selectedNode.getAddress() != null) {
                            parentTab.navigateToFunction(selectedNode.getAddress());
                        }
                    }
                } else {
                    clearSelection();
                }
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
        Object centerCell = null;

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

                // Track the center node's cell for centering later
                if (node.getId().equals(centerNode.getId())) {
                    centerCell = cell;
                }
            }

            // Find callers of the center node (nodes that have CALLS edges TO centerNode)
            // These should be at the top of the hierarchy (row 0)
            List<Object> callerCells = new java.util.ArrayList<>();
            for (GraphEdge edge : edges) {
                if (edge.getType() == EdgeType.CALLS &&
                    edge.getTargetId().equals(centerNode.getId())) {
                    Object callerCell = nodeIdToCellMap.get(edge.getSourceId());
                    if (callerCell != null && !callerCells.contains(callerCell)) {
                        callerCells.add(callerCell);
                    }
                }
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

            // Apply layout - use hierarchical if possible, fall back to organic for cyclic graphs
            try {
                mxHierarchicalLayout layout = new mxHierarchicalLayout(graph);
                layout.setInterRankCellSpacing(80);
                layout.setIntraCellSpacing(40);

                // If we have callers, use them as roots so they appear at the top
                // Otherwise let the layout determine roots automatically
                if (!callerCells.isEmpty()) {
                    layout.execute(parent, callerCells);
                } else {
                    layout.execute(parent);
                }
            } catch (Exception e) {
                // Hierarchical layout fails on cyclic graphs - fall back to organic layout
                Msg.debug(this, "Hierarchical layout failed, using organic layout: " + e.getMessage());
                mxOrganicLayout organicLayout = new mxOrganicLayout(graph);
                // Increase node separation to reduce overlaps
                organicLayout.setMinMoveRadius(50.0);
                organicLayout.setMaxIterations(500);
                organicLayout.execute(parent);
            }

        } finally {
            graph.getModel().endUpdate();
        }

        // Center on the root node
        if (centerCell != null) {
            graph.getView().setScale(1.0);  // Reset zoom first
            graphComponent.scrollCellToVisible(centerCell, true);
            if (centerCell instanceof mxCell) {
                handleNodeClick((mxCell) centerCell);
            }
        } else {
            graphComponent.zoomAndCenter();
        }
    }

    // ===== Private Helper Methods =====

    private Set<EdgeType> getSelectedEdgeTypes() {
        Set<EdgeType> types = new HashSet<>();
        if (showCallsCheckbox.isSelected()) {
            types.add(EdgeType.CALLS);
        }
        if (showVulnCheckbox.isSelected()) {
            types.add(EdgeType.CALLS_VULNERABLE);
        }
        if (showNetworkCheckbox.isSelected()) {
            types.add(EdgeType.NETWORK_SEND);
            types.add(EdgeType.NETWORK_RECV);
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
        boolean isExternal = node.getAddress() == null;

        if (name == null || name.isEmpty()) {
            if (isExternal) {
                name = "[Unknown External]";
            } else {
                name = "0x" + Long.toHexString(node.getAddress());
            }
        }
        if (name.length() > 20) {
            name = name.substring(0, 17) + "...";
        }

        String addr = isExternal ? "[EXTERNAL]" : "0x" + Long.toHexString(node.getAddress());

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
            case CALLS_VULNERABLE:
                return STYLE_EDGE_VULN;
            case NETWORK_SEND:
            case NETWORK_RECV:
                return STYLE_EDGE_NETWORK;
            default:
                return STYLE_EDGE_CALLS;
        }
    }

    private void handleNodeClick(mxCell cell) {
        KnowledgeNode node = cellToNodeMap.get(cell);
        if (node != null) {
            selectedNode = node;
            String addrStr = node.getAddress() != null
                ? "@ 0x" + Long.toHexString(node.getAddress())
                : "[EXTERNAL]";
            selectedNodeLabel.setText(node.getName() + " " + addrStr + "  (double-click to navigate)");
            selectedNodeLabel.setForeground(UIManager.getColor("Label.foreground"));

            String summary = node.getLlmSummary();
            if (summary != null && !summary.isEmpty()) {
                // Render markdown to HTML
                String html = markdownHelper.markdownToHtmlSimple(summary);
                summaryPane.setText(html);
                summaryPane.setCaretPosition(0);  // Scroll to top
            } else {
                summaryPane.setText("<html><body><i style='color:gray'>No summary available</i></body></html>");
            }

            // Highlight the selected cell
            graph.setSelectionCell(cell);
        }
    }

    private void clearSelection() {
        selectedNode = null;
        selectedNodeLabel.setText("Double-click a node to navigate");
        selectedNodeLabel.setForeground(UIManager.getColor("Label.disabledForeground"));
        summaryPane.setText("");
        graph.clearSelection();
    }
}
