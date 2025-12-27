package ghidrassist.ui.tabs.semanticgraph;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.concurrent.CompletableFuture;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidrassist.core.TabController;
import ghidrassist.ui.tabs.SemanticGraphTab;

/**
 * Search sub-panel for the Semantic Graph tab.
 * Provides a UI for testing and exploring Graph-RAG semantic query tools.
 */
public class SearchViewPanel extends JPanel {
    private static final long serialVersionUID = 1L;

    private final TabController controller;
    private final SemanticGraphTab parentTab;

    // Query type constants
    private static final String QUERY_SEMANTIC_SEARCH = "ga_search_semantic";
    private static final String QUERY_GET_ANALYSIS = "ga_get_semantic_analysis";
    private static final String QUERY_SIMILAR_FUNCTIONS = "ga_get_similar_functions";
    private static final String QUERY_CALL_CONTEXT = "ga_get_call_context";
    private static final String QUERY_SECURITY_ANALYSIS = "ga_get_security_analysis";
    private static final String QUERY_MODULE_SUMMARY = "ga_get_module_summary";
    private static final String QUERY_ACTIVITY_ANALYSIS = "ga_get_activity_analysis";

    // Query type radio buttons
    private ButtonGroup queryTypeGroup;
    private JRadioButton semanticSearchRadio;
    private JRadioButton getAnalysisRadio;
    private JRadioButton similarFunctionsRadio;
    private JRadioButton callContextRadio;
    private JRadioButton securityAnalysisRadio;
    private JRadioButton moduleSummaryRadio;
    private JRadioButton activityAnalysisRadio;

    // Parameter panels
    private JPanel paramsCardPanel;
    private CardLayout paramsCardLayout;

    // Common parameter fields
    private JTextField queryField;
    private JTextField addressField;
    private JSpinner limitSpinner;
    private JSpinner depthSpinner;
    private JComboBox<String> directionCombo;
    private JComboBox<String> scopeCombo;
    private JCheckBox useCurrentAddressCheckbox;
    private JButton executeButton;

    // Results table
    private JTable resultsTable;
    private DefaultTableModel resultsTableModel;
    private TableRowSorter<DefaultTableModel> tableSorter;
    private JLabel resultsCountLabel;

    // Details panel
    private JLabel detailsFunctionLabel;
    private JLabel detailsFlagsLabel;
    private JLabel detailsCallersLabel;
    private JLabel detailsCalleesLabel;
    private JTextArea detailsSummaryArea;
    private JButton goToButton;
    private JButton copyButton;

    // State
    private String selectedAddress;
    private JsonArray lastResults;

    public SearchViewPanel(TabController controller, SemanticGraphTab parentTab) {
        super(new BorderLayout(5, 5));
        this.controller = controller;
        this.parentTab = parentTab;
        initializeComponents();
        layoutComponents();
        setupListeners();
    }

    private void initializeComponents() {
        // Query type radio buttons
        queryTypeGroup = new ButtonGroup();

        semanticSearchRadio = new JRadioButton("Semantic Search");
        semanticSearchRadio.setToolTipText("Full-text search of function summaries");
        semanticSearchRadio.setActionCommand(QUERY_SEMANTIC_SEARCH);
        semanticSearchRadio.setSelected(true);

        getAnalysisRadio = new JRadioButton("Get Analysis");
        getAnalysisRadio.setToolTipText("Detailed analysis of a specific function");
        getAnalysisRadio.setActionCommand(QUERY_GET_ANALYSIS);

        similarFunctionsRadio = new JRadioButton("Similar Functions");
        similarFunctionsRadio.setToolTipText("Find functions similar to a given one");
        similarFunctionsRadio.setActionCommand(QUERY_SIMILAR_FUNCTIONS);

        callContextRadio = new JRadioButton("Call Context");
        callContextRadio.setToolTipText("Get callers/callees with summaries");
        callContextRadio.setActionCommand(QUERY_CALL_CONTEXT);

        securityAnalysisRadio = new JRadioButton("Security Analysis");
        securityAnalysisRadio.setToolTipText("Security flags, taint paths, attack surface");
        securityAnalysisRadio.setActionCommand(QUERY_SECURITY_ANALYSIS);

        moduleSummaryRadio = new JRadioButton("Module Summary");
        moduleSummaryRadio.setToolTipText("Community/subsystem summary");
        moduleSummaryRadio.setActionCommand(QUERY_MODULE_SUMMARY);

        activityAnalysisRadio = new JRadioButton("Activity Analysis");
        activityAnalysisRadio.setToolTipText("Network/file I/O activity detection");
        activityAnalysisRadio.setActionCommand(QUERY_ACTIVITY_ANALYSIS);

        queryTypeGroup.add(semanticSearchRadio);
        queryTypeGroup.add(getAnalysisRadio);
        queryTypeGroup.add(similarFunctionsRadio);
        queryTypeGroup.add(callContextRadio);
        queryTypeGroup.add(securityAnalysisRadio);
        queryTypeGroup.add(moduleSummaryRadio);
        queryTypeGroup.add(activityAnalysisRadio);

        // Parameter fields
        queryField = new JTextField(30);
        addressField = new JTextField(20);
        limitSpinner = new JSpinner(new SpinnerNumberModel(20, 1, 100, 5));
        depthSpinner = new JSpinner(new SpinnerNumberModel(1, 1, 5, 1));
        directionCombo = new JComboBox<>(new String[]{"both", "callers", "callees"});
        scopeCombo = new JComboBox<>(new String[]{"function", "binary"});
        useCurrentAddressCheckbox = new JCheckBox("Use Current Address");
        executeButton = new JButton("Execute Query");

        // Parameter card layout
        paramsCardLayout = new CardLayout();
        paramsCardPanel = new JPanel(paramsCardLayout);

        // Results table
        String[] columns = {"#", "Function", "Address", "Score", "Summary"};
        resultsTableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        resultsTable = new JTable(resultsTableModel);
        resultsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        resultsTable.getColumnModel().getColumn(0).setPreferredWidth(30);
        resultsTable.getColumnModel().getColumn(1).setPreferredWidth(150);
        resultsTable.getColumnModel().getColumn(2).setPreferredWidth(100);
        resultsTable.getColumnModel().getColumn(3).setPreferredWidth(60);
        resultsTable.getColumnModel().getColumn(4).setPreferredWidth(300);

        tableSorter = new TableRowSorter<>(resultsTableModel);
        resultsTable.setRowSorter(tableSorter);

        resultsCountLabel = new JLabel("RESULTS (0 matches)");

        // Details panel components
        detailsFunctionLabel = new JLabel("Function: -");
        detailsFlagsLabel = new JLabel("Security Flags: -");
        detailsCallersLabel = new JLabel("Callers: -");
        detailsCalleesLabel = new JLabel("Callees: -");
        detailsSummaryArea = new JTextArea(4, 40);
        detailsSummaryArea.setEditable(false);
        detailsSummaryArea.setLineWrap(true);
        detailsSummaryArea.setWrapStyleWord(true);

        goToButton = new JButton("Go To");
        goToButton.setEnabled(false);
        copyButton = new JButton("Copy");
        copyButton.setEnabled(false);
    }

    private void layoutComponents() {
        setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // ===== Top: Query Type Selection =====
        JPanel queryTypePanel = new JPanel(new GridLayout(2, 4, 10, 5));
        queryTypePanel.setBorder(BorderFactory.createTitledBorder("Query Type"));
        queryTypePanel.add(semanticSearchRadio);
        queryTypePanel.add(getAnalysisRadio);
        queryTypePanel.add(similarFunctionsRadio);
        queryTypePanel.add(callContextRadio);
        queryTypePanel.add(securityAnalysisRadio);
        queryTypePanel.add(moduleSummaryRadio);
        queryTypePanel.add(activityAnalysisRadio);
        queryTypePanel.add(new JLabel("")); // Spacer

        // ===== Parameters Panel with CardLayout =====
        createParameterPanels();
        JPanel paramsWrapper = new JPanel(new BorderLayout());
        paramsWrapper.setBorder(BorderFactory.createTitledBorder("Parameters"));
        paramsWrapper.add(paramsCardPanel, BorderLayout.CENTER);

        // Execute button row
        JPanel executeRow = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        executeRow.add(useCurrentAddressCheckbox);
        executeRow.add(executeButton);
        paramsWrapper.add(executeRow, BorderLayout.SOUTH);

        // Top combined panel
        JPanel topPanel = new JPanel(new BorderLayout(5, 5));
        topPanel.add(queryTypePanel, BorderLayout.NORTH);
        topPanel.add(paramsWrapper, BorderLayout.CENTER);

        // ===== Middle: Results Table =====
        JPanel resultsPanel = new JPanel(new BorderLayout(5, 5));
        resultsPanel.setBorder(BorderFactory.createTitledBorder("Results"));
        resultsPanel.add(resultsCountLabel, BorderLayout.NORTH);
        resultsPanel.add(new JScrollPane(resultsTable), BorderLayout.CENTER);

        // ===== Bottom: Details Panel =====
        JPanel detailsPanel = new JPanel(new BorderLayout(5, 5));
        detailsPanel.setBorder(BorderFactory.createTitledBorder("Details"));

        JPanel detailsLabelsPanel = new JPanel(new GridLayout(4, 1, 2, 2));
        detailsLabelsPanel.add(detailsFunctionLabel);
        detailsLabelsPanel.add(detailsFlagsLabel);
        detailsLabelsPanel.add(detailsCallersLabel);
        detailsLabelsPanel.add(detailsCalleesLabel);

        JPanel detailsButtonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        detailsButtonPanel.add(goToButton);
        detailsButtonPanel.add(copyButton);

        detailsPanel.add(detailsLabelsPanel, BorderLayout.NORTH);
        detailsPanel.add(new JScrollPane(detailsSummaryArea), BorderLayout.CENTER);
        detailsPanel.add(detailsButtonPanel, BorderLayout.SOUTH);

        // ===== Split pane for results and details =====
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                resultsPanel, detailsPanel);
        splitPane.setResizeWeight(0.6);

        // Main layout
        add(topPanel, BorderLayout.NORTH);
        add(splitPane, BorderLayout.CENTER);
    }

    private void createParameterPanels() {
        // Semantic Search params
        JPanel semanticSearchParams = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        semanticSearchParams.add(new JLabel("Query:"));
        semanticSearchParams.add(queryField);
        semanticSearchParams.add(new JLabel("Limit:"));
        semanticSearchParams.add(limitSpinner);
        paramsCardPanel.add(semanticSearchParams, QUERY_SEMANTIC_SEARCH);

        // Get Analysis params
        JPanel getAnalysisParams = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        getAnalysisParams.add(new JLabel("Address:"));
        JTextField analysisAddrField = new JTextField(20);
        getAnalysisParams.add(analysisAddrField);
        paramsCardPanel.add(getAnalysisParams, QUERY_GET_ANALYSIS);

        // Similar Functions params
        JPanel similarParams = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        similarParams.add(new JLabel("Address:"));
        JTextField similarAddrField = new JTextField(20);
        similarParams.add(similarAddrField);
        similarParams.add(new JLabel("Limit:"));
        JSpinner similarLimitSpinner = new JSpinner(new SpinnerNumberModel(10, 1, 50, 5));
        similarParams.add(similarLimitSpinner);
        paramsCardPanel.add(similarParams, QUERY_SIMILAR_FUNCTIONS);

        // Call Context params
        JPanel callContextParams = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        callContextParams.add(new JLabel("Address:"));
        JTextField contextAddrField = new JTextField(20);
        callContextParams.add(contextAddrField);
        callContextParams.add(new JLabel("Depth:"));
        callContextParams.add(depthSpinner);
        callContextParams.add(new JLabel("Direction:"));
        callContextParams.add(directionCombo);
        paramsCardPanel.add(callContextParams, QUERY_CALL_CONTEXT);

        // Security Analysis params
        JPanel securityParams = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        securityParams.add(new JLabel("Address (optional):"));
        JTextField securityAddrField = new JTextField(20);
        securityParams.add(securityAddrField);
        securityParams.add(new JLabel("Scope:"));
        securityParams.add(scopeCombo);
        paramsCardPanel.add(securityParams, QUERY_SECURITY_ANALYSIS);

        // Module Summary params
        JPanel moduleParams = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        moduleParams.add(new JLabel("Address:"));
        JTextField moduleAddrField = new JTextField(20);
        moduleParams.add(moduleAddrField);
        paramsCardPanel.add(moduleParams, QUERY_MODULE_SUMMARY);

        // Activity Analysis params
        JPanel activityParams = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        activityParams.add(new JLabel("Address:"));
        JTextField activityAddrField = new JTextField(20);
        activityParams.add(activityAddrField);
        paramsCardPanel.add(activityParams, QUERY_ACTIVITY_ANALYSIS);

        // Store all address fields for "Use Current Address" feature
        // We'll use a shared addressField reference
    }

    private void setupListeners() {
        // Query type selection changes parameter panel
        semanticSearchRadio.addActionListener(e -> {
            paramsCardLayout.show(paramsCardPanel, QUERY_SEMANTIC_SEARCH);
            clearResults();
        });
        getAnalysisRadio.addActionListener(e -> {
            paramsCardLayout.show(paramsCardPanel, QUERY_GET_ANALYSIS);
            clearResults();
        });
        similarFunctionsRadio.addActionListener(e -> {
            paramsCardLayout.show(paramsCardPanel, QUERY_SIMILAR_FUNCTIONS);
            clearResults();
        });
        callContextRadio.addActionListener(e -> {
            paramsCardLayout.show(paramsCardPanel, QUERY_CALL_CONTEXT);
            clearResults();
        });
        securityAnalysisRadio.addActionListener(e -> {
            paramsCardLayout.show(paramsCardPanel, QUERY_SECURITY_ANALYSIS);
            clearResults();
        });
        moduleSummaryRadio.addActionListener(e -> {
            paramsCardLayout.show(paramsCardPanel, QUERY_MODULE_SUMMARY);
            clearResults();
        });
        activityAnalysisRadio.addActionListener(e -> {
            paramsCardLayout.show(paramsCardPanel, QUERY_ACTIVITY_ANALYSIS);
            clearResults();
        });

        // Execute button
        executeButton.addActionListener(e -> executeQuery());

        // Enter key in query field
        queryField.addActionListener(e -> executeQuery());

        // Use current address checkbox
        useCurrentAddressCheckbox.addActionListener(e -> {
            if (useCurrentAddressCheckbox.isSelected()) {
                long addr = parentTab.getCurrentAddress();
                String addrHex = "0x" + Long.toHexString(addr);
                updateAllAddressFields(addrHex);
            }
        });

        // Table row selection
        resultsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = resultsTable.getSelectedRow();
                if (selectedRow >= 0) {
                    int modelRow = resultsTable.convertRowIndexToModel(selectedRow);
                    showResultDetails(modelRow);
                }
            }
        });

        // Table double-click to navigate
        resultsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int selectedRow = resultsTable.getSelectedRow();
                    if (selectedRow >= 0) {
                        navigateToSelectedResult();
                    }
                }
            }
        });

        // Go To button
        goToButton.addActionListener(e -> navigateToSelectedResult());

        // Copy button
        copyButton.addActionListener(e -> copyDetailsToClipboard());
    }

    private void updateAllAddressFields(String address) {
        // Update the shared address field for all panels
        // Since we're using CardLayout, update visible fields
        for (Component comp : paramsCardPanel.getComponents()) {
            if (comp instanceof JPanel) {
                for (Component inner : ((JPanel) comp).getComponents()) {
                    if (inner instanceof JTextField && inner != queryField) {
                        ((JTextField) inner).setText(address);
                    }
                }
            }
        }
    }

    private void executeQuery() {
        String queryType = queryTypeGroup.getSelection().getActionCommand();
        executeButton.setEnabled(false);
        executeButton.setText("Executing...");

        // Build arguments based on query type
        JsonObject args = buildQueryArguments(queryType);
        if (args == null) {
            executeButton.setEnabled(true);
            executeButton.setText("Execute Query");
            return;
        }

        // Execute in background
        CompletableFuture.runAsync(() -> {
            try {
                controller.handleSemanticGraphSearchQuery(queryType, args, this::handleQueryResult);
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    showError("Query failed: " + e.getMessage());
                    executeButton.setEnabled(true);
                    executeButton.setText("Execute Query");
                });
            }
        });
    }

    private JsonObject buildQueryArguments(String queryType) {
        JsonObject args = new JsonObject();

        // Get the visible parameter panel
        Component visiblePanel = null;
        for (Component comp : paramsCardPanel.getComponents()) {
            if (comp.isVisible()) {
                visiblePanel = comp;
                break;
            }
        }

        switch (queryType) {
            case QUERY_SEMANTIC_SEARCH:
                String query = queryField.getText().trim();
                if (query.isEmpty()) {
                    showError("Please enter a search query");
                    return null;
                }
                args.addProperty("query", query);
                args.addProperty("limit", (Integer) limitSpinner.getValue());
                break;

            case QUERY_GET_ANALYSIS:
            case QUERY_MODULE_SUMMARY:
            case QUERY_ACTIVITY_ANALYSIS:
                String addr = getAddressFromPanel(visiblePanel);
                if (addr == null || addr.isEmpty()) {
                    addr = getCurrentAddressHex();
                }
                if (addr == null || addr.isEmpty()) {
                    showError("Please enter an address or use current address");
                    return null;
                }
                args.addProperty("address", addr);
                break;

            case QUERY_SIMILAR_FUNCTIONS:
                String simAddr = getAddressFromPanel(visiblePanel);
                if (simAddr == null || simAddr.isEmpty()) {
                    simAddr = getCurrentAddressHex();
                }
                if (simAddr == null || simAddr.isEmpty()) {
                    showError("Please enter an address");
                    return null;
                }
                args.addProperty("address", simAddr);
                args.addProperty("limit", getLimitFromPanel(visiblePanel, 10));
                break;

            case QUERY_CALL_CONTEXT:
                String ctxAddr = getAddressFromPanel(visiblePanel);
                if (ctxAddr == null || ctxAddr.isEmpty()) {
                    ctxAddr = getCurrentAddressHex();
                }
                if (ctxAddr == null || ctxAddr.isEmpty()) {
                    showError("Please enter an address");
                    return null;
                }
                args.addProperty("address", ctxAddr);
                args.addProperty("depth", (Integer) depthSpinner.getValue());
                args.addProperty("direction", (String) directionCombo.getSelectedItem());
                break;

            case QUERY_SECURITY_ANALYSIS:
                String secAddr = getAddressFromPanel(visiblePanel);
                if (secAddr != null && !secAddr.isEmpty()) {
                    args.addProperty("address", secAddr);
                }
                args.addProperty("scope", (String) scopeCombo.getSelectedItem());
                break;
        }

        return args;
    }

    private String getAddressFromPanel(Component panel) {
        if (panel instanceof JPanel) {
            for (Component comp : ((JPanel) panel).getComponents()) {
                if (comp instanceof JTextField && comp != queryField) {
                    return ((JTextField) comp).getText().trim();
                }
            }
        }
        return null;
    }

    private int getLimitFromPanel(Component panel, int defaultValue) {
        if (panel instanceof JPanel) {
            for (Component comp : ((JPanel) panel).getComponents()) {
                if (comp instanceof JSpinner) {
                    Object val = ((JSpinner) comp).getValue();
                    if (val instanceof Integer) {
                        return (Integer) val;
                    }
                }
            }
        }
        return defaultValue;
    }

    private String getCurrentAddressHex() {
        long addr = parentTab.getCurrentAddress();
        if (addr != 0) {
            return "0x" + Long.toHexString(addr);
        }
        return null;
    }

    /**
     * Handle query result callback.
     */
    public void handleQueryResult(String jsonResult) {
        SwingUtilities.invokeLater(() -> {
            executeButton.setEnabled(true);
            executeButton.setText("Execute Query");

            if (jsonResult == null || jsonResult.isEmpty()) {
                showError("Empty result");
                return;
            }

            try {
                // Check for error in JSON response
                JsonElement parsed = JsonParser.parseString(jsonResult);
                if (parsed.isJsonObject()) {
                    JsonObject obj = parsed.getAsJsonObject();
                    if (obj.has("error")) {
                        showError(obj.get("error").getAsString());
                        return;
                    }
                }

                parseAndDisplayResults(jsonResult);
            } catch (Exception e) {
                showError("Failed to parse results: " + e.getMessage());
            }
        });
    }

    private void parseAndDisplayResults(String jsonResult) {
        // Clear previous results
        resultsTableModel.setRowCount(0);
        lastResults = null;

        if (jsonResult == null || jsonResult.isEmpty()) {
            resultsCountLabel.setText("RESULTS (0 matches)");
            return;
        }

        JsonElement parsed = JsonParser.parseString(jsonResult);

        if (parsed.isJsonObject()) {
            JsonObject obj = parsed.getAsJsonObject();

            // Check for results array
            if (obj.has("results") && obj.get("results").isJsonArray()) {
                lastResults = obj.getAsJsonArray("results");
                populateResultsTable(lastResults);
            } else if (obj.has("matches") && obj.get("matches").isJsonArray()) {
                lastResults = obj.getAsJsonArray("matches");
                populateResultsTable(lastResults);
            } else {
                // Single result - wrap in array for table
                lastResults = new JsonArray();
                lastResults.add(obj);
                populateResultsTable(lastResults);
            }
        } else if (parsed.isJsonArray()) {
            lastResults = parsed.getAsJsonArray();
            populateResultsTable(lastResults);
        }
    }

    private void populateResultsTable(JsonArray results) {
        resultsTableModel.setRowCount(0);
        int count = 0;

        for (JsonElement elem : results) {
            if (elem.isJsonObject()) {
                JsonObject obj = elem.getAsJsonObject();
                count++;

                String funcName = getJsonString(obj, "function_name",
                        getJsonString(obj, "name", "Unknown"));
                String address = getJsonString(obj, "address", "-");
                String score = obj.has("score") ?
                        String.format("%.2f", obj.get("score").getAsDouble()) : "-";
                String summary = getJsonString(obj, "summary",
                        getJsonString(obj, "description", ""));
                if (summary.length() > 80) {
                    summary = summary.substring(0, 77) + "...";
                }

                resultsTableModel.addRow(new Object[]{count, funcName, address, score, summary});
            }
        }

        resultsCountLabel.setText("RESULTS (" + count + " matches)");

        // Select first row if available
        if (count > 0) {
            resultsTable.setRowSelectionInterval(0, 0);
        }
    }

    private void showResultDetails(int modelRow) {
        if (lastResults == null || modelRow >= lastResults.size()) {
            clearDetails();
            return;
        }

        JsonObject result = lastResults.get(modelRow).getAsJsonObject();

        String funcName = getJsonString(result, "function_name",
                getJsonString(result, "name", "Unknown"));
        String address = getJsonString(result, "address", "-");
        selectedAddress = address;

        detailsFunctionLabel.setText("Function: " + funcName + " @ " + address);

        // Security flags
        if (result.has("security_flags") && result.get("security_flags").isJsonArray()) {
            JsonArray flags = result.getAsJsonArray("security_flags");
            StringBuilder sb = new StringBuilder();
            for (JsonElement f : flags) {
                if (sb.length() > 0) sb.append(", ");
                sb.append(f.getAsString());
            }
            detailsFlagsLabel.setText("Security Flags: " + (sb.length() > 0 ? sb.toString() : "None"));
        } else {
            detailsFlagsLabel.setText("Security Flags: -");
        }

        // Callers
        if (result.has("callers")) {
            detailsCallersLabel.setText("Callers: " + formatFunctionList(result.get("callers")));
        } else {
            detailsCallersLabel.setText("Callers: -");
        }

        // Callees
        if (result.has("callees")) {
            detailsCalleesLabel.setText("Callees: " + formatFunctionList(result.get("callees")));
        } else {
            detailsCalleesLabel.setText("Callees: -");
        }

        // Summary
        String summary = getJsonString(result, "summary",
                getJsonString(result, "description", ""));
        detailsSummaryArea.setText(summary);
        detailsSummaryArea.setCaretPosition(0);

        goToButton.setEnabled(true);
        copyButton.setEnabled(true);
    }

    private String formatFunctionList(JsonElement element) {
        if (element.isJsonArray()) {
            JsonArray arr = element.getAsJsonArray();
            StringBuilder sb = new StringBuilder();
            int count = 0;
            for (JsonElement e : arr) {
                if (count > 0) sb.append(", ");
                if (count >= 5) {
                    sb.append("... (").append(arr.size() - 5).append(" more)");
                    break;
                }
                if (e.isJsonObject()) {
                    sb.append(getJsonString(e.getAsJsonObject(), "name",
                            getJsonString(e.getAsJsonObject(), "function_name", "?")));
                } else {
                    sb.append(e.getAsString());
                }
                count++;
            }
            return sb.toString();
        } else if (element.isJsonPrimitive()) {
            return element.getAsString();
        }
        return "-";
    }

    private void clearDetails() {
        selectedAddress = null;
        detailsFunctionLabel.setText("Function: -");
        detailsFlagsLabel.setText("Security Flags: -");
        detailsCallersLabel.setText("Callers: -");
        detailsCalleesLabel.setText("Callees: -");
        detailsSummaryArea.setText("");
        goToButton.setEnabled(false);
        copyButton.setEnabled(false);
    }

    private void clearResults() {
        resultsTableModel.setRowCount(0);
        resultsCountLabel.setText("RESULTS (0 matches)");
        lastResults = null;
        clearDetails();
    }

    private void navigateToSelectedResult() {
        if (selectedAddress != null && !selectedAddress.isEmpty() && !selectedAddress.equals("-")) {
            try {
                long addr;
                if (selectedAddress.startsWith("0x") || selectedAddress.startsWith("0X")) {
                    addr = Long.parseLong(selectedAddress.substring(2), 16);
                } else {
                    addr = Long.parseLong(selectedAddress, 16);
                }
                parentTab.navigateToFunction(addr);
            } catch (NumberFormatException e) {
                showError("Invalid address format: " + selectedAddress);
            }
        }
    }

    private void copyDetailsToClipboard() {
        StringBuilder sb = new StringBuilder();
        sb.append(detailsFunctionLabel.getText()).append("\n");
        sb.append(detailsFlagsLabel.getText()).append("\n");
        sb.append(detailsCallersLabel.getText()).append("\n");
        sb.append(detailsCalleesLabel.getText()).append("\n\n");
        sb.append("Summary:\n").append(detailsSummaryArea.getText());

        StringSelection selection = new StringSelection(sb.toString());
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);
    }

    private String getJsonString(JsonObject obj, String key, String defaultValue) {
        if (obj.has(key) && !obj.get(key).isJsonNull()) {
            return obj.get(key).getAsString();
        }
        return defaultValue;
    }

    private void showError(String message) {
        JOptionPane.showMessageDialog(this, message, "Error", JOptionPane.ERROR_MESSAGE);
    }

    /**
     * Refresh the panel when the tab becomes visible.
     */
    public void refresh() {
        // Update address field if "use current" is checked
        if (useCurrentAddressCheckbox.isSelected()) {
            long addr = parentTab.getCurrentAddress();
            String addrHex = "0x" + Long.toHexString(addr);
            updateAllAddressFields(addrHex);
        }
    }
}
