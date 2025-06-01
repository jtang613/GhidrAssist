package ghidrassist.ui.tabs;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.Map;
import java.util.HashMap;
import ghidrassist.core.TabController;
import ghidrassist.core.ActionConstants;

public class ActionsTab extends JPanel {
    private static final long serialVersionUID = 1L;
	private final TabController controller;
    private JTable actionsTable;
    private Map<String, JCheckBox> filterCheckBoxes;
    private JButton analyzeFunctionButton;
    private JButton analyzeClearButton;
    private JButton applyActionsButton;

    public ActionsTab(TabController controller) {
        super(new BorderLayout());
        this.controller = controller;
        initializeComponents();
        layoutComponents();
        setupListeners();
    }

    private void initializeComponents() {
        // Initialize table
        actionsTable = createActionsTable();
        
        // Initialize filter checkboxes
        filterCheckBoxes = createFilterCheckboxes();
        
        // Initialize buttons
        analyzeFunctionButton = new JButton("Analyze Function");
        analyzeClearButton = new JButton("Clear");
        applyActionsButton = new JButton("Apply Actions");
    }

    private JTable createActionsTable() {
        DefaultTableModel model = new DefaultTableModel(
            new Object[]{"Select", "Action", "Description", "Status", "Arguments"}, 0) {
            private static final long serialVersionUID = 1L;

			@Override
            public Class<?> getColumnClass(int column) {
                return column == 0 ? Boolean.class : String.class;
            }
        };
        
        JTable table = new JTable(model);
        int w = table.getColumnModel().getColumn(0).getWidth();
        table.getColumnModel().getColumn(0).setMaxWidth((int)((double) (w*0.8)));
        return table;
    }

    private Map<String, JCheckBox> createFilterCheckboxes() {
        Map<String, JCheckBox> checkboxes = new HashMap<>();
        for (Map<String, Object> fnTemplate : ActionConstants.FN_TEMPLATES) {
            if (fnTemplate.get("type").equals("function")) {
                @SuppressWarnings("unchecked")
                Map<String, Object> functionMap = (Map<String, Object>) fnTemplate.get("function");
                String fnName = functionMap.get("name").toString();
                String fnDescription = functionMap.get("description").toString();
                String checkboxLabel = fnName.replace("_", " ") + ": " + fnDescription;
                checkboxes.put(fnName, new JCheckBox(checkboxLabel, true));
            }
        }
        return checkboxes;
    }

    private void layoutComponents() {
        // Filter panel
        JPanel filterPanel = new JPanel();
        filterPanel.setLayout(new BoxLayout(filterPanel, BoxLayout.Y_AXIS));
        filterPanel.setBorder(BorderFactory.createTitledBorder("Filters"));
        filterCheckBoxes.values().forEach(filterPanel::add);
        
        JScrollPane filterScrollPane = new JScrollPane(filterPanel);
        filterScrollPane.setPreferredSize(new Dimension(200, 150));
        add(filterScrollPane, BorderLayout.NORTH);

        // Table
        add(new JScrollPane(actionsTable), BorderLayout.CENTER);

        // Buttons
        JPanel buttonPanel = new JPanel();
        buttonPanel.add(analyzeFunctionButton);
        buttonPanel.add(analyzeClearButton);
        buttonPanel.add(applyActionsButton);
        add(buttonPanel, BorderLayout.SOUTH);
    }

    private void setupListeners() {
        analyzeFunctionButton.addActionListener(e -> 
            controller.handleAnalyzeFunction(filterCheckBoxes));
        analyzeClearButton.addActionListener(e -> 
            ((DefaultTableModel)actionsTable.getModel()).setRowCount(0));
        applyActionsButton.addActionListener(e -> 
            controller.handleApplyActions(actionsTable));
    }

    public DefaultTableModel getTableModel() {
        return (DefaultTableModel)actionsTable.getModel();
    }

    public void setAnalyzeFunctionButtonText(String text) {
        analyzeFunctionButton.setText(text);
    }
}
