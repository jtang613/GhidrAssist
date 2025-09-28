package ghidrassist.ui.tabs;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.JTableHeader;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
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
    private JCheckBox selectAllCheckBox;

    public ActionsTab(TabController controller) {
        super(new BorderLayout());
        this.controller = controller;
        initializeComponents();
        layoutComponents();
        setupListeners();
    }

    private void initializeComponents() {
        // Initialize select all checkbox
        selectAllCheckBox = new JCheckBox();

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
        // Set a reasonable preferred width for the Select column while allowing it to be resizable
        table.getColumnModel().getColumn(0).setPreferredWidth(60);

        // Set up custom header renderer for the Select column
        setupSelectAllHeader(table);

        // Add table model listener to update header checkbox state when individual selections change
        model.addTableModelListener(e -> {
            // Only update for changes to the Select column (column 0)
            if (e.getColumn() == 0 || e.getColumn() == javax.swing.event.TableModelEvent.ALL_COLUMNS) {
                SwingUtilities.invokeLater(this::updateSelectAllCheckboxState);
            }
        });

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

    private void setupSelectAllHeader(JTable table) {
        // Create custom header renderer for the Select column
        TableCellRenderer headerRenderer = new TableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                    boolean isSelected, boolean hasFocus, int row, int column) {
                if (column == 0) {
                    // Return checkbox for Select column header
                    selectAllCheckBox.setText("Select");
                    selectAllCheckBox.setHorizontalAlignment(SwingConstants.CENTER);
                    return selectAllCheckBox;
                } else {
                    // Use default renderer for other columns
                    return table.getTableHeader().getDefaultRenderer()
                        .getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                }
            }
        };

        // Set the custom renderer for the Select column
        table.getColumnModel().getColumn(0).setHeaderRenderer(headerRenderer);

        // Add mouse listener to handle header checkbox clicks
        table.getTableHeader().addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                JTableHeader header = (JTableHeader) e.getSource();
                int columnIndex = header.columnAtPoint(e.getPoint());

                // Only handle clicks on the Select column
                if (columnIndex == 0) {
                    boolean currentState = selectAllCheckBox.isSelected();
                    selectAllCheckBox.setSelected(!currentState);
                    toggleAllRowSelections(!currentState);
                    header.repaint();
                }
            }
        });
    }

    private void toggleAllRowSelections(boolean selectAll) {
        DefaultTableModel model = (DefaultTableModel) actionsTable.getModel();
        for (int row = 0; row < model.getRowCount(); row++) {
            model.setValueAt(selectAll, row, 0);
        }
        actionsTable.repaint();
    }

    public void updateSelectAllCheckboxState() {
        DefaultTableModel model = (DefaultTableModel) actionsTable.getModel();
        if (model.getRowCount() == 0) {
            selectAllCheckBox.setSelected(false);
            return;
        }

        boolean allSelected = true;
        boolean noneSelected = true;

        for (int row = 0; row < model.getRowCount(); row++) {
            Boolean value = (Boolean) model.getValueAt(row, 0);
            boolean isSelected = value != null && value;

            if (!isSelected) {
                allSelected = false;
            } else {
                noneSelected = false;
            }
        }

        if (allSelected) {
            selectAllCheckBox.setSelected(true);
        } else if (noneSelected) {
            selectAllCheckBox.setSelected(false);
        } else {
            // Mixed state - we'll show as unselected but could be enhanced to show indeterminate state
            selectAllCheckBox.setSelected(false);
        }

        actionsTable.getTableHeader().repaint();
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
        analyzeClearButton.addActionListener(e -> {
            ((DefaultTableModel)actionsTable.getModel()).setRowCount(0);
            updateSelectAllCheckboxState();
        });
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
