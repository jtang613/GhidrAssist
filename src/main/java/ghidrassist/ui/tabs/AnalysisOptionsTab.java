package ghidrassist.ui.tabs;

import javax.swing.*;
import java.awt.*;
import ghidrassist.core.TabController;

public class AnalysisOptionsTab extends JPanel {
    private static final String VERSION = "1.3.0";
    private static final String[] REASONING_EFFORT_OPTIONS = {"None", "Low", "Medium", "High"};

    private final TabController controller;
    private JTextArea contextArea;
    private JButton saveButton;
    private JButton revertButton;
    private JComboBox<String> reasoningEffortCombo;

    public AnalysisOptionsTab(TabController controller) {
        super(new BorderLayout());
        this.controller = controller;
        initializeComponents();
        layoutComponents();
        setupListeners();
        loadReasoningEffort(); // Load saved reasoning effort
    }

    private void initializeComponents() {
        contextArea = new JTextArea();
        contextArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        contextArea.setLineWrap(true);
        contextArea.setWrapStyleWord(true);

        saveButton = new JButton("Save");
        revertButton = new JButton("Revert");

        // Reasoning effort dropdown
        reasoningEffortCombo = new JComboBox<>(REASONING_EFFORT_OPTIONS);
        reasoningEffortCombo.setSelectedItem("None");
        reasoningEffortCombo.setToolTipText("Set reasoning/thinking effort level for supported models (o1, o3, gpt-oss, Claude with thinking, etc.)");
    }

    private void layoutComponents() {
        // Reasoning effort panel at the top
        JPanel reasoningPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        JLabel reasoningLabel = new JLabel("Reasoning Effort:");
        reasoningPanel.add(reasoningLabel);
        reasoningPanel.add(reasoningEffortCombo);
        reasoningPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        add(reasoningPanel, BorderLayout.NORTH);

        // Center panel with System Context label and text area
        JPanel centerPanel = new JPanel(new BorderLayout());

        // System Context label
        JLabel headerLabel = new JLabel("System Context");
        headerLabel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        centerPanel.add(headerLabel, BorderLayout.NORTH);

        // Text area with scroll pane
        JScrollPane scrollPane = new JScrollPane(contextArea);
        centerPanel.add(scrollPane, BorderLayout.CENTER);

        add(centerPanel, BorderLayout.CENTER);

        // Bottom panel with version and buttons
        JPanel bottomPanel = new JPanel(new BorderLayout());

        // Version label on the left
        JLabel versionLabel = new JLabel("GhidrAssist v" + VERSION);
        versionLabel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 5));
        bottomPanel.add(versionLabel, BorderLayout.WEST);

        // Buttons on the right
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonPanel.add(revertButton);
        buttonPanel.add(saveButton);
        bottomPanel.add(buttonPanel, BorderLayout.EAST);

        add(bottomPanel, BorderLayout.SOUTH);
    }

    private void setupListeners() {
        saveButton.addActionListener(e -> controller.handleContextSave(contextArea.getText()));
        revertButton.addActionListener(e -> controller.handleContextRevert());

        // Reasoning effort selection listener
        reasoningEffortCombo.addActionListener(e -> {
            String selectedEffort = (String) reasoningEffortCombo.getSelectedItem();
            controller.setReasoningEffort(selectedEffort);
        });
    }

    public void setContextText(String text) {
        contextArea.setText(text);
    }

    /**
     * Load the saved reasoning effort from the controller and update the dropdown.
     * Called when the tab is initialized or when the program changes.
     */
    public void loadReasoningEffort() {
        String savedEffort = controller.getReasoningEffort();
        if (savedEffort != null) {
            reasoningEffortCombo.setSelectedItem(savedEffort);
        }
    }
}
