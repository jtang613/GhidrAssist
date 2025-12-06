package ghidrassist.ui.tabs;

import javax.swing.*;
import java.awt.*;
import ghidrassist.core.TabController;

public class AnalysisOptionsTab extends JPanel {
    private static final String VERSION = "1.2.0";

    private final TabController controller;
    private JTextArea contextArea;
    private JButton saveButton;
    private JButton revertButton;

    public AnalysisOptionsTab(TabController controller) {
        super(new BorderLayout());
        this.controller = controller;
        initializeComponents();
        layoutComponents();
        setupListeners();
    }

    private void initializeComponents() {
        contextArea = new JTextArea();
        contextArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        contextArea.setLineWrap(true);
        contextArea.setWrapStyleWord(true);
        
        saveButton = new JButton("Save");
        revertButton = new JButton("Revert");
    }

    private void layoutComponents() {
        // Add header label
        JLabel headerLabel = new JLabel("System Context");
        headerLabel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        add(headerLabel, BorderLayout.NORTH);

        // Add text area with scroll pane
        JScrollPane scrollPane = new JScrollPane(contextArea);
        add(scrollPane, BorderLayout.CENTER);

        // Add bottom panel with version and buttons
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
    }

    public void setContextText(String text) {
        contextArea.setText(text);
    }
}
