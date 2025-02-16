package ghidrassist.ui.tabs;

import javax.swing.*;
import java.awt.*;
import ghidrassist.ui.common.UIConstants;
import ghidrassist.ui.common.PlaceholderTextField;
import ghidrassist.core.TabController;

public class ExplainTab extends JPanel {
    private final TabController controller;
    private JTextField offsetField;
    private JEditorPane explainTextPane;
    private JButton explainFunctionButton;
    private JButton explainLineButton;
    private JButton clearExplainButton;

    public ExplainTab(TabController controller) {
        super(new BorderLayout());
        this.controller = controller;
        initializeComponents();
        layoutComponents();
        setupListeners();
    }

    private void initializeComponents() {
        // Initialize offset field
        JLabel offsetLabel = new JLabel("Offset: ");
        offsetField = new JTextField(16);
        offsetField.setEditable(false);

        // Initialize text pane
        explainTextPane = new JEditorPane();
        explainTextPane.setEditable(false);
        explainTextPane.setContentType("text/html");
        explainTextPane.addHyperlinkListener(controller::handleHyperlinkEvent);

        // Initialize buttons
        explainFunctionButton = new JButton("Explain Function");
        explainLineButton = new JButton("Explain Line");
        clearExplainButton = new JButton("Clear");
    }

    private void layoutComponents() {
        // Offset panel
        JPanel offsetPanel = new JPanel();
        offsetPanel.add(new JLabel("Offset: "));
        offsetPanel.add(offsetField);
        add(offsetPanel, BorderLayout.NORTH);

        // Text pane with scroll
        JScrollPane scrollPane = new JScrollPane(explainTextPane);
        add(scrollPane, BorderLayout.CENTER);

        // Button panel
        JPanel buttonPanel = new JPanel();
        buttonPanel.add(explainFunctionButton);
        buttonPanel.add(explainLineButton);
        buttonPanel.add(clearExplainButton);
        add(buttonPanel, BorderLayout.SOUTH);
    }

    private void setupListeners() {
        explainFunctionButton.addActionListener(e -> controller.handleExplainFunction());
        explainLineButton.addActionListener(e -> controller.handleExplainLine());
        clearExplainButton.addActionListener(e -> explainTextPane.setText(""));
    }

    public void updateOffset(String offset) {
        offsetField.setText(offset);
    }

    public void setExplanationText(String text) {
        explainTextPane.setText(text);
        explainTextPane.setCaretPosition(0);
    }

    public void setFunctionButtonText(String text) {
        explainFunctionButton.setText(text);
    }

    public void setLineButtonText(String text) {
        explainLineButton.setText(text);
    }
}
