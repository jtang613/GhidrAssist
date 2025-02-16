package ghidrassist.ui.tabs;

import javax.swing.*;
import java.awt.*;
import ghidrassist.core.TabController;

public class QueryTab extends JPanel {
    private static final long serialVersionUID = 1L;
	private final TabController controller;
    private JEditorPane responseTextPane;
    private JTextArea queryTextArea;
    private JCheckBox useRAGCheckBox;
    private JButton submitButton;
    private JButton clearButton;
    private static final String QUERY_HINT_TEXT = 
        "#line to include the current disassembly line.\n" +
        "#func to include current function disassembly.\n" +
        "#addr to include the current hex address.\n" +
        "#range(start, end) to include the view data in a given range.";

    public QueryTab(TabController controller) {
        super(new BorderLayout());
        this.controller = controller;
        
        // Initialize components with optimized settings
        responseTextPane = new JEditorPane();
        responseTextPane.setEditable(false);
        responseTextPane.setContentType("text/html");
        responseTextPane.addHyperlinkListener(controller::handleHyperlinkEvent);
        responseTextPane.putClientProperty("JEditorPane.w3cLengthUnits", Boolean.TRUE);
        responseTextPane.putClientProperty("JEditorPane.honorDisplayProperties", Boolean.TRUE);
        
        // Enable double buffering for smoother updates
        responseTextPane.setDoubleBuffered(true);
        
        initializeComponents();
        layoutComponents();
        setupListeners();
    }

    private void initializeComponents() {
        useRAGCheckBox = new JCheckBox("Use RAG");
        useRAGCheckBox.setSelected(false);

        responseTextPane = new JEditorPane();
        responseTextPane.setEditable(false);
        responseTextPane.setContentType("text/html");
        responseTextPane.addHyperlinkListener(controller::handleHyperlinkEvent);

        queryTextArea = new JTextArea();
        queryTextArea.setRows(4);
        addHintTextToQueryTextArea();

        submitButton = new JButton("Submit");
        clearButton = new JButton("Clear");
    }

    private void layoutComponents() {
        add(useRAGCheckBox, BorderLayout.NORTH);

        JScrollPane responseScrollPane = new JScrollPane(responseTextPane);
        JScrollPane queryScrollPane = new JScrollPane(queryTextArea);
        
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, 
            responseScrollPane, queryScrollPane);
        splitPane.setResizeWeight(0.9);
        add(splitPane, BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel();
        buttonPanel.add(submitButton);
        buttonPanel.add(clearButton);
        add(buttonPanel, BorderLayout.SOUTH);
    }

    private void setupListeners() {
        submitButton.addActionListener(e -> controller.handleQuerySubmit(
            queryTextArea.getText(),
            useRAGCheckBox.isSelected()
        ));

        clearButton.addActionListener(e -> {
            responseTextPane.setText("");
            queryTextArea.setText("");
            addHintTextToQueryTextArea();
            controller.clearConversationHistory();
        });
    }

    private void addHintTextToQueryTextArea() {
        Color fgColor = queryTextArea.getForeground();
        queryTextArea.setText(QUERY_HINT_TEXT);
        queryTextArea.setForeground(Color.GRAY);
        
        queryTextArea.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override
            public void focusGained(java.awt.event.FocusEvent e) {
                if (queryTextArea.getText().equals(QUERY_HINT_TEXT)) {
                    queryTextArea.setText("");
                    queryTextArea.setForeground(fgColor);
                }
            }

            @Override
            public void focusLost(java.awt.event.FocusEvent e) {
                if (queryTextArea.getText().isEmpty()) {
                    queryTextArea.setForeground(Color.GRAY);
                    queryTextArea.setText(QUERY_HINT_TEXT);
                }
            }
        });
    }

    public void setResponseText(String text) {
        responseTextPane.setText(text);
        responseTextPane.setCaretPosition(responseTextPane.getDocument().getLength());
    }

    public void appendToResponse(String html) {
        // Only scroll if we're already at the bottom
        JScrollPane scrollPane = (JScrollPane) responseTextPane.getParent().getParent();
        JScrollBar vertical = scrollPane.getVerticalScrollBar();
        boolean shouldScroll = (vertical.getValue() + vertical.getVisibleAmount() == vertical.getMaximum());
        
        responseTextPane.setText(html);
        
        // Maintain scroll position if we were at the bottom
        if (shouldScroll) {
            SwingUtilities.invokeLater(() -> {
                vertical.setValue(vertical.getMaximum());
            });
        }
    }
    
    public void setSubmitButtonText(String text) {
        submitButton.setText(text);
    }
}
