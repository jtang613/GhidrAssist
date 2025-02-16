package ghidrassist.ui.tabs;

import javax.swing.*;
import java.awt.*;
import ghidrassist.core.TabController;

public class RAGManagementTab extends JPanel {
    private static final long serialVersionUID = 1L;
	private final TabController controller;
    private JList<String> documentList;
    private JButton addDocumentsButton;
    private JButton deleteSelectedButton;
    private JButton refreshListButton;

    public RAGManagementTab(TabController controller) {
        super(new BorderLayout());
        this.controller = controller;
        initializeComponents();
        layoutComponents();
        setupListeners();
    }

    private void initializeComponents() {
        addDocumentsButton = new JButton("Add Documents to RAG");
        documentList = new JList<>();
        deleteSelectedButton = new JButton("Delete Selected");
        refreshListButton = new JButton("Refresh List");
    }

    private void layoutComponents() {
        add(addDocumentsButton, BorderLayout.NORTH);
        add(new JScrollPane(documentList), BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel();
        buttonPanel.add(deleteSelectedButton);
        buttonPanel.add(refreshListButton);
        add(buttonPanel, BorderLayout.SOUTH);
    }

    private void setupListeners() {
        addDocumentsButton.addActionListener(e -> 
            controller.handleAddDocuments(documentList));
        deleteSelectedButton.addActionListener(e -> 
            controller.handleDeleteSelected(documentList));
        refreshListButton.addActionListener(e -> 
            controller.loadIndexedFiles(documentList));
    }

    public void updateDocumentList(String[] files) {
        documentList.setListData(files);
    }
    
    public JList<String> getDocumentList() {
        return documentList;
    }
}
