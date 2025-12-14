package ghidrassist.ui.tabs;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import ghidrassist.core.RAGDocumentInfo;
import ghidrassist.core.SearchResult;
import ghidrassist.core.TabController;

import java.util.List;

public class RAGManagementTab extends JPanel {
    private static final long serialVersionUID = 1L;
    private final TabController controller;

    // Document Management section
    private JTable documentTable;
    private DefaultTableModel documentTableModel;
    private JLabel statsLabel;
    private JButton addButton;
    private JButton refreshButton;
    private JButton deleteButton;
    private JButton clearIndexButton;

    // Search Documents section
    private JTextField queryField;
    private JComboBox<String> searchTypeCombo;
    private JButton searchButton;
    private JLabel resultsHeaderLabel;
    private JPanel resultsPanel;

    // Split pane
    private JSplitPane mainSplitPane;

    public RAGManagementTab(TabController controller) {
        super(new BorderLayout());
        this.controller = controller;
        initializeComponents();
        layoutComponents();
        setupListeners();
    }

    private void initializeComponents() {
        // Document Management components
        addButton = new JButton("Add Documents");
        refreshButton = new JButton("Refresh");
        deleteButton = new JButton("Delete");
        clearIndexButton = new JButton("Clear Index");
        statsLabel = new JLabel("Documents: 0 | Chunks: 0 | Embeddings: 0");

        // Document table
        documentTableModel = new DefaultTableModel(new Object[]{"Name", "Size", "Chunks"}, 0) {
            private static final long serialVersionUID = 1L;
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        documentTable = new JTable(documentTableModel);
        documentTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        documentTable.setRowHeight(20);
        documentTable.getColumnModel().getColumn(0).setPreferredWidth(200);
        documentTable.getColumnModel().getColumn(1).setPreferredWidth(80);
        documentTable.getColumnModel().getColumn(2).setPreferredWidth(60);

        // Search components
        queryField = new JTextField(20);
        searchTypeCombo = new JComboBox<>(new String[]{"Hybrid", "Semantic", "Keyword"});
        searchButton = new JButton("Search");
        resultsHeaderLabel = new JLabel(" ");
        resultsPanel = new JPanel();
        resultsPanel.setLayout(new BoxLayout(resultsPanel, BoxLayout.Y_AXIS));
    }

    private void layoutComponents() {
        // === TOP SECTION: Document Management ===
        JPanel documentManagementPanel = new JPanel(new BorderLayout());

        // Section header
        JLabel docHeader = new JLabel("Document Management");
        docHeader.setFont(docHeader.getFont().deriveFont(Font.BOLD));
        docHeader.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // Toolbar row: Add button + stats
        JPanel toolbarPanel = new JPanel(new BorderLayout());
        toolbarPanel.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 5));
        toolbarPanel.add(addButton, BorderLayout.WEST);
        toolbarPanel.add(statsLabel, BorderLayout.EAST);

        // Top section (header + toolbar)
        JPanel docTopPanel = new JPanel(new BorderLayout());
        docTopPanel.add(docHeader, BorderLayout.NORTH);
        docTopPanel.add(toolbarPanel, BorderLayout.SOUTH);

        // Bottom buttons
        JPanel docButtonPanel = new JPanel(new BorderLayout());
        docButtonPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        JPanel leftButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        leftButtons.add(refreshButton);
        leftButtons.add(deleteButton);
        JPanel rightButtons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
        rightButtons.add(clearIndexButton);
        docButtonPanel.add(leftButtons, BorderLayout.WEST);
        docButtonPanel.add(rightButtons, BorderLayout.EAST);

        // Assemble document management panel
        documentManagementPanel.add(docTopPanel, BorderLayout.NORTH);
        documentManagementPanel.add(new JScrollPane(documentTable), BorderLayout.CENTER);
        documentManagementPanel.add(docButtonPanel, BorderLayout.SOUTH);

        // === BOTTOM SECTION: Search Documents ===
        JPanel searchPanel = new JPanel(new BorderLayout());

        // Section header
        JLabel searchHeader = new JLabel("Search Documents");
        searchHeader.setFont(searchHeader.getFont().deriveFont(Font.BOLD));
        searchHeader.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // Search controls row
        JPanel searchControlsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        searchControlsPanel.add(new JLabel("Query:"));
        searchControlsPanel.add(queryField);
        searchControlsPanel.add(new JLabel("Type:"));
        searchControlsPanel.add(searchTypeCombo);
        searchControlsPanel.add(searchButton);

        // Top section (header + controls)
        JPanel searchTopPanel = new JPanel(new BorderLayout());
        searchTopPanel.add(searchHeader, BorderLayout.NORTH);
        searchTopPanel.add(searchControlsPanel, BorderLayout.SOUTH);

        // Results container
        resultsHeaderLabel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        resultsHeaderLabel.setFont(resultsHeaderLabel.getFont().deriveFont(Font.BOLD));

        JPanel resultsContainer = new JPanel(new BorderLayout());
        resultsContainer.add(resultsHeaderLabel, BorderLayout.NORTH);
        JScrollPane resultsScrollPane = new JScrollPane(resultsPanel);
        resultsScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        resultsContainer.add(resultsScrollPane, BorderLayout.CENTER);

        // Assemble search panel
        searchPanel.add(searchTopPanel, BorderLayout.NORTH);
        searchPanel.add(resultsContainer, BorderLayout.CENTER);

        // === MAIN SPLIT ===
        mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                documentManagementPanel, searchPanel);
        mainSplitPane.setResizeWeight(0.6);

        // Set divider location to 60% after component is shown
        addHierarchyListener(e -> {
            if ((e.getChangeFlags() & java.awt.event.HierarchyEvent.SHOWING_CHANGED) != 0 && isShowing()) {
                SwingUtilities.invokeLater(() -> {
                    mainSplitPane.setDividerLocation(0.6);
                });
            }
        });

        add(mainSplitPane, BorderLayout.CENTER);
    }

    private void setupListeners() {
        addButton.addActionListener(e -> controller.handleAddDocuments());
        deleteButton.addActionListener(e -> {
            int selectedRow = documentTable.getSelectedRow();
            if (selectedRow >= 0) {
                String filename = (String) documentTableModel.getValueAt(selectedRow, 0);
                controller.handleDeleteDocument(filename);
            }
        });
        refreshButton.addActionListener(e -> controller.refreshRAGDocuments());
        clearIndexButton.addActionListener(e -> controller.handleClearIndex());
        searchButton.addActionListener(e -> {
            String query = queryField.getText().trim();
            String searchType = (String) searchTypeCombo.getSelectedItem();
            if (!query.isEmpty()) {
                controller.handleRAGSearch(query, searchType, this);
            }
        });

        // Allow Enter key to trigger search
        queryField.addActionListener(e -> searchButton.doClick());
    }

    /**
     * Update the document table with document info.
     */
    public void updateDocumentTable(List<RAGDocumentInfo> docs) {
        documentTableModel.setRowCount(0);
        for (RAGDocumentInfo doc : docs) {
            documentTableModel.addRow(new Object[]{
                    doc.getFilename(),
                    doc.getFormattedSize(),
                    doc.getChunkCount()
            });
        }
    }

    /**
     * Update the statistics label.
     */
    public void updateStats(int docCount, int chunkCount, int embeddingCount) {
        statsLabel.setText(String.format("Documents: %d | Chunks: %d | Embeddings: %d",
                docCount, chunkCount, embeddingCount));
    }

    /**
     * Display search results.
     */
    public void displaySearchResults(String query, List<SearchResult> results, String searchType) {
        resultsPanel.removeAll();

        if (results.isEmpty()) {
            resultsHeaderLabel.setText(String.format("Search Results for '%s' (0 found)", query));
            JLabel noResults = new JLabel("No results found.");
            noResults.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
            resultsPanel.add(noResults);
        } else {
            resultsHeaderLabel.setText(String.format("Search Results for '%s' (%d found)", query, results.size()));

            for (int i = 0; i < results.size(); i++) {
                SearchResult result = results.get(i);
                JPanel resultPanel = createResultPanel(i + 1, result, searchType);
                resultsPanel.add(resultPanel);
            }
        }

        resultsPanel.revalidate();
        resultsPanel.repaint();
    }

    /**
     * Create a panel for a single search result.
     */
    private JPanel createResultPanel(int index, SearchResult result, String searchType) {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY),
                BorderFactory.createEmptyBorder(5, 5, 5, 5)
        ));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Title: "1. filename.c"
        JLabel titleLabel = new JLabel(index + ". " + result.getFilename());
        titleLabel.setForeground(new Color(0, 102, 204)); // Blue color
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD));
        titleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Metadata: "Score: 60% | Type: hybrid | Chunk: 7"
        String meta = String.format("Score: %.0f%% | Type: %s | Chunk: %d",
                result.getScore() * 100, searchType.toLowerCase(), result.getChunkId());
        JLabel metaLabel = new JLabel(meta);
        metaLabel.setFont(metaLabel.getFont().deriveFont(Font.PLAIN, 10f));
        metaLabel.setForeground(Color.GRAY);
        metaLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Content preview (truncated)
        String snippet = result.getSnippet();
        if (snippet != null && snippet.length() > 150) {
            snippet = snippet.substring(0, 150) + "...";
        }
        // Replace newlines with spaces for display
        if (snippet != null) {
            snippet = snippet.replace("\n", " ").replace("\r", "");
        }
        JLabel contentLabel = new JLabel("<html>" + escapeHtml(snippet != null ? snippet : "") + "</html>");
        contentLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        contentLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        panel.add(titleLabel);
        panel.add(Box.createVerticalStrut(2));
        panel.add(metaLabel);
        panel.add(Box.createVerticalStrut(2));
        panel.add(contentLabel);

        // Set max width
        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, panel.getPreferredSize().height + 20));

        return panel;
    }

    /**
     * Escape HTML special characters.
     */
    private String escapeHtml(String text) {
        return text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }

    /**
     * Clear search results.
     */
    public void clearSearchResults() {
        resultsHeaderLabel.setText(" ");
        resultsPanel.removeAll();
        resultsPanel.revalidate();
        resultsPanel.repaint();
    }

    /**
     * Get the document table for external access.
     */
    public JTable getDocumentTable() {
        return documentTable;
    }

    /**
     * Get selected document filename.
     */
    public String getSelectedDocument() {
        int selectedRow = documentTable.getSelectedRow();
        if (selectedRow >= 0) {
            return (String) documentTableModel.getValueAt(selectedRow, 0);
        }
        return null;
    }
}
