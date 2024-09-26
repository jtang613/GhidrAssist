package ghidrassist;

import docking.DialogComponentProvider;
import ghidra.framework.preferences.Preferences;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.File;
import java.lang.reflect.Type;
import java.util.List;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

public class SettingsDialog extends DialogComponentProvider {

    private DefaultTableModel tableModel;
    private JTable table;
    private JComboBox<String> activeProviderComboBox;
    private List<APIProvider> apiProviders;
    private String selectedProviderName;

    // Components for RLHF Database Path
    private JTextField rlhfDbPathField;
    private JButton rlhfDbBrowseButton;
    
    // Components for the RAG index path
    private JTextField luceneIndexPathField;
    private JButton luceneIndexBrowseButton;

    public SettingsDialog(Component parent, String title) {
        super(title, true, false, true, false);

        // Load the list of API providers from preferences
        String providersJson = Preferences.getProperty("GhidrAssist.APIProviders", "[]");
        Gson gson = new Gson();
        Type listType = new TypeToken<List<APIProvider>>() {}.getType();
        apiProviders = gson.fromJson(providersJson, listType);

        // Load the selected provider name
        selectedProviderName = Preferences.getProperty("GhidrAssist.SelectedAPIProvider", "");

        // Load the RLHF database path
        String rlhfDbPath = Preferences.getProperty("GhidrAssist.RLHFDatabasePath", "ghidrassist_rlhf.db");

        // Load the Lucene index path
        String luceneIndexPath = Preferences.getProperty("GhidrAssist.LuceneIndexPath", "");

        // Initialize the UI components
        JPanel panel = new JPanel(new BorderLayout());

        // Create the table
        String[] columnNames = {"Name", "Model", "Max Tokens", "URL", "Key"};
        tableModel = new DefaultTableModel(columnNames, 0);
        table = new JTable(tableModel);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        // Populate the table model with the data
        for (APIProvider provider : apiProviders) {
            tableModel.addRow(new Object[] {
                provider.getName(),
                provider.getModel(),
                provider.getMaxTokens(),
                provider.getUrl(),
                provider.getKey()
            });
        }

        JScrollPane tableScrollPane = new JScrollPane(table);

        // Create the buttons
        JButton addButton = new JButton("Add");
        JButton editButton = new JButton("Edit");
        JButton deleteButton = new JButton("Delete");

        addButton.addActionListener(e -> onAddProvider());
        editButton.addActionListener(e -> onEditProvider());
        deleteButton.addActionListener(e -> onDeleteProvider());

        JPanel buttonPanel = new JPanel();
        buttonPanel.add(addButton);
        buttonPanel.add(editButton);
        buttonPanel.add(deleteButton);

        // Create the active provider combo box
        activeProviderComboBox = new JComboBox<>();
        for (APIProvider provider : apiProviders) {
            activeProviderComboBox.addItem(provider.getName());
        }
        activeProviderComboBox.setSelectedItem(selectedProviderName);

        JPanel activeProviderPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        activeProviderPanel.add(new JLabel("Active API Provider:"));
        activeProviderPanel.add(activeProviderComboBox);

        // Create the RLHF database path components
        JLabel rlhfDbPathLabel = new JLabel("RLHF Database Path:");
        rlhfDbPathField = new JTextField(rlhfDbPath, 20);
        rlhfDbBrowseButton = new JButton("Browse...");

        rlhfDbBrowseButton.addActionListener(e -> onBrowseRLHFDbPath());

        JPanel rlhfDbPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        rlhfDbPanel.add(rlhfDbPathLabel);
        rlhfDbPanel.add(rlhfDbPathField);
        rlhfDbPanel.add(rlhfDbBrowseButton);

        // Create the Lucene index path components
        JLabel luceneIndexPathLabel = new JLabel("Lucene Index Path:");
        luceneIndexPathField = new JTextField(luceneIndexPath, 20);
        luceneIndexBrowseButton = new JButton("Browse...");

        luceneIndexBrowseButton.addActionListener(e -> onBrowseLuceneIndexPath());

        JPanel luceneIndexPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        luceneIndexPanel.add(luceneIndexPathLabel);
        luceneIndexPanel.add(luceneIndexPathField);
        luceneIndexPanel.add(luceneIndexBrowseButton);

        // Create a panel to hold the active provider panel and RLHF database panel
        JPanel topPanel = new JPanel();
        topPanel.setLayout(new BoxLayout(topPanel, BoxLayout.Y_AXIS));
        topPanel.add(activeProviderPanel);
        topPanel.add(rlhfDbPanel);
        topPanel.add(luceneIndexPanel);

        // Add components to the panel
        panel.add(topPanel, BorderLayout.NORTH);
        panel.add(tableScrollPane, BorderLayout.CENTER);
        panel.add(buttonPanel, BorderLayout.SOUTH);

        addWorkPanel(panel);

        addOKButton();
        addCancelButton();

        setRememberSize(false);
    }

    private void onBrowseLuceneIndexPath() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Select Lucene Index Directory");
        fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

        // Set current directory to the existing path if it exists
        String currentPath = luceneIndexPathField.getText();
        if (!currentPath.isEmpty()) {
            File currentFile = new File(currentPath);
            fileChooser.setCurrentDirectory(currentFile.getParentFile());
            fileChooser.setSelectedFile(currentFile);
        }

        int result = fileChooser.showOpenDialog(getComponent());
        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedDir = fileChooser.getSelectedFile();
            luceneIndexPathField.setText(selectedDir.getAbsolutePath());
        }
    }
    
    private void onBrowseRLHFDbPath() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Select RLHF Database File");
        fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);

        // Set current directory to the existing path if it exists
        String currentPath = rlhfDbPathField.getText();
        if (!currentPath.isEmpty()) {
            File currentFile = new File(currentPath);
            fileChooser.setCurrentDirectory(currentFile.getParentFile());
            fileChooser.setSelectedFile(currentFile);
        }

        int result = fileChooser.showOpenDialog(getComponent());
        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            rlhfDbPathField.setText(selectedFile.getAbsolutePath());
        }
    }

    private void onAddProvider() {
        APIProvider newProvider = new APIProvider("", "", "", "", "");
        boolean isSaved = openProviderDialog(newProvider);
        if (isSaved) {
            apiProviders.add(newProvider);
            tableModel.addRow(new Object[] {
                newProvider.getName(),
                newProvider.getModel(),
                newProvider.getMaxTokens(),
                newProvider.getUrl(),
                newProvider.getKey()
            });
            activeProviderComboBox.addItem(newProvider.getName());
        }
    }

    private void onEditProvider() {
        int selectedRow = table.getSelectedRow();
        if (selectedRow >= 0) {
            APIProvider provider = apiProviders.get(selectedRow);
            APIProvider editedProvider = new APIProvider(
                provider.getName(),
                provider.getModel(),
                provider.getMaxTokens(),
                provider.getUrl(),
                provider.getKey()
            );
            boolean isSaved = openProviderDialog(editedProvider);
            if (isSaved) {
                // Update the provider
                provider.setName(editedProvider.getName());
                provider.setModel(editedProvider.getModel());
                provider.setMaxTokens(editedProvider.getMaxTokens());
                provider.setUrl(editedProvider.getUrl());
                provider.setKey(editedProvider.getKey());
                // Update the table model
                tableModel.setValueAt(provider.getName(), selectedRow, 0);
                tableModel.setValueAt(provider.getModel(), selectedRow, 1);
                tableModel.setValueAt(provider.getMaxTokens(), selectedRow, 2);
                tableModel.setValueAt(provider.getUrl(), selectedRow, 3);
                tableModel.setValueAt(provider.getKey(), selectedRow, 4);
                // Update the combo box
                activeProviderComboBox.removeItemAt(selectedRow);
                activeProviderComboBox.insertItemAt(provider.getName(), selectedRow);
                if (selectedProviderName.equals(provider.getName())) {
                    activeProviderComboBox.setSelectedItem(provider.getName());
                }
            }
        } else {
            JOptionPane.showMessageDialog(getComponent(), "Please select a provider to edit.", "No Selection", JOptionPane.WARNING_MESSAGE);
        }
    }

    private void onDeleteProvider() {
        int selectedRow = table.getSelectedRow();
        if (selectedRow >= 0) {
            int result = JOptionPane.showConfirmDialog(getComponent(), "Are you sure you want to delete the selected provider?", "Confirm Delete", JOptionPane.YES_NO_OPTION);
            if (result == JOptionPane.YES_OPTION) {
                APIProvider provider = apiProviders.get(selectedRow);
                apiProviders.remove(selectedRow);
                tableModel.removeRow(selectedRow);
                activeProviderComboBox.removeItemAt(selectedRow);
                // If the deleted provider was the selected provider, update the selection
                if (selectedProviderName.equals(provider.getName())) {
                    selectedProviderName = "";
                    activeProviderComboBox.setSelectedItem(selectedProviderName);
                }
            }
        } else {
            JOptionPane.showMessageDialog(getComponent(), "Please select a provider to delete.", "No Selection", JOptionPane.WARNING_MESSAGE);
        }
    }

    private boolean openProviderDialog(APIProvider provider) {
        JTextField nameField = new JTextField(provider.getName(), 20);
        JTextField modelField = new JTextField(provider.getModel(), 20);
        JTextField maxTokensField = new JTextField(provider.getMaxTokens(), 20);
        JTextField urlField = new JTextField(provider.getUrl(), 20);
        JTextField keyField = new JTextField(provider.getKey(), 20);

        JPanel panel = new JPanel(new GridLayout(0, 2));
        panel.add(new JLabel("Name:"));
        panel.add(nameField);
        panel.add(new JLabel("Model:"));
        panel.add(modelField);
        panel.add(new JLabel("Max Tokens:"));
        panel.add(maxTokensField);
        panel.add(new JLabel("URL:"));
        panel.add(urlField);
        panel.add(new JLabel("Key:"));
        panel.add(keyField);

        int result = JOptionPane.showConfirmDialog(getComponent(), panel, "API Provider", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        if (result == JOptionPane.OK_OPTION) {
            provider.setName(nameField.getText().trim());
            provider.setModel(modelField.getText().trim());
            provider.setMaxTokens(maxTokensField.getText().trim());
            provider.setUrl(urlField.getText().trim());
            provider.setKey(keyField.getText().trim());
            return true;
        } else {
            return false;
        }
    }

    @Override
    protected void okCallback() {
        // Save settings
        // Get the selected provider name
        selectedProviderName = (String) activeProviderComboBox.getSelectedItem();

        // Serialize the list of providers to JSON
        Gson gson = new Gson();
        String providersJson = gson.toJson(apiProviders);

        // Get the RLHF database path from the text field
        String rlhfDbPath = rlhfDbPathField.getText().trim();
        // Get the Lucene index path from the text field
        String luceneIndexPath = luceneIndexPathField.getText().trim();

        // Store settings
        Preferences.setProperty("GhidrAssist.APIProviders", providersJson);
        Preferences.setProperty("GhidrAssist.SelectedAPIProvider", selectedProviderName);
        Preferences.setProperty("GhidrAssist.RLHFDatabasePath", rlhfDbPath);
        Preferences.setProperty("GhidrAssist.LuceneIndexPath", luceneIndexPath);
        Preferences.store(); // Save preferences to disk

        close();
    }
}
