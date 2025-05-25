package ghidrassist;

import docking.DialogComponentProvider;
import ghidra.framework.preferences.Preferences;
import ghidrassist.apiprovider.APIProvider;
import ghidrassist.apiprovider.APIProviderConfig;
import ghidrassist.ui.tabs.MCPServersTab;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.awt.image.BufferedImage;
import java.io.File;
import java.lang.reflect.Type;
import java.util.List;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

public class SettingsDialog extends DialogComponentProvider {
    private final GhidrAssistPlugin plugin;

    private DefaultTableModel tableModel;
    private JTable table;
    private JComboBox<String> activeProviderComboBox;
    private List<APIProviderConfig> apiProviders;
    private String selectedProviderName;

    // Components for RLHF Database Path
    private JTextField rlhfDbPathField;
    private JButton rlhfDbBrowseButton;
    
    // Components for the RAG index path
    private JTextField luceneIndexPathField;
    private JButton luceneIndexBrowseButton;

    // Analysis database
    private JTextField analysisDbPathField;
    private JButton analysisDbBrowseButton;

    // API Timeout
    private JTextField apiTimeoutField;
    
    public SettingsDialog(Component parent, String title, GhidrAssistPlugin plugin) {
        super(title, true, false, true, false);
        this.plugin = plugin;

        // Load the list of API providers from preferences
        String providersJson = Preferences.getProperty("GhidrAssist.APIProviders", "[]");
        Gson gson = new Gson();
        Type listType = new TypeToken<List<APIProviderConfig>>() {}.getType();
        apiProviders = gson.fromJson(providersJson, listType);

        // Load the selected provider name
        selectedProviderName = Preferences.getProperty("GhidrAssist.SelectedAPIProvider", "");

        // Load the RLHF database path
        String rlhfDbPath = Preferences.getProperty("GhidrAssist.RLHFDatabasePath", "ghidrassist_rlhf.db");
        
        // Create the Analysis database path components
        String analysisDbPath = Preferences.getProperty("GhidrAssist.AnalysisDBPath", "ghidrassist_analysis.db");
        JLabel analysisDbPathLabel = new JLabel("Analysis Database Path:");
        analysisDbPathField = new JTextField(analysisDbPath, 20);
        analysisDbBrowseButton = new JButton("Browse...");

        analysisDbBrowseButton.addActionListener(e -> onBrowseAnalysisDbPath());

        JPanel analysisDbPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        analysisDbPanel.add(analysisDbPathLabel);
        analysisDbPanel.add(analysisDbPathField);
        analysisDbPanel.add(analysisDbBrowseButton);

        // Load the Lucene index path
        String luceneIndexPath = Preferences.getProperty("GhidrAssist.LuceneIndexPath", "ghidrassist_lucene");
        
        // Load the API timeout
        String apiTimeout = Preferences.getProperty("GhidrAssist.APITimeout", "120");
        JLabel apiTimeoutLabel = new JLabel("API Timeout (seconds):");
        apiTimeoutField = new JTextField(apiTimeout, 5);
        
        JPanel apiTimeoutPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        apiTimeoutPanel.add(apiTimeoutLabel);
        apiTimeoutPanel.add(apiTimeoutField);
        
        // Create tabbed pane for settings
        JTabbedPane tabbedPane = new JTabbedPane();
        
        // API Providers Tab
        JPanel apiProvidersTab = createAPIProvidersTab();
        tabbedPane.addTab("API Providers", apiProvidersTab);
        
        // MCP Servers Tab
        MCPServersTab mcpServersTab = new MCPServersTab();
        tabbedPane.addTab("MCP Servers", mcpServersTab);
        
        // General Settings Tab
        JPanel generalTab = createGeneralSettingsTab();
        tabbedPane.addTab("General", generalTab);

        addWorkPanel(tabbedPane);

        addOKButton();
        addCancelButton();

        setRememberSize(false);
    }
    
    private JPanel createAPIProvidersTab() {
        JPanel panel = new JPanel(new BorderLayout());

        // Create the table
        String[] columnNames = {"Name", "Model", "Max Tokens", "URL", "Key", "Disable TLS Verify"};
        tableModel = new DefaultTableModel(columnNames, 0) {
            private static final long serialVersionUID = 1L;

            @Override
            public Class<?> getColumnClass(int column) {
                // Return Boolean.class for the Disable TLS Verify column
                return column == 5 ? Boolean.class : String.class;
            }
            
            @Override
            public boolean isCellEditable(int row, int column) {
                return false; // Make all cells non-editable
            }
        };
        table = new JTable(tableModel);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        // Populate the table model with the data
        for (APIProviderConfig provider : apiProviders) {
            tableModel.addRow(new Object[] {
                provider.getName(),
                provider.getModel(),
                provider.getMaxTokens(),
                provider.getUrl(),
                provider.getKey(),
                provider.isDisableTlsVerification()
            });
        }

        // Make the TLS column use checkboxes
        table.getColumnModel().getColumn(5).setCellRenderer(table.getDefaultRenderer(Boolean.class));
        table.getColumnModel().getColumn(5).setCellEditor(table.getDefaultEditor(Boolean.class));

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
        for (APIProviderConfig provider : apiProviders) {
            activeProviderComboBox.addItem(provider.getName());
        }
        activeProviderComboBox.setSelectedItem(selectedProviderName);

        // Create the active provider panel with test button
        JPanel activeProviderPanel = new JPanel();
        activeProviderPanel.setLayout(new BoxLayout(activeProviderPanel, BoxLayout.X_AXIS));
        activeProviderPanel.add(new JLabel("Active API Provider:"));
        activeProviderPanel.add(Box.createHorizontalStrut(5)); // Add some spacing
        activeProviderComboBox.setMaximumSize(new Dimension(200, activeProviderComboBox.getPreferredSize().height));
        activeProviderPanel.add(activeProviderComboBox);
        activeProviderPanel.add(Box.createHorizontalStrut(5)); // Add some spacing
        activeProviderPanel.add(new APITestPanel(plugin));
        activeProviderPanel.add(Box.createHorizontalGlue()); // This will push everything to the left

        // Add components to the panel
        panel.add(activeProviderPanel, BorderLayout.NORTH);
        panel.add(tableScrollPane, BorderLayout.CENTER);
        panel.add(buttonPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    private JPanel createGeneralSettingsTab() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        
        // Create the RLHF database path components
        JLabel rlhfDbPathLabel = new JLabel("RLHF Database Path:");
        rlhfDbPathField = new JTextField(Preferences.getProperty("GhidrAssist.RLHFDatabasePath", "ghidrassist_rlhf.db"), 20);
        rlhfDbBrowseButton = new JButton("Browse...");
        rlhfDbBrowseButton.addActionListener(e -> onBrowseRLHFDbPath());

        JPanel rlhfDbPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        rlhfDbPanel.add(rlhfDbPathLabel);
        rlhfDbPanel.add(rlhfDbPathField);
        rlhfDbPanel.add(rlhfDbBrowseButton);

        // Create the Analysis database path components
        String analysisDbPath = Preferences.getProperty("GhidrAssist.AnalysisDBPath", "ghidrassist_analysis.db");
        JLabel analysisDbPathLabel = new JLabel("Analysis Database Path:");
        analysisDbPathField = new JTextField(analysisDbPath, 20);
        analysisDbBrowseButton = new JButton("Browse...");
        analysisDbBrowseButton.addActionListener(e -> onBrowseAnalysisDbPath());

        JPanel analysisDbPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        analysisDbPanel.add(analysisDbPathLabel);
        analysisDbPanel.add(analysisDbPathField);
        analysisDbPanel.add(analysisDbBrowseButton);

        // Create the Lucene index path components
        String luceneIndexPath = Preferences.getProperty("GhidrAssist.LuceneIndexPath", "ghidrassist_lucene");
        JLabel luceneIndexPathLabel = new JLabel("Lucene Index Path:");
        luceneIndexPathField = new JTextField(luceneIndexPath, 20);
        luceneIndexBrowseButton = new JButton("Browse...");
        luceneIndexBrowseButton.addActionListener(e -> onBrowseLuceneIndexPath());

        JPanel luceneIndexPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        luceneIndexPanel.add(luceneIndexPathLabel);
        luceneIndexPanel.add(luceneIndexPathField);
        luceneIndexPanel.add(luceneIndexBrowseButton);
        
        // Load the API timeout
        String apiTimeout = Preferences.getProperty("GhidrAssist.APITimeout", "120");
        JLabel apiTimeoutLabel = new JLabel("API Timeout (seconds):");
        apiTimeoutField = new JTextField(apiTimeout, 5);
        
        JPanel apiTimeoutPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        apiTimeoutPanel.add(apiTimeoutLabel);
        apiTimeoutPanel.add(apiTimeoutField);
        
        panel.add(rlhfDbPanel);
        panel.add(analysisDbPanel);
        panel.add(luceneIndexPanel);
        panel.add(apiTimeoutPanel);
        
        return panel;
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
    
    private void onBrowseAnalysisDbPath() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Select Analysis Database File");
        fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);

        // Set current directory to the existing path if it exists
        String currentPath = analysisDbPathField.getText();
        if (!currentPath.isEmpty()) {
            File currentFile = new File(currentPath);
            fileChooser.setCurrentDirectory(currentFile.getParentFile());
            fileChooser.setSelectedFile(currentFile);
        }

        int result = fileChooser.showOpenDialog(getComponent());
        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            analysisDbPathField.setText(selectedFile.getAbsolutePath());
        }
    }

    private void onAddProvider() {
        APIProviderConfig newProvider = new APIProviderConfig(
            "",  // name
            APIProvider.ProviderType.OPENAI,  // default type
            "",  // model
            16384,  // maxTokens
            "",  // url
            "",  // key
            false  // disableTlsVerification
        );
        boolean isSaved = openProviderDialog(newProvider);
        if (isSaved) {
            apiProviders.add(newProvider);
            tableModel.addRow(new Object[] {
                newProvider.getName(),
                newProvider.getModel(),
                newProvider.getMaxTokens(),
                newProvider.getUrl(),
                newProvider.getKey(),
                newProvider.isDisableTlsVerification()
            });
            activeProviderComboBox.addItem(newProvider.getName());
        }
    }

    private void onEditProvider() {
        int selectedRow = table.getSelectedRow();
        if (selectedRow >= 0) {
            APIProviderConfig provider = apiProviders.get(selectedRow);
            APIProviderConfig editedProvider = new APIProviderConfig(
                provider.getName(),
                provider.getType(),
                provider.getModel(),
                provider.getMaxTokens(),
                provider.getUrl(),
                provider.getKey(),
                provider.isDisableTlsVerification()
            );
            boolean isSaved = openProviderDialog(editedProvider);
            if (isSaved) {
                // Update the provider
                provider.setName(editedProvider.getName());
                provider.setType(editedProvider.getType());
                provider.setModel(editedProvider.getModel());
                provider.setMaxTokens(editedProvider.getMaxTokens());
                provider.setUrl(editedProvider.getUrl());
                provider.setKey(editedProvider.getKey());
                provider.setDisableTlsVerification(editedProvider.isDisableTlsVerification());
                
                // Update the table model
                tableModel.setValueAt(provider.getName(), selectedRow, 0);
                tableModel.setValueAt(provider.getModel(), selectedRow, 1);
                tableModel.setValueAt(provider.getMaxTokens(), selectedRow, 2);
                tableModel.setValueAt(provider.getUrl(), selectedRow, 3);
                tableModel.setValueAt(provider.getKey(), selectedRow, 4);
                tableModel.setValueAt(provider.isDisableTlsVerification(), selectedRow, 5);
                
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
                APIProviderConfig provider = apiProviders.get(selectedRow);
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

    private boolean validateProviderFields(String name, String model, Integer maxTokens, String url, String key) {
        StringBuilder errorMessage = new StringBuilder();
        
        // Check for empty fields
        if (name.isEmpty()) errorMessage.append("Name is required.\n");
        if (model.isEmpty()) errorMessage.append("Model is required.\n");
        if (maxTokens <= 0) errorMessage.append("Max tokens must be a positive integer.\n");
        if (url.isEmpty()) errorMessage.append("URL is required.\n");
        if (key.isEmpty()) errorMessage.append("Key is required.\n");
        
        // Show error message if any validation failed
        if (errorMessage.length() > 0) {
            JOptionPane.showMessageDialog(
                getComponent(),
                errorMessage.toString(),
                "Validation Error",
                JOptionPane.ERROR_MESSAGE
            );
            return false;
        }
        
        return true;
    }

    private String ensureTrailingSlash(String url) {
        return url.endsWith("/") ? url : url + "/";
    }

    private boolean openProviderDialog(APIProviderConfig newProvider) {  // Changed type
        // Create text fields with placeholders for new providers
        JTextField nameField;
        JTextField modelField;
        JTextField maxTokensField;
        JTextField urlField;
        JTextField keyField;
        JComboBox<APIProvider.ProviderType> typeComboBox = new JComboBox<>(APIProvider.ProviderType.values());
        
        if (newProvider.getName().isEmpty()) {
            // This is a new provider, use placeholder text
            nameField = new PlaceholderTextField("gpt-4o-mini", 20);
            modelField = new PlaceholderTextField("gpt-4o-mini", 20);
            maxTokensField = new PlaceholderTextField("8192", 20);
            urlField = new PlaceholderTextField("https://api.openai.com/v1/", 20);
            keyField = new PlaceholderTextField("Enter your API key", 20);
            typeComboBox.setSelectedItem(APIProvider.ProviderType.OPENAI);
        } else {
            // This is an existing provider, use current values
            nameField = new JTextField(newProvider.getName(), 20);
            modelField = new JTextField(newProvider.getModel(), 20);
            maxTokensField = new JTextField(newProvider.getMaxTokens().toString(), 20);
            urlField = new JTextField(newProvider.getUrl(), 20);
            keyField = new JTextField(newProvider.getKey(), 20);
            typeComboBox.setSelectedItem(newProvider.getType());
        }

        JCheckBox disableTlsVerifyCheckbox = new JCheckBox("Disable TLS Certificate Verification", 
            newProvider.isDisableTlsVerification());

        JPanel panel = new JPanel(new GridLayout(0, 2));
        panel.add(new JLabel("Name:"));
        panel.add(nameField);
        panel.add(new JLabel("Type:"));
        panel.add(typeComboBox);
        panel.add(new JLabel("Model:"));
        panel.add(modelField);
        panel.add(new JLabel("Max Tokens:"));
        panel.add(maxTokensField);
        panel.add(new JLabel("URL:"));
        panel.add(urlField);
        panel.add(new JLabel("Key:"));
        panel.add(keyField);
        panel.add(new JLabel("Insecure TLS:"));
        panel.add(disableTlsVerifyCheckbox);

        while (true) {
            int result = JOptionPane.showConfirmDialog(getComponent(), panel, 
                "API Provider", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

            if (result == JOptionPane.OK_OPTION) {
                String name = nameField.getText().trim();
                String model = modelField.getText().trim();
                Integer maxTokens = Integer.decode(maxTokensField.getText().trim());
                String url = urlField.getText().trim();
                String key = keyField.getText().trim();
                APIProvider.ProviderType type = (APIProvider.ProviderType) typeComboBox.getSelectedItem();
                
                // Validate all fields
                if (validateProviderFields(name, model, maxTokens, url, key)) {
                    // Ensure URL has trailing slash
                    url = ensureTrailingSlash(url);
                    
                    // Set the values in the provider object
                    newProvider.setName(name);
                    newProvider.setType(type);
                    newProvider.setModel(model);
                    newProvider.setMaxTokens(maxTokens);
                    newProvider.setUrl(url);
                    newProvider.setKey(key);
                    newProvider.setDisableTlsVerification(disableTlsVerifyCheckbox.isSelected());
                    return true;
                }
                continue;
            }
            return false;
        }
    }

    @Override
    protected void okCallback() {
        // Save settings
        // Get the selected provider name
        selectedProviderName = (String) activeProviderComboBox.getSelectedItem();

        // Get the API timeout from the text field
        String apiTimeout = apiTimeoutField.getText().trim();
        try {
            int timeout = Integer.parseInt(apiTimeout);
            if (timeout <= 0) {
                JOptionPane.showMessageDialog(getComponent(), 
                    "API Timeout must be a positive integer.", 
                    "Validation Error", 
                    JOptionPane.ERROR_MESSAGE);
                return;
            }
        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(getComponent(), 
                "API Timeout must be a valid integer.", 
                "Validation Error", 
                JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        // Serialize the list of providers to JSON
        Gson gson = new Gson();
        String providersJson = gson.toJson(apiProviders);

        // Get the RLHF database path from the text field
        String rlhfDbPath = rlhfDbPathField.getText().trim();
        // Get the Analysis database path from the text field
        String analysisDbPath = analysisDbPathField.getText().trim();
        // Add to the preferences storage:
        Preferences.setProperty("GhidrAssist.AnalysisDBPath", analysisDbPath);
        // Get the Lucene index path from the text field
        String luceneIndexPath = luceneIndexPathField.getText().trim();

        // Store settings
        Preferences.setProperty("GhidrAssist.APIProviders", providersJson);
        Preferences.setProperty("GhidrAssist.SelectedAPIProvider", selectedProviderName);
        Preferences.setProperty("GhidrAssist.RLHFDatabasePath", rlhfDbPath);
        Preferences.setProperty("GhidrAssist.LuceneIndexPath", luceneIndexPath);
        Preferences.setProperty("GhidrAssist.APITimeout", apiTimeout);
        Preferences.store(); // Save preferences to disk

        close();
    }
    
    public class PlaceholderTextField extends JTextField {
        private static final long serialVersionUID = 1L;
    	private boolean showingPlaceholder;
        private Color placeholderColor;
        private Color textColor;

        public PlaceholderTextField(String placeholder, int columns) {
            super(columns);
            this.showingPlaceholder = true;
            this.placeholderColor = Color.GRAY;
            this.textColor = getForeground();
            
            // Show placeholder initially
            super.setText(placeholder);
            setForeground(placeholderColor);

            addFocusListener(new FocusListener() {
                @Override
                public void focusGained(FocusEvent e) {
                    if (showingPlaceholder) {
                        showingPlaceholder = false;
                        setText("");
                        setForeground(textColor);
                    }
                }

                @Override
                public void focusLost(FocusEvent e) {
                    if (getText().isEmpty()) {
                        showingPlaceholder = true;
                        setText(placeholder);
                        setForeground(placeholderColor);
                    }
                }
            });
        }

        @Override
        public String getText() {
            return showingPlaceholder ? "" : super.getText();
        }
    }
    
    private class APITestPanel extends JPanel {
        private static final long serialVersionUID = 1L;
        private final GhidrAssistPlugin plugin;
        private JButton testButton;
        private JLabel statusLabel;
        private ImageIcon successIcon;
        private ImageIcon failureIcon;
        private boolean isTestInProgress = false;

        public APITestPanel(GhidrAssistPlugin plugin) {
            this.plugin = plugin;
            setLayout(new FlowLayout(FlowLayout.LEFT));
            
            // Create icons
            successIcon = createColoredIcon(Color.GREEN);
            failureIcon = createColoredIcon(Color.RED);
            
            // Create components
            testButton = new JButton("Test");
            statusLabel = new JLabel();
            statusLabel.setPreferredSize(new Dimension(20, 20));
            
            // Add action listener
            testButton.addActionListener(e -> performTest());
            
            // Add components
            add(testButton);
            add(statusLabel);
        }
        
        private ImageIcon createColoredIcon(Color color) {
            int size = 16;
            BufferedImage image = new BufferedImage(size, size, BufferedImage.TYPE_INT_ARGB);
            Graphics2D g2d = image.createGraphics();
            
            if (color == Color.GREEN) {
                // Draw checkmark
                g2d.setColor(color);
                g2d.setStroke(new BasicStroke(2));
                g2d.drawLine(3, 8, 7, 12);
                g2d.drawLine(7, 12, 13, 4);
            } else {
                // Draw X
                g2d.setColor(color);
                g2d.setStroke(new BasicStroke(2));
                g2d.drawLine(4, 4, 12, 12);
                g2d.drawLine(4, 12, 12, 4);
            }
            
            g2d.dispose();
            return new ImageIcon(image);
        }
        
        public void performTest() {
            if (isTestInProgress) {
                return;
            }
            
            String selectedProvider = (String) activeProviderComboBox.getSelectedItem();
            if (selectedProvider == null || selectedProvider.isEmpty()) {
                JOptionPane.showMessageDialog(this, 
                    "Please select an API provider first.", 
                    "No Provider Selected", 
                    JOptionPane.WARNING_MESSAGE);
                return;
            }
            
            // Find the selected provider
            APIProviderConfig provider = null;
            for (APIProviderConfig p : apiProviders) {
                if (p.getName().equals(selectedProvider)) {
                    provider = p;
                    break;
                }
            }
            
            if (provider == null) {
                JOptionPane.showMessageDialog(this,
                    "Selected provider not found.",
                    "Error",
                    JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            isTestInProgress = true;
            testButton.setEnabled(false);
            statusLabel.setIcon(null);
            statusLabel.setText("Testing...");
            
            // Create a new LlmApi instance for testing
            LlmApi testApi = new LlmApi(provider, plugin);
            
            // Create a simple test prompt
            String testPrompt = "Testing connection. Please respond with 'OK' and nothing else.";
            
            testApi.sendRequestAsync(testPrompt, new LlmApi.LlmResponseHandler() {
                StringBuilder response = new StringBuilder();
                
                @Override
                public void onStart() {}
                
                @Override
                public void onUpdate(String partialResponse) {
                    response.append(partialResponse);
                }
                
                @Override
                public void onComplete(String fullResponse) {
                    SwingUtilities.invokeLater(() -> {
                        statusLabel.setIcon(successIcon);
                        statusLabel.setText("");
                        testButton.setEnabled(true);
                        isTestInProgress = false;
                    });
                }
                
                @Override
                public void onError(Throwable error) {
                    SwingUtilities.invokeLater(() -> {
                        statusLabel.setIcon(failureIcon);
                        statusLabel.setText("");
                        testButton.setEnabled(true);
                        isTestInProgress = false;
                    });
                }
            });
        }
    }
}
