package ghidrassist.ui.tabs;

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

import ghidra.framework.preferences.Preferences;
import ghidrassist.GhidrAssistPlugin;
import ghidrassist.LlmApi;
import ghidrassist.apiprovider.APIProvider;
import ghidrassist.apiprovider.APIProviderConfig;
import ghidrassist.core.TabController;
import ghidrassist.mcp2.server.MCPServerConfig;
import ghidrassist.mcp2.server.MCPServerRegistry;

/**
 * Unified Settings tab matching BinAssist's layout.
 * Contains all settings in scrollable grouped sections:
 * - LLM Providers
 * - MCP Servers
 * - System Prompt
 * - Database Paths
 * - Analysis Options
 */
public class SettingsTab extends JPanel {
    private static final long serialVersionUID = 1L;
    private static final String VERSION = "1.12.0";
    private static final String[] REASONING_EFFORT_OPTIONS = {"None", "Low", "Medium", "High"};

    private final TabController controller;
    private final GhidrAssistPlugin plugin;

    // LLM Providers section components
    private DefaultTableModel llmTableModel;
    private JTable llmTable;
    private JComboBox<String> activeProviderComboBox;
    private JComboBox<String> reasoningEffortCombo;
    private List<APIProviderConfig> apiProviders;
    private String selectedProviderName;

    // MCP Servers section components
    private JTable mcpServersTable;
    private MCPServersTableModel mcpTableModel;

    // System Prompt section components
    private JTextArea contextArea;
    private JButton saveButton;
    private JButton revertButton;

    // Database Paths section components
    private JTextField analysisDbPathField;
    private JTextField rlhfDbPathField;
    private JTextField luceneIndexPathField;

    // Analysis Options section components
    private JSpinner maxToolCallsSpinner;
    private JTextField apiTimeoutField;

    // Test status indicators
    private JButton llmTestButton;
    private JLabel llmTestStatusLabel;
    private JButton mcpTestButton;
    private JLabel mcpTestStatusLabel;
    private ImageIcon successIcon;
    private ImageIcon failureIcon;

    public SettingsTab(TabController controller) {
        super(new BorderLayout());
        this.controller = controller;
        this.plugin = controller.getPlugin();

        loadApiProviders();
        initializeComponents();
        layoutComponents();
        setupListeners();
        loadSettings();
    }

    private void loadApiProviders() {
        String providersJson = Preferences.getProperty("GhidrAssist.APIProviders", "[]");
        Gson gson = new Gson();
        Type listType = new TypeToken<List<APIProviderConfig>>() {}.getType();
        apiProviders = gson.fromJson(providersJson, listType);
        selectedProviderName = Preferences.getProperty("GhidrAssist.SelectedAPIProvider", "");
    }

    private void initializeComponents() {
        // Create test status icons
        successIcon = createSuccessIcon();
        failureIcon = createFailureIcon();

        // Test status labels
        llmTestStatusLabel = new JLabel();
        llmTestStatusLabel.setPreferredSize(new Dimension(20, 20));
        mcpTestStatusLabel = new JLabel();
        mcpTestStatusLabel.setPreferredSize(new Dimension(20, 20));

        // LLM Providers
        String[] llmColumnNames = {"Name", "Model", "Max Tokens", "URL", "Key", "Disable TLS"};
        llmTableModel = new DefaultTableModel(llmColumnNames, 0) {
            @Override
            public Class<?> getColumnClass(int column) {
                return column == 5 ? Boolean.class : String.class;
            }
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        llmTable = new JTable(llmTableModel);
        llmTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        activeProviderComboBox = new JComboBox<>();
        reasoningEffortCombo = new JComboBox<>(REASONING_EFFORT_OPTIONS);
        reasoningEffortCombo.setToolTipText(
            "Extended thinking for complex queries\n" +
            "None: Standard response (default)\n" +
            "Low: ~2K thinking tokens\n" +
            "Medium: ~10K thinking tokens\n" +
            "High: ~25K thinking tokens"
        );

        // Populate LLM table and combo
        for (APIProviderConfig provider : apiProviders) {
            llmTableModel.addRow(new Object[] {
                provider.getName(),
                provider.getModel(),
                provider.getMaxTokens(),
                provider.getUrl(),
                maskApiKey(provider.getKey()),
                provider.isDisableTlsVerification()
            });
            activeProviderComboBox.addItem(provider.getName());
        }
        activeProviderComboBox.setSelectedItem(selectedProviderName);

        // MCP Servers
        mcpTableModel = new MCPServersTableModel();
        mcpServersTable = new JTable(mcpTableModel);
        mcpServersTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        mcpServersTable.getColumnModel().getColumn(0).setPreferredWidth(150);
        mcpServersTable.getColumnModel().getColumn(1).setPreferredWidth(300);
        mcpServersTable.getColumnModel().getColumn(2).setPreferredWidth(80);
        mcpServersTable.getColumnModel().getColumn(3).setPreferredWidth(100);

        // System Prompt
        contextArea = new JTextArea();
        contextArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        contextArea.setLineWrap(true);
        contextArea.setWrapStyleWord(true);
        saveButton = new JButton("Save");
        revertButton = new JButton("Revert");

        // Database Paths
        analysisDbPathField = new JTextField(30);
        rlhfDbPathField = new JTextField(30);
        luceneIndexPathField = new JTextField(30);

        // Analysis Options
        SpinnerNumberModel spinnerModel = new SpinnerNumberModel(10, 1, 50, 1);
        maxToolCallsSpinner = new JSpinner(spinnerModel);
        maxToolCallsSpinner.setPreferredSize(new Dimension(75, maxToolCallsSpinner.getPreferredSize().height));
        maxToolCallsSpinner.setToolTipText("Maximum tool calls per iteration (default: 10)");

        apiTimeoutField = new JTextField(5);
        apiTimeoutField.setToolTipText("API timeout in seconds");
    }

    private void layoutComponents() {
        // Create scroll area
        JPanel contentPanel = new JPanel();
        contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.Y_AXIS));
        contentPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Add sections
        contentPanel.add(createLLMProvidersSection());
        contentPanel.add(Box.createVerticalStrut(10));
        contentPanel.add(createMCPServersSection());
        contentPanel.add(Box.createVerticalStrut(10));
        contentPanel.add(createSystemPromptSection());
        contentPanel.add(Box.createVerticalStrut(10));
        contentPanel.add(createDatabasePathsSection());
        contentPanel.add(Box.createVerticalStrut(10));
        contentPanel.add(createAnalysisOptionsSection());
        contentPanel.add(Box.createVerticalGlue());

        JScrollPane scrollPane = new JScrollPane(contentPanel);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);

        add(scrollPane, BorderLayout.CENTER);

        // Bottom panel with version
        JPanel bottomPanel = new JPanel(new BorderLayout());
        JLabel versionLabel = new JLabel("GhidrAssist v" + VERSION);
        versionLabel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 5));
        bottomPanel.add(versionLabel, BorderLayout.WEST);
        add(bottomPanel, BorderLayout.SOUTH);
    }

    private JPanel createLLMProvidersSection() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("LLM Providers"));

        // Table
        llmTable.getColumnModel().getColumn(5).setCellRenderer(llmTable.getDefaultRenderer(Boolean.class));
        JScrollPane tableScrollPane = new JScrollPane(llmTable);
        tableScrollPane.setMinimumSize(new Dimension(200, 120));
        tableScrollPane.setPreferredSize(new Dimension(Integer.MAX_VALUE, 120));

        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton addButton = new JButton("Add");
        JButton editButton = new JButton("Edit");
        JButton deleteButton = new JButton("Delete");
        llmTestButton = new JButton("Test");

        addButton.addActionListener(e -> onAddProvider());
        editButton.addActionListener(e -> onEditProvider());
        deleteButton.addActionListener(e -> onDeleteProvider());
        llmTestButton.addActionListener(e -> onTestProvider());

        buttonPanel.add(addButton);
        buttonPanel.add(editButton);
        buttonPanel.add(deleteButton);
        buttonPanel.add(llmTestButton);
        buttonPanel.add(llmTestStatusLabel);

        // Active provider and reasoning effort
        JPanel selectionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        selectionPanel.add(new JLabel("Active Provider:"));
        activeProviderComboBox.setMaximumSize(new Dimension(200, activeProviderComboBox.getPreferredSize().height));
        selectionPanel.add(activeProviderComboBox);
        selectionPanel.add(Box.createHorizontalStrut(20));
        selectionPanel.add(new JLabel("Reasoning Effort:"));
        selectionPanel.add(reasoningEffortCombo);

        JPanel southPanel = new JPanel();
        southPanel.setLayout(new BoxLayout(southPanel, BoxLayout.Y_AXIS));
        southPanel.add(buttonPanel);
        southPanel.add(selectionPanel);

        panel.add(tableScrollPane, BorderLayout.CENTER);
        panel.add(southPanel, BorderLayout.SOUTH);

        return panel;
    }

    private JPanel createMCPServersSection() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("MCP Servers"));

        JScrollPane tableScrollPane = new JScrollPane(mcpServersTable);
        tableScrollPane.setMinimumSize(new Dimension(200, 100));
        tableScrollPane.setPreferredSize(new Dimension(Integer.MAX_VALUE, 100));

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton addButton = new JButton("Add Server");
        JButton editButton = new JButton("Edit");
        JButton removeButton = new JButton("Remove");
        mcpTestButton = new JButton("Test Connection");

        addButton.addActionListener(e -> showMCPAddEditDialog(null));
        editButton.addActionListener(e -> {
            int row = mcpServersTable.getSelectedRow();
            if (row >= 0) showMCPAddEditDialog(mcpTableModel.getServerAt(row));
        });
        removeButton.addActionListener(e -> onRemoveMCPServer());
        mcpTestButton.addActionListener(e -> onTestMCPServer());

        buttonPanel.add(addButton);
        buttonPanel.add(editButton);
        buttonPanel.add(removeButton);
        buttonPanel.add(mcpTestButton);
        buttonPanel.add(mcpTestStatusLabel);

        panel.add(tableScrollPane, BorderLayout.CENTER);
        panel.add(buttonPanel, BorderLayout.SOUTH);

        return panel;
    }
    private JPanel createSystemPromptSection() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("System Prompt"));

        JScrollPane scrollPane = new JScrollPane(contextArea);
        scrollPane.setMinimumSize(new Dimension(200, 100));
        scrollPane.setPreferredSize(new Dimension(Integer.MAX_VALUE, 100));

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonPanel.add(revertButton);
        buttonPanel.add(saveButton);

        panel.add(scrollPane, BorderLayout.CENTER);
        panel.add(buttonPanel, BorderLayout.SOUTH);

        return panel;
    }

    private JPanel createDatabasePathsSection() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Database Paths"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(2, 5, 2, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Analysis DB
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        panel.add(new JLabel("Analysis DB:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        analysisDbPathField.setText(Preferences.getProperty("GhidrAssist.AnalysisDBPath", "ghidrassist_analysis.db"));
        panel.add(analysisDbPathField, gbc);
        gbc.gridx = 2; gbc.weightx = 0;
        JButton analysisDbBrowse = new JButton("Browse...");
        analysisDbBrowse.addActionListener(e -> browseFile(analysisDbPathField, "Select Analysis Database", false));
        panel.add(analysisDbBrowse, gbc);

        // RLHF DB
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0;
        panel.add(new JLabel("RLHF DB:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        rlhfDbPathField.setText(Preferences.getProperty("GhidrAssist.RLHFDatabasePath", "ghidrassist_rlhf.db"));
        panel.add(rlhfDbPathField, gbc);
        gbc.gridx = 2; gbc.weightx = 0;
        JButton rlhfDbBrowse = new JButton("Browse...");
        rlhfDbBrowse.addActionListener(e -> browseFile(rlhfDbPathField, "Select RLHF Database", false));
        panel.add(rlhfDbBrowse, gbc);

        // Lucene Index
        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0;
        panel.add(new JLabel("RAG Index:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        luceneIndexPathField.setText(Preferences.getProperty("GhidrAssist.LuceneIndexPath", "ghidrassist_lucene"));
        panel.add(luceneIndexPathField, gbc);
        gbc.gridx = 2; gbc.weightx = 0;
        JButton luceneBrowse = new JButton("Browse...");
        luceneBrowse.addActionListener(e -> browseFile(luceneIndexPathField, "Select RAG Index Directory", true));
        panel.add(luceneBrowse, gbc);

        return panel;
    }

    private JPanel createAnalysisOptionsSection() {
        JPanel panel = new JPanel();
        panel.setBorder(BorderFactory.createTitledBorder("Analysis Options"));
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

        // Max Tool Calls
        JPanel toolCallsRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        toolCallsRow.add(new JLabel("Max Tool Calls/Iteration:"));
        toolCallsRow.add(maxToolCallsSpinner);

        // API Timeout
        JPanel timeoutRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        timeoutRow.add(new JLabel("API Timeout (seconds):"));
        apiTimeoutField.setText(Preferences.getProperty("GhidrAssist.APITimeout", "120"));
        timeoutRow.add(apiTimeoutField);

        panel.add(toolCallsRow);
        panel.add(timeoutRow);

        return panel;
    }

    private void setupListeners() {
        // Active provider change
        activeProviderComboBox.addActionListener(e -> {
            selectedProviderName = (String) activeProviderComboBox.getSelectedItem();
            Preferences.setProperty("GhidrAssist.SelectedAPIProvider", selectedProviderName);
            Preferences.store();
        });

        // Reasoning effort change
        reasoningEffortCombo.addActionListener(e -> {
            String selectedEffort = (String) reasoningEffortCombo.getSelectedItem();
            controller.setReasoningEffort(selectedEffort);
        });

        // Max tool calls change
        maxToolCallsSpinner.addChangeListener(e -> {
            int maxToolCalls = (Integer) maxToolCallsSpinner.getValue();
            controller.setMaxToolCalls(maxToolCalls);
        });

        // Database paths save on focus lost
        analysisDbPathField.addFocusListener(createPathFocusListener("GhidrAssist.AnalysisDBPath"));
        rlhfDbPathField.addFocusListener(createPathFocusListener("GhidrAssist.RLHFDatabasePath"));
        luceneIndexPathField.addFocusListener(createPathFocusListener("GhidrAssist.LuceneIndexPath"));

        // API timeout save on focus lost
        apiTimeoutField.addFocusListener(new FocusListener() {
            @Override
            public void focusGained(FocusEvent e) {}
            @Override
            public void focusLost(FocusEvent e) {
                Preferences.setProperty("GhidrAssist.APITimeout", apiTimeoutField.getText().trim());
                Preferences.store();
            }
        });

        // System prompt buttons
        saveButton.addActionListener(e -> controller.handleContextSave(contextArea.getText()));
        revertButton.addActionListener(e -> controller.handleContextRevert());
    }

    private FocusListener createPathFocusListener(String preferenceKey) {
        return new FocusListener() {
            @Override
            public void focusGained(FocusEvent e) {}
            @Override
            public void focusLost(FocusEvent e) {
                JTextField field = (JTextField) e.getSource();
                Preferences.setProperty(preferenceKey, field.getText().trim());
                Preferences.store();
            }
        };
    }

    private void loadSettings() {
        // Load reasoning effort
        String savedEffort = controller.getReasoningEffort();
        if (savedEffort != null) {
            reasoningEffortCombo.setSelectedItem(savedEffort);
        }

        // Load max tool calls
        int savedMaxToolCalls = controller.getMaxToolCalls();
        maxToolCallsSpinner.setValue(savedMaxToolCalls);
    }

    public void setContextText(String text) {
        contextArea.setText(text);
    }

    public void loadReasoningEffort() {
        String savedEffort = controller.getReasoningEffort();
        if (savedEffort != null) {
            reasoningEffortCombo.setSelectedItem(savedEffort);
        }
    }

    public void loadMaxToolCalls() {
        int savedMaxToolCalls = controller.getMaxToolCalls();
        maxToolCallsSpinner.setValue(savedMaxToolCalls);
    }

    // ==== LLM Provider Operations ====

    private void onAddProvider() {
        APIProviderConfig newProvider = new APIProviderConfig(
            "", APIProvider.ProviderType.OPENAI, "", 16384, "", "", false
        );
        if (openProviderDialog(newProvider)) {
            apiProviders.add(newProvider);
            llmTableModel.addRow(new Object[] {
                newProvider.getName(),
                newProvider.getModel(),
                newProvider.getMaxTokens(),
                newProvider.getUrl(),
                maskApiKey(newProvider.getKey()),
                newProvider.isDisableTlsVerification()
            });
            activeProviderComboBox.addItem(newProvider.getName());
            saveProviders();
        }
    }

    private void onEditProvider() {
        int selectedRow = llmTable.getSelectedRow();
        if (selectedRow < 0) {
            JOptionPane.showMessageDialog(this, "Please select a provider to edit.", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }
        APIProviderConfig provider = apiProviders.get(selectedRow);
        APIProviderConfig editedProvider = new APIProviderConfig(
            provider.getName(), provider.getType(), provider.getModel(),
            provider.getMaxTokens(), provider.getUrl(), provider.getKey(),
            provider.isDisableTlsVerification()
        );
        if (openProviderDialog(editedProvider)) {
            provider.setName(editedProvider.getName());
            provider.setType(editedProvider.getType());
            provider.setModel(editedProvider.getModel());
            provider.setMaxTokens(editedProvider.getMaxTokens());
            provider.setUrl(editedProvider.getUrl());
            provider.setKey(editedProvider.getKey());
            provider.setDisableTlsVerification(editedProvider.isDisableTlsVerification());

            llmTableModel.setValueAt(provider.getName(), selectedRow, 0);
            llmTableModel.setValueAt(provider.getModel(), selectedRow, 1);
            llmTableModel.setValueAt(provider.getMaxTokens(), selectedRow, 2);
            llmTableModel.setValueAt(provider.getUrl(), selectedRow, 3);
            llmTableModel.setValueAt(maskApiKey(provider.getKey()), selectedRow, 4);
            llmTableModel.setValueAt(provider.isDisableTlsVerification(), selectedRow, 5);

            activeProviderComboBox.removeItemAt(selectedRow);
            activeProviderComboBox.insertItemAt(provider.getName(), selectedRow);
            saveProviders();
        }
    }

    private void onDeleteProvider() {
        int selectedRow = llmTable.getSelectedRow();
        if (selectedRow < 0) {
            JOptionPane.showMessageDialog(this, "Please select a provider to delete.", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }
        int result = JOptionPane.showConfirmDialog(this, "Are you sure you want to delete the selected provider?", "Confirm Delete", JOptionPane.YES_NO_OPTION);
        if (result == JOptionPane.YES_OPTION) {
            APIProviderConfig provider = apiProviders.get(selectedRow);
            apiProviders.remove(selectedRow);
            llmTableModel.removeRow(selectedRow);
            activeProviderComboBox.removeItemAt(selectedRow);
            if (selectedProviderName.equals(provider.getName())) {
                selectedProviderName = "";
                activeProviderComboBox.setSelectedItem(selectedProviderName);
            }
            saveProviders();
        }
    }

    private void onTestProvider() {
        String providerName = (String) activeProviderComboBox.getSelectedItem();
        if (providerName == null || providerName.isEmpty()) {
            llmTestStatusLabel.setIcon(failureIcon);
            llmTestStatusLabel.setToolTipText("No provider selected");
            return;
        }

        APIProviderConfig provider = null;
        for (APIProviderConfig p : apiProviders) {
            if (p.getName().equals(providerName)) {
                provider = p;
                break;
            }
        }

        if (provider == null) {
            llmTestStatusLabel.setIcon(failureIcon);
            llmTestStatusLabel.setToolTipText("Provider not found");
            return;
        }

        final APIProviderConfig testProvider = provider;

        // Show testing state
        llmTestButton.setEnabled(false);
        llmTestStatusLabel.setIcon(null);
        llmTestStatusLabel.setText("...");
        llmTestStatusLabel.setToolTipText("Testing connection...");

        SwingWorker<Boolean, Void> worker = new SwingWorker<Boolean, Void>() {
            private String errorMessage = "";

            @Override
            protected Boolean doInBackground() {
                try {
                    LlmApi testApi = new LlmApi(testProvider, plugin);
                    String testPrompt = "Testing connection. Please respond with 'OK' and nothing else.";
                    final boolean[] success = {false};

                    testApi.sendRequestAsync(testPrompt, new LlmApi.LlmResponseHandler() {
                        @Override
                        public void onStart() {}
                        @Override
                        public void onUpdate(String partialResponse) {}
                        @Override
                        public void onComplete(String fullResponse) {
                            success[0] = true;
                        }
                        @Override
                        public void onError(Throwable error) {
                            errorMessage = error.getMessage();
                        }
                    });

                    // Wait briefly for async response
                    Thread.sleep(5000);
                    return success[0];
                } catch (Exception e) {
                    errorMessage = e.getMessage();
                    return false;
                }
            }

            @Override
            protected void done() {
                llmTestButton.setEnabled(true);
                llmTestStatusLabel.setText("");
                try {
                    if (get()) {
                        llmTestStatusLabel.setIcon(successIcon);
                        llmTestStatusLabel.setToolTipText("Connection successful");
                    } else {
                        llmTestStatusLabel.setIcon(failureIcon);
                        llmTestStatusLabel.setToolTipText("Connection failed: " + errorMessage);
                    }
                } catch (Exception e) {
                    llmTestStatusLabel.setIcon(failureIcon);
                    llmTestStatusLabel.setToolTipText("Test error: " + e.getMessage());
                }
            }
        };
        worker.execute();
    }

    private boolean openProviderDialog(APIProviderConfig provider) {
        JTextField nameField = new JTextField(provider.getName(), 20);
        JTextField modelField = new JTextField(provider.getModel(), 20);
        JTextField maxTokensField = new JTextField(String.valueOf(provider.getMaxTokens()), 20);
        JTextField urlField = new JTextField(provider.getUrl(), 20);
        JTextField keyField = new JTextField(provider.getKey(), 20);
        JComboBox<APIProvider.ProviderType> typeComboBox = new JComboBox<>(APIProvider.ProviderType.values());
        typeComboBox.setSelectedItem(provider.getType());
        JCheckBox disableTlsCheckbox = new JCheckBox("Disable TLS Verification", provider.isDisableTlsVerification());

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
        panel.add(new JLabel(""));
        panel.add(disableTlsCheckbox);

        int result = JOptionPane.showConfirmDialog(this, panel, "API Provider", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result == JOptionPane.OK_OPTION) {
            String name = nameField.getText().trim();
            String model = modelField.getText().trim();
            String url = urlField.getText().trim();
            String key = keyField.getText().trim();
            int maxTokens;
            try {
                maxTokens = Integer.parseInt(maxTokensField.getText().trim());
            } catch (NumberFormatException e) {
                maxTokens = 16384;
            }

            if (name.isEmpty() || model.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Name and Model are required.", "Validation Error", JOptionPane.ERROR_MESSAGE);
                return false;
            }

            provider.setName(name);
            provider.setType((APIProvider.ProviderType) typeComboBox.getSelectedItem());
            provider.setModel(model);
            provider.setMaxTokens(maxTokens);
            provider.setUrl(url.endsWith("/") ? url : url + "/");
            provider.setKey(key);
            provider.setDisableTlsVerification(disableTlsCheckbox.isSelected());
            return true;
        }
        return false;
    }

    private void saveProviders() {
        Gson gson = new Gson();
        String providersJson = gson.toJson(apiProviders);
        Preferences.setProperty("GhidrAssist.APIProviders", providersJson);
        Preferences.setProperty("GhidrAssist.SelectedAPIProvider", selectedProviderName);
        Preferences.store();
    }

    private String maskApiKey(String key) {
        if (key == null || key.isEmpty()) return "";
        return "\u2022".repeat(Math.min(key.length(), 20));
    }

    // ==== MCP Server Operations ====

    private void showMCPAddEditDialog(MCPServerConfig existingServer) {
        MCPServerDialog dialog = new MCPServerDialog(
            SwingUtilities.getWindowAncestor(this),
            existingServer
        );
        dialog.setVisible(true);

        if (dialog.isConfirmed()) {
            MCPServerConfig config = dialog.getServerConfig();
            if (existingServer != null) {
                MCPServerRegistry.getInstance().removeServer(existingServer.getName());
            }
            MCPServerRegistry.getInstance().addServer(config);
            mcpTableModel.refresh();
        }
    }

    private void onRemoveMCPServer() {
        int selectedRow = mcpServersTable.getSelectedRow();
        if (selectedRow < 0) {
            JOptionPane.showMessageDialog(this, "Please select a server to remove.", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }
        MCPServerConfig server = mcpTableModel.getServerAt(selectedRow);
        int result = JOptionPane.showConfirmDialog(this, "Remove server '" + server.getName() + "'?", "Confirm Removal", JOptionPane.YES_NO_OPTION);
        if (result == JOptionPane.YES_OPTION) {
            MCPServerRegistry.getInstance().removeServer(server.getName());
            mcpTableModel.refresh();
        }
    }

    private void onTestMCPServer() {
        int selectedRow = mcpServersTable.getSelectedRow();
        if (selectedRow < 0) {
            mcpTestStatusLabel.setIcon(failureIcon);
            mcpTestStatusLabel.setToolTipText("No server selected");
            return;
        }

        MCPServerConfig server = mcpTableModel.getServerAt(selectedRow);

        // Show testing state
        mcpTestButton.setEnabled(false);
        mcpTestStatusLabel.setIcon(null);
        mcpTestStatusLabel.setText("...");
        mcpTestStatusLabel.setToolTipText("Testing connection to " + server.getName() + "...");

        SwingWorker<Boolean, Void> worker = new SwingWorker<Boolean, Void>() {
            private String errorMessage = "";

            @Override
            protected Boolean doInBackground() {
                try {
                    ghidrassist.mcp2.protocol.MCPClientAdapter client =
                        new ghidrassist.mcp2.protocol.MCPClientAdapter(server);
                    client.connect().get();
                    client.disconnect();
                    return true;
                } catch (Exception e) {
                    Throwable cause = e.getCause() != null ? e.getCause() : e;
                    errorMessage = cause.getMessage();
                    return false;
                }
            }

            @Override
            protected void done() {
                mcpTestButton.setEnabled(true);
                mcpTestStatusLabel.setText("");
                try {
                    if (get()) {
                        mcpTestStatusLabel.setIcon(successIcon);
                        mcpTestStatusLabel.setToolTipText("Connection successful");
                    } else {
                        mcpTestStatusLabel.setIcon(failureIcon);
                        mcpTestStatusLabel.setToolTipText("Connection failed: " + errorMessage);
                    }
                } catch (Exception e) {
                    mcpTestStatusLabel.setIcon(failureIcon);
                    mcpTestStatusLabel.setToolTipText("Test error: " + e.getMessage());
                }
            }
        };
        worker.execute();
    }

    // ==== Utility Methods ====

    private void browseFile(JTextField field, String title, boolean directoriesOnly) {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle(title);
        fileChooser.setFileSelectionMode(directoriesOnly ? JFileChooser.DIRECTORIES_ONLY : JFileChooser.FILES_ONLY);

        String currentPath = field.getText();
        if (!currentPath.isEmpty()) {
            File currentFile = new File(currentPath);
            fileChooser.setCurrentDirectory(currentFile.getParentFile());
            fileChooser.setSelectedFile(currentFile);
        }

        int result = fileChooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            field.setText(fileChooser.getSelectedFile().getAbsolutePath());
        }
    }

    private ImageIcon createSuccessIcon() {
        int size = 16;
        BufferedImage image = new BufferedImage(size, size, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g2d = image.createGraphics();
        g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2d.setColor(new Color(0, 180, 0));  // Green
        g2d.setStroke(new BasicStroke(2.5f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
        g2d.drawLine(3, 8, 6, 12);
        g2d.drawLine(6, 12, 13, 4);
        g2d.dispose();
        return new ImageIcon(image);
    }

    private ImageIcon createFailureIcon() {
        int size = 16;
        BufferedImage image = new BufferedImage(size, size, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g2d = image.createGraphics();
        g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2d.setColor(new Color(220, 0, 0));  // Red
        g2d.setStroke(new BasicStroke(2.5f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
        g2d.drawLine(4, 4, 12, 12);
        g2d.drawLine(4, 12, 12, 4);
        g2d.dispose();
        return new ImageIcon(image);
    }

    // ==== Inner Classes ====

    private static class MCPServersTableModel extends javax.swing.table.AbstractTableModel {
        private static final String[] COLUMN_NAMES = {"Name", "URL", "Enabled", "Transport"};
        private List<MCPServerConfig> servers;

        public MCPServersTableModel() {
            refresh();
        }

        public void refresh() {
            servers = MCPServerRegistry.getInstance().getAllServers();
            fireTableDataChanged();
        }

        @Override
        public int getRowCount() {
            return servers.size();
        }

        @Override
        public int getColumnCount() {
            return COLUMN_NAMES.length;
        }

        @Override
        public String getColumnName(int column) {
            return COLUMN_NAMES[column];
        }

        @Override
        public Class<?> getColumnClass(int column) {
            return column == 2 ? Boolean.class : String.class;
        }

        @Override
        public Object getValueAt(int row, int column) {
            MCPServerConfig server = servers.get(row);
            switch (column) {
                case 0: return server.getName();
                case 1: return server.getBaseUrl();
                case 2: return server.isEnabled();
                case 3: return server.getTransport().getDisplayName();
                default: return null;
            }
        }

        @Override
        public boolean isCellEditable(int row, int column) {
            return column == 2;
        }

        @Override
        public void setValueAt(Object value, int row, int column) {
            if (column == 2 && value instanceof Boolean) {
                MCPServerConfig server = servers.get(row);
                MCPServerConfig updated = new MCPServerConfig(
                    server.getName(),
                    server.getBaseUrl(),
                    server.getTransport(),
                    (Boolean) value
                );
                MCPServerRegistry.getInstance().updateServer(updated);
                fireTableCellUpdated(row, column);
            }
        }

        public MCPServerConfig getServerAt(int row) {
            return servers.get(row);
        }
    }
}
