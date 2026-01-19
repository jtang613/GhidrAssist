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
import ghidrassist.apiprovider.oauth.OAuthCallbackServer;
import ghidrassist.apiprovider.oauth.OAuthTokenManager;
import ghidrassist.apiprovider.oauth.OpenAIOAuthTokenManager;

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
    private static final String VERSION = "1.14.0";
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
            private static final long serialVersionUID = 1L;
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
        tableScrollPane.setPreferredSize(new Dimension(600, 120));

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
        tableScrollPane.setPreferredSize(new Dimension(600, 100));

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
        scrollPane.setPreferredSize(new Dimension(600, 100));

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonPanel.add(revertButton);
        buttonPanel.add(saveButton);

        panel.add(scrollPane, BorderLayout.CENTER);
        panel.add(buttonPanel, BorderLayout.SOUTH);

        return panel;
    }

    private JPanel createDatabasePathsSection() {
        JPanel panel = new JPanel();
        panel.setBorder(BorderFactory.createTitledBorder("Database Paths"));
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

        // Analysis DB
        JPanel analysisRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        analysisRow.add(new JLabel("Analysis DB:"));
        analysisDbPathField.setText(Preferences.getProperty("GhidrAssist.AnalysisDBPath", "ghidrassist_analysis.db"));
        analysisRow.add(analysisDbPathField);
        JButton analysisDbBrowse = new JButton("Browse...");
        analysisDbBrowse.addActionListener(e -> browseFile(analysisDbPathField, "Select Analysis Database", false));
        analysisRow.add(analysisDbBrowse);

        // RLHF DB
        JPanel rlhfRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        rlhfRow.add(new JLabel("RLHF DB:"));
        rlhfDbPathField.setText(Preferences.getProperty("GhidrAssist.RLHFDatabasePath", "ghidrassist_rlhf.db"));
        rlhfRow.add(rlhfDbPathField);
        JButton rlhfDbBrowse = new JButton("Browse...");
        rlhfDbBrowse.addActionListener(e -> browseFile(rlhfDbPathField, "Select RLHF Database", false));
        rlhfRow.add(rlhfDbBrowse);

        // Lucene Index
        JPanel luceneRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        luceneRow.add(new JLabel("RAG Index:"));
        luceneIndexPathField.setText(Preferences.getProperty("GhidrAssist.LuceneIndexPath", "ghidrassist_lucene"));
        luceneRow.add(luceneIndexPathField);
        JButton luceneBrowse = new JButton("Browse...");
        luceneBrowse.addActionListener(e -> browseFile(luceneIndexPathField, "Select RAG Index Directory", true));
        luceneRow.add(luceneBrowse);

        panel.add(analysisRow);
        panel.add(rlhfRow);
        panel.add(luceneRow);

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
            "", APIProvider.ProviderType.OPENAI_PLATFORM_API, "", 16384, "", "", false
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
        int selectedRow = llmTable.getSelectedRow();
        if (selectedRow < 0) {
            llmTestStatusLabel.setIcon(failureIcon);
            llmTestStatusLabel.setToolTipText("No provider selected in table");
            JOptionPane.showMessageDialog(this, "Please select a provider in the table to test.", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }

        final APIProviderConfig testProvider = apiProviders.get(selectedRow);

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
        
        // OAuth-specific components
        JLabel urlLabel = new JLabel("URL:");
        JLabel keyLabel = new JLabel("Key:");
        JButton authenticateButton = new JButton("Authenticate");
        JLabel oauthNoteLabel = new JLabel("<html><i>Click 'Authenticate' to sign in with Claude Pro/Max subscription.</i></html>");
        oauthNoteLabel.setForeground(Color.GRAY);
        
        // Claude Code note
        JLabel claudeCodeNoteLabel = new JLabel("<html><i>Requires 'claude' CLI installed and authenticated.<br>Install: npm install -g @anthropic-ai/claude-code</i></html>");
        claudeCodeNoteLabel.setForeground(Color.GRAY);

        // Panel with GridBagLayout for more control
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 4, 4, 4);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        
        int row = 0;
        
        // Name
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        panel.add(new JLabel("Name:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1; gbc.gridwidth = 2;
        panel.add(nameField, gbc);
        gbc.gridwidth = 1;
        row++;
        
        // Type
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        panel.add(new JLabel("Type:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1; gbc.gridwidth = 2;
        panel.add(typeComboBox, gbc);
        gbc.gridwidth = 1;
        row++;
        
        // Model
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        panel.add(new JLabel("Model:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1; gbc.gridwidth = 2;
        panel.add(modelField, gbc);
        gbc.gridwidth = 1;
        row++;
        
        // Max Tokens
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        panel.add(new JLabel("Max Tokens:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1; gbc.gridwidth = 2;
        panel.add(maxTokensField, gbc);
        gbc.gridwidth = 1;
        row++;
        
        // URL (hidden for OAuth)
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        panel.add(urlLabel, gbc);
        gbc.gridx = 1; gbc.weightx = 1; gbc.gridwidth = 2;
        panel.add(urlField, gbc);
        gbc.gridwidth = 1;
        row++;
        
        // Key with optional Authenticate button
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        panel.add(keyLabel, gbc);
        gbc.gridx = 1; gbc.weightx = 1;
        panel.add(keyField, gbc);
        gbc.gridx = 2; gbc.weightx = 0;
        panel.add(authenticateButton, gbc);
        row++;
        
        // OAuth note (below key field)
        gbc.gridx = 1; gbc.gridy = row; gbc.gridwidth = 2;
        panel.add(oauthNoteLabel, gbc);
        gbc.gridwidth = 1;
        row++;
        
        // Claude Code note (below OAuth note, same row)
        gbc.gridx = 1; gbc.gridy = row; gbc.gridwidth = 2;
        panel.add(claudeCodeNoteLabel, gbc);
        gbc.gridwidth = 1;
        row++;
        
        // Disable TLS
        gbc.gridx = 1; gbc.gridy = row; gbc.gridwidth = 2;
        panel.add(disableTlsCheckbox, gbc);
        
        // Function to update UI based on provider type
        Runnable updateUIForProviderType = () -> {
            APIProvider.ProviderType selectedType = (APIProvider.ProviderType) typeComboBox.getSelectedItem();
            boolean isAnthropicOAuth = selectedType == APIProvider.ProviderType.ANTHROPIC_OAUTH;
            boolean isOpenAIOAuth = selectedType == APIProvider.ProviderType.OPENAI_OAUTH;
            boolean isOAuth = isAnthropicOAuth || isOpenAIOAuth;
            boolean isAnthropicClaudeCli = selectedType == APIProvider.ProviderType.ANTHROPIC_CLAUDE_CLI;
            
            // Hide URL for OAuth (uses fixed endpoints)
            urlLabel.setVisible(!isOAuth);
            urlField.setVisible(!isOAuth);
            
            // Show Authenticate button only for OAuth
            authenticateButton.setVisible(isOAuth);
            oauthNoteLabel.setVisible(isOAuth);
            
            // Update OAuth note text based on provider type
            if (isAnthropicOAuth) {
                oauthNoteLabel.setText("<html><i>Click 'Authenticate' to sign in with Claude Pro/Max subscription.</i></html>");
            } else if (isOpenAIOAuth) {
                oauthNoteLabel.setText("<html><i>Click 'Authenticate' to sign in with ChatGPT Pro/Plus subscription.</i></html>");
            }
            
            // Show Claude Code note only for Claude Code
            claudeCodeNoteLabel.setVisible(isAnthropicClaudeCli);
            
            // Update key label for OAuth
            if (isOAuth) {
                keyLabel.setText("Token:");
                keyField.setToolTipText("OAuth token JSON (populated by Authenticate button)");
            } else {
                keyLabel.setText("Key:");
                keyField.setToolTipText(null);
            }
            
            // Set default model for OAuth if empty
            if (isAnthropicOAuth && modelField.getText().trim().isEmpty()) {
                modelField.setText("claude-sonnet-4-20250514");
            } else if (isOpenAIOAuth && modelField.getText().trim().isEmpty()) {
                modelField.setText("gpt-5.1-codex");
            }
        };
        
        // Add listener to update UI when type changes
        typeComboBox.addActionListener(e -> updateUIForProviderType.run());
        
        // Initial UI update
        updateUIForProviderType.run();
        
        // Authenticate button action - uses automatic callback capture with manual fallback
        authenticateButton.addActionListener(e -> {
            APIProvider.ProviderType selectedType = (APIProvider.ProviderType) typeComboBox.getSelectedItem();
            boolean isOpenAIOAuth = selectedType == APIProvider.ProviderType.OPENAI_OAUTH;
            
            if (isOpenAIOAuth) {
                authenticateOpenAIOAuth(panel, keyField);
            } else {
                authenticateAnthropicOAuth(panel, keyField);
            }
        });

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
            
            APIProvider.ProviderType selectedType = (APIProvider.ProviderType) typeComboBox.getSelectedItem();

            if (name.isEmpty() || model.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Name and Model are required.", "Validation Error", JOptionPane.ERROR_MESSAGE);
                return false;
            }
            
            // For OAuth, key must contain valid JSON token
            if (selectedType == APIProvider.ProviderType.ANTHROPIC_OAUTH || 
                selectedType == APIProvider.ProviderType.OPENAI_OAUTH) {
                if (key.isEmpty() || !key.trim().startsWith("{")) {
                    JOptionPane.showMessageDialog(this, 
                        "OAuth token is required. Please click 'Authenticate' to sign in.",
                        "Validation Error", JOptionPane.ERROR_MESSAGE);
                    return false;
                }
            }

            provider.setName(name);
            provider.setType(selectedType);
            provider.setModel(model);
            provider.setMaxTokens(maxTokens);
            // For OAuth, URL is not used - set to fixed endpoint
            if (selectedType == APIProvider.ProviderType.ANTHROPIC_OAUTH) {
                provider.setUrl("https://api.anthropic.com/");
            } else if (selectedType == APIProvider.ProviderType.OPENAI_OAUTH) {
                provider.setUrl("https://chatgpt.com/");
            } else {
                provider.setUrl(url.endsWith("/") ? url : url + "/");
            }
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

    // ==== OAuth Authentication Methods ====
    
    /**
     * Authenticates with OpenAI OAuth using automatic callback capture.
     * Falls back to manual code entry if automatic capture fails.
     */
    private void authenticateOpenAIOAuth(JPanel parentPanel, JTextField keyField) {
        OpenAIOAuthTokenManager tokenManager = new OpenAIOAuthTokenManager();
        
        // Create progress dialog with cancel option
        JDialog progressDialog = new JDialog(SwingUtilities.getWindowAncestor(parentPanel), 
            "OpenAI OAuth Authentication", Dialog.ModalityType.APPLICATION_MODAL);
        JPanel progressPanel = new JPanel(new BorderLayout(10, 10));
        progressPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
        
        JLabel statusLabel = new JLabel("Opening browser for authentication...");
        JProgressBar progressBar = new JProgressBar();
        progressBar.setIndeterminate(true);
        
        JButton cancelButton = new JButton("Cancel");
        JButton manualButton = new JButton("Use Manual Entry");
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 0));
        buttonPanel.add(manualButton);
        buttonPanel.add(cancelButton);
        
        progressPanel.add(statusLabel, BorderLayout.NORTH);
        progressPanel.add(progressBar, BorderLayout.CENTER);
        progressPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        progressDialog.setContentPane(progressPanel);
        progressDialog.setSize(400, 150);
        progressDialog.setLocationRelativeTo(parentPanel);
        
        // Track authentication state
        final boolean[] authCompleted = {false};
        final boolean[] cancelled = {false};
        
        // Worker for automatic callback authentication
        SwingWorker<String, Void> authWorker = new SwingWorker<String, Void>() {
            private String errorMessage = null;
            private OAuthCallbackServer callbackServer = null;
            
            @Override
            protected String doInBackground() {
                try {
                    callbackServer = tokenManager.startAuthorizationFlowWithCallback();
                    publish(); // Update status
                    
                    // Wait for callback with 5 minute timeout
                    tokenManager.completeAuthorizationWithCallback(callbackServer, 5);
                    return tokenManager.toJson();
                } catch (Exception ex) {
                    if (!cancelled[0]) {
                        errorMessage = ex.getMessage();
                    }
                    return null;
                }
            }
            
            @Override
            protected void process(java.util.List<Void> chunks) {
                statusLabel.setText("Waiting for authentication in browser...");
            }
            
            @Override
            protected void done() {
                if (cancelled[0]) return;
                
                try {
                    String credentialsJson = get();
                    if (credentialsJson != null && !credentialsJson.isEmpty()) {
                        authCompleted[0] = true;
                        progressDialog.dispose();
                        keyField.setText(credentialsJson);
                        JOptionPane.showMessageDialog(parentPanel, 
                            "Successfully authenticated with ChatGPT Pro/Plus!\n\nThe OAuth token has been stored.",
                            "Authentication Successful", 
                            JOptionPane.INFORMATION_MESSAGE);
                    } else if (errorMessage != null && !cancelled[0]) {
                        progressDialog.dispose();
                        // Fall back to manual entry on error
                        authenticateOpenAIOAuthManual(parentPanel, keyField);
                    }
                } catch (Exception ex) {
                    if (!cancelled[0]) {
                        progressDialog.dispose();
                        authenticateOpenAIOAuthManual(parentPanel, keyField);
                    }
                }
            }
            
            public void cancel() {
                cancelled[0] = true;
                tokenManager.cancelAuthentication();
            }
        };
        
        // Cancel button action
        cancelButton.addActionListener(e -> {
            cancelled[0] = true;
            tokenManager.cancelAuthentication();
            authWorker.cancel(true);
            progressDialog.dispose();
        });
        
        // Manual entry button action
        manualButton.addActionListener(e -> {
            cancelled[0] = true;
            tokenManager.cancelAuthentication();
            authWorker.cancel(true);
            progressDialog.dispose();
            authenticateOpenAIOAuthManual(parentPanel, keyField);
        });
        
        // Start the worker
        authWorker.execute();
        
        // Show progress dialog (blocks until closed)
        progressDialog.setVisible(true);
    }
    
    /**
     * Manual OAuth code entry for OpenAI (fallback).
     */
    private void authenticateOpenAIOAuthManual(JPanel parentPanel, JTextField keyField) {
        OpenAIOAuthTokenManager tokenManager = new OpenAIOAuthTokenManager();
        tokenManager.startAuthorizationFlow();
        
        String code = (String) JOptionPane.showInputDialog(
            parentPanel,
            "<html>A browser window has been opened for ChatGPT Pro/Plus authentication.<br><br>" +
            "<b>Instructions:</b><br>" +
            "1. Sign in to your OpenAI/ChatGPT account in the browser<br>" +
            "2. Authorize GhidrAssist to access your account<br>" +
            "3. After authorization, you'll be redirected to localhost<br>" +
            "4. Copy the URL from the browser (or just the code value)<br>" +
            "5. Paste it below:<br><br>" +
            "<b>Paste URL or Code:</b></html>",
            "OpenAI OAuth Authentication",
            JOptionPane.PLAIN_MESSAGE,
            null,
            null,
            ""
        );
        
        if (code == null || code.trim().isEmpty()) {
            return;
        }
        
        SwingWorker<String, Void> exchangeWorker = new SwingWorker<String, Void>() {
            private String errorMessage = null;
            
            @Override
            protected String doInBackground() {
                try {
                    tokenManager.authenticateWithCode(code.trim());
                    return tokenManager.toJson();
                } catch (Exception ex) {
                    errorMessage = ex.getMessage();
                    return null;
                }
            }
            
            @Override
            protected void done() {
                try {
                    String credentialsJson = get();
                    if (credentialsJson != null && !credentialsJson.isEmpty()) {
                        keyField.setText(credentialsJson);
                        JOptionPane.showMessageDialog(parentPanel, 
                            "Successfully authenticated with ChatGPT Pro/Plus!\n\nThe OAuth token has been stored.",
                            "Authentication Successful", 
                            JOptionPane.INFORMATION_MESSAGE);
                    } else if (errorMessage != null) {
                        JOptionPane.showMessageDialog(parentPanel,
                            "Authentication failed: " + errorMessage,
                            "Authentication Error",
                            JOptionPane.ERROR_MESSAGE);
                    }
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(parentPanel,
                        "Authentication error: " + ex.getMessage(),
                        "Authentication Error",
                        JOptionPane.ERROR_MESSAGE);
                }
            }
        };
        
        exchangeWorker.execute();
    }
    
    /**
     * Authenticates with Anthropic OAuth using automatic callback capture.
     * Falls back to manual code entry if automatic capture fails.
     */
    private void authenticateAnthropicOAuth(JPanel parentPanel, JTextField keyField) {
        OAuthTokenManager tokenManager = new OAuthTokenManager();
        
        // Create progress dialog with cancel option
        JDialog progressDialog = new JDialog(SwingUtilities.getWindowAncestor(parentPanel), 
            "Claude OAuth Authentication", Dialog.ModalityType.APPLICATION_MODAL);
        JPanel progressPanel = new JPanel(new BorderLayout(10, 10));
        progressPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
        
        JLabel statusLabel = new JLabel("Opening browser for authentication...");
        JProgressBar progressBar = new JProgressBar();
        progressBar.setIndeterminate(true);
        
        JButton cancelButton = new JButton("Cancel");
        JButton manualButton = new JButton("Use Manual Entry");
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 0));
        buttonPanel.add(manualButton);
        buttonPanel.add(cancelButton);
        
        progressPanel.add(statusLabel, BorderLayout.NORTH);
        progressPanel.add(progressBar, BorderLayout.CENTER);
        progressPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        progressDialog.setContentPane(progressPanel);
        progressDialog.setSize(400, 150);
        progressDialog.setLocationRelativeTo(parentPanel);
        
        // Track authentication state
        final boolean[] authCompleted = {false};
        final boolean[] cancelled = {false};
        
        // Worker for automatic callback authentication
        SwingWorker<String, Void> authWorker = new SwingWorker<String, Void>() {
            private String errorMessage = null;
            private OAuthCallbackServer callbackServer = null;
            
            @Override
            protected String doInBackground() {
                try {
                    callbackServer = tokenManager.startAuthorizationFlowWithCallback();
                    publish(); // Update status
                    
                    // Wait for callback with 5 minute timeout
                    tokenManager.completeAuthorizationWithCallback(callbackServer, 5);
                    return tokenManager.toJson();
                } catch (Exception ex) {
                    if (!cancelled[0]) {
                        errorMessage = ex.getMessage();
                    }
                    return null;
                }
            }
            
            @Override
            protected void process(java.util.List<Void> chunks) {
                statusLabel.setText("Waiting for authentication in browser...");
            }
            
            @Override
            protected void done() {
                if (cancelled[0]) return;
                
                try {
                    String credentialsJson = get();
                    if (credentialsJson != null && !credentialsJson.isEmpty()) {
                        authCompleted[0] = true;
                        progressDialog.dispose();
                        keyField.setText(credentialsJson);
                        JOptionPane.showMessageDialog(parentPanel, 
                            "Successfully authenticated with Claude Pro/Max!\n\nThe OAuth token has been stored.",
                            "Authentication Successful", 
                            JOptionPane.INFORMATION_MESSAGE);
                    } else if (errorMessage != null && !cancelled[0]) {
                        progressDialog.dispose();
                        // Fall back to manual entry on error
                        authenticateAnthropicOAuthManual(parentPanel, keyField);
                    }
                } catch (Exception ex) {
                    if (!cancelled[0]) {
                        progressDialog.dispose();
                        authenticateAnthropicOAuthManual(parentPanel, keyField);
                    }
                }
            }
            
            public void cancel() {
                cancelled[0] = true;
                tokenManager.cancelAuthentication();
            }
        };
        
        // Cancel button action
        cancelButton.addActionListener(e -> {
            cancelled[0] = true;
            tokenManager.cancelAuthentication();
            authWorker.cancel(true);
            progressDialog.dispose();
        });
        
        // Manual entry button action
        manualButton.addActionListener(e -> {
            cancelled[0] = true;
            tokenManager.cancelAuthentication();
            authWorker.cancel(true);
            progressDialog.dispose();
            authenticateAnthropicOAuthManual(parentPanel, keyField);
        });
        
        // Start the worker
        authWorker.execute();
        
        // Show progress dialog (blocks until closed)
        progressDialog.setVisible(true);
    }
    
    /**
     * Manual OAuth code entry for Anthropic (fallback).
     * Uses Anthropic's hosted callback page where user copies the code.
     */
    private void authenticateAnthropicOAuthManual(JPanel parentPanel, JTextField keyField) {
        OAuthTokenManager tokenManager = new OAuthTokenManager();
        tokenManager.startAuthorizationFlow();
        
        String code = (String) JOptionPane.showInputDialog(
            parentPanel,
            "<html>A browser window has been opened for Claude Pro/Max authentication.<br><br>" +
            "<b>Instructions:</b><br>" +
            "1. Sign in to your Anthropic account in the browser<br>" +
            "2. Authorize GhidrAssist to access your account<br>" +
            "3. Copy the authorization code shown on the page<br>" +
            "4. Paste it below:<br><br>" +
            "<b>Authorization Code:</b></html>",
            "Claude OAuth Authentication",
            JOptionPane.PLAIN_MESSAGE,
            null,
            null,
            ""
        );
        
        if (code == null || code.trim().isEmpty()) {
            return;
        }
        
        SwingWorker<String, Void> exchangeWorker = new SwingWorker<String, Void>() {
            private String errorMessage = null;
            
            @Override
            protected String doInBackground() {
                try {
                    tokenManager.authenticateWithCode(code.trim());
                    return tokenManager.toJson();
                } catch (Exception ex) {
                    errorMessage = ex.getMessage();
                    return null;
                }
            }
            
            @Override
            protected void done() {
                try {
                    String credentialsJson = get();
                    if (credentialsJson != null && !credentialsJson.isEmpty()) {
                        keyField.setText(credentialsJson);
                        JOptionPane.showMessageDialog(parentPanel, 
                            "Successfully authenticated with Claude Pro/Max!\n\nThe OAuth token has been stored.",
                            "Authentication Successful", 
                            JOptionPane.INFORMATION_MESSAGE);
                    } else if (errorMessage != null) {
                        JOptionPane.showMessageDialog(parentPanel,
                            "Authentication failed: " + errorMessage,
                            "Authentication Error",
                            JOptionPane.ERROR_MESSAGE);
                    }
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(parentPanel,
                        "Authentication error: " + ex.getMessage(),
                        "Authentication Error",
                        JOptionPane.ERROR_MESSAGE);
                }
            }
        };
        
        exchangeWorker.execute();
    }

    // ==== Inner Classes ====

    private static class MCPServersTableModel extends javax.swing.table.AbstractTableModel {
        private static final long serialVersionUID = 1L;
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
