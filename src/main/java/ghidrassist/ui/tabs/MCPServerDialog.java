package ghidrassist.ui.tabs;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.*;

import ghidrassist.mcp2.server.MCPServerConfig;

public class MCPServerDialog extends JDialog {
    private static final long serialVersionUID = 1L;
    
    private JTextField nameField;
    private JTextField urlField;
    private JComboBox<MCPServerConfig.TransportType> transportCombo;
    private JCheckBox enabledCheckBox;
    private JButton okButton;
    private JButton cancelButton;
    private boolean confirmed = false;
    
    public MCPServerDialog(Window parent, MCPServerConfig existingServer) {
        super(parent, existingServer == null ? "Add MCP Server" : "Edit MCP Server", 
              ModalityType.APPLICATION_MODAL);
        
        initializeComponents();
        layoutComponents();
        setupEventHandlers();
        
        if (existingServer != null) {
            populateFields(existingServer);
        } else {
            setDefaults();
        }
        
        pack();
        setLocationRelativeTo(parent);
        nameField.requestFocusInWindow();
    }
    
    private void initializeComponents() {
        nameField = new JTextField(20);
        urlField = new JTextField(30);
        transportCombo = new JComboBox<>(MCPServerConfig.TransportType.values());
        enabledCheckBox = new JCheckBox("Enabled", true);
        
        okButton = new JButton("OK");
        cancelButton = new JButton("Cancel");
        
        getRootPane().setDefaultButton(okButton);
    }
    
    private void layoutComponents() {
        setLayout(new BorderLayout());
        
        // Form panel
        JPanel formPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        
        // Name
        gbc.gridx = 0; gbc.gridy = 0; gbc.anchor = GridBagConstraints.EAST;
        formPanel.add(new JLabel("Name:"), gbc);
        gbc.gridx = 1; gbc.anchor = GridBagConstraints.WEST; gbc.fill = GridBagConstraints.HORIZONTAL;
        formPanel.add(nameField, gbc);
        
        // URL
        gbc.gridx = 0; gbc.gridy = 1; gbc.anchor = GridBagConstraints.EAST; gbc.fill = GridBagConstraints.NONE;
        formPanel.add(new JLabel("URL:"), gbc);
        gbc.gridx = 1; gbc.anchor = GridBagConstraints.WEST; gbc.fill = GridBagConstraints.HORIZONTAL;
        formPanel.add(urlField, gbc);
        
        // Transport
        gbc.gridx = 0; gbc.gridy = 2; gbc.anchor = GridBagConstraints.EAST; gbc.fill = GridBagConstraints.NONE;
        formPanel.add(new JLabel("Transport:"), gbc);
        gbc.gridx = 1; gbc.anchor = GridBagConstraints.WEST; gbc.fill = GridBagConstraints.HORIZONTAL;
        formPanel.add(transportCombo, gbc);
        
        // Enabled
        gbc.gridx = 1; gbc.gridy = 3; gbc.anchor = GridBagConstraints.WEST;
        formPanel.add(enabledCheckBox, gbc);
        
        // Help text
        JPanel helpPanel = new JPanel(new BorderLayout());
        JTextArea helpText = new JTextArea(
            "Examples:\n" +
            "• Name: GhidraMCP, URL: http://localhost:8080\n" +
            "• Name: Local Tools, URL: http://127.0.0.1:3000\n\n" +
            "The server must implement the Model Context Protocol (MCP) specification."
        );
        helpText.setEditable(false);
        helpText.setOpaque(false);
        helpText.setFont(helpText.getFont().deriveFont(Font.ITALIC, 11f));
        helpPanel.add(helpText, BorderLayout.CENTER);
        helpPanel.setBorder(BorderFactory.createTitledBorder("Help"));
        
        // Button panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonPanel.add(okButton);
        buttonPanel.add(cancelButton);
        
        // Layout
        add(formPanel, BorderLayout.CENTER);
        add(helpPanel, BorderLayout.NORTH);
        add(buttonPanel, BorderLayout.SOUTH);
        
        // Add border to content pane instead
        getRootPane().setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
    }
    
    private void setupEventHandlers() {
        okButton.addActionListener(e -> {
            if (validateInput()) {
                confirmed = true;
                dispose();
            }
        });
        
        cancelButton.addActionListener(e -> {
            confirmed = false;
            dispose();
        });
        
        // Transport selection updates URL placeholder
        transportCombo.addActionListener(e -> updateUrlPlaceholder());
    }
    
    private void setDefaults() {
        transportCombo.setSelectedItem(MCPServerConfig.TransportType.SSE);
        updateUrlPlaceholder();
    }
    
    private void populateFields(MCPServerConfig server) {
        nameField.setText(server.getName());
        urlField.setText(server.getBaseUrl());
        transportCombo.setSelectedItem(server.getTransport());
        enabledCheckBox.setSelected(server.isEnabled());
    }
    
    private void updateUrlPlaceholder() {
        MCPServerConfig.TransportType transport = 
            (MCPServerConfig.TransportType) transportCombo.getSelectedItem();
        
        if (transport == MCPServerConfig.TransportType.SSE) {
            urlField.setToolTipText("HTTP(S) URL for Server-Sent Events transport (e.g., http://localhost:8080)");
        } else {
            urlField.setToolTipText("Command or path for stdio transport");
        }
    }
    
    private boolean validateInput() {
        String name = nameField.getText().trim();
        String url = urlField.getText().trim();
        
        if (name.isEmpty()) {
            showError("Name cannot be empty.");
            nameField.requestFocus();
            return false;
        }
        
        if (url.isEmpty()) {
            showError("URL cannot be empty.");
            urlField.requestFocus();
            return false;
        }
        
        // Basic URL validation for SSE transport
        MCPServerConfig.TransportType transport = 
            (MCPServerConfig.TransportType) transportCombo.getSelectedItem();
        
        if (transport == MCPServerConfig.TransportType.SSE) {
            if (!url.startsWith("http://") && !url.startsWith("https://")) {
                showError("URL must start with http:// or https:// for SSE transport.");
                urlField.requestFocus();
                return false;
            }
        }
        
        return true;
    }
    
    private void showError(String message) {
        JOptionPane.showMessageDialog(this, message, "Validation Error", JOptionPane.ERROR_MESSAGE);
    }
    
    public boolean isConfirmed() {
        return confirmed;
    }
    
    public MCPServerConfig getServerConfig() {
        if (!confirmed) return null;
        
        return new MCPServerConfig(
            nameField.getText().trim(),
            urlField.getText().trim(),
            (MCPServerConfig.TransportType) transportCombo.getSelectedItem(),
            enabledCheckBox.isSelected()
        );
    }
}