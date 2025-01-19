package ghidrassist;

import docking.ComponentProvider;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import ghidrassist.GhidrAssistPlugin.CodeViewType;
import ghidra.util.task.TaskLauncher;

import javax.swing.*;
import javax.swing.event.HyperlinkEvent;
import javax.swing.event.HyperlinkListener;
import javax.swing.table.DefaultTableModel;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
import com.google.gson.stream.JsonReader;
import com.vladsch.flexmark.html.HtmlRenderer;
import com.vladsch.flexmark.parser.Parser;
import com.vladsch.flexmark.util.ast.Document;
import com.vladsch.flexmark.util.data.MutableDataSet;

import ghidrassist.SearchResult; 

public class GhidrAssistProvider extends ComponentProvider {

    private JPanel panel;
    private JTabbedPane tabbedPane;
    private GhidrAssistPlugin plugin;

    // For stopping running queries
    private AtomicBoolean isQueryRunning = new AtomicBoolean(false);
    private AtomicInteger numRunners = new AtomicInteger(0);
    
    // Components for Explain tab
    private JTextField offsetField;
    private JEditorPane explainTextPane;
    private JButton explainFunctionButton;
    private JButton explainLineButton;
    private JButton clearExplainButton;

    // Components for Query tab
    private JEditorPane responseTextPane;
    private JTextArea queryTextArea;
    private JCheckBox useRAGCheckBox;
    private StringBuilder conversationHistory;
    private StringBuilder currentResponse;
    private JButton submitButton;
    private Timer updateTimer;
    private static final int UPDATE_DELAY = 500; // milliseconds
    
    // Actions tab components
    private JTable actionsTable;
    private Map<String, JCheckBox> filterCheckBoxes;
    private JButton analyzeFunctionButton;
    private JButton analyzeClearButton;
    private JButton applyActionsButton;

    // RLHF
    private RLHFDatabase rlhfDatabase;
    private String lastPrompt;
    private String lastResponse;
    
    // Analysis database
    private AnalysisDB analysisDB;

    // Flexmark parser and renderer
    private Parser markdownParser;
    private HtmlRenderer htmlRenderer;

    // Hint text for queryTextArea
    private final String queryHintText = "#line to include the current disassembly line.\n" +
            "#func to include current function disassembly.\n" +
            "#addr to include the current hex address.\n" +
            "#range(start, end) to include the view data in a given range.";

    public GhidrAssistProvider(GhidrAssistPlugin plugin, String owner) {
        super(plugin.getTool(), owner, owner);
        this.plugin = plugin;

        // Initialize RLHFDatabase
        rlhfDatabase = new RLHFDatabase();

        // Initialize AnalysisDB
        analysisDB = new AnalysisDB();
        
        // Initialize Markdown parser and renderer
        MutableDataSet options = new MutableDataSet();
        options.set(HtmlRenderer.SOFT_BREAK, "<br />\n");
        markdownParser = Parser.builder(options).build();
        htmlRenderer = HtmlRenderer.builder(options).build();
        
        conversationHistory = new StringBuilder();
        currentResponse = new StringBuilder();

        // Initialize update timer
        updateTimer = new Timer(UPDATE_DELAY, e -> updateConversationDisplay());
        updateTimer.setRepeats(false);
        
        buildPanel();

        setVisible(true);
    }
    
    

    private void buildPanel() {
        panel = new JPanel(new BorderLayout());

        tabbedPane = new JTabbedPane();

        // Create tabs
        JPanel explainTab = createExplainTab();
        JPanel queryTab = createQueryTab();
        JPanel actionsTab = createActionsTab();
        JPanel ragManagementTab = createRAGManagementTab();

        tabbedPane.addTab("Explain", explainTab);
        tabbedPane.addTab("Custom Query", queryTab);
        tabbedPane.addTab("Actions", actionsTab);
        tabbedPane.addTab("RAG Management", ragManagementTab);

        panel.add(tabbedPane, BorderLayout.CENTER);
    }

    private JPanel createExplainTab() {
        JPanel explainPanel = new JPanel(new BorderLayout());

        // Components for Explain tab
        JLabel offsetLabel = new JLabel("Offset: ");
        offsetField = new JTextField(16);
        offsetField.setEditable(false);
        JPanel offsetPanel = new JPanel();
        offsetPanel.add(offsetLabel);
        offsetPanel.add(offsetField);

        explainTextPane = new JEditorPane();
        explainTextPane.setEditable(false);
        explainTextPane.setContentType("text/html"); // Set content type to HTML
        explainTextPane.addHyperlinkListener(new HyperlinkListener() {
            @Override
            public void hyperlinkUpdate(HyperlinkEvent e) {
                if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED) {
                    String desc = e.getDescription();
                    if (desc.equals("thumbsup")) {
                        storeRLHFFeedback(1);
                    } else if (desc.equals("thumbsdown")) {
                        storeRLHFFeedback(0);
                    }
                }
            }
        });

        JScrollPane textScrollPane = new JScrollPane(explainTextPane);

        explainFunctionButton = new JButton("Explain Function");
        explainLineButton = new JButton("Explain Line");
        clearExplainButton = new JButton("Clear");

        JPanel buttonPanel = new JPanel();
        buttonPanel.add(explainFunctionButton);
        buttonPanel.add(explainLineButton);
        buttonPanel.add(clearExplainButton);

        explainPanel.add(offsetPanel, BorderLayout.NORTH);
        explainPanel.add(textScrollPane, BorderLayout.CENTER);
        explainPanel.add(buttonPanel, BorderLayout.SOUTH);

        // Add action listeners
        explainFunctionButton.addActionListener(e -> onExplainFunctionClicked());
        explainLineButton.addActionListener(e -> onExplainLineClicked());
        clearExplainButton.addActionListener(e -> explainTextPane.setText(""));

        return explainPanel;
    }

    private JPanel createQueryTab() {
        JPanel queryPanel = new JPanel(new BorderLayout());

        useRAGCheckBox = new JCheckBox("Use RAG");
        useRAGCheckBox.setSelected(false);

        responseTextPane = new JEditorPane();
        responseTextPane.setEditable(false);
        responseTextPane.setContentType("text/html"); // Set content type to HTML
        responseTextPane.addHyperlinkListener(new HyperlinkListener() {
            @Override
            public void hyperlinkUpdate(HyperlinkEvent e) {
                if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED) {
                    String desc = e.getDescription();
                    if (desc.equals("thumbsup")) {
                        storeRLHFFeedback(1);
                    } else if (desc.equals("thumbsdown")) {
                        storeRLHFFeedback(0);
                    }
                }
            }
        });

        JScrollPane responseScrollPane = new JScrollPane(responseTextPane);

        queryTextArea = new JTextArea();
        JScrollPane queryScrollPane = new JScrollPane(queryTextArea);
        queryTextArea.setRows(4);

        // Set hint text for queryTextArea
        addHintTextToQueryTextArea();

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, responseScrollPane, queryScrollPane);
        splitPane.setResizeWeight(0.9);

        submitButton = new JButton("Submit");
        JButton clearButton = new JButton("Clear");

        JPanel buttonPanel = new JPanel();
        buttonPanel.add(submitButton);
        buttonPanel.add(clearButton);

        queryPanel.add(useRAGCheckBox, BorderLayout.NORTH);
        queryPanel.add(splitPane, BorderLayout.CENTER);
        queryPanel.add(buttonPanel, BorderLayout.SOUTH);

        // Add action listeners
        submitButton.addActionListener(e -> onQuerySubmitClicked());
        clearButton.addActionListener(e -> {
            responseTextPane.setText("");
            queryTextArea.setText("");
            addHintTextToQueryTextArea(); // Reset hint text
            conversationHistory.setLength(0);
            updateConversationDisplay();
        });

        return queryPanel;
    }

    private void addHintTextToQueryTextArea() {
    	Color fgColor = queryTextArea.getForeground();
        queryTextArea.setText(queryHintText);
        queryTextArea.setForeground(Color.GRAY);
        queryTextArea.addFocusListener(new FocusAdapter() {
            @Override
            public void focusGained(FocusEvent e) {
                if (queryTextArea.getText().equals(queryHintText)) {
                    queryTextArea.setText("");
                    queryTextArea.setForeground(fgColor);
                }
            }

            @Override
            public void focusLost(FocusEvent e) {
                if (queryTextArea.getText().isEmpty()) {
                    queryTextArea.setForeground(Color.GRAY);
                    queryTextArea.setText(queryHintText);
                }
            }
        });
    }

    private JPanel createActionsTab() {
        JPanel actionsPanel = new JPanel(new BorderLayout());
        actionsTable = new JTable();

        // Create the table
        DefaultTableModel tableModel = new DefaultTableModel(new Object[]{"Select", "Action", "Description", "Status", "Arguments"}, 0) {
            private static final long serialVersionUID = 1L;

			@Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex == 0) {
                    return Boolean.class; // First column is a checkbox
                }
                return String.class;
            }
        };
        actionsTable.setModel(tableModel);

        // Set the "Select" column to a minimum size
        int w = actionsTable.getColumnModel().getColumn(0).getWidth();
        actionsTable.getColumnModel().getColumn(0).setMaxWidth((int)((double) (w*0.8)));
        // Hide the "Arguments" column from the user
//        actionsTable.getColumnModel().getColumn(4).setMinWidth(0);
//        actionsTable.getColumnModel().getColumn(4).setMaxWidth(0);
//        actionsTable.getColumnModel().getColumn(4).setWidth(0);
        JScrollPane tableScrollPane = new JScrollPane(actionsTable);

        // Create the filter checkboxes
        JPanel filterPanel = new JPanel();
        filterPanel.setLayout(new BoxLayout(filterPanel, BoxLayout.Y_AXIS));
        filterPanel.setBorder(BorderFactory.createTitledBorder("Filters"));

        filterCheckBoxes = new HashMap<>();
        for (Map<String, Object> fnTemplate : ToolCalling.FN_TEMPLATES) {
            if (fnTemplate.get("type").equals("function")) {
                @SuppressWarnings("unchecked")
				Map<String, Object> functionMap = (Map<String, Object>) fnTemplate.get("function");
                String fnName = functionMap.get("name").toString();
                String fnDescription = functionMap.get("description").toString();
                String checkboxLabel = fnName.replace("_", " ") + ": " + fnDescription;
                JCheckBox checkbox = new JCheckBox(checkboxLabel, true);
                filterCheckBoxes.put(fnName, checkbox);
                filterPanel.add(checkbox);
            }
        }
        JScrollPane filterScrollPane = new JScrollPane(filterPanel);
        filterScrollPane.setPreferredSize(new Dimension(200, 150));

        // Create buttons
        analyzeFunctionButton = new JButton("Analyze Function");
        analyzeClearButton = new JButton("Clear");
        applyActionsButton = new JButton("Apply Actions");

        JPanel buttonPanel = new JPanel();
        buttonPanel.add(analyzeFunctionButton);
        buttonPanel.add(analyzeClearButton);
        buttonPanel.add(applyActionsButton);

        // Add action listeners
        analyzeFunctionButton.addActionListener(e -> onAnalyzeFunctionClicked());
        analyzeClearButton.addActionListener(e -> onAnalyzeClearClicked());
        applyActionsButton.addActionListener(e -> onApplyActionsClicked());

        // Assemble the panel
        actionsPanel.add(filterScrollPane, BorderLayout.NORTH);
        actionsPanel.add(tableScrollPane, BorderLayout.CENTER);
        actionsPanel.add(buttonPanel, BorderLayout.SOUTH);

        return actionsPanel;
    }

    private JPanel createRAGManagementTab() {
        JPanel ragPanel = new JPanel(new BorderLayout());

        JButton addDocumentsButton = new JButton("Add Documents to RAG");
        JList<String> documentList = new JList<>();
        JScrollPane listScrollPane = new JScrollPane(documentList);

        JButton deleteSelectedButton = new JButton("Delete Selected");
        JButton refreshListButton = new JButton("Refresh List");

        JPanel buttonPanel = new JPanel();
        buttonPanel.add(deleteSelectedButton);
        buttonPanel.add(refreshListButton);

        ragPanel.add(addDocumentsButton, BorderLayout.NORTH);
        ragPanel.add(listScrollPane, BorderLayout.CENTER);
        ragPanel.add(buttonPanel, BorderLayout.SOUTH);

        // Add action listeners
        addDocumentsButton.addActionListener(e -> onAddDocumentsClicked(documentList));
        deleteSelectedButton.addActionListener(e -> onDeleteSelectedClicked(documentList));
        refreshListButton.addActionListener(e -> loadIndexedFiles(documentList));

        // Load the indexed files into the document list
        loadIndexedFiles(documentList);

        return ragPanel;
    }
    
    private void loadIndexedFiles(JList<String> documentList) {
        try {
            List<String> fileNames = (ArrayList<String>) RAGEngine.listIndexedFiles();
            // Update the documentList JList
            documentList.setListData(fileNames.toArray(new String[0]));
        } catch (IOException ex) {
            Msg.showError(this, panel, "Error", "Failed to load indexed files: " + ex.getMessage());
        }
    }

    private void onAddDocumentsClicked(JList<String> documentList) {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Select Documents to Add to RAG");
        fileChooser.setMultiSelectionEnabled(true);
        fileChooser.addChoosableFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("Text and Markdown Files", "txt", "md"));
        fileChooser.addChoosableFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("Source Code", "c", "h", "cpp", "hpp", "py", "java", "rs", "asm"));

        int result = fileChooser.showOpenDialog(panel);
        if (result == JFileChooser.APPROVE_OPTION) {
            File[] files = fileChooser.getSelectedFiles();
            try {
                RAGEngine.ingestDocuments(Arrays.asList(files));
                loadIndexedFiles(documentList);
                Msg.showInfo(this, panel, "Success", "Documents added to RAG.");
            } catch (IOException ex) {
                Msg.showError(this, panel, "Error", "Failed to ingest documents: " + ex.getMessage());
            }
        }
    }

    private void onDeleteSelectedClicked(JList<String> documentList) {
        List<String> selectedFiles = (ArrayList<String>) documentList.getSelectedValuesList();
        if (selectedFiles.isEmpty()) {
            Msg.showInfo(this, panel, "No Selection", "No documents selected for deletion.");
            return;
        }
        int confirmation = JOptionPane.showConfirmDialog(panel, "Are you sure you want to delete the selected documents?", "Confirm Deletion", JOptionPane.YES_NO_OPTION);
        if (confirmation == JOptionPane.YES_OPTION) {
            try {
                for (String fileName : selectedFiles) {
                    RAGEngine.deleteDocument(fileName);
                }
                loadIndexedFiles(documentList);
                Msg.showInfo(this, panel, "Success", "Selected documents deleted from RAG.");
            } catch (IOException ex) {
                Msg.showError(this, panel, "Error", "Failed to delete documents: " + ex.getMessage());
            }
        }
    }


    @Override
    public JComponent getComponent() {
        return panel;
    }

    public void updateLocation(ProgramLocation loc) {
        if (loc != null) {
            Address address = loc.getAddress();
            if (address != null) {
                offsetField.setText(address.toString());
                
                // Check for existing analysis
                Function function = plugin.getCurrentFunction();
                if (function != null) {
                    AnalysisDB.Analysis analysis = analysisDB.getAnalysis(
                        plugin.getCurrentProgram().getName(),
                        function.getEntryPoint()
                    );
                    if (analysis != null) {
                        String html = markdownToHtml(analysis.getResponse());
                        explainTextPane.setText(html);
                        explainTextPane.setCaretPosition(0);
                    } else {
                        explainTextPane.setText("");
                    }
                }
            }
        }
    }

    private void onAnalyzeFunctionClicked() {
        if (isQueryRunning.get()) {
            // If the query is running, stop it
            analyzeFunctionButton.setText("Analyze Function");
            isQueryRunning.set(false);
            return;
        } else {
            // Count number of request types
            for (Map.Entry<String, JCheckBox> entry : filterCheckBoxes.entrySet()) {
                if (entry.getValue().isSelected()) {
                	numRunners.getAndIncrement();
                }
            }
            // Set the button to "Stop" and set the query as running
            analyzeFunctionButton.setText("Stop");
            isQueryRunning.set(true);
        }

        Function currentFunction = plugin.getCurrentFunction();
        if (currentFunction == null) {
            Msg.showInfo(getClass(), panel, "No Function", "No function at current location.");
            return;
        }

        TaskMonitor monitor = TaskMonitor.DUMMY; // Replace with actual monitor if needed

        String code = getFunctionCode(currentFunction, monitor);
        if (code == null) {
            Msg.showError(this, panel, "Error", "Failed to get code from the current address.");
            return;
        }

        boolean hasSelectedActions = false;

        // Use LlmApi to send request
        LlmApi llmApi = new LlmApi(GhidrAssistPlugin.getCurrentAPIProvider());

        // For each selected action, send an individual request
        for (Map.Entry<String, JCheckBox> entry : filterCheckBoxes.entrySet()) {
            if (!isQueryRunning.get()) {
                break; // If "Stop" is pressed, exit the loop
            }

            if (entry.getValue().isSelected()) {
                hasSelectedActions = true;
                String action = entry.getKey();
                String actionPromptTemplate = ToolCalling.ACTION_PROMPTS.get(action);
                if (actionPromptTemplate != null) {
                    String actionPrompt = actionPromptTemplate.replace("{code}", code);

                    // Get the function definition for this action
                    Map<String, Object> functionDefinition = null;
                    for (Map<String, Object> fnTemplate : ToolCalling.FN_TEMPLATES) {
                        @SuppressWarnings("unchecked")
                        Map<String, Object> functionMap = (Map<String, Object>) fnTemplate.get("function");
                        if (functionMap.get("name").equals(action)) {
                            functionDefinition = functionMap;
                            break;
                        }
                    }

                    if (functionDefinition == null) {
                        Msg.showError(this, panel, "Error", "Function definition not found for action: " + action);
                        continue;
                    }

                    // Send the request with this prompt and function definition
                    List<Map<String, Object>> functions = new ArrayList<>();
                    functions.add(functionDefinition);

                    // Send the request
                    llmApi.sendRequestAsyncWithFunctions(actionPrompt, functions, new LlmApi.LlmResponseHandler() {
                        @Override
                        public void onStart() {
                            // No need to clear the results here; already done
                        }

                        @Override
                        public void onUpdate(String partialResponse) {
                            // No streaming in function calling
                        }

                        @Override
                        public void onComplete(String fullResponse) {
                            SwingUtilities.invokeLater(() -> {
                                // Parse the response and populate the table
                                parseAndDisplayActions(fullResponse);
                            	numRunners.decrementAndGet();
                                
                                if (numRunners.get() <= 0) {
                                	numRunners.set(0);
                                    // After all actions, reset the button text and stop the query
                                    analyzeFunctionButton.setText("Analyze Function");
                                    isQueryRunning.set(false);
                                }
                            });
                        }

                        @Override
                        public void onError(Throwable error) {
                            SwingUtilities.invokeLater(() -> {
                                // After all actions, reset the button text and stop the query
                                analyzeFunctionButton.setText("Analyze Function");
                            	numRunners.decrementAndGet();
                                
                                if (numRunners.get() <= 0) {
                                	numRunners.set(0);
                                    // After all actions, reset the button text and stop the query
                                    analyzeFunctionButton.setText("Analyze Function");
                                    isQueryRunning.set(false);
                                }

                                error.printStackTrace();
                                Msg.showError(this, panel, "Error", "An error occurred: " + error.getMessage());
                            });
                        }

                        @Override
                        public boolean shouldContinue() {
                            return isQueryRunning.get();  // Only continue if query is running
                        }
                    });
                }
            }
        }

        if (!hasSelectedActions) {
            Msg.showError(this, panel, "Error", "No actions selected.");
        }
    }


    private void parseAndDisplayActions(String response) {
        try {
            Gson gson = new Gson();

            String responseJson = preprocessJsonResponse(response);

            // Create a JsonReader with lenient mode enabled
            JsonReader jsonReader = new JsonReader(new StringReader(responseJson));
            jsonReader.setLenient(true);

            JsonElement jsonElement = gson.fromJson(jsonReader, JsonElement.class);

            if (!jsonElement.isJsonObject()) {
            	System.out.println("Error: Unexpected JSON structure in response");
                return;
            }

            JsonObject jsonObject = jsonElement.getAsJsonObject();

            // Check if the JSON object contains "tool_calls"
            if (jsonObject.has("tool_calls")) {
                JsonArray toolCallsArray = jsonObject.getAsJsonArray("tool_calls");

                for (JsonElement toolCallElement : toolCallsArray) {
                    if (toolCallElement.isJsonObject()) {
                        JsonObject toolCallObject = toolCallElement.getAsJsonObject();

                        String functionName = null;
                        JsonObject arguments = null;

                        if (toolCallObject.has("name") && toolCallObject.has("arguments")) {
                            functionName = toolCallObject.get("name").getAsString();
                            arguments = toolCallObject.getAsJsonObject("arguments");
                        } else {
                            System.out.println("Error: Tool call does not contain 'name' and 'arguments' fields");
                            continue;
                        }

                        // Only process actions that are in our function templates
                        List<String> functionNames = new ArrayList<>();
                        for (Map<String, Object> fnTemplate : ToolCalling.FN_TEMPLATES) {
                            @SuppressWarnings("unchecked")
                            Map<String, Object> functionMap = (Map<String, Object>) fnTemplate.get("function");
                            functionNames.add(functionMap.get("name").toString());
                        }

                        if (!functionNames.contains(functionName)) {
                        	System.out.println("Error: Unknown function: " + functionName);
                            continue;
                        }

                        // Add to actions table
                        DefaultTableModel model = (DefaultTableModel) actionsTable.getModel();
                        Object[] rowData = new Object[]{
                            Boolean.FALSE, // Deselected by default
                            functionName.replace("_", " "),
                            formatDescription(functionName, arguments),
                            "", // Status
                            arguments.toString() // Store arguments as a string (you might add a hidden column)
                        };
                        model.addRow(rowData);
                    } else {
                        System.out.println("Error: Unexpected structure in 'tool_calls' array");
                    }
                }
            } else {
            	System.out.println("Error: Response does not contain 'tool_calls' field");
                return;
            }

        } catch (JsonSyntaxException e) {
            System.out.println("Error: Failed to parse LLM response: " + e.getMessage());
        }
    }


    private String preprocessJsonResponse(String response) {
        String json = response.trim();

        // Define regex patterns to match code block markers
        Pattern codeBlockPattern = Pattern.compile("(?s)^[`']{3}(\\w+)?\\s*(.*?)\\s*[`']{3}$");
        Matcher matcher = codeBlockPattern.matcher(json);

        if (matcher.find()) {
            // Extract the content inside the code block
            json = matcher.group(2).trim();
        } else {
            // If no code block markers, attempt to find the JSON content directly
            // Remove any leading or trailing quotes
            if ((json.startsWith("\"") && json.endsWith("\"")) || (json.startsWith("'") && json.endsWith("'"))) {
                json = json.substring(1, json.length() - 1).trim();
            }
        }

        return json;
    }
    
    private String formatDescription(String functionName, JsonObject arguments) {
    	try {
	        switch (functionName) {
	            case "rename_function":
	                return arguments.get("new_name").getAsString();
	            case "rename_variable":
	                return arguments.get("var_name").getAsString() + " -> " + arguments.get("new_name").getAsString();
	            case "retype_variable":
	                return arguments.get("var_name").getAsString() + " -> " + arguments.get("new_type").getAsString();
	            case "auto_create_struct":
	                return arguments.get("var_name").getAsString();
	            default:
	                return "";
	        }
    	}
    	catch(Exception e) {
    		System.out.println("Error: Failed to parse Json: " + e.getMessage());
    	}
    	return "";
    }

    private void onAnalyzeClearClicked() {
        // Get the table model
        DefaultTableModel model = (DefaultTableModel) actionsTable.getModel();

        // Clear all rows
        model.setRowCount(0);
    }
    
    private void onApplyActionsClicked() {
        DefaultTableModel model = (DefaultTableModel) actionsTable.getModel();
        Program program = plugin.getCurrentProgram();
        Address currentAddress = plugin.getCurrentAddress();

        for (int row = 0; row < model.getRowCount(); row++) {
            Boolean isSelected = (Boolean) model.getValueAt(row, 0);
            if (isSelected) {
                String action = model.getValueAt(row, 1).toString().replace(" ", "_");
                String argumentsJson = model.getValueAt(row, 4).toString(); // Column 4 stores arguments

                // Parse arguments
                Gson gson = new Gson();
                JsonObject arguments = gson.fromJson(argumentsJson, JsonObject.class);

                // Call the appropriate handler
                switch (action) {
                    case "rename_function":
                    	try {
	                        String newName = arguments.get("new_name").getAsString().strip();
	                        ToolCalling.handle_rename_function(program, currentAddress, newName);
	                        model.setValueAt("Applied", row, 3);
	                        model.setValueAt(Boolean.FALSE, row, 0);
                    	}
                    	catch (Exception e) {
                    		model.setValueAt("Failed: " + e.getMessage(), row, 3);
                    	}
                        break;
                    case "rename_variable":
                    	try {
	                        String funcName = arguments.get("func_name").getAsString().strip();
	                        String varName = arguments.get("var_name").getAsString().strip();
	                        String newVarName = arguments.get("new_name").getAsString().strip();
	                        ToolCalling.handle_rename_variable(program, currentAddress, funcName, varName, newVarName);
	                        model.setValueAt("Applied", row, 3);
	                        model.setValueAt(Boolean.FALSE, row, 0);
                    	}
                    	catch (Exception e) {
                    		model.setValueAt("Failed: " + e.getMessage(), row, 3);
                    	}
                        break;
                    case "retype_variable":
                    	try {
	                        String funcName = arguments.get("func_name").getAsString().strip();
	                        String varName = arguments.get("var_name").getAsString().strip();
	                        String newType = arguments.get("new_type").getAsString().strip();
	                        ToolCalling.handle_retype_variable(program, currentAddress, funcName, varName, newType);
	                        model.setValueAt("Applied", row, 3);
	                        model.setValueAt(Boolean.FALSE, row, 0);
                    	}
                    	catch (Exception e) {
                    		model.setValueAt("Failed: " + e.getMessage(), row, 3);
                    	}
                        break;
                    case "auto_create_struct":
                    	try {
	                        String funcName = arguments.get("func_name").getAsString().strip();
	                        String varName = arguments.get("var_name").getAsString().strip();
	                        ToolCalling.handle_auto_create_struct(program, currentAddress, funcName, varName);
	                        model.setValueAt("Applied", row, 3);
	                        model.setValueAt(Boolean.FALSE, row, 0);
                    	}
                    	catch (Exception e) {
                    		model.setValueAt("Failed: " + e.getMessage(), row, 3);
                    	}
                        break;
                    default:
                        model.setValueAt("Failed: Unknown action", row, 3);
                        break;
                }
            }
        }
    }

    private void onExplainFunctionClicked() {
        if (isQueryRunning.get()) {
            // If the query is running, stop it
            isQueryRunning.set(false);
            return;
        }
        else {
            // Set the button to "Stop" and set the query as running
            explainFunctionButton.setText("Stop");
            isQueryRunning.set(true);
        }
        
        Function currentFunction = plugin.getCurrentFunction();
        if (currentFunction == null) {
            Msg.showInfo(getClass(), panel, "No Function", "No function at current location.");
            return;
        }

        Task task = new Task("Explain Function", true, true, true) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    String functionCode = null;
                    String codeType = null;

                    CodeViewType viewType = plugin.checkLastActiveCodeView();
                    if (viewType == CodeViewType.IS_DECOMPILER) {
                        functionCode = getFunctionCode(currentFunction, monitor);
                        codeType = "pseudo-C";
                    } else if (viewType == CodeViewType.IS_DISASSEMBLER) {
                        functionCode = getFunctionDisassembly(currentFunction);
                        codeType = "assembly";
                    } else {
                        throw new Exception("Unknown code view type.");
                    }

                    String prompt = "Explain the following " + codeType + " code:\n```\n" + functionCode + "\n```";
                    lastPrompt = prompt;

                    // Use LlmApi to send request
                    LlmApi llmApi = new LlmApi(GhidrAssistPlugin.getCurrentAPIProvider());
                    llmApi.sendRequestAsync(prompt, new LlmApi.LlmResponseHandler() {
                        @Override
                        public void onStart() {
                            SwingUtilities.invokeLater(() -> {
                                explainTextPane.setText("Processing...");
                            });
                        }

                        @Override
                        public void onUpdate(String partialResponse) {
                            SwingUtilities.invokeLater(() -> {
                                String html = markdownToHtml(partialResponse);
                                explainTextPane.setText(html);
                                //explainTextPane.setCaretPosition(0); // Scroll to top
                            });
                        }

                        @Override
                        public void onComplete(String fullResponse) {
                            SwingUtilities.invokeLater(() -> {
                                lastResponse = fullResponse;
                                String html = markdownToHtml(fullResponse);
                                explainTextPane.setText(html);
                                explainTextPane.setCaretPosition(0);
                                explainFunctionButton.setText("Explain Function");
                                isQueryRunning.set(false);
                                
                                // Store the analysis result
                                Function currentFunction = plugin.getCurrentFunction();
                                if (currentFunction != null) {
                                    analysisDB.upsertAnalysis(
                                        plugin.getCurrentProgram().getName(),
                                        currentFunction.getEntryPoint(),
                                        prompt,
                                        fullResponse
                                    );
                                }
                            });
                        }

                        @Override
                        public void onError(Throwable error) {
                            SwingUtilities.invokeLater(() -> {
                                explainTextPane.setText("An error occurred: " + error.getMessage());
                                explainFunctionButton.setText("Explain Function");
                                isQueryRunning.set(false);
                            });
                        }
                        
                        @Override
                        public boolean shouldContinue() {
                            return isQueryRunning.get();  // Only continue if query is running
                        }
                    });


                } catch (Exception e) {
                    Msg.showError(getClass(), panel, "Error", "Failed to explain function: " + e.getMessage());
                }
            }
        };

        new TaskLauncher(task, plugin.getTool().getToolFrame());
    }

    private void onExplainLineClicked() {
        if (isQueryRunning.get()) {
            // If the query is running, stop it
            isQueryRunning.set(false);
            return;
        }
        else {
            // Set the button to "Stop" and set the query as running
            explainLineButton.setText("Stop");
            isQueryRunning.set(true);
        }
        
        Address currentAddress = plugin.getCurrentAddress();
        if (currentAddress == null) {
            Msg.showInfo(getClass(), panel, "No Address", "No address at current location.");
            return;
        }

        Task task = new Task("Explain Line", true, true, true) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    String codeLine = null;
                    String codeType = null;
                    String prompt = null;

                    CodeViewType viewType = plugin.checkLastActiveCodeView();
                    if (viewType == CodeViewType.IS_DECOMPILER) {
                        // Get the decompiled code line
                        codeLine = getLineCode(currentAddress, monitor);
                        if (codeLine == null || codeLine.isEmpty()) {
                            throw new Exception("Failed to get decompiled code line.");
                        }
                        codeType = "pseudo-C";
                    } else if (viewType == CodeViewType.IS_DISASSEMBLER) {
                        // Get the disassembly line
                        codeLine = getLineDisassembly(currentAddress);
                        if (codeLine == null || codeLine.isEmpty()) {
                            throw new Exception("Failed to get disassembly instruction.");
                        }
                        codeType = "assembly";
                    } else {
                        throw new Exception("Unknown code view type.");
                    }

                    prompt = "Explain the following " + codeType + " line:\n```\n" + codeLine + "\n```";
                    lastPrompt = prompt;

                    // Use LlmApi to send request
                    LlmApi llmApi = new LlmApi(GhidrAssistPlugin.getCurrentAPIProvider());
                    llmApi.sendRequestAsync(prompt, new LlmApi.LlmResponseHandler() {
                        @Override
                        public void onStart() {
                            SwingUtilities.invokeLater(() -> {
                                explainTextPane.setText("Processing...");
                            });
                        }

                        @Override
                        public void onUpdate(String partialResponse) {
                            SwingUtilities.invokeLater(() -> {
                                String html = markdownToHtml(partialResponse);
                                explainTextPane.setText(html);
                                //explainTextPane.setCaretPosition(0); // Scroll to top
                            });
                        }

                        @Override
                        public void onComplete(String fullResponse) {
                            SwingUtilities.invokeLater(() -> {
                                lastResponse = fullResponse;
                                String html = markdownToHtml(fullResponse);
                                explainTextPane.setText(html);
                                explainTextPane.setCaretPosition(0); // Scroll to top
                                explainLineButton.setText("Explain Line");
                                isQueryRunning.set(false);
                            });
                        }

                        @Override
                        public void onError(Throwable error) {
                            SwingUtilities.invokeLater(() -> {
                                explainTextPane.setText("An error occurred: " + error.getMessage());
                                explainLineButton.setText("Explain Line");
                                isQueryRunning.set(false);
                            });
                        }
                        
                        @Override
                        public boolean shouldContinue() {
                            return isQueryRunning.get();  // Only continue if query is running
                        }
                    });


                } catch (Exception e) {
                    Msg.showError(getClass(), panel, "Error", "Failed to explain line: " + e.getMessage());
                }
            }
        };

        new TaskLauncher(task, plugin.getTool().getToolFrame());
    }

    private void onQuerySubmitClicked() {
        if (isQueryRunning.get()) {
            // If the query is running, stop it
            isQueryRunning.set(false);
            return;
        }
        else {
	        // Set the button to "Stop" and set the query as running
	        submitButton.setText("Stop");
	        isQueryRunning.set(true);
        }
        
        String query = queryTextArea.getText();

        // Check if the query is just the hint text
        if (query.equals(queryHintText)) {
            Msg.showInfo(getClass(), panel, "Empty Query", "Please enter a query.");
            return;
        }

        // Process macros in the query
        String processedQuery = processMacrosInQuery(query);

        // If 'Use RAG' is selected, perform a RAG search and prepend context
        if (useRAGCheckBox.isSelected()) {
            try {
                // Perform RAG search
                List<SearchResult> results = RAGEngine.hybridSearch(processedQuery, 5); // Retrieve top 5 results
                if (!results.isEmpty()) {
                    StringBuilder contextBuilder = new StringBuilder();
                    contextBuilder.append("<context>\n");
                    for (SearchResult result : results) {
                    	contextBuilder.append("<result>\n");
                    	contextBuilder.append("</br><file>" + result.getFilename() + "</file>").append("\n");
                    	contextBuilder.append("</br><chunkid>" + result.getChunkId() + "</chunkid>").append("\n");
                    	contextBuilder.append("</br><score>" + result.getScore() + "</score>").append("\n");
                        contextBuilder.append("</br><content>\n" + result.getSnippet() + "\n</content>").append("\n");
                    	contextBuilder.append("\n</result>\n\n");
                    }
                    contextBuilder.append("\n</context>\n");

                    // Prepend context to the processed query
                    processedQuery = contextBuilder.toString() + processedQuery;
                }
            } catch (Exception e) {
                Msg.showError(this, panel, "Error", "Failed to perform RAG search: " + e.getMessage());
                return;
            }
        }
        
        lastPrompt = processedQuery;
        final String prompt = processedQuery;

        // Add user query to conversation history
        conversationHistory.append("**User**:\n").append(prompt).append("\n\n");
        currentResponse.setLength(0);

        Task task = new Task("Custom Query", true, true, true) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    // Use LlmApi to send request
                    LlmApi llmApi = new LlmApi(GhidrAssistPlugin.getCurrentAPIProvider());
                    llmApi.sendRequestAsync(prompt, new LlmApi.LlmResponseHandler() {
                        @Override
                        public void onStart() {
                            SwingUtilities.invokeLater(() -> {
                                responseTextPane.setText("Processing...");
                            });
                        }

                        private String previousResponseChunk = "";

                        @Override
                        public void onUpdate(String partialResponse) {
                            // Append only the new portion of the response
                            if (!partialResponse.equals(previousResponseChunk)) {
                                String newChunk = partialResponse.substring(previousResponseChunk.length());
                                currentResponse.append(newChunk);
                                previousResponseChunk = partialResponse;
                                scheduleUpdate();
                            }
                        }


                        @Override
                        public void onComplete(String fullResponse) {
                            SwingUtilities.invokeLater(() -> {
                                lastResponse = fullResponse;
                                conversationHistory.append("**Assistant**:\n").append(fullResponse).append("\n\n");
                                currentResponse.setLength(0);
                                updateConversationDisplay();
                                submitButton.setText("Submit");
                                isQueryRunning.set(false);
                            });
                        }

                        @Override
                        public void onError(Throwable error) {
                            SwingUtilities.invokeLater(() -> {
                                conversationHistory.append("**Error**:\n").append(error.getMessage()).append("\n\n");
                                updateConversationDisplay();
                                submitButton.setText("Submit");
                                isQueryRunning.set(false);
                            });
                        }
                    });

                } catch (Exception e) {
                    Msg.showError(getClass(), panel, "Error", "Failed to perform query: " + e.getMessage());
                }
            }
        };

        new TaskLauncher(task, plugin.getTool().getToolFrame());
    }

    private void scheduleUpdate() {
        if (!updateTimer.isRunning()) {
            updateTimer.restart();
        }
    }

    private void updateConversationDisplay() {
        String fullConversation = conversationHistory.toString() + "**Assistant**:\n" + currentResponse.toString();
        String html = markdownToHtml(fullConversation);
        responseTextPane.setText(html);
        responseTextPane.setCaretPosition(responseTextPane.getDocument().getLength());
    }

    
    private String processMacrosInQuery(String query) {
        // Replace macros with actual code/data
        // Handle #line, #func, #addr, #range(start,end)

        try {
            CodeViewType viewType = plugin.checkLastActiveCodeView();
            TaskMonitor monitor = TaskMonitor.DUMMY; // Replace with actual monitor if needed

            // Replace #line
            if (query.contains("#line")) {
                String codeLine = null;
                if (viewType == CodeViewType.IS_DECOMPILER) {
                    codeLine = getLineCode(plugin.getCurrentAddress(), monitor);
                } else if (viewType == CodeViewType.IS_DISASSEMBLER) {
                    codeLine = getLineDisassembly(plugin.getCurrentAddress());
                }
                if (codeLine != null) {
                    query = query.replace("#line", codeLine);
                }
            }

            // Replace #func
            if (query.contains("#func")) {
                Function currentFunction = plugin.getCurrentFunction();
                String functionCode = null;
                if (currentFunction != null) {
                    if (viewType == CodeViewType.IS_DECOMPILER) {
                        functionCode = getFunctionCode(currentFunction, monitor);
                    } else if (viewType == CodeViewType.IS_DISASSEMBLER) {
                        functionCode = getFunctionDisassembly(currentFunction);
                    }
                    if (functionCode != null) {
                        query = query.replace("#func", functionCode);
                    }
                } else {
                    query = query.replace("#func", "No function at current location.");
                }
            }

            // Replace #addr
            if (query.contains("#addr")) {
                Address currentAddress = plugin.getCurrentAddress();
                String addressString = (currentAddress != null) ? currentAddress.toString() : "No address available.";
                query = query.replace("#addr", addressString);
            }

            // Replace #range(start,end)
            // Use regex to find all occurrences of #range(start,end)
            query = replaceRangeMacros(query);

        } catch (Exception e) {
            Msg.showError(getClass(), panel, "Error", "Failed to process macros: " + e.getMessage());
        }

        return query;
    }

    private String replaceRangeMacros(String query) {
        // Pattern to match #range(start, end)
        String pattern = "#range\\(([^,]+),\\s*([^\\)]+)\\)";
        java.util.regex.Pattern regex = java.util.regex.Pattern.compile(pattern);
        java.util.regex.Matcher matcher = regex.matcher(query);

        while (matcher.find()) {
            String startStr = matcher.group(1);
            String endStr = matcher.group(2);
            String rangeData = getRangeData(startStr, endStr);
            // Replace the entire macro with the range data
            String macro = matcher.group(0);
            query = query.replace(macro, rangeData);
            // Reset matcher after replacement
            matcher = regex.matcher(query);
        }
        return query;
    }

    private String getRangeData(String startStr, String endStr) {
        try {
            Program program = plugin.getCurrentProgram();
            if (program == null) {
                return "No program loaded.";
            }
            AddressFactory addressFactory = program.getAddressFactory();
            Address startAddr = addressFactory.getAddress(startStr.trim());
            Address endAddr = addressFactory.getAddress(endStr.trim());

            if (startAddr == null || endAddr == null) {
                return "Invalid addresses.";
            }

            // Get the bytes in the range
            byte[] bytes = new byte[(int) (endAddr.getOffset() - startAddr.getOffset()) + 1];
            program.getMemory().getBytes(startAddr, bytes);

            // Convert bytes to hex string
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) {
                sb.append(String.format("%02X ", b));
            }
            return sb.toString();

        } catch (Exception e) {
            return "Failed to get range data: " + e.getMessage();
        }
    }

    private String getFunctionCode(Function function, TaskMonitor monitor) {
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(function.getProgram());

        try {
            DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
            if (results != null && results.decompileCompleted()) {
                String decompiledCode = results.getDecompiledFunction().getC();
                return decompiledCode;
            } else {
                return "Failed to decompile function.";
            }
        } catch (Exception e) {
            return "Failed to decompile function: " + e.getMessage();
        } finally {
            decompiler.dispose();
        }
    }

    private String getFunctionDisassembly(Function function) {
        StringBuilder sb = new StringBuilder();
        Listing listing = function.getProgram().getListing();

        InstructionIterator instructions = listing.getInstructions(function.getBody(), true);

        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            sb.append(instr.getAddress().toString() + "  " + instr.toString() + "\n");
        }

        return sb.toString();
    }

    private String getLineCode(Address address, TaskMonitor monitor) {
        DecompInterface decompiler = new DecompInterface();
        Program program = plugin.getCurrentProgram();
        decompiler.openProgram(program);

        try {
            Function function = program.getFunctionManager().getFunctionContaining(address);
            if (function == null) {
                return "No function containing the address.";
            }

            DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
            if (results != null && results.decompileCompleted()) {
                ClangTokenGroup tokens = results.getCCodeMarkup();
                if (tokens != null) {
                    StringBuilder codeLineBuilder = new StringBuilder();
                    boolean found = collectCodeLine(tokens, address, codeLineBuilder);
                    if (found && codeLineBuilder.length() > 0) {
                        return codeLineBuilder.toString();
                    } else {
                        return "No code line found at the address.";
                    }
                } else {
                    return "Failed to get code tokens.";
                }
            } else {
                return "Failed to decompile function.";
            }
        } catch (Exception e) {
            return "Failed to decompile line: " + e.getMessage();
        } finally {
            decompiler.dispose();
        }
    }

    private boolean collectCodeLine(ClangNode node, Address address, StringBuilder codeLineBuilder) {
        if (node instanceof ClangToken) {
            ClangToken token = (ClangToken) node;
            if (token.getMinAddress() != null && token.getMaxAddress() != null) {
                if (token.getMinAddress().compareTo(address) <= 0 && token.getMaxAddress().compareTo(address) >= 0) {
                    // Found the token corresponding to the address
                    ClangNode parent = token.Parent();
                    if (parent != null) {
                        for (int i = 0; i < parent.numChildren(); i++) {
                            ClangNode sibling = parent.Child(i);
                            codeLineBuilder.append(((ClangToken) sibling).getText());
                        }
                    } else {
                        codeLineBuilder.append(token.getText());
                    }
                    return true;
                }
            }
        } else if (node instanceof ClangTokenGroup) {
            ClangTokenGroup group = (ClangTokenGroup) node;
            for (int i = 0; i < group.numChildren(); i++) {
                ClangNode child = group.Child(i);
                boolean found = collectCodeLine(child, address, codeLineBuilder);
                if (found) {
                    return true;
                }
            }
        }
        return false;
    }

    private String getLineDisassembly(Address address) {
        Instruction instruction = plugin.getCurrentProgram().getListing().getInstructionAt(address);
        if (instruction != null) {
            return instruction.getAddressString(true, true) + "  " + instruction.toString();
        } else {
            return null;
        }
    }

    private String markdownToHtml(String markdown) {
        // Parse the Markdown into a document
        Document document = markdownParser.parse(markdown);

        // Render the document to HTML
        String html = htmlRenderer.render(document);

        // Add RLHF feedback thumbs-up / thumbs-down buttons
        String feedbackLinks = "<br> <div style=\"text-align: center; color: grey; font-size: 18px;\"><a href='thumbsup'>&#128077;</a> | <a href='thumbsdown'>&#128078;</a></div>";

        // Optionally, wrap the HTML in basic tags to improve rendering
        String wrappedHtml = "<html><body>" + html + feedbackLinks + "</body></html>";

        return wrappedHtml;
    }

    private void storeRLHFFeedback(int feedback) {
        if (lastPrompt != null && lastResponse != null) {
            LlmApi llmApi = new LlmApi(GhidrAssistPlugin.getCurrentAPIProvider());
            String modelName = GhidrAssistPlugin.getCurrentAPIProvider().getModel();
            String systemContext = llmApi.getSystemPrompt();
            rlhfDatabase.storeFeedback(modelName, lastPrompt, systemContext, lastResponse, feedback);
            Msg.showInfo(getClass(), panel, "Feedback", "Thank you for your feedback!");
        } else {
            Msg.showError(getClass(), panel, "Error", "No explain response to provide feedback on.");
        }
    }
}
