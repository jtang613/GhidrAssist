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

import java.awt.*;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;

import com.vladsch.flexmark.html.HtmlRenderer;
import com.vladsch.flexmark.parser.Parser;
import com.vladsch.flexmark.util.ast.Document;
import com.vladsch.flexmark.util.data.MutableDataSet;

public class GhidrAssistProvider extends ComponentProvider {

    private JPanel panel;
    private JTabbedPane tabbedPane;
    private GhidrAssistPlugin plugin;

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
    
    // RLHF
    private RLHFDatabase rlhfDatabase;

    private String lastPrompt;
    private String lastResponse;

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
        
        // Initialize Markdown parser and renderer
        MutableDataSet options = new MutableDataSet();
        options.set(HtmlRenderer.SOFT_BREAK, "<br />\n");
        markdownParser = Parser.builder(options).build();
        htmlRenderer = HtmlRenderer.builder(options).build();

        buildPanel();
        createActions();

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
        queryTextArea.setRows(5);

        // Set hint text for queryTextArea
        addHintTextToQueryTextArea();

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, responseScrollPane, queryScrollPane);
        splitPane.setResizeWeight(0.8);

        JButton submitButton = new JButton("Submit");
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

        JTable actionsTable = new JTable(); // Set up table model as needed

        JScrollPane tableScrollPane = new JScrollPane(actionsTable);

        JButton analyzeFunctionButton = new JButton("Analyze Function");
        JButton clearButton = new JButton("Clear");
        JButton applyActionsButton = new JButton("Apply Actions");

        JPanel buttonPanel = new JPanel();
        buttonPanel.add(analyzeFunctionButton);
        buttonPanel.add(clearButton);
        buttonPanel.add(applyActionsButton);

        actionsPanel.add(tableScrollPane, BorderLayout.CENTER);
        actionsPanel.add(buttonPanel, BorderLayout.SOUTH);

        // Add action listeners
        clearButton.addActionListener(e -> {
            // Clear actions table (implement as needed)
        });

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

        return ragPanel;
    }

    private void createActions() {
        // Create any actions if needed
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
            }
        }
    }

    private void onExplainFunctionClicked() {
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
                    LlmApi llmApi = new LlmApi(plugin.getCurrentAPIProvider());
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
                                explainTextPane.setCaretPosition(0); // Scroll to top
                            });
                        }

                        @Override
                        public void onComplete(String fullResponse) {
                            SwingUtilities.invokeLater(() -> {
                            	lastResponse = fullResponse;
                                String html = markdownToHtml(fullResponse);
                                explainTextPane.setText(html);
                                explainTextPane.setCaretPosition(0); // Scroll to top
                            });
                        }

                        @Override
                        public void onError(Throwable error) {
                            SwingUtilities.invokeLater(() -> {
                                explainTextPane.setText("An error occurred: " + error.getMessage());
                            });
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
                    LlmApi llmApi = new LlmApi(plugin.getCurrentAPIProvider());
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
                                explainTextPane.setCaretPosition(0); // Scroll to top
                            });
                        }

                        @Override
                        public void onComplete(String fullResponse) {
                            SwingUtilities.invokeLater(() -> {
                                lastResponse = fullResponse;
                                String html = markdownToHtml(fullResponse);
                                explainTextPane.setText(html);
                                explainTextPane.setCaretPosition(0); // Scroll to top
                            });
                        }

                        @Override
                        public void onError(Throwable error) {
                            SwingUtilities.invokeLater(() -> {
                                explainTextPane.setText("An error occurred: " + error.getMessage());
                            });
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
        String query = queryTextArea.getText();

        // Check if the query is just the hint text
        if (query.equals(queryHintText)) {
            Msg.showInfo(getClass(), panel, "Empty Query", "Please enter a query.");
            return;
        }

        // Process macros in the query
        String processedQuery = processMacrosInQuery(query);
        lastPrompt = processedQuery;


        Task task = new Task("Custom Query", true, true, true) {
            @Override
            public void run(TaskMonitor monitor) {
                try {

                    // Use LlmApi to send request
                    LlmApi llmApi = new LlmApi(plugin.getCurrentAPIProvider());
                    llmApi.sendRequestAsync(processedQuery, new LlmApi.LlmResponseHandler() {
                        @Override
                        public void onStart() {
                            SwingUtilities.invokeLater(() -> {
                                responseTextPane.setText("Processing...");
                            });
                        }

                        @Override
                        public void onUpdate(String partialResponse) {
                            SwingUtilities.invokeLater(() -> {
                                String html = markdownToHtml(partialResponse);
                                responseTextPane.setText(html);
                                responseTextPane.setCaretPosition(0); // Scroll to top
                            });
                        }

                        @Override
                        public void onComplete(String fullResponse) {
                            SwingUtilities.invokeLater(() -> {
                                lastResponse = fullResponse;
                                String html = markdownToHtml(fullResponse);
                                responseTextPane.setText(html);
                                responseTextPane.setCaretPosition(0); // Scroll to top
                            });
                        }

                        @Override
                        public void onError(Throwable error) {
                            SwingUtilities.invokeLater(() -> {
                                responseTextPane.setText("An error occurred: " + error.getMessage());
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
            sb.append(instr.getAddress().toString());
            sb.append("  ");
            sb.append(instr.toString());
            sb.append("\n");
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
            LlmApi llmApi = new LlmApi(plugin.getCurrentAPIProvider());
            String modelName = plugin.getCurrentAPIProvider().getModel();
            String systemContext = llmApi.getSystemPrompt();
            rlhfDatabase.storeFeedback(modelName, lastPrompt, systemContext, lastResponse, feedback);
            Msg.showInfo(getClass(), panel, "Feedback", "Thank you for your feedback!");
        } else {
            Msg.showError(getClass(), panel, "Error", "No explain response to provide feedback on.");
        }
    }

}
