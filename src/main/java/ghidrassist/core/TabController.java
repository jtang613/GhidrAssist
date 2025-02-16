package ghidrassist.core;

import javax.swing.*;
import javax.swing.event.HyperlinkEvent;
import javax.swing.table.DefaultTableModel;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import ghidrassist.AnalysisDB;
import ghidrassist.GhidrAssistPlugin;
import ghidrassist.LlmApi;
import ghidrassist.RLHFDatabase;
import ghidrassist.apiprovider.APIProviderConfig;
import ghidrassist.ui.tabs.*;

public class TabController {
    private final GhidrAssistPlugin plugin;
    private final StringBuilder conversationHistory;
    private final StringBuilder currentResponse;
    private volatile boolean isQueryRunning;
    private final AtomicInteger numRunners;
    private final MarkdownHelper markdownHelper;
    private final AnalysisDB analysisDB;
    private final RLHFDatabase rlhfDB;
    
    // Cache for last prompt/response for RLHF
    private String lastPrompt;
    private String lastResponse;
    
    // UI Component references
    private ExplainTab explainTab;
    private QueryTab queryTab;
    private ActionsTab actionsTab;
    private RAGManagementTab ragManagementTab;

    public TabController(GhidrAssistPlugin plugin) {
        this.plugin = plugin;
        this.conversationHistory = new StringBuilder();
        this.currentResponse = new StringBuilder();
        this.isQueryRunning = false;
        this.numRunners = new AtomicInteger(0);
        new UIState();
        this.markdownHelper = new MarkdownHelper();
        this.analysisDB = new AnalysisDB();
        this.rlhfDB = new RLHFDatabase();
    }

    public void setTabs(ExplainTab explainTab, QueryTab queryTab, 
                       ActionsTab actionsTab, RAGManagementTab ragManagementTab) {
        this.explainTab = explainTab;
        this.queryTab = queryTab;
        this.actionsTab = actionsTab;
        this.ragManagementTab = ragManagementTab;
    }

    public void setExplainTab(ExplainTab tab) {
        this.explainTab = tab;
    }
    
    public void setQueryTab(QueryTab tab) {
        this.queryTab = tab;
    }
    
    public void setActionsTab(ActionsTab tab) {
        this.actionsTab = tab;
    }
    
    public void setRAGManagementTab(RAGManagementTab tab) {
        this.ragManagementTab = tab;
    }
    
    public void handleExplainFunction() {
        if (isQueryRunning) {
            explainTab.setFunctionButtonText("Explain Function");
            isQueryRunning = false;
            
            APIProviderConfig config = GhidrAssistPlugin.getCurrentProviderConfig();
            if (config != null) {
                LlmApi llmApi = new LlmApi(config);
                llmApi.cancelCurrentRequest();
            }
            return;
        }
        
        explainTab.setFunctionButtonText("Stop");
        isQueryRunning = true;
        
        Function currentFunction = plugin.getCurrentFunction();
        if (currentFunction == null) {
            Msg.showInfo(getClass(), explainTab, "No Function", "No function at current location.");
            return;
        }

        Task task = new Task("Explain Function", true, true, true) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    String functionCode = null;
                    String codeType = null;

                    GhidrAssistPlugin.CodeViewType viewType = plugin.checkLastActiveCodeView();
                    if (viewType == GhidrAssistPlugin.CodeViewType.IS_DECOMPILER) {
                        functionCode = CodeUtils.getFunctionCode(currentFunction, monitor);
                        codeType = "pseudo-C";
                    } else if (viewType == GhidrAssistPlugin.CodeViewType.IS_DISASSEMBLER) {
                        functionCode = CodeUtils.getFunctionDisassembly(currentFunction);
                        codeType = "assembly";
                    } else {
                        throw new Exception("Unknown code view type.");
                    }

                    String prompt = "Explain the following " + codeType + " code:\n```\n" + functionCode + "\n```";
                    lastPrompt = prompt;

                    APIProviderConfig config = GhidrAssistPlugin.getCurrentProviderConfig();
                    if (config == null) {
                        throw new Exception("No API provider configured.");
                    }
                    
                    LlmApi llmApi = new LlmApi(config);
                    llmApi.sendRequestAsync(prompt, new LlmApi.LlmResponseHandler() {
                        @Override
                        public void onStart() {
                            SwingUtilities.invokeLater(() -> 
                                explainTab.setExplanationText("Processing..."));
                        }

                        @Override
                        public void onUpdate(String partialResponse) {
                            SwingUtilities.invokeLater(() -> 
                                explainTab.setExplanationText(
                                    markdownHelper.markdownToHtml(partialResponse)));
                        }

                        @Override
                        public void onComplete(String fullResponse) {
                            SwingUtilities.invokeLater(() -> {
                                lastResponse = fullResponse;
                                explainTab.setExplanationText(
                                    markdownHelper.markdownToHtml(fullResponse));
                                explainTab.setFunctionButtonText("Explain Function");
                                isQueryRunning = false;
                                
                                // Store analysis result
                                if (currentFunction != null) {
                                    analysisDB.upsertAnalysis(
                                        plugin.getCurrentProgram().getExecutableSHA256(),
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
                                explainTab.setExplanationText("An error occurred: " + error.getMessage());
                                explainTab.setFunctionButtonText("Explain Function");
                                isQueryRunning = false;
                            });
                        }
                        
                        @Override
                        public boolean shouldContinue() {
                            return isQueryRunning;
                        }
                    });

                } catch (Exception e) {
                    Msg.showError(getClass(), explainTab, "Error", 
                        "Failed to explain function: " + e.getMessage());
                }
            }
        };

        new TaskLauncher(task, plugin.getTool().getToolFrame());
    }

    public void handleExplainLine() {
        if (isQueryRunning) {
            explainTab.setLineButtonText("Explain Line");
            isQueryRunning = false;
            
            APIProviderConfig config = GhidrAssistPlugin.getCurrentProviderConfig();
            if (config != null) {
                LlmApi llmApi = new LlmApi(config);
                llmApi.cancelCurrentRequest();
            }
            return;
        }
        
        explainTab.setLineButtonText("Stop");
        isQueryRunning = true;
        
        Address currentAddress = plugin.getCurrentAddress();
        if (currentAddress == null) {
            Msg.showInfo(getClass(), explainTab, "No Address", "No address at current location.");
            return;
        }

        Task task = new Task("Explain Line", true, true, true) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    String codeLine = null;
                    String codeType = null;

                    GhidrAssistPlugin.CodeViewType viewType = plugin.checkLastActiveCodeView();
                    if (viewType == GhidrAssistPlugin.CodeViewType.IS_DECOMPILER) {
                        codeLine = CodeUtils.getLineCode(currentAddress, monitor, plugin.getCurrentProgram());
                        codeType = "pseudo-C";
                    } else if (viewType == GhidrAssistPlugin.CodeViewType.IS_DISASSEMBLER) {
                        codeLine = CodeUtils.getLineDisassembly(currentAddress, plugin.getCurrentProgram());
                        codeType = "assembly";
                    } else {
                        throw new Exception("Unknown code view type.");
                    }

                    String prompt = "Explain the following " + codeType + " line:\n```\n" + codeLine + "\n```";
                    lastPrompt = prompt;

                    APIProviderConfig config = GhidrAssistPlugin.getCurrentProviderConfig();
                    if (config == null) {
                        throw new Exception("No API provider configured.");
                    }
                    
                    LlmApi llmApi = new LlmApi(config);
                    llmApi.sendRequestAsync(prompt, createResponseHandler(explainTab));

                } catch (Exception e) {
                    Msg.showError(getClass(), explainTab, "Error", 
                        "Failed to explain line: " + e.getMessage());
                }
            }
        };

        new TaskLauncher(task, plugin.getTool().getToolFrame());
    }

    public void handleQuerySubmit(String query, boolean useRAG) {
        if (isQueryRunning) {
            queryTab.setSubmitButtonText("Submit");
            isQueryRunning = false;
            
            APIProviderConfig config = GhidrAssistPlugin.getCurrentProviderConfig();
            if (config != null) {
                LlmApi llmApi = new LlmApi(config);
                llmApi.cancelCurrentRequest();
            }
            return;
        }
        
        queryTab.setSubmitButtonText("Stop");
        isQueryRunning = true;

        String processedQuery = QueryProcessor.processMacrosInQuery(query, plugin);
        
        if (useRAG) {
            try {
                processedQuery = QueryProcessor.appendRAGContext(processedQuery);
            } catch (Exception e) {
                Msg.showError(this, queryTab, "Error", 
                    "Failed to perform RAG search: " + e.getMessage());
                return;
            }
        }
        
        lastPrompt = processedQuery;
        conversationHistory.append("**User**:\n").append(processedQuery).append("\n\n");
        currentResponse.setLength(0);

        Task task = new Task("Custom Query", true, true, true) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    APIProviderConfig config = GhidrAssistPlugin.getCurrentProviderConfig();
                    if (config == null) {
                        throw new Exception("No API provider configured.");
                    }
                    
                    LlmApi llmApi = new LlmApi(config);
                    llmApi.sendRequestAsync(conversationHistory.toString(), 
                        createConversationHandler(queryTab));

                } catch (Exception e) {
                    Msg.showError(getClass(), queryTab, "Error", 
                        "Failed to perform query: " + e.getMessage());
                }
            }
        };

        new TaskLauncher(task, plugin.getTool().getToolFrame());
    }

    public void handleAnalyzeFunction(Map<String, JCheckBox> filterCheckBoxes) {
        if (isQueryRunning) {
            actionsTab.setAnalyzeFunctionButtonText("Analyze Function");
            isQueryRunning = false;
            return;
        }

        // Count number of request types
        for (Map.Entry<String, JCheckBox> entry : filterCheckBoxes.entrySet()) {
            if (entry.getValue().isSelected()) {
                numRunners.incrementAndGet();
            }
        }
        
        actionsTab.setAnalyzeFunctionButtonText("Stop");
        isQueryRunning = true;

        Function currentFunction = plugin.getCurrentFunction();
        if (currentFunction == null) {
            Msg.showInfo(getClass(), actionsTab, "No Function", 
                "No function at current location.");
            return;
        }

        String code = CodeUtils.getFunctionCode(currentFunction, TaskMonitor.DUMMY);
        if (code == null) {
            Msg.showError(this, actionsTab, "Error", 
                "Failed to get code from the current address.");
            return;
        }

        handleActionRequests(code, filterCheckBoxes);
    }

    private void handleActionRequests(String code, Map<String, JCheckBox> filterCheckBoxes) {
        LlmApi llmApi = new LlmApi(GhidrAssistPlugin.getCurrentProviderConfig());

        for (Map.Entry<String, JCheckBox> entry : filterCheckBoxes.entrySet()) {
            if (!isQueryRunning) {
                break;
            }

            if (entry.getValue().isSelected()) {
                String action = entry.getKey();
                String actionPrompt = ToolCalling.ACTION_PROMPTS.get(action);
                if (actionPrompt != null) {
                    String prompt = actionPrompt.replace("{code}", code);
                    List<Map<String, Object>> functions = new ArrayList<>();
                    functions.add(getActionFunction(action));
                    
                    llmApi.sendRequestAsyncWithFunctions(prompt, functions, 
                        createActionResponseHandler(action));
                }
            }
        }
    }

    private Map<String, Object> getActionFunction(String actionName) {
        for (Map<String, Object> fnTemplate : ToolCalling.FN_TEMPLATES) {
            @SuppressWarnings("unchecked")
            Map<String, Object> functionMap = (Map<String, Object>) fnTemplate.get("function");
            if (functionMap.get("name").equals(actionName)) {
                return functionMap;
            }
        }
        return null;
    }

    public void handleApplyActions(JTable actionsTable) {
        DefaultTableModel model = (DefaultTableModel) actionsTable.getModel();
        Program program = plugin.getCurrentProgram();
        Address currentAddress = plugin.getCurrentAddress();

        for (int row = 0; row < model.getRowCount(); row++) {
            Boolean isSelected = (Boolean) model.getValueAt(row, 0);
            if (isSelected) {
                applyAction(model, row, program, currentAddress);
            }
        }
    }

    private void applyAction(DefaultTableModel model, int row, Program program, Address address) {
        String action = model.getValueAt(row, 1).toString().replace(" ", "_");
        String argumentsJson = model.getValueAt(row, 4).toString();

        try {
            ActionExecutor.executeAction(action, argumentsJson, program, address);
            model.setValueAt("Applied", row, 3);
            model.setValueAt(Boolean.FALSE, row, 0);
        } catch (Exception e) {
            model.setValueAt("Failed: " + e.getMessage(), row, 3);
        }
    }

    public void handleAddDocuments(JList<String> documentList) {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Select Documents to Add to RAG");
        fileChooser.setMultiSelectionEnabled(true);
        fileChooser.addChoosableFileFilter(
            new javax.swing.filechooser.FileNameExtensionFilter(
                "Text and Markdown Files", "txt", "md"));
        fileChooser.addChoosableFileFilter(
            new javax.swing.filechooser.FileNameExtensionFilter(
                "Source Code", "c", "h", "cpp", "hpp", "py", "java", "rs", "asm"));

        int result = fileChooser.showOpenDialog(ragManagementTab);
        if (result == JFileChooser.APPROVE_OPTION) {
            File[] files = fileChooser.getSelectedFiles();
            try {
                RAGEngine.ingestDocuments(Arrays.asList(files));
                loadIndexedFiles(documentList);
                Msg.showInfo(this, ragManagementTab, "Success", "Documents added to RAG.");
            } catch (IOException ex) {
                Msg.showError(this, ragManagementTab, "Error", 
                    "Failed to ingest documents: " + ex.getMessage());
            }
        }
    }

    public void handleDeleteSelected(JList<String> documentList) {
        List<String> selectedFiles = documentList.getSelectedValuesList();
        if (selectedFiles.isEmpty()) {
            Msg.showInfo(this, ragManagementTab, "No Selection", 
                "No documents selected for deletion.");
            return;
        }

        int confirmation = JOptionPane.showConfirmDialog(ragManagementTab,
            "Are you sure you want to delete the selected documents?",
            "Confirm Deletion", JOptionPane.YES_NO_OPTION);
            
        if (confirmation == JOptionPane.YES_OPTION) {
            try {
                for (String fileName : selectedFiles) {
                    RAGEngine.deleteDocument(fileName);
                }
                loadIndexedFiles(documentList);
                Msg.showInfo(this, ragManagementTab, "Success", 
                    "Selected documents deleted from RAG.");
            } catch (IOException ex) {
                Msg.showError(this, ragManagementTab, "Error", 
                    "Failed to delete documents: " + ex.getMessage());
            }
        }
    }

    public void loadIndexedFiles(JList<String> documentList) {
        try {
            List<String> fileNames = RAGEngine.listIndexedFiles();
            documentList.setListData(fileNames.toArray(new String[0]));
        } catch (IOException ex) {
            Msg.showError(this, ragManagementTab, "Error", 
                "Failed to load indexed files: " + ex.getMessage());
        }
    }

    public void handleHyperlinkEvent(HyperlinkEvent e) {
        if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED) {
            String desc = e.getDescription();
            if (desc.equals("thumbsup")) {
                storeRLHFFeedback(1);
            } else if (desc.equals("thumbsdown")) {
                storeRLHFFeedback(0);
            }
        }
    }

    private void storeRLHFFeedback(int feedback) {
        if (lastPrompt != null && lastResponse != null) {
            APIProviderConfig config = GhidrAssistPlugin.getCurrentProviderConfig();
            if (config == null) {
                Msg.showError(this, null, "Error", "No API provider configured.");
                return;
            }
            
            LlmApi llmApi = new LlmApi(config);
            String modelName = config.getModel();
            String systemContext = llmApi.getSystemPrompt();
            rlhfDB.storeFeedback(modelName, lastPrompt, systemContext, lastResponse, feedback);
            Msg.showInfo(getClass(), null, "Feedback", "Thank you for your feedback!");
        }
    }

    private LlmApi.LlmResponseHandler createResponseHandler(ExplainTab tab) {
        return new LlmApi.LlmResponseHandler() {
            @Override
            public void onStart() {
                SwingUtilities.invokeLater(() -> 
                    tab.setExplanationText("Processing..."));
            }

            @Override
            public void onUpdate(String partialResponse) {
                SwingUtilities.invokeLater(() -> 
                    tab.setExplanationText(
                        markdownHelper.markdownToHtml(partialResponse)));
            }

            @Override
            public void onComplete(String fullResponse) {
                SwingUtilities.invokeLater(() -> {
                    lastResponse = fullResponse;
                    tab.setExplanationText(
                        markdownHelper.markdownToHtml(fullResponse));
                    tab.setLineButtonText("Explain Line");
                    isQueryRunning = false;
                });
            }

            @Override
            public void onError(Throwable error) {
                SwingUtilities.invokeLater(() -> {
                    tab.setExplanationText("An error occurred: " + error.getMessage());
                    tab.setLineButtonText("Explain Line");
                    isQueryRunning = false;
                });
            }

            @Override
            public boolean shouldContinue() {
                return isQueryRunning;
            }
        };
    }

    private LlmApi.LlmResponseHandler createActionResponseHandler(String action) {
        return new LlmApi.LlmResponseHandler() {
            @Override
            public void onStart() {}

            @Override
            public void onUpdate(String partialResponse) {}

            @Override
            public void onComplete(String fullResponse) {
                SwingUtilities.invokeLater(() -> {
                    parseAndDisplayActions(fullResponse);
                    numRunners.decrementAndGet();
                    
                    if (numRunners.get() <= 0) {
                        numRunners.set(0);
                        actionsTab.setAnalyzeFunctionButtonText("Analyze Function");
                        isQueryRunning = false;
                    }
                });
            }

            @Override
            public void onError(Throwable error) {
                SwingUtilities.invokeLater(() -> {
                    numRunners.decrementAndGet();
                    
                    if (numRunners.get() <= 0) {
                        numRunners.set(0);
                        actionsTab.setAnalyzeFunctionButtonText("Analyze Function");
                        isQueryRunning = false;
                    }

                    error.printStackTrace();
                    Msg.showError(this, actionsTab, "Error", 
                        "An error occurred: " + error.getMessage());
                });
            }

            @Override
            public boolean shouldContinue() {
                return isQueryRunning;
            }
        };
    }

    private LlmApi.LlmResponseHandler createConversationHandler(QueryTab tab) {
        return new LlmApi.LlmResponseHandler() {
            private String previousResponseChunk = "";

            @Override
            public void onStart() {
                SwingUtilities.invokeLater(() -> 
                    tab.setResponseText("Processing..."));
            }

            @Override
            public void onUpdate(String partialResponse) {
                if (!partialResponse.equals(previousResponseChunk)) {
                    String newChunk = partialResponse.substring(
                        previousResponseChunk.length());
                    currentResponse.append(newChunk);
                    previousResponseChunk = partialResponse;
                    updateConversationDisplay();
                }
            }

            @Override
            public void onComplete(String fullResponse) {
                SwingUtilities.invokeLater(() -> {
                    lastResponse = fullResponse;
                    conversationHistory.append("**Assistant**:\n")
                        .append(fullResponse).append("\n\n");
                    currentResponse.setLength(0);
                    updateConversationDisplay();
                    tab.setSubmitButtonText("Submit");
                    isQueryRunning = false;
                });
            }

            @Override
            public void onError(Throwable error) {
                SwingUtilities.invokeLater(() -> {
                    conversationHistory.append("**Error**:\n")
                        .append(error.getMessage()).append("\n\n");
                    updateConversationDisplay();
                    tab.setSubmitButtonText("Submit");
                    isQueryRunning = false;
                });
            }

            @Override
            public boolean shouldContinue() {
                return isQueryRunning;
            }
        };
    }

    private void updateConversationDisplay() {
        String fullConversation = conversationHistory.toString() + 
            "**Assistant**:\n" + currentResponse.toString();
        queryTab.setResponseText(markdownHelper.markdownToHtml(fullConversation));
    }

    private void parseAndDisplayActions(String response) {
        try {
            ActionParser.parseAndDisplay(response, actionsTab.getTableModel());
        } catch (Exception e) {
            Msg.showError(this, actionsTab, "Error", 
                "Failed to parse actions: " + e.getMessage());
        }
    }

    public void clearConversationHistory() {
        conversationHistory.setLength(0);
        currentResponse.setLength(0);
    }

    public boolean isQueryRunning() {
        return isQueryRunning;
    }

    public void setQueryRunning(boolean running) {
        isQueryRunning = running;
    }

    public void updateAnalysis(ProgramLocation loc) {
        Function function = plugin.getCurrentFunction();
        if (function != null) {
            AnalysisDB.Analysis analysis = analysisDB.getAnalysis(
                plugin.getCurrentProgram().getExecutableSHA256(),
                function.getEntryPoint()
            );
            if (analysis != null) {
                explainTab.setExplanationText(
                    markdownHelper.markdownToHtml(analysis.getResponse()));
            } else {
                explainTab.setExplanationText("");
            }
        }
    }
}