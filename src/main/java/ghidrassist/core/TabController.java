package ghidrassist.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import ghidrassist.AnalysisDB.Analysis;
import ghidrassist.GhidrAssistPlugin;
import ghidrassist.LlmApi;
import ghidrassist.apiprovider.APIProviderConfig;
import ghidrassist.services.*;
import ghidrassist.ui.tabs.*;

import javax.swing.*;
import javax.swing.event.HyperlinkEvent;
import javax.swing.table.DefaultTableModel;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Responsibilities:
 * - UI event coordination
 * - Task lifecycle management
 * - Service orchestration
 * - UI state updates
 */
public class TabController {
    
    // Services (business logic)
    private final CodeAnalysisService codeAnalysisService;
    private final QueryService queryService;
    private final ActionAnalysisService actionAnalysisService;
    private final RAGManagementService ragManagementService;
    private final AnalysisDataService analysisDataService;
    private final FeedbackService feedbackService;
    
    // UI utilities
    private final GhidrAssistPlugin plugin;
    private final MarkdownHelper markdownHelper;
    
    // Shared LLM API instance for cancellation
    private volatile LlmApi currentLlmApi;
    
    // UI state
    private volatile boolean isQueryRunning;
    
    // UI Component references
    private ExplainTab explainTab;
    private QueryTab queryTab;
    private ActionsTab actionsTab;
    private RAGManagementTab ragManagementTab;
    private AnalysisOptionsTab analysisOptionsTab;

    public TabController(GhidrAssistPlugin plugin) {
        this.plugin = plugin;
        this.markdownHelper = new MarkdownHelper();
        this.isQueryRunning = false;
        
        // Initialize services
        this.codeAnalysisService = new CodeAnalysisService(plugin);
        this.queryService = new QueryService(plugin);
        this.actionAnalysisService = new ActionAnalysisService(plugin);
        this.ragManagementService = new RAGManagementService();
        this.analysisDataService = new AnalysisDataService(plugin);
        this.feedbackService = new FeedbackService(plugin);
        
        new UIState();
    }

    // ==== UI Component Registration ====
    
    public void setTabs(ExplainTab explainTab, QueryTab queryTab, 
                       ActionsTab actionsTab, RAGManagementTab ragManagementTab) {
        this.explainTab = explainTab;
        this.queryTab = queryTab;
        this.actionsTab = actionsTab;
        this.ragManagementTab = ragManagementTab;
    }

    public void setExplainTab(ExplainTab tab) { this.explainTab = tab; }
    public void setQueryTab(QueryTab tab) { 
        this.queryTab = tab; 
    }
    public void setActionsTab(ActionsTab tab) { this.actionsTab = tab; }
    public void setRAGManagementTab(RAGManagementTab tab) { this.ragManagementTab = tab; }
    public void setAnalysisOptionsTab(AnalysisOptionsTab tab) { this.analysisOptionsTab = tab; }

    // ==== Code Analysis Operations ====
    
    public void handleExplainFunction() {
        if (isQueryRunning) {
            cancelCurrentOperation();
            return;
        }
        
        Function currentFunction = plugin.getCurrentFunction();
        if (currentFunction == null) {
            Msg.showInfo(getClass(), explainTab, "No Function", "No function at current location.");
            return;
        }
        
        setUIState(true, "Stop", "Processing...");
        
        Task task = new Task("Explain Function", true, true, true) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    CodeAnalysisService.AnalysisRequest request = 
                        codeAnalysisService.createFunctionAnalysisRequest(currentFunction);
                    
                    feedbackService.cacheLastInteraction(request.getPrompt(), null);
                    
                    codeAnalysisService.executeAnalysis(request, new LlmApi.LlmResponseHandler() {
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
                                feedbackService.cacheLastInteraction(request.getPrompt(), fullResponse);
                                explainTab.setExplanationText(
                                    markdownHelper.markdownToHtml(fullResponse));
                                
                                // Store analysis result
                                codeAnalysisService.storeAnalysisResult(
                                    currentFunction, request.getPrompt(), fullResponse);
                                
                                setUIState(false, "Explain Function", null);
                            });
                        }

                        @Override
                        public void onError(Throwable error) {
                            SwingUtilities.invokeLater(() -> {
                                explainTab.setExplanationText("An error occurred: " + error.getMessage());
                                setUIState(false, "Explain Function", null);
                            });
                        }
                        
                        @Override
                        public boolean shouldContinue() {
                            return isQueryRunning;
                        }
                    });

                } catch (Exception e) {
                    SwingUtilities.invokeLater(() -> {
                        Msg.showError(getClass(), explainTab, "Error", 
                            "Failed to explain function: " + e.getMessage());
                        setUIState(false, "Explain Function", null);
                    });
                }
            }
        };

        new TaskLauncher(task, plugin.getTool().getToolFrame());
    }

    public void handleExplainLine() {
        if (isQueryRunning) {
            cancelCurrentOperation();
            return;
        }
        
        Address currentAddress = plugin.getCurrentAddress();
        if (currentAddress == null) {
            Msg.showInfo(getClass(), explainTab, "No Address", "No address at current location.");
            return;
        }
        
        setUIState(true, "Stop", "Processing...");
        
        Task task = new Task("Explain Line", true, true, true) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    CodeAnalysisService.AnalysisRequest request = 
                        codeAnalysisService.createLineAnalysisRequest(currentAddress);
                    
                    feedbackService.cacheLastInteraction(request.getPrompt(), null);
                    
                    codeAnalysisService.executeAnalysis(request, createExplainResponseHandler());

                } catch (Exception e) {
                    SwingUtilities.invokeLater(() -> {
                        Msg.showError(getClass(), explainTab, "Error", 
                            "Failed to explain line: " + e.getMessage());
                        setUIState(false, "Explain Line", null);
                    });
                }
            }
        };

        new TaskLauncher(task, plugin.getTool().getToolFrame());
    }

    // ==== Query Operations ====

    public void handleQuerySubmit(String query, boolean useRAG, boolean useMCP, boolean useAgentic) {
        if (isQueryRunning) {
            cancelCurrentOperation();
            return;
        }

        // Agentic mode requires MCP tools
        if (useAgentic && !useMCP) {
            Msg.showInfo(getClass(), queryTab, "MCP Required",
                "Agentic mode requires MCP tools to be enabled.");
            return;
        }

        setUIState(true, "Stop", null);

        // Route to appropriate handler
        if (useAgentic) {
            handleAgenticQuery(query);
        } else {
            handleRegularQuery(query, useRAG, useMCP);
        }
    }

    private void handleRegularQuery(String query, boolean useRAG, boolean useMCP) {
        Task task = new Task("Custom Query", true, true, true) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    QueryService.QueryRequest request = queryService.createQueryRequest(query, useRAG, useMCP);

                    feedbackService.cacheLastInteraction(request.getProcessedQuery(), null);

                    // Use shared LlmApi instance for cancellation support
                    LlmApi llmApi = getCurrentLlmApi();
                    queryService.executeQuery(request, llmApi, createConversationHandler());

                } catch (Exception e) {
                    SwingUtilities.invokeLater(() -> {
                        Msg.showError(getClass(), queryTab, "Error",
                            "Failed to perform query: " + e.getMessage());
                        setUIState(false, "Submit", null);
                        currentLlmApi = null; // Clear on error
                    });
                }
            }
        };

        new TaskLauncher(task, plugin.getTool().getToolFrame());
    }

    private void handleAgenticQuery(String query) {
        // Add user query to conversation history and ensure we have a session
        try {
            String processedQuery = ghidrassist.core.QueryProcessor.processMacrosInQuery(query, plugin);
            queryService.addUserQuery(processedQuery);
        } catch (Exception e) {
            Msg.error(this, "Failed to add query to conversation history: " + e.getMessage(), e);
        }

        // Get initial context (decompiled code if available)
        final String initialContext;
        ghidra.program.model.listing.Function currentFunction = plugin.getCurrentFunction();
        if (currentFunction != null) {
            initialContext = ghidrassist.core.CodeUtils.getFunctionCode(currentFunction, ghidra.util.task.TaskMonitor.DUMMY);
        } else {
            initialContext = "";
        }

        // Container to hold iteration history so it can be accessed in the final result handler
        final StringBuilder[] historyContainer = new StringBuilder[]{new StringBuilder()};

        // Initialize MCP servers if needed
        ghidrassist.mcp2.tools.MCPToolManager toolManager =
            ghidrassist.mcp2.tools.MCPToolManager.getInstance();

        java.util.concurrent.CompletableFuture<Void> initFuture;
        if (!toolManager.isInitialized()) {
            Msg.info(this, "Initializing MCP servers for agentic analysis...");
            SwingUtilities.invokeLater(() ->
                queryTab.setResponseText("<html><body>Initializing MCP servers...</body></html>"));
            initFuture = toolManager.initializeServers();
        } else {
            initFuture = java.util.concurrent.CompletableFuture.completedFuture(null);
        }

        // Chain the analysis after MCP initialization
        initFuture.thenCompose(v -> {
            // Create ReAct orchestrator with new architecture
            ghidrassist.agent.react.ReActOrchestrator orchestrator =
                new ghidrassist.agent.react.ReActOrchestrator(
                    ghidrassist.GhidrAssistPlugin.getCurrentProviderConfig(),
                    plugin
                );

            // Create progress handler for UI updates with todos and findings support
            ghidrassist.agent.react.ReActProgressHandler progressHandler =
                createReActProgressHandler(historyContainer);

            // Start analysis asynchronously
            return orchestrator.analyze(
                query,
                initialContext,
                "", // session ID - can be implemented later if needed
                progressHandler
            );
        }).thenAccept(result -> {
            // Display result on EDT - append to iteration history
            SwingUtilities.invokeLater(() -> {
                // Build final display: iteration history + final result
                StringBuilder finalDisplay = new StringBuilder();
                finalDisplay.append(historyContainer[0]);  // All the iteration history
                finalDisplay.append("# Final Result\n\n");
                finalDisplay.append(result.toMarkdown());

                // Save the assistant response to conversation history
                queryService.addAssistantResponse(finalDisplay.toString());

                // Show in UI (using conversation history for consistency with regular queries)
                String html = markdownHelper.markdownToHtml(queryService.getConversationHistory());
                queryTab.setResponseText(html);
                setUIState(false, "Submit", null);

                // Refresh chat history to show updated timestamp
                refreshChatHistory();
            });
        }).exceptionally(error -> {
            // Handle errors on EDT
            Msg.error(this, "Agentic analysis failed: " + error.getMessage(), error);
            SwingUtilities.invokeLater(() -> {
                Msg.showError(getClass(), queryTab, "Agentic Analysis Error",
                    "Analysis failed: " + error.getMessage());
                setUIState(false, "Submit", null);
            });
            return null;
        });
    }

    // ==== Action Analysis Operations ====
    
    public void handleAnalyzeFunction(Map<String, JCheckBox> filterCheckBoxes) {
        // Refresh MCP state before analyzing
        if (queryTab != null) {
            queryTab.refreshMCPState();
        }
        
        if (isQueryRunning) {
            cancelCurrentOperation();
            return;
        }

        // Extract selected actions
        List<String> selectedActions = new ArrayList<>();
        for (Map.Entry<String, JCheckBox> entry : filterCheckBoxes.entrySet()) {
            if (entry.getValue().isSelected()) {
                selectedActions.add(entry.getKey());
            }
        }
        
        if (selectedActions.isEmpty()) {
            Msg.showInfo(getClass(), actionsTab, "No Actions Selected", 
                "Please select at least one analysis type.");
            return;
        }
        
        Function currentFunction = plugin.getCurrentFunction();
        if (currentFunction == null) {
            Msg.showInfo(getClass(), actionsTab, "No Function", 
                "No function at current location.");
            return;
        }
        
        setUIState(true, "Stop", null);
        
        try {
            ActionAnalysisService.ActionAnalysisRequest request = 
                actionAnalysisService.createAnalysisRequest(currentFunction, selectedActions);
            
            actionAnalysisService.executeActionAnalysis(request, createActionAnalysisHandler());
            
        } catch (Exception e) {
            Msg.showError(this, actionsTab, "Error", e.getMessage());
            setUIState(false, "Analyze Function", null);
        }
    }

    public void handleApplyActions(JTable actionsTable) {
        DefaultTableModel model = (DefaultTableModel) actionsTable.getModel();
        actionAnalysisService.applyActions(model, plugin.getCurrentProgram(), plugin.getCurrentAddress());
    }

    // ==== RAG Management Operations ====
    
    public void handleAddDocuments(JList<String> documentList) {
        JFileChooser fileChooser = createDocumentFileChooser();
        
        int result = fileChooser.showOpenDialog(ragManagementTab);
        if (result == JFileChooser.APPROVE_OPTION) {
            File[] files = fileChooser.getSelectedFiles();
            try {
                ragManagementService.addDocuments(files);
                loadIndexedFiles(documentList);
                Msg.showInfo(this, ragManagementTab, "Success", "Documents added to RAG.");
            } catch (Exception ex) {
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
                ragManagementService.deleteDocuments(selectedFiles);
                loadIndexedFiles(documentList);
                Msg.showInfo(this, ragManagementTab, "Success", 
                    "Selected documents deleted from RAG.");
            } catch (Exception ex) {
                Msg.showError(this, ragManagementTab, "Error", 
                    "Failed to delete documents: " + ex.getMessage());
            }
        }
    }

    public void loadIndexedFiles(JList<String> documentList) {
        try {
            List<String> fileNames = ragManagementService.getIndexedFiles();
            documentList.setListData(fileNames.toArray(new String[0]));
        } catch (Exception ex) {
            Msg.showError(this, ragManagementTab, "Error", 
                "Failed to load indexed files: " + ex.getMessage());
        }
    }

    // ==== Analysis Data Operations ====
    
    public void handleContextSave(String context) {
        try {
            analysisDataService.saveContext(context);
            Msg.showInfo(this, analysisOptionsTab, "Success", "Context saved successfully.");
        } catch (Exception e) {
            Msg.showError(this, analysisOptionsTab, "Error", 
                "Failed to save context: " + e.getMessage());
        }
    }

    public void handleContextLoad() {
        try {
            String currentContext = analysisDataService.getContext();
            analysisOptionsTab.setContextText(currentContext);
        } catch (Exception e) {
            Msg.showError(this, analysisOptionsTab, "Error", 
                "Failed to load context: " + e.getMessage());
        }
    }

    public void handleContextRevert() {
        try {
            String defaultContext = analysisDataService.revertToDefaultContext();
            analysisOptionsTab.setContextText(defaultContext);
        } catch (Exception e) {
            Msg.showError(this, analysisOptionsTab, "Error", 
                "Failed to revert context: " + e.getMessage());
        }
    }

    // ==== Feedback Operations ====
    
    public void handleHyperlinkEvent(HyperlinkEvent e) {
        if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED) {
            String desc = e.getDescription();
            try {
                if (desc.equals("thumbsup")) {
                    feedbackService.storePositiveFeedback();
                    Msg.showInfo(getClass(), null, "Feedback", "Thank you for your positive feedback!");
                } else if (desc.equals("thumbsdown")) {
                    feedbackService.storeNegativeFeedback();
                    Msg.showInfo(getClass(), null, "Feedback", "Thank you for your feedback!");
                }
            } catch (Exception ex) {
                Msg.showError(this, null, "Error", "Failed to store feedback: " + ex.getMessage());
            }
        }
    }

    // ==== Location Updates ====
    
    public void handleLocationUpdate(ProgramLocation loc) {
        if (loc != null && loc.getAddress() != null) {
            explainTab.updateOffset(loc.getAddress().toString());
            updateAnalysisDisplay();
        }
    }

    public void updateAnalysis(ProgramLocation loc) {
        updateAnalysisDisplay();
    }
    
    public void handleUpdateAnalysis(String updatedContent) {
        try {
            Function function = plugin.getCurrentFunction();
            codeAnalysisService.updateAnalysis(function, updatedContent);
        } catch (Exception e) {
            Msg.showError(this, null, "Error", "Failed to update analysis: " + e.getMessage());
        }
    }
    
    public void handleClearAnalysisData() {
        try {
            Function function = plugin.getCurrentFunction();
            boolean success = codeAnalysisService.clearAnalysis(function);
            
            if (success) {
                Msg.showInfo(this, null, "Success", "Analysis data cleared.");
                if (explainTab != null) {
                    explainTab.setExplanationText("");
                }
            } else {
                Msg.showInfo(this, null, "Info", "No analysis data found to clear.");
            }
        } catch (Exception e) {
            Msg.showError(this, null, "Error", "Failed to clear analysis: " + e.getMessage());
        }
    }

    // ==== State Management ====
    
    public void clearConversationHistory() {
        queryService.clearConversationHistory();
    }
    
    // ==== Chat History Management ====
    
    public void handleNewChatSession() {
        SwingUtilities.invokeLater(() -> {
            // Clear current conversation and create new session immediately
            queryService.clearConversationHistory();
            queryTab.setResponseText("");
            queryTab.clearChatSelection();
            
            // Create new session immediately instead of waiting for first query
            int newSessionId = queryService.createNewChatSession();
            if (newSessionId != -1) {
                refreshChatHistory();
                // Select the new session in the table
                java.util.List<ghidrassist.AnalysisDB.ChatSession> sessions = queryService.getChatSessions();
                for (int i = 0; i < sessions.size(); i++) {
                    if (sessions.get(i).getId() == newSessionId) {
                        queryTab.selectChatSession(i);
                        break;
                    }
                }
            }
        });
    }
    
    public void handleDeleteCurrentSession() {
        boolean deleted = queryService.deleteCurrentSession();
        SwingUtilities.invokeLater(() -> {
            if (deleted) {
                queryTab.setResponseText("");
                queryTab.clearChatSelection();
                refreshChatHistory();
            } else {
                // If no session to delete, just clear the UI
                queryTab.setResponseText("");
                queryService.clearConversationHistory();
            }
        });
    }
    
    public void handleChatSessionSelection(int rowIndex) {
        java.util.List<ghidrassist.AnalysisDB.ChatSession> sessions = queryService.getChatSessions();
        if (rowIndex >= 0 && rowIndex < sessions.size()) {
            ghidrassist.AnalysisDB.ChatSession selectedSession = sessions.get(rowIndex);
            boolean success = queryService.switchToChatSession(selectedSession.getId());
            
            if (success) {
                SwingUtilities.invokeLater(() -> {
                    String html = markdownHelper.markdownToHtml(queryService.getConversationHistory());
                    queryTab.setResponseText(html);
                });
            }
        }
    }
    
    public void handleChatDescriptionUpdate(int rowIndex, String newDescription) {
        java.util.List<ghidrassist.AnalysisDB.ChatSession> sessions = queryService.getChatSessions();
        if (rowIndex >= 0 && rowIndex < sessions.size()) {
            ghidrassist.AnalysisDB.ChatSession session = sessions.get(rowIndex);
            queryService.updateChatDescription(session.getId(), newDescription);
        }
    }
    
    public void refreshChatHistory() {
        if (queryTab != null) {
            java.util.List<ghidrassist.AnalysisDB.ChatSession> sessions = queryService.getChatSessions();
            SwingUtilities.invokeLater(() -> {
                queryTab.updateChatHistory(sessions);
            });
        }
    }

    public boolean isQueryRunning() {
        return isQueryRunning;
    }

    public void setQueryRunning(boolean running) {
        this.isQueryRunning = running;
    }

    // ==== Private Helper Methods ====
    
    private LlmApi getCurrentLlmApi() throws Exception {
        APIProviderConfig config = GhidrAssistPlugin.getCurrentProviderConfig();
        if (config == null) {
            throw new Exception("No API provider configured.");
        }
        
        // Create new instance for this operation
        currentLlmApi = new LlmApi(config, plugin);
        return currentLlmApi;
    }
    
    private void cancelCurrentOperation() {
        setUIState(false, null, null);
        
        // Cancel the current LLM API instance if it exists
        if (currentLlmApi != null) {
            currentLlmApi.cancelCurrentRequest();
            currentLlmApi = null;
        }
        
        actionAnalysisService.cancelAnalysis();
    }
    
    private void setUIState(boolean running, String buttonText, String statusText) {
        isQueryRunning = running;
        
        SwingUtilities.invokeLater(() -> {
            if (buttonText != null && explainTab != null) {
                explainTab.setFunctionButtonText(buttonText);
                explainTab.setLineButtonText(buttonText.equals("Stop") ? "Stop" : "Explain Line");
            }
            if (buttonText != null && queryTab != null) {
                queryTab.setSubmitButtonText(buttonText.equals("Stop") ? "Stop" : "Submit");
            }
            if (buttonText != null && actionsTab != null) {
                actionsTab.setAnalyzeFunctionButtonText(buttonText.equals("Stop") ? "Stop" : "Analyze Function");
            }
            if (statusText != null && explainTab != null) {
                explainTab.setExplanationText(statusText);
            }
        });
    }
    
    private void updateAnalysisDisplay() {
        Function function = plugin.getCurrentFunction();
        if (function != null) {
            Analysis existingAnalysis = codeAnalysisService.getExistingAnalysis(function);
            if (existingAnalysis != null) {
                explainTab.setExplanationText(
                    markdownHelper.markdownToHtml(existingAnalysis.getResponse()));
            } else {
                explainTab.setExplanationText("");
            }
        } else {
            explainTab.setExplanationText("");
        }
    }
    
    private JFileChooser createDocumentFileChooser() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Select Documents to Add to RAG");
        fileChooser.setMultiSelectionEnabled(true);
        fileChooser.addChoosableFileFilter(
            new javax.swing.filechooser.FileNameExtensionFilter(
                "Text and Markdown Files", "txt", "md"));
        fileChooser.addChoosableFileFilter(
            new javax.swing.filechooser.FileNameExtensionFilter(
                "Source Code", "c", "h", "cpp", "hpp", "py", "java", "rs", "asm"));
        return fileChooser;
    }
    
    // ==== Response Handler Factories ====
    
    private LlmApi.LlmResponseHandler createExplainResponseHandler() {
        return new LlmApi.LlmResponseHandler() {
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
                    feedbackService.cacheLastInteraction(feedbackService.getLastPrompt(), fullResponse);
                    explainTab.setExplanationText(
                        markdownHelper.markdownToHtml(fullResponse));
                    setUIState(false, "Explain Line", null);
                });
            }

            @Override
            public void onError(Throwable error) {
                SwingUtilities.invokeLater(() -> {
                    explainTab.setExplanationText("An error occurred: " + error.getMessage());
                    setUIState(false, "Explain Line", null);
                });
            }

            @Override
            public boolean shouldContinue() {
                return isQueryRunning;
            }
        };
    }
    
    private LlmApi.LlmResponseHandler createConversationHandler() {
        return new LlmApi.LlmResponseHandler() {
            private final StringBuilder responseBuffer = new StringBuilder();
            private final Object bufferLock = new Object();

            @Override
            public void onStart() {
                SwingUtilities.invokeLater(() -> {
                    synchronized (bufferLock) {
                        responseBuffer.setLength(0);
                    }
                    queryTab.setResponseText("Processing...");
                });
            }

            @Override
            public void onUpdate(String partialResponse) {
                // Synchronize access to the buffer to prevent race conditions
                synchronized (bufferLock) {
                    // Skip empty or null responses
                    if (partialResponse == null || partialResponse.isEmpty()) {
                        return;
                    }
                    
                    // Check if this is cumulative content (contains what we already have)
                    String currentBuffer = responseBuffer.toString();
                    if (partialResponse.startsWith(currentBuffer)) {
                        // This is cumulative content, extract only the new part
                        String newContent = partialResponse.substring(currentBuffer.length());
                        if (!newContent.isEmpty()) {
                            responseBuffer.append(newContent);
                        }
                    } else {
                        // This is a true delta, append it
                        responseBuffer.append(partialResponse);
                    }
                    
                    // Capture the current buffer state for display
                    final String currentResponse = responseBuffer.toString();
                    
                    SwingUtilities.invokeLater(() -> {
                        // Show conversation history + current assistant response
                        String fullConversation = queryService.getConversationHistory() + 
                            "**Assistant**:\n" + currentResponse;
                        
                        String html = markdownHelper.markdownToHtml(fullConversation);
                        queryTab.setResponseText(html);
                    });
                }
            }

            @Override
            public void onComplete(String fullResponse) {
                SwingUtilities.invokeLater(() -> {
                    feedbackService.cacheLastInteraction(feedbackService.getLastPrompt(), fullResponse);
                    queryService.addAssistantResponse(responseBuffer.toString());
                    
                    String html = markdownHelper.markdownToHtml(queryService.getConversationHistory());
                    queryTab.setResponseText(html);
                    setUIState(false, "Submit", null);
                    currentLlmApi = null; // Clear after completion
                    
                    // Refresh chat history to show updated timestamp
                    refreshChatHistory();
                });
            }

            @Override
            public void onError(Throwable error) {
                SwingUtilities.invokeLater(() -> {
                    queryService.addError(error.getMessage());
                    String html = markdownHelper.markdownToHtml(queryService.getConversationHistory());
                    queryTab.setResponseText(html);
                    setUIState(false, "Submit", null);
                    currentLlmApi = null; // Clear after error
                });
            }

            @Override
            public boolean shouldContinue() {
                return isQueryRunning;
            }
        };
    }
    
    private ghidrassist.agent.react.ReActProgressHandler createReActProgressHandler(final StringBuilder[] historyContainer) {
        return new ghidrassist.agent.react.ReActProgressHandler() {
            private final StringBuilder progressLog = new StringBuilder();
            private final StringBuilder iterationHistory = new StringBuilder();
            private String currentTodos = "";
            private String currentIterationOutput = "";
            private int lastIterationSeen = 0;

            @Override
            public void onStart(String objective) {
                SwingUtilities.invokeLater(() -> {
                    progressLog.setLength(0);
                    iterationHistory.setLength(0);
                    progressLog.append("# ReAct Investigation\n\n");
                    progressLog.append("**Objective**: ").append(objective).append("\n\n");
                    progressLog.append("---\n\n");
                    updateDisplay();
                });
            }

            @Override
            public void onThought(String thought, int iteration) {
                SwingUtilities.invokeLater(() -> {
                    // If this is a new iteration, archive the previous iteration's output
                    if (iteration > lastIterationSeen && !currentIterationOutput.isEmpty()) {
                        iterationHistory.append("### Iteration ").append(lastIterationSeen).append("\n\n");
                        iterationHistory.append(currentIterationOutput).append("\n\n");
                        iterationHistory.append("---\n\n");
                        lastIterationSeen = iteration;
                        currentIterationOutput = "";
                    }

                    // Store the current iteration's streaming output
                    currentIterationOutput = thought;
                    updateDisplay();
                });
            }

            @Override
            public void onAction(String toolName, com.google.gson.JsonObject args) {
                SwingUtilities.invokeLater(() -> {
                    progressLog.append("🔧 **Calling tool**: `").append(toolName).append("`");

                    // Show tool arguments if present
                    if (args != null && args.size() > 0) {
                        progressLog.append(" with args:\n```json\n");
                        progressLog.append(new com.google.gson.GsonBuilder().setPrettyPrinting().create().toJson(args));
                        progressLog.append("\n```\n\n");
                    } else {
                        progressLog.append("\n\n");
                    }

                    updateDisplay();
                });
            }

            @Override
            public void onObservation(String toolName, String result) {
                SwingUtilities.invokeLater(() -> {
                    // Show condensed result - up to 300 chars
                    String truncated = result.length() > 300
                        ? result.substring(0, 300) + "\n... [+" + (result.length() - 300) + " more chars]"
                        : result;

                    progressLog.append("**Result**:\n```\n");
                    progressLog.append(truncated);
                    progressLog.append("\n```\n\n");

                    updateDisplay();
                });
            }

            @Override
            public void onFinding(String finding) {
                SwingUtilities.invokeLater(() -> {
                    progressLog.append("💡 **Finding**: ").append(finding).append("\n\n");
                    updateDisplay();
                });
            }

            @Override
            public void onComplete(ghidrassist.agent.react.ReActResult result) {
                SwingUtilities.invokeLater(() -> {
                    // Archive the last iteration's output before showing final result
                    if (!currentIterationOutput.isEmpty()) {
                        iterationHistory.append("### Iteration ").append(lastIterationSeen).append("\n\n");
                        iterationHistory.append(currentIterationOutput).append("\n\n");
                        iterationHistory.append("---\n\n");
                        currentIterationOutput = "";
                    }

                    // Save the complete history for display with final result
                    StringBuilder fullHistory = new StringBuilder();
                    fullHistory.append(progressLog);
                    fullHistory.append(iterationHistory);
                    fullHistory.append("\n\n---\n\n");
                    historyContainer[0] = fullHistory;

                    // Final result will be displayed by handleAgenticQuery's thenAccept handler
                });
            }

            @Override
            public void onError(Throwable error) {
                SwingUtilities.invokeLater(() -> {
                    progressLog.append("\n\n❌ **ERROR**: ").append(error.getMessage()).append("\n");
                    updateDisplay();
                });
            }

            @Override
            public boolean shouldContinue() {
                return isQueryRunning;
            }

            @Override
            public void onIterationWarning(int remaining) {
                SwingUtilities.invokeLater(() -> {
                    progressLog.append("⚠️ *").append(remaining).append(" iteration(s) remaining*\n\n");
                    updateDisplay();
                });
            }

            @Override
            public void onToolCallWarning(int remaining) {
                SwingUtilities.invokeLater(() -> {
                    progressLog.append("⚠️ *").append(remaining).append(" tool call(s) remaining*\n\n");
                    updateDisplay();
                });
            }

            @Override
            public void onTodosUpdated(String todosFormatted) {
                SwingUtilities.invokeLater(() -> {
                    currentTodos = todosFormatted;
                    updateDisplay();
                });
            }

            @Override
            public void onSummarizing(String summary) {
                SwingUtilities.invokeLater(() -> {
                    progressLog.append("📝 **Summarizing context...**\n\n");
                    progressLog.append("```\n").append(summary).append("\n```\n\n");
                    updateDisplay();
                });
            }

            private void updateDisplay() {
                StringBuilder display = new StringBuilder();

                // Show todos at the top if available
                if (!currentTodos.isEmpty()) {
                    display.append("## Investigation Progress\n\n");
                    display.append(currentTodos).append("\n\n");
                    display.append("---\n\n");
                }

                // Append activity log (objective, etc.)
                display.append(progressLog);

                // Show all previous iteration outputs (preserved history)
                if (iterationHistory.length() > 0) {
                    display.append(iterationHistory);
                }

                // Show current iteration output (streaming from ConversationalToolHandler)
                if (!currentIterationOutput.isEmpty()) {
                    display.append("### Current Activity\n\n");
                    display.append(currentIterationOutput).append("\n\n");
                }

                String html = markdownHelper.markdownToHtml(display.toString());
                queryTab.setResponseText(html);
            }
        };
    }

    private ActionAnalysisService.ActionAnalysisHandler createActionAnalysisHandler() {
        return new ActionAnalysisService.ActionAnalysisHandler() {
            @Override
            public void onActionStart(String action) {
                SwingUtilities.invokeLater(() -> {
                    actionsTab.setAnalyzeFunctionButtonText("Stop");
                });
            }

            @Override
            public void onActionComplete(String action, String response) {
                SwingUtilities.invokeLater(() -> {
                    try {
                        actionAnalysisService.parseAndDisplayActions(response, actionsTab.getTableModel());
                    } catch (Exception e) {
                        Msg.showError(this, actionsTab, "Error",
                            "Failed to parse actions: " + e.getMessage());
                    }
                });
            }

            @Override
            public void onActionError(String action, Throwable error) {
                SwingUtilities.invokeLater(() -> {
                    Msg.showError(this, actionsTab, "Error", 
                        "Action " + action + " failed: " + error.getMessage());
                });
            }

            @Override
            public void onAllActionsComplete() {
                SwingUtilities.invokeLater(() -> {
                    setUIState(false, "Analyze Function", null);
                });
            }

            @Override
            public boolean shouldContinue() {
                return isQueryRunning;
            }
        };
    }
    
    // ==== Cleanup ====
    
    public void dispose() {
        codeAnalysisService.close();
        analysisDataService.close();
        feedbackService.close();
    }
}