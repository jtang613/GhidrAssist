package ghidrassist.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import ghidrassist.AnalysisDB;
import ghidrassist.AnalysisDB.Analysis;
import ghidrassist.GhidrAssistPlugin;
import ghidrassist.LlmApi;
import ghidrassist.apiprovider.APIProviderConfig;
import ghidrassist.apiprovider.ReasoningConfig;
import ghidrassist.chat.ChatChange;
import ghidrassist.chat.ChatEditManager;
import ghidrassist.chat.ChangeType;
import ghidrassist.chat.PersistedChatMessage;
import ghidrassist.services.*;
import ghidrassist.services.RAGManagementService.RAGIndexStats;
import ghidrassist.ui.tabs.*;

import java.sql.Timestamp;

import javax.swing.*;
import javax.swing.event.HyperlinkEvent;
import javax.swing.table.DefaultTableModel;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

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

    // ReAct orchestrator for cancellation
    private volatile ghidrassist.agent.react.ReActOrchestrator currentOrchestrator;

    // UI state
    private volatile boolean isQueryRunning;
    private volatile boolean isCancelling;  // Guard against concurrent operations during cancellation
    private volatile ReasoningConfig currentReasoningConfig;  // Current reasoning/thinking effort setting

    // Streaming performance: debounced HTML rendering
    private static final int RENDER_INTERVAL_MS = 1000;  // Render markdown every 1 second
    private final ScheduledExecutorService updateScheduler = Executors.newSingleThreadScheduledExecutor();
    private volatile ScheduledFuture<?> activeRenderTask;  // Tracked at class level for proper cancellation
    private final Object renderLock = new Object();

    // Chat edit manager for chunked editing
    private final ChatEditManager chatEditManager = new ChatEditManager();

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
        this.isCancelling = false;
        this.currentReasoningConfig = new ReasoningConfig(); // Default to NONE

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

    // ==== Reasoning Configuration ====

    /**
     * Set the reasoning/thinking effort level.
     * Called by the UI when the user changes the dropdown selection.
     */
    public void setReasoningEffort(String level) {
        this.currentReasoningConfig = ReasoningConfig.fromString(level);

        // Save to database
        try {
            analysisDataService.saveReasoningEffort(level.toLowerCase());
            Msg.info(this, "Reasoning effort set to: " + level);
        } catch (IllegalStateException e) {
            // No program loaded - just update in-memory config
            Msg.info(this, "Reasoning effort set to: " + level + " (not saved - no program loaded)");
        }
    }

    /**
     * Get the current reasoning effort level as a string for UI display.
     * Loads from database if available.
     */
    public String getReasoningEffort() {
        // Try to load from database first
        try {
            String savedEffort = analysisDataService.getReasoningEffort();
            if (savedEffort != null && !savedEffort.equalsIgnoreCase("none")) {
                // Update in-memory config to match saved value
                this.currentReasoningConfig = ReasoningConfig.fromString(savedEffort);
                // Return with proper capitalization for UI
                return savedEffort.substring(0, 1).toUpperCase() + savedEffort.substring(1);
            }
        } catch (Exception e) {
            // Fall through to in-memory value
        }

        // Fall back to in-memory config
        if (currentReasoningConfig == null || !currentReasoningConfig.isEnabled()) {
            return "None";
        }
        String effort = currentReasoningConfig.getEffortString();
        return effort != null ? effort.substring(0, 1).toUpperCase() + effort.substring(1) : "None";
    }

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
                        private final StringBuilder responseBuffer = new StringBuilder();
                        private final Object bufferLock = new Object();

                        @Override
                        public void onStart() {
                            synchronized (bufferLock) {
                                responseBuffer.setLength(0);
                            }

                            // Cancel any existing render task before starting new one
                            cancelActiveRenderTask();

                            // Show initial processing message
                            SwingUtilities.invokeLater(() -> {
                                explainTab.setExplanationText("<html><body><i>Processing...</i></body></html>");
                            });

                            // Start periodic markdown rendering using class-level tracking
                            synchronized (renderLock) {
                                activeRenderTask = updateScheduler.scheduleAtFixedRate(
                                    this::renderCurrentContent,
                                    RENDER_INTERVAL_MS,
                                    RENDER_INTERVAL_MS,
                                    TimeUnit.MILLISECONDS
                                );
                            }
                        }

                        @Override
                        public void onUpdate(String partialResponse) {
                            synchronized (bufferLock) {
                                if (partialResponse == null || partialResponse.isEmpty()) {
                                    return;
                                }

                                // Handle cumulative vs delta responses - just accumulate in buffer
                                String currentBuffer = responseBuffer.toString();
                                if (partialResponse.startsWith(currentBuffer)) {
                                    String newContent = partialResponse.substring(currentBuffer.length());
                                    if (!newContent.isEmpty()) {
                                        responseBuffer.append(newContent);
                                    }
                                } else {
                                    responseBuffer.append(partialResponse);
                                }

                                // No immediate UI update - let the periodic render handle it
                                // This prevents UI flooding while keeping content responsive
                            }
                        }

                        /**
                         * Periodic render task - renders markdown to HTML every RENDER_INTERVAL_MS
                         */
                        private void renderCurrentContent() {
                            final String content;
                            synchronized (bufferLock) {
                                if (responseBuffer.length() == 0) {
                                    return;
                                }
                                content = responseBuffer.toString();
                            }

                            SwingUtilities.invokeLater(() -> {
                                String html = markdownHelper.markdownToHtml(content);
                                explainTab.setExplanationText(html);
                            });
                        }

                        @Override
                        public void onComplete(String fullResponse) {
                            // Cancel periodic render task
                            cancelActiveRenderTask();

                            synchronized (bufferLock) {
                                // Use fullResponse if it's more complete than current buffer
                                if (fullResponse != null && fullResponse.length() > responseBuffer.length()) {
                                    responseBuffer.setLength(0);
                                    responseBuffer.append(fullResponse);
                                }

                                final String finalResponse = responseBuffer.toString();

                                SwingUtilities.invokeLater(() -> {
                                    feedbackService.cacheLastInteraction(request.getPrompt(), finalResponse);
                                    explainTab.setExplanationText(
                                        markdownHelper.markdownToHtml(finalResponse));

                                    // Store analysis result
                                    codeAnalysisService.storeAnalysisResult(
                                        currentFunction, request.getPrompt(), finalResponse);

                                    setUIState(false, "Explain Function", null);
                                });
                            }
                        }

                        @Override
                        public void onError(Throwable error) {
                            // Cancel periodic render task on error
                            cancelActiveRenderTask();

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
        // If cancellation is in progress, ignore the click
        if (isCancelling) {
            Msg.info(this, "Cancellation in progress, please wait...");
            return;
        }

        // If a query is running, cancel it
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
            currentOrchestrator = new ghidrassist.agent.react.ReActOrchestrator(
                    ghidrassist.GhidrAssistPlugin.getCurrentProviderConfig(),
                    plugin
                );

            // Create progress handler for UI updates with todos and findings support
            ghidrassist.agent.react.ReActProgressHandler progressHandler =
                createReActProgressHandler(historyContainer);

            // Start analysis asynchronously
            return currentOrchestrator.analyze(
                query,
                initialContext,
                String.valueOf(queryService.getCurrentSessionId()),
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

                // Save ReAct analysis with proper chunking to database
                queryService.saveReActAnalysis(
                    query,
                    result.getAnswer(),
                    result.getIterationSummaries()
                );

                // Show in UI (using conversation history for consistency with regular queries)
                String html = markdownHelper.markdownToHtml(queryService.getConversationHistory());
                queryTab.setResponseText(html);

                // Clear the orchestrator reference
                currentOrchestrator = null;
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

                // Clear the orchestrator reference
                currentOrchestrator = null;
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

    /**
     * Handle adding documents to RAG index.
     */
    public void handleAddDocuments() {
        JFileChooser fileChooser = createDocumentFileChooser();

        int result = fileChooser.showOpenDialog(ragManagementTab);
        if (result == JFileChooser.APPROVE_OPTION) {
            File[] files = fileChooser.getSelectedFiles();
            try {
                ragManagementService.addDocuments(files);
                refreshRAGDocuments();
                Msg.showInfo(this, ragManagementTab, "Success", "Documents added to RAG.");
            } catch (Exception ex) {
                Msg.showError(this, ragManagementTab, "Error",
                        "Failed to ingest documents: " + ex.getMessage());
            }
        }
    }

    /**
     * Handle deleting a single document from RAG index.
     */
    public void handleDeleteDocument(String filename) {
        if (filename == null || filename.isEmpty()) {
            Msg.showInfo(this, ragManagementTab, "No Selection",
                    "No document selected for deletion.");
            return;
        }

        int confirmation = JOptionPane.showConfirmDialog(ragManagementTab,
                "Are you sure you want to delete '" + filename + "'?",
                "Confirm Deletion", JOptionPane.YES_NO_OPTION);

        if (confirmation == JOptionPane.YES_OPTION) {
            try {
                ragManagementService.deleteDocuments(java.util.Collections.singletonList(filename));
                refreshRAGDocuments();
                Msg.showInfo(this, ragManagementTab, "Success",
                        "Document deleted from RAG.");
            } catch (Exception ex) {
                Msg.showError(this, ragManagementTab, "Error",
                        "Failed to delete document: " + ex.getMessage());
            }
        }
    }

    /**
     * Handle clearing the entire RAG index.
     */
    public void handleClearIndex() {
        int confirmation = JOptionPane.showConfirmDialog(ragManagementTab,
                "Are you sure you want to clear the entire RAG index?\nThis will delete all indexed documents.",
                "Confirm Clear Index", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);

        if (confirmation == JOptionPane.YES_OPTION) {
            try {
                ragManagementService.clearAllDocuments();
                refreshRAGDocuments();
                if (ragManagementTab != null) {
                    ragManagementTab.clearSearchResults();
                }
                Msg.showInfo(this, ragManagementTab, "Success", "RAG index cleared.");
            } catch (Exception ex) {
                Msg.showError(this, ragManagementTab, "Error",
                        "Failed to clear index: " + ex.getMessage());
            }
        }
    }

    /**
     * Refresh the document table and statistics.
     */
    public void refreshRAGDocuments() {
        if (ragManagementTab == null) {
            return;
        }
        try {
            // Get documents with metadata
            List<RAGDocumentInfo> docs = ragManagementService.getIndexedDocumentsWithInfo();
            ragManagementTab.updateDocumentTable(docs);

            // Get statistics
            RAGIndexStats stats = ragManagementService.getIndexStats();
            ragManagementTab.updateStats(
                    stats.getTotalFiles(),
                    stats.getTotalChunks(),
                    stats.getTotalEmbeddings()
            );
        } catch (Exception ex) {
            Msg.showError(this, ragManagementTab, "Error",
                    "Failed to load indexed files: " + ex.getMessage());
        }
    }

    /**
     * Handle RAG search.
     */
    public void handleRAGSearch(String query, String searchType, RAGManagementTab tab) {
        if (query == null || query.trim().isEmpty()) {
            return;
        }

        try {
            List<SearchResult> results;
            int maxResults = 10;

            switch (searchType) {
                case "Semantic":
                    results = ragManagementService.searchSemantic(query, maxResults);
                    break;
                case "Keyword":
                    results = ragManagementService.searchKeyword(query, maxResults);
                    break;
                case "Hybrid":
                default:
                    results = ragManagementService.searchHybrid(query, maxResults);
                    break;
            }

            tab.displaySearchResults(query, results, searchType);
        } catch (Exception ex) {
            Msg.showError(this, tab, "Search Error",
                    "Failed to perform search: " + ex.getMessage());
        }
    }

    /**
     * Legacy method for backwards compatibility.
     * @deprecated Use handleAddDocuments() instead
     */
    @Deprecated
    public void handleAddDocuments(JList<String> documentList) {
        handleAddDocuments();
    }

    /**
     * Legacy method for backwards compatibility.
     * @deprecated Use handleDeleteDocument(String) instead
     */
    @Deprecated
    public void handleDeleteSelected(JList<String> documentList) {
        List<String> selectedFiles = documentList.getSelectedValuesList();
        if (!selectedFiles.isEmpty()) {
            handleDeleteDocument(selectedFiles.get(0));
        }
    }

    /**
     * Legacy method for backwards compatibility.
     * @deprecated Use refreshRAGDocuments() instead
     */
    @Deprecated
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
            // Also reload reasoning effort when context is loaded
            analysisOptionsTab.loadReasoningEffort();
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
        // Cancel any running operation and render task first
        if (isQueryRunning) {
            cancelCurrentOperation();
        }
        cancelActiveRenderTask();

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
        // Cancel any running operation and render task first
        if (isQueryRunning) {
            cancelCurrentOperation();
        }
        cancelActiveRenderTask();

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

    // ==== Chat Edit Mode Handlers ====

    /**
     * Handle when user clicks Edit button - prepare editable content
     */
    public void handleChatEditStart() {
        if (queryTab == null) {
            return;
        }

        int currentSessionId = queryService.getCurrentSessionId();
        Msg.info(this, "Edit Start: currentSessionId=" + currentSessionId);
        if (currentSessionId == -1) {
            Msg.showInfo(this, queryTab, "No Chat",
                    "No active chat session to edit.");
            queryTab.exitEditMode();
            return;
        }

        // Load messages from database if not already loaded
        queryService.loadMessagesFromDatabase();

        // Get messages for current session
        List<PersistedChatMessage> messages = queryService.getMessages();
        Msg.info(this, "Edit Start: loaded " + messages.size() + " messages from memory");
        if (messages.isEmpty()) {
            Msg.showInfo(this, queryTab, "Empty Chat",
                    "No messages to edit in this chat.");
            queryTab.exitEditMode();
            return;
        }

        // Get chat name from sessions list
        List<AnalysisDB.ChatSession> sessions = queryService.getChatSessions();
        String chatName = "Untitled";
        for (AnalysisDB.ChatSession session : sessions) {
            if (session.getId() == currentSessionId) {
                chatName = session.getDescription();
                break;
            }
        }

        // Generate editable content with chunk markers
        String editableContent = chatEditManager.generateEditableContent(chatName, messages);
        queryTab.setEditableContent(editableContent);
    }

    /**
     * Handle when user clicks Save button - parse and apply changes
     */
    public void handleChatEditSave(String editedContent) {
        if (queryTab == null || editedContent == null) {
            Msg.info(this, "Edit Save: null queryTab or editedContent");
            return;
        }

        int currentSessionId = queryService.getCurrentSessionId();
        Msg.info(this, "Edit Save: currentSessionId=" + currentSessionId);
        if (currentSessionId == -1) {
            return;
        }

        String programHash = getProgramHash();
        Msg.info(this, "Edit Save: programHash=" + (programHash != null ? programHash.substring(0, 8) + "..." : "null"));
        if (programHash == null) {
            return;
        }

        // Detect changes
        List<ChatChange> changes = chatEditManager.parseEditedContent(editedContent);
        Msg.info(this, "Edit Save: detected " + changes.size() + " changes");
        for (ChatChange change : changes) {
            Msg.info(this, "  Change: " + change.getChangeType() + " - " + change.getChunkId());
        }

        if (!changes.isEmpty()) {
            applyChanges(programHash, currentSessionId, changes, editedContent);
            reloadCurrentChat();
        } else {
            // No changes detected - still save all messages as a full rebuild
            Msg.info(this, "Edit Save: no changes detected, performing full rebuild anyway");
            List<ChatEditManager.ExtractedMessage> finalMessages =
                    chatEditManager.extractAllMessages(editedContent);
            Msg.info(this, "Edit Save: extracted " + finalMessages.size() + " messages for rebuild");

            if (!finalMessages.isEmpty()) {
                AnalysisDB analysisDB = queryService.getAnalysisDB();
                analysisDB.deleteMessages(programHash, currentSessionId);

                List<PersistedChatMessage> newMessageList = new ArrayList<>();
                for (int i = 0; i < finalMessages.size(); i++) {
                    ChatEditManager.ExtractedMessage msg = finalMessages.get(i);
                    Msg.info(this, "  Saving message " + i + ": role=" + msg.role);
                    analysisDB.saveMessage(
                            programHash, currentSessionId, i,
                            "edited", "{}",
                            msg.role, msg.content, "edited"
                    );

                    PersistedChatMessage persistedMsg = new PersistedChatMessage(
                            null, msg.role, msg.content,
                            new Timestamp(System.currentTimeMillis()), i
                    );
                    persistedMsg.setProviderType("edited");
                    persistedMsg.setMessageType("edited");
                    newMessageList.add(persistedMsg);
                }

                queryService.setMessages(newMessageList);
            }
            reloadCurrentChat();
        }
    }

    /**
     * Apply detected changes to the database
     */
    private void applyChanges(String programHash, int chatId,
                              List<ChatChange> changes, String editedContent) {
        boolean messagesUpdated = false;
        boolean titleUpdated = false;
        String newTitle = null;

        // Detect what changed
        for (ChatChange change : changes) {
            if (change.getChangeType() == ChangeType.MODIFIED) {
                if (change.isTitleChange()) {
                    titleUpdated = true;
                    newTitle = change.getNewContent();
                } else {
                    messagesUpdated = true;
                }
            } else if (change.getChangeType() == ChangeType.DELETED ||
                       change.getChangeType() == ChangeType.ADDED) {
                messagesUpdated = true;
            }
        }

        // Full rebuild from scratch
        if (messagesUpdated) {
            List<ChatEditManager.ExtractedMessage> finalMessages =
                    chatEditManager.extractAllMessages(editedContent);

            AnalysisDB analysisDB = queryService.getAnalysisDB();

            // Delete existing messages
            analysisDB.deleteMessages(programHash, chatId);

            // Save each message
            List<PersistedChatMessage> newMessageList = new ArrayList<>();
            for (int i = 0; i < finalMessages.size(); i++) {
                ChatEditManager.ExtractedMessage msg = finalMessages.get(i);
                analysisDB.saveMessage(
                        programHash, chatId, i,
                        "edited", "{}",
                        msg.role, msg.content, "edited"
                );

                PersistedChatMessage persistedMsg = new PersistedChatMessage(
                        null, msg.role, msg.content,
                        new Timestamp(System.currentTimeMillis()), i
                );
                persistedMsg.setProviderType("edited");
                persistedMsg.setMessageType("edited");
                newMessageList.add(persistedMsg);
            }

            // Update in-memory state
            queryService.setMessages(newMessageList);
        }

        // Handle title changes
        if (titleUpdated && newTitle != null) {
            queryService.updateChatDescription(chatId, newTitle);
            refreshChatHistory();
        }
    }

    /**
     * Reload and display the current chat
     */
    private void reloadCurrentChat() {
        if (queryTab == null) {
            return;
        }

        // Get updated conversation history
        String conversationHistory = queryService.getConversationHistory();

        // Convert to HTML and display
        String html = markdownHelper.markdownToHtml(conversationHistory);
        queryTab.setResponseText(html);
        queryTab.setMarkdownSource(conversationHistory);
    }

    /**
     * Get program hash for current program
     */
    private String getProgramHash() {
        if (plugin.getCurrentProgram() != null) {
            return plugin.getCurrentProgram().getExecutableSHA256();
        }
        return null;
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

        // Debug: Log current in-memory config before creating API
        if (currentReasoningConfig != null) {
            Msg.info(this, "DEBUG: In-memory reasoning config before create: " +
                currentReasoningConfig.getEffort() + ", enabled=" + currentReasoningConfig.isEnabled());
        } else {
            Msg.info(this, "DEBUG: In-memory reasoning config is NULL");
        }

        // Create new instance for this operation
        currentLlmApi = new LlmApi(config, plugin);

        // Load and apply reasoning configuration from database
        try {
            String savedEffort = analysisDataService.getReasoningEffort();
            Msg.info(this, "DEBUG: Database returned reasoning effort: " + savedEffort);
            // Only override in-memory config if we have a saved non-none value
            // Otherwise keep the current in-memory setting (e.g., when no program is loaded)
            if (savedEffort != null && !savedEffort.equalsIgnoreCase("none")) {
                currentReasoningConfig = ReasoningConfig.fromString(savedEffort);
                Msg.info(this, "DEBUG: Loaded from DB, new config: " + currentReasoningConfig.getEffort());
            } else {
                Msg.info(this, "DEBUG: Keeping in-memory config (DB returned none or null)");
            }
        } catch (Exception e) {
            // Use current in-memory config if database load fails
            Msg.info(this, "DEBUG: Database load failed: " + e.getMessage());
        }

        // Always set reasoning config (even if NONE) to ensure provider has correct state
        if (currentReasoningConfig != null) {
            Msg.info(this, "DEBUG: Setting reasoning config on LlmApi: " +
                currentReasoningConfig.getEffort() + ", enabled=" + currentReasoningConfig.isEnabled());
            currentLlmApi.setReasoningConfig(currentReasoningConfig);
        } else {
            Msg.info(this, "DEBUG: currentReasoningConfig is NULL, setting default NONE");
            currentLlmApi.setReasoningConfig(new ReasoningConfig()); // Default to NONE
        }

        // Verify it was set
        ReasoningConfig verifyConfig = currentLlmApi.getReasoningConfig();
        Msg.info(this, "DEBUG: Verified LlmApi config after set: " +
            verifyConfig.getEffort() + ", enabled=" + verifyConfig.isEnabled());

        return currentLlmApi;
    }
    
    private void cancelCurrentOperation() {
        // Mark that we're cancelling to prevent concurrent operations
        isCancelling = true;

        // Cancel active render task FIRST to stop stale UI updates
        cancelActiveRenderTask();

        // Cancel the ReAct orchestrator if it exists
        if (currentOrchestrator != null) {
            currentOrchestrator.cancel();
            // Don't set to null here - let the completion handler do it
        }

        // Cancel the current LLM API instance if it exists
        if (currentLlmApi != null) {
            currentLlmApi.cancelCurrentRequest();
            // Don't set to null here - let the completion handler do it
        }

        actionAnalysisService.cancelAnalysis();

        // Update button text immediately to show cancellation is in progress
        SwingUtilities.invokeLater(() -> {
            if (queryTab != null) {
                queryTab.setSubmitButtonText("Cancelling...");
            }
        });

        // Schedule a safety reset in case the completion handlers don't fire
        // This prevents the UI from getting stuck if something goes wrong
        updateScheduler.schedule(() -> {
            if (isCancelling) {
                Msg.warn(this, "Cancellation safety timeout - forcing UI reset");
                SwingUtilities.invokeLater(() -> {
                    isCancelling = false;
                    isQueryRunning = false;
                    currentOrchestrator = null;
                    currentLlmApi = null;
                    setUIState(false, "Submit", null);
                });
            }
        }, 5, TimeUnit.SECONDS);
    }
    
    /**
     * Cancel the active render task to prevent stale UI updates.
     * Should be called when cancelling, starting new queries, or clearing state.
     */
    private void cancelActiveRenderTask() {
        synchronized (renderLock) {
            if (activeRenderTask != null) {
                activeRenderTask.cancel(false);
                activeRenderTask = null;
            }
        }
    }

    private void setUIState(boolean running, String buttonText, String statusText) {
        isQueryRunning = running;
        // Reset cancellation flag when transitioning to non-running state
        if (!running) {
            isCancelling = false;
        }

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
                synchronized (bufferLock) {
                    responseBuffer.setLength(0);
                }

                // Cancel any existing render task before starting new one
                cancelActiveRenderTask();

                // Show initial processing message
                SwingUtilities.invokeLater(() -> {
                    queryTab.setResponseText("<html><body><i>Processing...</i></body></html>");
                });

                // Start periodic markdown rendering using class-level tracking
                synchronized (renderLock) {
                    activeRenderTask = updateScheduler.scheduleAtFixedRate(
                        this::renderCurrentContent,
                        RENDER_INTERVAL_MS,
                        RENDER_INTERVAL_MS,
                        TimeUnit.MILLISECONDS
                    );
                }
            }

            @Override
            public void onUpdate(String partialResponse) {
                synchronized (bufferLock) {
                    if (partialResponse == null || partialResponse.isEmpty()) {
                        return;
                    }

                    // Handle cumulative vs delta responses - just accumulate in buffer
                    String currentBuffer = responseBuffer.toString();
                    if (partialResponse.startsWith(currentBuffer)) {
                        String newContent = partialResponse.substring(currentBuffer.length());
                        if (!newContent.isEmpty()) {
                            responseBuffer.append(newContent);
                        }
                    } else {
                        responseBuffer.append(partialResponse);
                    }

                    // No immediate UI update - let the periodic render handle it
                    // This prevents UI flooding while keeping content responsive
                }
            }

            /**
             * Periodic render task - renders markdown to HTML every RENDER_INTERVAL_MS
             */
            private void renderCurrentContent() {
                final String content;
                synchronized (bufferLock) {
                    if (responseBuffer.length() == 0) {
                        return;
                    }
                    content = queryService.getConversationHistory() +
                        "**Assistant**:\n" + responseBuffer.toString();
                }

                SwingUtilities.invokeLater(() -> {
                    String html = markdownHelper.markdownToHtml(content);
                    queryTab.setResponseText(html);
                });
            }

            @Override
            public void onComplete(String fullResponse) {
                // Cancel periodic render task
                cancelActiveRenderTask();

                synchronized (bufferLock) {
                    // IMPORTANT: Don't clear responseBuffer!
                    // It contains all streaming content including tool calling details.
                    // fullResponse might only contain the final text without tool call history.
                    // Only replace if fullResponse is more complete than current buffer.
                    if (fullResponse != null && fullResponse.length() > responseBuffer.length()) {
                        responseBuffer.setLength(0);
                        responseBuffer.append(fullResponse);
                    }

                    final String finalResponse = responseBuffer.toString();

                    SwingUtilities.invokeLater(() -> {
                        feedbackService.cacheLastInteraction(feedbackService.getLastPrompt(), finalResponse);
                        queryService.addAssistantResponse(finalResponse);

                        // Final markdown rendering
                        String html = markdownHelper.markdownToHtml(queryService.getConversationHistory());
                        queryTab.setResponseText(html);
                        setUIState(false, "Submit", null);
                        currentLlmApi = null;

                        refreshChatHistory();
                    });
                }
            }

            @Override
            public void onError(Throwable error) {
                // Cancel periodic render task
                cancelActiveRenderTask();

                SwingUtilities.invokeLater(() -> {
                    queryService.addError(error.getMessage());
                    String html = markdownHelper.markdownToHtml(queryService.getConversationHistory());
                    queryTab.setResponseText(html);
                    setUIState(false, "Submit", null);
                    currentLlmApi = null;
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
            private final StringBuilder chronologicalHistory = new StringBuilder();  // Single sequential history
            private final Object historyLock = new Object();  // Protect concurrent access
            private String currentIterationOutput = "";
            private int lastIterationSeen = -1;  // Start at -1 so iteration 0 triggers header

            @Override
            public void onStart(String objective) {
                synchronized (historyLock) {
                    chronologicalHistory.setLength(0);
                    chronologicalHistory.append("# ReAct Investigation\n\n");
                    chronologicalHistory.append("**Objective**: ").append(objective).append("\n\n");
                    chronologicalHistory.append("---\n\n");
                    currentIterationOutput = "";
                    lastIterationSeen = -1;
                }

                // Cancel any existing render task before starting new one
                cancelActiveRenderTask();

                // Show initial message
                SwingUtilities.invokeLater(() -> {
                    queryTab.setResponseText("<html><body><i>Starting ReAct investigation...</i></body></html>");
                });

                // Start periodic markdown rendering using class-level tracking
                synchronized (renderLock) {
                    activeRenderTask = updateScheduler.scheduleAtFixedRate(
                        this::renderCurrentContent,
                        RENDER_INTERVAL_MS,
                        RENDER_INTERVAL_MS,
                        TimeUnit.MILLISECONDS
                    );
                }
            }

            @Override
            public void onThought(String thought, int iteration) {
                synchronized (historyLock) {
                    // If this is a new iteration, archive the previous iteration
                    if (iteration > lastIterationSeen) {
                        if (!currentIterationOutput.isEmpty()) {
                            chronologicalHistory.append(currentIterationOutput).append("\n\n");
                            chronologicalHistory.append("---\n\n");
                        }
                        chronologicalHistory.append("### Iteration ").append(iteration).append("\n\n");
                        lastIterationSeen = iteration;
                        currentIterationOutput = "";
                    }
                    currentIterationOutput = thought;
                }
                // No immediate render - let periodic task handle it
            }

            @Override
            public void onAction(String toolName, com.google.gson.JsonObject args) {
                // Actions are shown via streaming thought output
            }

            @Override
            public void onObservation(String toolName, String result) {
                // Observations are shown via streaming thought output
            }

            @Override
            public void onFinding(String finding) {
                synchronized (historyLock) {
                    if (!currentIterationOutput.isEmpty()) {
                        chronologicalHistory.append(currentIterationOutput).append("\n\n");
                        currentIterationOutput = "";
                    }
                    chronologicalHistory.append("💡 **Finding**: ").append(finding).append("\n\n");
                }
                // No immediate render - let periodic task handle it
            }

            @Override
            public void onComplete(ghidrassist.agent.react.ReActResult result) {
                // Cancel periodic render task
                cancelActiveRenderTask();

                synchronized (historyLock) {
                    if (!currentIterationOutput.isEmpty()) {
                        chronologicalHistory.append(currentIterationOutput).append("\n\n");
                        chronologicalHistory.append("---\n\n");
                        currentIterationOutput = "";
                    }
                    historyContainer[0] = chronologicalHistory;
                }
                // Final render happens in handleAgenticQuery's thenAccept handler
            }

            @Override
            public void onError(Throwable error) {
                // Cancel periodic render task
                cancelActiveRenderTask();

                synchronized (historyLock) {
                    chronologicalHistory.append("\n\n❌ **ERROR**: ").append(error.getMessage()).append("\n");
                }
                // Render error immediately
                renderCurrentContent();
            }

            @Override
            public boolean shouldContinue() {
                return isQueryRunning;
            }

            @Override
            public void onIterationWarning(int remaining) {
                synchronized (historyLock) {
                    chronologicalHistory.append("⚠️ *").append(remaining).append(" iteration(s) remaining*\n\n");
                }
            }

            @Override
            public void onToolCallWarning(int remaining) {
                synchronized (historyLock) {
                    chronologicalHistory.append("⚠️ *").append(remaining).append(" tool call(s) remaining*\n\n");
                }
            }

            @Override
            public void onTodosUpdated(String todosFormatted) {
                synchronized (historyLock) {
                    if (!currentIterationOutput.isEmpty()) {
                        chronologicalHistory.append(currentIterationOutput).append("\n\n");
                        currentIterationOutput = "";
                    }
                    chronologicalHistory.append("## 📋 Investigation Progress\n\n");
                    chronologicalHistory.append(todosFormatted).append("\n\n");
                    chronologicalHistory.append("---\n\n");
                }
            }

            @Override
            public void onSummarizing(String summary) {
                synchronized (historyLock) {
                    chronologicalHistory.append("📝 **Summarizing context...**\n\n");
                    chronologicalHistory.append("```\n").append(summary).append("\n```\n\n");
                }
            }

            /**
             * Periodic render task - renders markdown to HTML every RENDER_INTERVAL_MS
             */
            private void renderCurrentContent() {
                final String content;
                synchronized (historyLock) {
                    StringBuilder display = new StringBuilder();
                    display.append(chronologicalHistory);
                    if (!currentIterationOutput.isEmpty()) {
                        display.append(currentIterationOutput).append("\n\n");
                    }
                    content = display.toString();
                }

                if (content.isEmpty()) {
                    return;
                }

                SwingUtilities.invokeLater(() -> {
                    String html = markdownHelper.markdownToHtml(content);
                    queryTab.setResponseText(html);
                });
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

        // Shutdown update scheduler
        if (updateScheduler != null) {
            updateScheduler.shutdown();
        }
    }
}