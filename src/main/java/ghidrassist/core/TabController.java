package ghidrassist.core;

import ghidra.app.services.GoToService;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import ghidrassist.AnalysisDB;
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
import ghidrassist.graphrag.BinaryKnowledgeGraph;
import ghidrassist.graphrag.nodes.EdgeType;
import ghidrassist.graphrag.nodes.KnowledgeNode;
import ghidrassist.graphrag.nodes.NodeType;
import ghidrassist.graphrag.extraction.StructureExtractor;
import ghidrassist.graphrag.extraction.SemanticExtractor;
import ghidrassist.graphrag.extraction.SecurityFeatureExtractor;
import ghidrassist.graphrag.extraction.SecurityFeatures;
import ghidrassist.services.symgraph.SymGraphService;
import ghidrassist.services.symgraph.SymGraphModels.*;
import ghidrassist.workers.*;
import ghidrassist.core.streaming.StreamingMarkdownRenderer;

import com.google.gson.Gson;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

import javax.swing.*;
import javax.swing.event.HyperlinkEvent;
import javax.swing.table.DefaultTableModel;
import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
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

    // Line explanation LLM API instance (separate from function explain)
    private volatile LlmApi currentLineExplainLlmApi;

    // ReAct orchestrator for cancellation
    private volatile ghidrassist.agent.react.ReActOrchestrator currentOrchestrator;

    // UI state
    private volatile boolean isQueryRunning;
    private volatile boolean isLineQueryRunning;
    private volatile boolean isCancelling;  // Guard against concurrent operations during cancellation
    private volatile ReasoningConfig currentReasoningConfig;  // Current reasoning/thinking effort setting

    // Streaming markdown renderer for incremental HTML updates
    private volatile StreamingMarkdownRenderer currentStreamingRenderer;

    // Streaming markdown renderer for Explain tab (separate from Query tab)
    private volatile StreamingMarkdownRenderer currentExplainStreamingRenderer;

    // Streaming markdown renderer for Line Explanation (separate from Function Explain)
    private volatile StreamingMarkdownRenderer currentLineExplainStreamingRenderer;

    // Scheduler for safety timeouts
    private final ScheduledExecutorService safetyScheduler = Executors.newSingleThreadScheduledExecutor();

    // Chat edit manager for chunked editing
    private final ChatEditManager chatEditManager = new ChatEditManager();

    // UI Component references
    private ExplainTab explainTab;
    private QueryTab queryTab;
    private ActionsTab actionsTab;
    private RAGManagementTab ragManagementTab;
    private SettingsTab settingsTab;
    private SemanticGraphTab semanticGraphTab;
    private SymGraphTab symGraphTab;

    // SymGraph service
    private SymGraphService symGraphService;


    // Background workers for non-blocking analysis
    private volatile ReindexWorker reindexWorker;
    private volatile SemanticAnalysisWorker semanticAnalysisWorker;
    private volatile SecurityAnalysisWorker securityAnalysisWorker;
    private volatile RefreshNamesWorker refreshNamesWorker;
    private volatile NetworkFlowAnalysisWorker networkFlowWorker;
    private volatile CommunityDetectionWorker communityDetectionWorker;

    // Database for semantic graph operations
    private final AnalysisDB analysisDB;

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
        this.analysisDB = new AnalysisDB();

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
    public void setSemanticGraphTab(SemanticGraphTab tab) { this.semanticGraphTab = tab; }
    public void setSymGraphTab(SymGraphTab tab) {
        this.symGraphTab = tab;
        if (this.symGraphService == null) {
            this.symGraphService = new SymGraphService();
        }
    }
    public void setSettingsTab(SettingsTab tab) { this.settingsTab = tab; }

    // ==== Plugin Access ====

    public GhidrAssistPlugin getPlugin() {
        return plugin;
    }

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

    /**
     * Set the max tool calls per iteration.
     * Saves to database for persistence across sessions.
     */
    public void setMaxToolCalls(int maxToolCalls) {
        // Validate range (must be at least 1)
        if (maxToolCalls < 1) {
            maxToolCalls = 10;
        }

        // Save to database
        try {
            analysisDataService.saveMaxToolCalls(maxToolCalls);
            Msg.info(this, "Max tool calls per iteration set to: " + maxToolCalls);
        } catch (IllegalStateException e) {
            // No program loaded - just log
            Msg.info(this, "Max tool calls set to: " + maxToolCalls + " (not saved - no program loaded)");
        }
    }

    /**
     * Get the max tool calls per iteration.
     * Loads from database if available.
     */
    public int getMaxToolCalls() {
        // Try to load from database first
        try {
            return analysisDataService.getMaxToolCalls();
        } catch (Exception e) {
            // Fall back to default
            return 10;
        }
    }

    // ==== Code Analysis Operations ====
    
    public void handleExplainFunction() {
        Msg.info(this, "handleExplainFunction called, isQueryRunning=" + isQueryRunning);

        if (isQueryRunning) {
            Msg.info(this, "Query already running, cancelling...");
            cancelCurrentOperation();
            return;
        }

        Function currentFunction = plugin.getCurrentFunction();
        if (currentFunction == null) {
            Msg.showInfo(getClass(), explainTab, "No Function", "No function at current location.");
            return;
        }

        Msg.info(this, "Explaining function: " + currentFunction.getName());

        try {
            setUIState(true, "Stop", "Processing...");
        } catch (Exception e) {
            Msg.error(this, "Failed to set UI state: " + e.getMessage());
            return;
        }

        // Run in background thread (no modal dialog)
        Thread explainThread = new Thread(() -> {
            try {
                String programHash = plugin.getCurrentProgram().getExecutableSHA256();
                BinaryKnowledgeGraph graph = analysisDB.getKnowledgeGraph(programHash);
                long address = currentFunction.getEntryPoint().getOffset();

                // Step 1: Check if node exists with decompilation, if not extract structure
                KnowledgeNode node = graph.getNodeByAddress(address);
                boolean needsExtraction = (node == null) ||
                    (node.getRawContent() == null || node.getRawContent().isEmpty());

                if (needsExtraction) {
                    // Need to index/re-index this function
                    SwingUtilities.invokeLater(() ->
                        explainTab.setExplanationText("<html><body><i>Indexing function structure...</i></body></html>"));

                    StructureExtractor extractor = new StructureExtractor(
                            plugin.getCurrentProgram(), graph, TaskMonitor.DUMMY);
                    try {
                        node = extractor.extractFunction(currentFunction);

                        // If still no rawContent, try to get decompilation directly
                        if (node != null && (node.getRawContent() == null || node.getRawContent().isEmpty())) {
                            String decompilation = extractor.getDecompiledCode(currentFunction);
                            if (decompilation != null && !decompilation.isEmpty()) {
                                node.setRawContent(decompilation);
                                graph.upsertNode(node);
                            }
                        }
                    } finally {
                        extractor.dispose();
                    }
                }

                // Step 2: Extract security features if not present or incomplete
                boolean needsSecurityAnalysis = node != null && (
                    (node.getSecurityFlags() == null || node.getSecurityFlags().isEmpty()) ||
                    (node.getNetworkAPIs() == null || node.getNetworkAPIs().isEmpty())
                );
                if (needsSecurityAnalysis) {
                    SecurityFeatureExtractor secExtractor = new SecurityFeatureExtractor(
                            plugin.getCurrentProgram(), TaskMonitor.DUMMY);
                    // Pass decompiled code for additional API detection via regex parsing
                    String decompiledCode = node.getRawContent();
                    SecurityFeatures features = secExtractor.extractFeatures(currentFunction, decompiledCode);
                    if (features != null) {
                        node.applySecurityFeatures(features);
                    }
                }

                // Step 3: Run semantic analysis if no summary OR stale AND not user-edited
                if (node != null) {
                    boolean hasExistingSummary = node.getLlmSummary() != null && !node.getLlmSummary().isEmpty();
                    boolean isStaleAndNotEdited = node.isStale() && !node.isUserEdited();
                    boolean needsSummary = !hasExistingSummary || isStaleAndNotEdited;

                    Msg.info(this, String.format("Semantic analysis check: hasExistingSummary=%b, isStale=%b, isUserEdited=%b, needsSummary=%b",
                            hasExistingSummary, node.isStale(), node.isUserEdited(), needsSummary));

                    if (needsSummary) {
                        // Create semantic extractor
                        APIProviderConfig providerConfig = GhidrAssistPlugin.getCurrentProviderConfig();
                        if (providerConfig == null) {
                            throw new Exception("No LLM provider configured. Please configure an API provider in Analysis Options.");
                        }

                        Msg.info(this, "Creating SemanticExtractor with provider: " + providerConfig.getType());
                        SemanticExtractor semanticExtractor = new SemanticExtractor(
                                providerConfig.createProvider(), graph);

                        // Initialize streaming UI
                        // Note: StreamingMarkdownRenderer already calls invokeLater, so callback runs on EDT
                        currentExplainStreamingRenderer = new StreamingMarkdownRenderer(
                            update -> explainTab.applyRenderUpdate(update),
                            markdownHelper
                        );
                        SwingUtilities.invokeLater(() -> explainTab.initializeForStreaming(""));

                        // Use streaming summarizeNode method
                        Msg.info(this, "Calling summarizeNodeStreaming...");
                        semanticExtractor.summarizeNodeStreaming(node, new SemanticExtractor.StreamingSummaryCallback() {
                            // Track previously received content to compute deltas
                            private final StringBuilder previousContent = new StringBuilder();

                            @Override
                            public void onStart() {
                                previousContent.setLength(0);
                                Msg.info(this, "Streaming started for function explain");
                            }

                            @Override
                            public void onPartialSummary(String accumulated) {
                                if (currentExplainStreamingRenderer != null) {
                                    // Compute delta from accumulated content
                                    String prev = previousContent.toString();
                                    String delta;
                                    if (accumulated.startsWith(prev)) {
                                        delta = accumulated.substring(prev.length());
                                    } else {
                                        // Fallback: treat as new content
                                        delta = accumulated;
                                        previousContent.setLength(0);
                                    }
                                    previousContent.append(delta);

                                    if (!delta.isEmpty()) {
                                        currentExplainStreamingRenderer.onChunkReceived(delta);
                                    }
                                }
                            }

                            @Override
                            public void onSummaryComplete(String fullSummary, KnowledgeNode updatedNode) {
                                Msg.info(this, "Streaming complete for function explain");

                                // Complete streaming
                                if (currentExplainStreamingRenderer != null) {
                                    currentExplainStreamingRenderer.onStreamComplete();
                                    currentExplainStreamingRenderer = null;
                                }

                                // Mark as not stale
                                updatedNode.setStale(false);
                                graph.upsertNode(updatedNode);

                                // Update security info panel only (don't overwrite streamed content)
                                SwingUtilities.invokeLater(() -> {
                                    explainTab.setMarkdownSource(fullSummary);
                                    explainTab.updateSecurityInfo(
                                        updatedNode.getRiskLevel(),
                                        updatedNode.getActivityProfile(),
                                        updatedNode.getSecurityFlags(),
                                        updatedNode.getNetworkAPIs(),
                                        updatedNode.getFileIOAPIs()
                                    );
                                    setUIState(false, "Explain Function", null);
                                });
                            }

                            @Override
                            public void onError(Throwable error) {
                                Msg.error(this, "Streaming error: " + error.getMessage());
                                currentExplainStreamingRenderer = null;
                                SwingUtilities.invokeLater(() -> {
                                    explainTab.setExplanationText("Error: " + error.getMessage());
                                    setUIState(false, "Explain Function", null);
                                });
                            }

                            @Override
                            public boolean shouldContinue() {
                                return isQueryRunning;
                            }
                        });

                        // Return early - the callback will handle completion
                        return;
                    } else {
                        Msg.info(this, "Skipping semantic analysis - using existing summary");
                    }

                    // Step 4: Save node to graph (only reached if no summary needed)
                    graph.upsertNode(node);

                    // Step 5: Update display
                    final KnowledgeNode finalNode = node;
                    SwingUtilities.invokeLater(() -> {
                        updateExplainDisplay(finalNode);
                        setUIState(false, "Explain Function", null);
                    });
                } else {
                    SwingUtilities.invokeLater(() -> {
                        explainTab.setExplanationText("Failed to analyze function.");
                        explainTab.clearSecurityInfo();
                        setUIState(false, "Explain Function", null);
                    });
                }

            } catch (Exception e) {
                // Clean up any active streaming renderer
                if (currentExplainStreamingRenderer != null) {
                    currentExplainStreamingRenderer = null;
                }
                SwingUtilities.invokeLater(() -> {
                    Msg.showError(getClass(), explainTab, "Error",
                        "Failed to explain function: " + e.getMessage());
                    setUIState(false, "Explain Function", null);
                });
            }
        }, "GhidrAssist-ExplainFunction");

        explainThread.start();
    }

    /**
     * Update the Explain tab display with data from a KnowledgeNode.
     */
    private void updateExplainDisplay(KnowledgeNode node) {
        if (node == null) {
            explainTab.setExplanationText("");
            explainTab.clearSecurityInfo();
            return;
        }

        // Update main summary
        String summary = node.getLlmSummary();
        if (summary != null && !summary.isEmpty()) {
            explainTab.setExplanationText(markdownHelper.markdownToHtml(summary));
        } else {
            explainTab.setExplanationText("<i>No summary available. Click 'Explain Function' to analyze.</i>");
        }

        // Update security info panel
        explainTab.updateSecurityInfo(
            node.getRiskLevel(),
            node.getActivityProfile(),
            node.getSecurityFlags(),
            node.getNetworkAPIs(),
            node.getFileIOAPIs()
        );
    }

    public void handleExplainLine() {
        Msg.info(this, "handleExplainLine called, isLineQueryRunning=" + isLineQueryRunning);

        if (isLineQueryRunning) {
            Msg.info(this, "Line query already running, cancelling...");
            cancelLineExplainOperation();
            return;
        }

        Address currentAddress = plugin.getCurrentAddress();
        if (currentAddress == null) {
            Msg.showInfo(getClass(), explainTab, "No Address", "No address at current location.");
            return;
        }

        Function currentFunction = plugin.getCurrentFunction();
        if (currentFunction == null) {
            Msg.showInfo(getClass(), explainTab, "No Function", "Current address is not within a function.");
            return;
        }

        Program program = plugin.getCurrentProgram();
        if (program == null) {
            return;
        }

        String programHash = program.getExecutableSHA256();
        long lineAddress = currentAddress.getOffset();

        // Determine view type based on current location
        GhidrAssistPlugin.CodeViewType codeViewType = plugin.checkLastActiveCodeView();
        String viewType = (codeViewType == GhidrAssistPlugin.CodeViewType.IS_DECOMPILER) ? "DECOMPILER" : "DISASSEMBLY";
        Msg.info(this, "ExplainLine: Detected view type: " + viewType + " (codeViewType=" + codeViewType + ")");

        // Check cache first
        AnalysisDB.LineExplanation cached = analysisDB.getLineExplanation(programHash, lineAddress, viewType);
        if (cached != null) {
            Msg.info(this, "Using cached line explanation for address " + currentAddress);
            SwingUtilities.invokeLater(() -> {
                String html = markdownHelper.markdownToHtml(cached.getExplanation());
                explainTab.setLineExplanationText(html);
            });
            return;
        }

        // Set UI state for line explanation
        isLineQueryRunning = true;
        SwingUtilities.invokeLater(() -> {
            explainTab.setLineButtonText("Stop");
            explainTab.setLineExplanationText("<html><body><i>Extracting line context...</i></body></html>");
        });

        // Run in background thread
        Thread lineExplainThread = new Thread(() -> {
            try {
                Msg.info(this, "ExplainLine: Starting extraction for address " + currentAddress +
                         " (offset=0x" + Long.toHexString(currentAddress.getOffset()) + ")" +
                         ", viewType=" + viewType + ", function=" + currentFunction.getName());

                // Extract line context with 5 lines before/after
                CodeUtils.LineContext lineContext;

                if (viewType.equals("DECOMPILER")) {
                    Msg.info(this, "ExplainLine: Calling getDecompiledLineWithContext...");
                    lineContext = CodeUtils.getDecompiledLineWithContext(
                            currentAddress, ghidra.util.task.TaskMonitor.DUMMY, program, 5);
                } else {
                    Msg.info(this, "ExplainLine: Calling getDisassemblyLineWithContext...");
                    lineContext = CodeUtils.getDisassemblyLineWithContext(currentAddress, program, 5);
                }

                if (lineContext == null) {
                    Msg.warn(this, "ExplainLine: lineContext is NULL - extraction failed");
                    SwingUtilities.invokeLater(() -> {
                        explainTab.setLineExplanationText("<html><body><i>Could not extract code (null context). Check Ghidra console for details.</i></body></html>");
                        setLineExplainUIState(false, "Explain Line");
                    });
                    return;
                }

                if (!lineContext.isValid()) {
                    Msg.warn(this, "ExplainLine: lineContext is invalid - currentLine is empty or null");
                    Msg.warn(this, "ExplainLine: currentLine='" + lineContext.getCurrentLine() + "'");
                    SwingUtilities.invokeLater(() -> {
                        explainTab.setLineExplanationText("<html><body><i>Could not extract code (empty line). Check Ghidra console for details.</i></body></html>");
                        setLineExplainUIState(false, "Explain Line");
                    });
                    return;
                }

                Msg.info(this, "ExplainLine: SUCCESS - extracted line context:");
                Msg.info(this, "  currentLine: '" + lineContext.getCurrentLine() + "'");
                Msg.info(this, "  linesBefore (" + (lineContext.getLinesBefore() != null ? lineContext.getLinesBefore().split("\n").length : 0) + " lines)");
                Msg.info(this, "  linesAfter (" + (lineContext.getLinesAfter() != null ? lineContext.getLinesAfter().split("\n").length : 0) + " lines)");

                // Update UI to show we're generating explanation
                SwingUtilities.invokeLater(() ->
                        explainTab.setLineExplanationText("<html><body><i>Generating explanation...</i></body></html>"));

                // Generate prompt
                String prompt = ghidrassist.graphrag.extraction.ExtractionPrompts.lineExplanationPrompt(
                        lineContext.getCurrentLine(),
                        lineContext.getLinesBefore(),
                        lineContext.getLinesAfter(),
                        lineContext.getFunctionName(),
                        viewType.equals("DECOMPILER")
                );

                // Create LLM API and send request
                APIProviderConfig providerConfig = GhidrAssistPlugin.getCurrentProviderConfig();
                if (providerConfig == null) {
                    throw new Exception("No LLM provider configured.");
                }

                currentLineExplainLlmApi = new LlmApi(providerConfig, plugin);

                // Create response handler
                LlmApi.LlmResponseHandler handler = createLineExplainResponseHandler(
                        programHash,
                        currentFunction.getEntryPoint().getOffset(),
                        lineAddress,
                        viewType,
                        lineContext.getCurrentLine(),
                        lineContext.getLinesBefore(),
                        lineContext.getLinesAfter()
                );

                // Execute streaming request
                currentLineExplainLlmApi.sendRequestAsync(prompt, handler);

            } catch (Exception e) {
                Msg.error(this, "Line explanation failed: " + e.getMessage(), e);
                SwingUtilities.invokeLater(() -> {
                    explainTab.setLineExplanationText("<html><body>Error: " + e.getMessage() + "</body></html>");
                    setLineExplainUIState(false, "Explain Line");
                });
            }
        }, "GhidrAssist-ExplainLine");

        lineExplainThread.start();
    }

    /**
     * Cancel the current line explanation operation.
     */
    private void cancelLineExplainOperation() {
        if (currentLineExplainLlmApi != null) {
            currentLineExplainLlmApi.cancelCurrentRequest();
            currentLineExplainLlmApi = null;
        }

        // Clean up streaming renderer
        if (currentLineExplainStreamingRenderer != null) {
            currentLineExplainStreamingRenderer = null;
        }

        setLineExplainUIState(false, "Explain Line");
    }

    /**
     * Set the line explanation UI state.
     */
    private void setLineExplainUIState(boolean running, String buttonText) {
        isLineQueryRunning = running;
        SwingUtilities.invokeLater(() -> {
            if (explainTab != null) {
                explainTab.setLineButtonText(buttonText);
            }
        });
    }

    /**
     * Create a response handler for line explanation streaming.
     * Uses StreamingMarkdownRenderer for incremental HTML updates.
     */
    private LlmApi.LlmResponseHandler createLineExplainResponseHandler(
            String programHash, long functionAddress, long lineAddress,
            String viewType, String lineContent, String contextBefore, String contextAfter) {

        return new LlmApi.LlmResponseHandler() {
            private final StringBuilder responseBuffer = new StringBuilder();

            @Override
            public void onStart() {
                responseBuffer.setLength(0);

                // Initialize streaming for line explanation pane
                // Note: StreamingMarkdownRenderer already calls invokeLater, so callback runs on EDT
                currentLineExplainStreamingRenderer = new StreamingMarkdownRenderer(
                    update -> explainTab.applyLineRenderUpdate(update),
                    markdownHelper
                );

                SwingUtilities.invokeLater(() -> explainTab.initializeLineExplanationForStreaming());
            }

            @Override
            public void onUpdate(String partialResponse) {
                if (partialResponse == null || partialResponse.isEmpty()) {
                    return;
                }

                // Extract delta from cumulative response
                String currentBuffer = responseBuffer.toString();
                String delta;
                if (partialResponse.startsWith(currentBuffer)) {
                    delta = partialResponse.substring(currentBuffer.length());
                    responseBuffer.append(delta);
                } else {
                    delta = partialResponse;
                    responseBuffer.append(delta);
                }

                // Feed delta to streaming renderer
                if (!delta.isEmpty() && currentLineExplainStreamingRenderer != null) {
                    currentLineExplainStreamingRenderer.onChunkReceived(delta);
                }
            }

            @Override
            public void onComplete(String fullResponse) {
                final String finalResponse = (fullResponse != null && !fullResponse.isEmpty())
                        ? fullResponse : responseBuffer.toString();

                // Complete streaming
                if (currentLineExplainStreamingRenderer != null) {
                    currentLineExplainStreamingRenderer.onStreamComplete();
                    currentLineExplainStreamingRenderer = null;
                }

                // Cache the result
                analysisDB.upsertLineExplanation(
                        programHash, functionAddress, lineAddress,
                        viewType, lineContent, contextBefore, contextAfter,
                        finalResponse
                );

                SwingUtilities.invokeLater(() -> {
                    setLineExplainUIState(false, "Explain Line");
                    currentLineExplainLlmApi = null;
                });
            }

            @Override
            public void onError(Throwable error) {
                // Clean up streaming renderer
                if (currentLineExplainStreamingRenderer != null) {
                    // Try to complete with what we have
                    currentLineExplainStreamingRenderer.onStreamComplete();
                    currentLineExplainStreamingRenderer = null;
                }

                SwingUtilities.invokeLater(() -> {
                    String partialContent = responseBuffer.toString();
                    if (!partialContent.isEmpty()) {
                        String html = markdownHelper.markdownToHtml(partialContent + "\n\n[Error: " + error.getMessage() + "]");
                        explainTab.setLineExplanationText(html);
                    } else {
                        explainTab.setLineExplanationText("<html><body>Error: " + error.getMessage() + "</body></html>");
                    }
                    setLineExplainUIState(false, "Explain Line");
                    currentLineExplainLlmApi = null;
                });
            }

            @Override
            public boolean shouldContinue() {
                return isLineQueryRunning;
            }
        };
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
        Task task = new Task("Query", true, true, true) {
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

        // NOTE: Program context for semantic tools is now handled via ToolRegistry
        // in ReActOrchestrator. MCPToolManager only handles MCP server tools.

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
            int maxToolRounds = getMaxToolCalls();  // Load user's max tool calls setting
            currentOrchestrator = new ghidrassist.agent.react.ReActOrchestrator(
                    ghidrassist.GhidrAssistPlugin.getCurrentProviderConfig(),
                    plugin,
                    18,  // maxIterations
                    8000,  // contextSummaryThreshold
                    maxToolRounds  // maxToolRounds per iteration
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
            // Display result on EDT
            SwingUtilities.invokeLater(() -> {
                // historyContainer[0] now contains the complete investigation including:
                // - All iterations and tool calls
                // - The final synthesis (streamed answer)
                // - Completion metadata (status, iterations, duration)
                // No need to append result.toMarkdown() which would duplicate the answer

                // Save ReAct analysis with proper chunking to database
                // Pass the FULL chronological history, not just summaries
                queryService.saveReActAnalysis(
                    query,
                    historyContainer[0].toString(),  // Full investigation details
                    result.getAnswer()
                );

                // Show in UI - display the full chronological history
                String html = markdownHelper.markdownToHtml(historyContainer[0].toString());
                queryTab.setResponseText(html);

                // Clear the orchestrator reference
                currentOrchestrator = null;
                setUIState(false, "Submit", null);

                // Refresh chat history to show updated timestamp
                refreshChatHistory();
            });
        }).exceptionally(error -> {
            // Handle errors on EDT - but SAVE progress first!
            String errorMsg = error.getMessage() != null ? error.getMessage() : "Unknown error";
            Msg.error(this, "Agentic analysis failed: " + errorMsg, error);

            SwingUtilities.invokeLater(() -> {
                // Save partial progress even on error/cancellation
                String partialHistory = historyContainer[0].toString();
                if (partialHistory != null && !partialHistory.isEmpty()) {
                    // Determine if this was a cancellation or error
                    boolean isCancellation = errorMsg.toLowerCase().contains("cancel");

                    String suffix = isCancellation ?
                        "\n\n---\n\n**[Analysis cancelled by user]**" :
                        "\n\n---\n\n**[Analysis failed: " + errorMsg + "]**";

                    // Save the partial investigation to database
                    queryService.saveReActAnalysis(
                        query,
                        partialHistory + suffix,
                        isCancellation ? "[Cancelled]" : "[Error: " + errorMsg + "]"
                    );

                    // Show partial progress in UI
                    String html = markdownHelper.markdownToHtml(partialHistory + suffix);
                    queryTab.setResponseText(html);

                    // Refresh chat history to show the saved session
                    refreshChatHistory();
                }

                if (!errorMsg.toLowerCase().contains("cancel")) {
                    Msg.showError(getClass(), queryTab, "Agentic Analysis Error",
                        "Analysis failed: " + errorMsg);
                }

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

    // ==== Analysis Data Operations ====

    public void handleContextSave(String context) {
        try {
            analysisDataService.saveContext(context);
            Msg.showInfo(this, settingsTab, "Success", "Context saved successfully.");
        } catch (Exception e) {
            Msg.showError(this, settingsTab, "Error",
                "Failed to save context: " + e.getMessage());
        }
    }

    public void handleContextLoad() {
        try {
            String currentContext = analysisDataService.getContext();
            if (settingsTab != null) {
                settingsTab.setContextText(currentContext);
                settingsTab.loadReasoningEffort();
                settingsTab.loadMaxToolCalls();
            }
        } catch (Exception e) {
            Msg.showError(this, settingsTab, "Error",
                "Failed to load context: " + e.getMessage());
        }
    }

    public void handleContextRevert() {
        try {
            String defaultContext = analysisDataService.revertToDefaultContext();
            if (settingsTab != null) {
                settingsTab.setContextText(defaultContext);
            }
        } catch (Exception e) {
            Msg.showError(this, settingsTab, "Error",
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
            Msg.info(this, "handleLocationUpdate: address=" + loc.getAddress());
            explainTab.updateOffset(loc.getAddress().toString());
            updateAnalysisDisplay();
            updateLineExplanationDisplay(loc.getAddress());
        }
    }

    /**
     * Update the line explanation display when the cursor moves.
     * Shows cached explanation if available, otherwise clears the panel.
     */
    private void updateLineExplanationDisplay(Address address) {
        Msg.info(this, "updateLineExplanationDisplay: address=" + address);

        if (address == null || explainTab == null) {
            Msg.info(this, "updateLineExplanationDisplay: address or explainTab is null, returning");
            return;
        }

        // Don't update if a line query is currently running
        if (isLineQueryRunning) {
            Msg.info(this, "updateLineExplanationDisplay: line query running, skipping");
            return;
        }

        Program program = plugin.getCurrentProgram();
        if (program == null) {
            Msg.info(this, "updateLineExplanationDisplay: no program, clearing");
            explainTab.clearLineExplanation();
            return;
        }

        // Must be within a function
        Function function = plugin.getCurrentFunction();
        if (function == null) {
            Msg.info(this, "updateLineExplanationDisplay: no function at address, clearing");
            explainTab.clearLineExplanation();
            return;
        }

        String programHash = program.getExecutableSHA256();
        long lineAddress = address.getOffset();

        // Detect current view type
        GhidrAssistPlugin.CodeViewType codeViewType = plugin.checkLastActiveCodeView();
        String viewType = (codeViewType == GhidrAssistPlugin.CodeViewType.IS_DECOMPILER) ? "DECOMPILER" : "DISASSEMBLY";

        Msg.info(this, "updateLineExplanationDisplay: Looking up cache for hash=" + programHash.substring(0, 8) +
                 "..., address=0x" + Long.toHexString(lineAddress) + ", viewType=" + viewType);

        // Check for cached explanation for this view type
        AnalysisDB.LineExplanation cached = analysisDB.getLineExplanation(programHash, lineAddress, viewType);
        if (cached != null) {
            Msg.info(this, "updateLineExplanationDisplay: CACHE HIT - displaying cached explanation");
            String html = markdownHelper.markdownToHtml(cached.getExplanation());
            explainTab.setLineExplanationText(html);
        } else {
            Msg.info(this, "updateLineExplanationDisplay: CACHE MISS - clearing panel");
            explainTab.clearLineExplanation();
        }
    }

    public void updateAnalysis(ProgramLocation loc) {
        updateAnalysisDisplay();
    }
    
    public void handleUpdateAnalysis(String updatedContent) {
        Function function = plugin.getCurrentFunction();
        if (function == null) {
            return;
        }

        try {
            String programHash = function.getProgram().getExecutableSHA256();
            BinaryKnowledgeGraph graph = analysisDB.getKnowledgeGraph(programHash);
            KnowledgeNode node = graph.getNodeByAddress(function.getEntryPoint().getOffset());

            if (node == null) {
                Msg.showWarn(this, explainTab, "Not Indexed",
                    "Function not indexed. Run 'Explain Function' first.");
                return;
            }

            node.setLlmSummary(updatedContent);
            node.setUserEdited(true);  // Protect from auto-overwrite
            node.markUpdated();
            graph.upsertNode(node);
        } catch (Exception e) {
            Msg.showError(this, null, "Error", "Failed to update analysis: " + e.getMessage());
        }
    }

    public void handleClearAnalysisData() {
        Function function = plugin.getCurrentFunction();
        if (function == null) {
            return;
        }

        try {
            String programHash = function.getProgram().getExecutableSHA256();
            BinaryKnowledgeGraph graph = analysisDB.getKnowledgeGraph(programHash);
            KnowledgeNode node = graph.getNodeByAddress(function.getEntryPoint().getOffset());

            if (node != null) {
                node.setLlmSummary(null);
                node.setUserEdited(false);
                node.markStale();
                graph.upsertNode(node);
            }

            // Clear all line explanations for this function
            int deletedLines = analysisDB.clearLineExplanationsForFunction(
                programHash, function.getEntryPoint().getOffset()
            );
            if (deletedLines > 0) {
                Msg.info(this, "Cleared " + deletedLines + " line explanation(s) for function");
            }

            explainTab.setExplanationText("");
            explainTab.clearSecurityInfo();
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
        // Cancel any running operation first
        if (isQueryRunning) {
            cancelCurrentOperation();
        }
        // Clean up any active streaming renderer
        if (currentStreamingRenderer != null) {
            currentStreamingRenderer = null;
        }

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
        // Cancel any running operation first
        if (isQueryRunning) {
            cancelCurrentOperation();
        }
        // Clean up any active streaming renderer
        if (currentStreamingRenderer != null) {
            currentStreamingRenderer = null;
        }

        // Get all selected rows from the table (supports multi-select)
        int[] selectedRows = queryTab.getSelectedChatSessions();
        java.util.List<ghidrassist.AnalysisDB.ChatSession> sessions = queryService.getChatSessions();

        int deletedCount = 0;
        if (selectedRows != null && selectedRows.length > 0) {
            // Delete in reverse order to avoid index shifting issues
            for (int i = selectedRows.length - 1; i >= 0; i--) {
                int rowIndex = selectedRows[i];
                if (rowIndex >= 0 && rowIndex < sessions.size()) {
                    int sessionId = sessions.get(rowIndex).getId();
                    if (queryService.deleteSession(sessionId)) {
                        deletedCount++;
                    }
                }
            }
        } else {
            // Fall back to deleting current session if no table selection
            if (queryService.deleteCurrentSession()) {
                deletedCount = 1;
            }
        }

        final boolean anyDeleted = deletedCount > 0;
        SwingUtilities.invokeLater(() -> {
            if (anyDeleted) {
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
                    String conversationHistory = queryService.getConversationHistory();
                    String html = markdownHelper.markdownToHtml(conversationHistory);
                    queryTab.setResponseText(html);
                    queryTab.setMarkdownSource(conversationHistory);
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

        // DEBUG: Log first few messages to see if user query is present
        for (int i = 0; i < Math.min(3, messages.size()); i++) {
            PersistedChatMessage msg = messages.get(i);
            Msg.info(this, String.format("  Message[%d]: role=%s, order=%d, content=%s",
                i, msg.getRole(), msg.getOrder(),
                msg.getContent().substring(0, Math.min(50, msg.getContent().length()))));
        }

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
                List<PersistedChatMessage> newMessageList = new ArrayList<>();
                for (int i = 0; i < finalMessages.size(); i++) {
                    ChatEditManager.ExtractedMessage msg = finalMessages.get(i);
                    Msg.info(this, "  Saving message " + i + ": role=" + msg.role);

                    PersistedChatMessage persistedMsg = new PersistedChatMessage(
                            null, msg.role, msg.content,
                            new Timestamp(System.currentTimeMillis()), i
                    );
                    persistedMsg.setProviderType("edited");
                    persistedMsg.setMessageType("edited");
                    newMessageList.add(persistedMsg);
                }

                queryService.replaceAllMessages(newMessageList);
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

            // Build new message list
            List<PersistedChatMessage> newMessageList = new ArrayList<>();
            for (int i = 0; i < finalMessages.size(); i++) {
                ChatEditManager.ExtractedMessage msg = finalMessages.get(i);

                PersistedChatMessage persistedMsg = new PersistedChatMessage(
                        null, msg.role, msg.content,
                        new Timestamp(System.currentTimeMillis()), i
                );
                persistedMsg.setProviderType("edited");
                persistedMsg.setMessageType("edited");
                newMessageList.add(persistedMsg);
            }

            // Replace all messages in memory and database atomically
            queryService.replaceAllMessages(newMessageList);
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

    private String formatIndexedTimestamp(Long epochMs) {
        if (epochMs == null || epochMs <= 0) {
            return "unknown";
        }
        DateTimeFormatter formatter =
                DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());
        return formatter.format(Instant.ofEpochMilli(epochMs));
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

        // Clean up streaming renderers FIRST to stop stale UI updates
        if (currentStreamingRenderer != null) {
            currentStreamingRenderer = null;
        }
        if (currentExplainStreamingRenderer != null) {
            currentExplainStreamingRenderer = null;
        }

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
        safetyScheduler.schedule(() -> {
            if (isCancelling) {
                Msg.warn(this, "Cancellation safety timeout - forcing UI reset");
                SwingUtilities.invokeLater(() -> {
                    isCancelling = false;
                    isQueryRunning = false;
                    currentOrchestrator = null;
                    currentLlmApi = null;
                    currentStreamingRenderer = null;
                    setUIState(false, "Submit", null);
                });
            }
        }, 5, TimeUnit.SECONDS);
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
        if (function == null) {
            explainTab.setExplanationText("");
            explainTab.clearSecurityInfo();
            return;
        }

        try {
            String programHash = function.getProgram().getExecutableSHA256();
            BinaryKnowledgeGraph graph = analysisDB.getKnowledgeGraph(programHash);
            KnowledgeNode node = graph.getNodeByAddress(function.getEntryPoint().getOffset());

            updateExplainDisplay(node);
        } catch (Exception e) {
            // Fall back to empty display on error
            explainTab.setExplanationText("");
            explainTab.clearSecurityInfo();
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
                    explainTab.setMarkdownSource(fullResponse);
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

                // Render existing conversation history as prefix
                String existingHtml = markdownHelper.markdownToHtmlFragment(
                    queryService.getConversationHistory());

                // Create streaming renderer with callback to update UI
                // Note: StreamingMarkdownRenderer already calls invokeLater, so callback runs on EDT
                currentStreamingRenderer = new StreamingMarkdownRenderer(
                    update -> queryTab.applyRenderUpdate(update),
                    markdownHelper
                );
                currentStreamingRenderer.setConversationPrefix(existingHtml);

                // Initialize streaming display with conversation history
                SwingUtilities.invokeLater(() -> queryTab.initializeForStreaming(existingHtml));
            }

            @Override
            public void onUpdate(String partialResponse) {
                if (partialResponse == null || partialResponse.isEmpty()) {
                    return;
                }

                String delta;
                synchronized (bufferLock) {
                    // Handle cumulative vs delta responses - extract only new content
                    String currentBuffer = responseBuffer.toString();
                    if (partialResponse.startsWith(currentBuffer)) {
                        delta = partialResponse.substring(currentBuffer.length());
                        if (!delta.isEmpty()) {
                            responseBuffer.append(delta);
                        }
                    } else {
                        delta = partialResponse;
                        responseBuffer.append(delta);
                    }
                }

                // Send delta to streaming renderer for incremental processing
                if (!delta.isEmpty() && currentStreamingRenderer != null) {
                    currentStreamingRenderer.onChunkReceived(delta);
                }
            }

            @Override
            public void onComplete(String fullResponse) {
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

                    // Signal stream complete to renderer
                    if (currentStreamingRenderer != null) {
                        currentStreamingRenderer.onStreamComplete();
                        currentStreamingRenderer = null;
                    }

                    SwingUtilities.invokeLater(() -> {
                        feedbackService.cacheLastInteraction(feedbackService.getLastPrompt(), finalResponse);
                        queryService.addAssistantResponse(finalResponse);

                        // Final markdown rendering
                        String conversationHistory = queryService.getConversationHistory();
                        String html = markdownHelper.markdownToHtml(conversationHistory);
                        queryTab.setResponseText(html);
                        queryTab.setMarkdownSource(conversationHistory);
                        setUIState(false, "Submit", null);
                        currentLlmApi = null;

                        refreshChatHistory();
                    });
                }
            }

            @Override
            public void onError(Throwable error) {
                // Clean up streaming renderer
                if (currentStreamingRenderer != null) {
                    currentStreamingRenderer = null;
                }

                // Save partial response if we have content before the error
                synchronized (bufferLock) {
                    if (responseBuffer.length() > 0) {
                        final String partialResponse = responseBuffer.toString();
                        SwingUtilities.invokeLater(() -> {
                            // Save partial response as assistant message before the error
                            queryService.addAssistantMessage(partialResponse + "\n\n[Incomplete - Error occurred]",
                                queryService.getCurrentProviderType(), null);
                        });
                    }
                }

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
                // Check if we should continue - if not, save partial progress
                if (!isQueryRunning) {
                    savePartialResponseOnCancel();
                }
                return isQueryRunning;
            }

            /**
             * Save partial response when cancellation is detected.
             * This ensures we don't lose work even if the user cancels.
             */
            private void savePartialResponseOnCancel() {
                synchronized (bufferLock) {
                    if (responseBuffer.length() > 0) {
                        final String partialResponse = responseBuffer.toString();
                        // Clear buffer to prevent duplicate saves
                        responseBuffer.setLength(0);

                        // Clean up streaming renderer
                        if (currentStreamingRenderer != null) {
                            currentStreamingRenderer = null;
                        }

                        SwingUtilities.invokeLater(() -> {
                            // Save partial response
                            queryService.addAssistantMessage(partialResponse + "\n\n[Cancelled by user]",
                                queryService.getCurrentProviderType(), null);

                            // Update UI with saved content
                            String html = markdownHelper.markdownToHtml(queryService.getConversationHistory());
                            queryTab.setResponseText(html);
                            setUIState(false, "Submit", null);
                            currentLlmApi = null;

                            refreshChatHistory();
                        });
                    }
                }
            }
        };
    }
    
    private ghidrassist.agent.react.ReActProgressHandler createReActProgressHandler(final StringBuilder[] historyContainer) {
        return new ghidrassist.agent.react.ReActProgressHandler() {
            private final StringBuilder chronologicalHistory = new StringBuilder();  // Single sequential history
            private final Object historyLock = new Object();  // Protect concurrent access
            private String currentIterationOutput = "";
            private final StringBuilder synthesisBuffer = new StringBuilder();  // Separate buffer for synthesis streaming
            private boolean synthesisStarted = false;
            private int lastIterationSeen = -1;  // Start at -1 so iteration 0 triggers header
            private StreamingMarkdownRenderer synthesisRenderer = null;  // Used for synthesis phase streaming

            @Override
            public void onStart(String objective) {
                synchronized (historyLock) {
                    chronologicalHistory.setLength(0);
                    chronologicalHistory.append("# ReAct Investigation\n\n");
                    chronologicalHistory.append("**Objective**: ").append(objective).append("\n\n");
                    chronologicalHistory.append("---\n\n");
                    currentIterationOutput = "";
                    lastIterationSeen = -1;
                    synthesisBuffer.setLength(0);
                    synthesisStarted = false;
                }

                // Initialize streaming display
                SwingUtilities.invokeLater(() -> queryTab.initializeForStreaming(""));

                // Render initial state
                renderCurrentContent();
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
                // Render immediately for thought updates (they're discrete events)
                renderCurrentContent();
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
                renderCurrentContent();
            }

            @Override
            public void onComplete(ghidrassist.agent.react.ReActResult result) {
                // Clean up synthesis renderer if used
                synthesisRenderer = null;

                synchronized (historyLock) {
                    if (!currentIterationOutput.isEmpty()) {
                        chronologicalHistory.append(currentIterationOutput).append("\n\n");
                        chronologicalHistory.append("---\n\n");
                        currentIterationOutput = "";
                    }
                    // Archive synthesis buffer if present
                    if (synthesisBuffer.length() > 0) {
                        chronologicalHistory.append(synthesisBuffer).append("\n\n");
                    }

                    // Add completion metadata
                    chronologicalHistory.append("---\n\n");
                    chronologicalHistory.append("**Status**: ").append(result.isSuccess() ? "✓ Complete" : result.getStatus()).append("\n");
                    chronologicalHistory.append("**Iterations**: ").append(result.getIterationCount()).append("\n");
                    chronologicalHistory.append("**Tool Calls**: ").append(result.getToolCallCount()).append("\n");
                    if (result.getDuration() != null) {
                        long seconds = result.getDuration().getSeconds();
                        chronologicalHistory.append("**Duration**: ").append(seconds).append("s\n");
                    }
                    chronologicalHistory.append("\n");

                    historyContainer[0] = chronologicalHistory;
                }

                // Do a final render immediately to ensure complete content is shown
                renderCurrentContent();
            }

            @Override
            public void onError(Throwable error) {
                // Clean up synthesis renderer
                synthesisRenderer = null;

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
                renderCurrentContent();
            }

            @Override
            public void onToolCallWarning(int remaining) {
                synchronized (historyLock) {
                    chronologicalHistory.append("⚠️ *").append(remaining).append(" tool call(s) remaining*\n\n");
                }
                renderCurrentContent();
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
                renderCurrentContent();
            }

            @Override
            public void onSummarizing(String summary) {
                synchronized (historyLock) {
                    chronologicalHistory.append("📝 **Summarizing context...**\n\n");
                    chronologicalHistory.append("```\n").append(summary).append("\n```\n\n");
                }
                renderCurrentContent();
            }

            @Override
            public void onSynthesisChunk(String chunk) {
                String delta;
                synchronized (historyLock) {
                    // Add synthesis header on first chunk
                    if (!synthesisStarted) {
                        // Archive any remaining iteration output
                        if (!currentIterationOutput.isEmpty()) {
                            chronologicalHistory.append(currentIterationOutput).append("\n\n");
                            currentIterationOutput = "";
                        }
                        chronologicalHistory.append("---\n\n");
                        chronologicalHistory.append("## 🎯 Final Analysis\n\n");
                        synthesisStarted = true;

                        // Create streaming renderer for synthesis phase with committed history as prefix
                        String prefixHtml = markdownHelper.markdownToHtmlFragment(chronologicalHistory.toString());
                        synthesisRenderer = new StreamingMarkdownRenderer(
                            update -> queryTab.applyRenderUpdate(update),
                            markdownHelper
                        );
                        synthesisRenderer.setConversationPrefix(prefixHtml);
                        SwingUtilities.invokeLater(() -> queryTab.initializeForStreaming(prefixHtml));
                    }

                    // Handle cumulative vs delta responses - extract only new content
                    String currentBuffer = synthesisBuffer.toString();
                    if (chunk.startsWith(currentBuffer)) {
                        // Cumulative response - extract delta
                        delta = chunk.substring(currentBuffer.length());
                        if (!delta.isEmpty()) {
                            synthesisBuffer.append(delta);
                        }
                    } else {
                        // Delta response - append directly
                        delta = chunk;
                        synthesisBuffer.append(delta);
                    }
                }

                // Send delta to streaming renderer for incremental processing
                if (!delta.isEmpty() && synthesisRenderer != null) {
                    synthesisRenderer.onChunkReceived(delta);
                }
            }

            /**
             * Render the current content state to the UI.
             * Used for discrete event updates (not during synthesis streaming).
             */
            private void renderCurrentContent() {
                final String content;
                synchronized (historyLock) {
                    StringBuilder display = new StringBuilder();
                    display.append(chronologicalHistory);

                    // Include current iteration output if present
                    if (!currentIterationOutput.isEmpty()) {
                        display.append(currentIterationOutput).append("\n\n");
                    }

                    // Include synthesis buffer if streaming (only if not using streaming renderer)
                    if (synthesisBuffer.length() > 0 && synthesisRenderer == null) {
                        display.append(synthesisBuffer);
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
    
    // ==== Semantic Graph Tab Handlers ====

    /**
     * Update the semantic graph tab when the Ghidra cursor location changes.
     */
    public void updateSemanticGraphLocation(ProgramLocation loc) {
        if (semanticGraphTab == null || loc == null || loc.getAddress() == null) {
            return;
        }

        long address = loc.getAddress().getOffset();
        Function function = plugin.getCurrentFunction();
        String functionName = function != null ? function.getName() : null;

        SwingUtilities.invokeLater(() -> {
            semanticGraphTab.updateLocation(address, functionName);
        });
    }

    /**
     * Handle navigation to a function/address in the semantic graph tab.
     */
    public void handleSemanticGraphGo(String text) {
        if (plugin.getCurrentProgram() == null) {
            return;
        }

        try {
            // Try to parse as address
            long address = 0;
            text = text.trim();
            if (text.startsWith("0x") || text.startsWith("0X")) {
                address = Long.parseLong(text.substring(2), 16);
            } else if (text.matches("[0-9a-fA-F]+")) {
                address = Long.parseLong(text, 16);
            } else {
                // Try to find function by name
                ghidra.program.model.listing.FunctionManager fm = plugin.getCurrentProgram().getFunctionManager();
                for (Function func : fm.getFunctions(true)) {
                    if (func.getName().equalsIgnoreCase(text) ||
                        text.contains(func.getName())) {
                        address = func.getEntryPoint().getOffset();
                        break;
                    }
                }
            }

            if (address != 0) {
                Address addr = plugin.getCurrentProgram().getAddressFactory()
                        .getDefaultAddressSpace().getAddress(address);
                navigateToAddress(addr);
            }
        } catch (NumberFormatException e) {
            Msg.showWarn(this, null, "Invalid Address", "Could not parse address: " + text);
        }
    }

    /**
     * Handle navigation to a specific address.
     */
    public void handleSemanticGraphNavigate(long address) {
        if (plugin.getCurrentProgram() == null) {
            return;
        }

        Address addr = plugin.getCurrentProgram().getAddressFactory()
                .getDefaultAddressSpace().getAddress(address);
        navigateToAddress(addr);
    }

    /**
     * Navigate to an address using GoToService.
     */
    private void navigateToAddress(Address addr) {
        GoToService goToService = plugin.getTool().getService(GoToService.class);
        if (goToService != null) {
            goToService.goTo(addr);
        }
    }

    /**
     * Handle reset graph button.
     */
    public void handleSemanticGraphReset() {
        if (plugin.getCurrentProgram() == null) {
            Msg.showWarn(this, null, "No Program", "No program loaded");
            return;
        }

        Task task = new Task("Reset Graph", true, true, true) {
            @Override
            public void run(TaskMonitor monitor) throws ghidra.util.exception.CancelledException {
                try {
                    ghidrassist.graphrag.GraphRAGService service =
                            ghidrassist.graphrag.GraphRAGService.getInstance(analysisDB);
                    service.clearGraph(plugin.getCurrentProgram());

                    SwingUtilities.invokeLater(() -> {
                        semanticGraphTab.refreshCurrentView();
                        semanticGraphTab.updateStats(0, 0, 0, null);
                        Msg.showInfo(this, null, "Graph Reset", "Knowledge graph has been cleared.");
                    });
                } catch (Exception e) {
                    Msg.showError(this, null, "Error", "Failed to reset graph: " + e.getMessage());
                }
            }
        };
        TaskLauncher.launch(task);
    }

    /**
     * Handle reindex button with background progress.
     * Uses SwingWorker for non-blocking operation.
     */
    public void handleSemanticGraphReindex() {
        if (plugin.getCurrentProgram() == null) {
            Msg.showWarn(this, null, "No Program", "No program loaded");
            return;
        }

        // If already running, cancel it
        if (reindexWorker != null && !reindexWorker.isDone()) {
            reindexWorker.requestCancel();
            return;
        }

        // Create and configure the worker
        reindexWorker = new ReindexWorker(analysisDB, plugin.getCurrentProgram());

        reindexWorker.setProgressCallback(progress -> {
            semanticGraphTab.showProgress(progress.getPercentage(), progress.message);
        });

        reindexWorker.setCompletedCallback(result -> {
            semanticGraphTab.hideProgress();
            semanticGraphTab.setReindexRunning(false);
            semanticGraphTab.refreshCurrentView();

            String programHash = plugin.getCurrentProgram().getExecutableSHA256();
            Long lastIndexed = analysisDB.getKnowledgeGraphLastIndexed(programHash);
            if (lastIndexed == null) {
                lastIndexed = System.currentTimeMillis();
            }
            semanticGraphTab.updateStats(
                    result.functionsExtracted,
                    result.callEdgesCreated,
                    0,
                    formatIndexedTimestamp(lastIndexed)
            );

            Msg.info(this, String.format("Structure indexing complete: %d functions, %d edges. Starting Security Analysis...",
                    result.functionsExtracted, result.callEdgesCreated));

            // Chain to Security Analysis (which will chain to Network Flow, then Community Detection)
            startSecurityAnalysisChain();
        });

        reindexWorker.setCancelledCallback(() -> {
            semanticGraphTab.hideProgress();
            semanticGraphTab.setReindexRunning(false);
            semanticGraphTab.refreshCurrentView();
        });

        reindexWorker.setFailedCallback(error -> {
            semanticGraphTab.hideProgress();
            semanticGraphTab.setReindexRunning(false);
            Msg.showError(this, null, "Error", "Failed to index binary: " + error);
        });

        // Start the worker
        semanticGraphTab.setReindexRunning(true);
        semanticGraphTab.showProgress(0, "Starting reindex...");
        reindexWorker.execute();
    }

    /**
     * Handle refresh names button.
     * Uses SwingWorker for non-blocking operation.
     */
    public void handleSemanticGraphRefreshNames() {
        if (plugin.getCurrentProgram() == null) {
            return;
        }

        // If already running, cancel it
        if (refreshNamesWorker != null && !refreshNamesWorker.isDone()) {
            refreshNamesWorker.requestCancel();
            return;
        }

        // Create and configure the worker
        refreshNamesWorker = new RefreshNamesWorker(analysisDB, plugin.getCurrentProgram());

        refreshNamesWorker.setProgressCallback(progress -> {
            semanticGraphTab.showIndeterminateProgress(progress.message);
        });

        refreshNamesWorker.setCompletedCallback(result -> {
            semanticGraphTab.hideProgress();
            semanticGraphTab.setRefreshNamesRunning(false);
            semanticGraphTab.refreshCurrentView();
            Msg.showInfo(this, null, "Names Refreshed", "Function names have been refreshed.");
        });

        refreshNamesWorker.setCancelledCallback(() -> {
            semanticGraphTab.hideProgress();
            semanticGraphTab.setRefreshNamesRunning(false);
        });

        refreshNamesWorker.setFailedCallback(error -> {
            semanticGraphTab.hideProgress();
            semanticGraphTab.setRefreshNamesRunning(false);
            Msg.showError(this, null, "Error", "Failed to refresh names: " + error);
        });

        // Start the worker
        semanticGraphTab.setRefreshNamesRunning(true);
        semanticGraphTab.showIndeterminateProgress("Refreshing function names...");
        refreshNamesWorker.execute();
    }

    /**
     * Handle community detection - group related functions.
     */
    public void handleSemanticGraphCommunityDetection() {
        if (plugin.getCurrentProgram() == null) {
            Msg.showWarn(this, null, "No Program", "No program loaded");
            return;
        }

        // If already running, cancel it
        if (communityDetectionWorker != null && !communityDetectionWorker.isDone()) {
            communityDetectionWorker.requestCancel();
            return;
        }

        // Create and configure the worker
        communityDetectionWorker = new CommunityDetectionWorker(analysisDB, plugin.getCurrentProgram());

        communityDetectionWorker.setProgressCallback(progress -> {
            semanticGraphTab.showProgress(progress.getPercentage(), progress.message);
        });

        communityDetectionWorker.setCompletedCallback(result -> {
            semanticGraphTab.hideProgress();
            semanticGraphTab.setCommunityDetectionRunning(false);
            semanticGraphTab.refreshCurrentView();
            Msg.showInfo(this, null, "Community Detection Complete",
                    String.format("Detected %d communities", result.communityCount));
        });

        communityDetectionWorker.setCancelledCallback(() -> {
            semanticGraphTab.hideProgress();
            semanticGraphTab.setCommunityDetectionRunning(false);
            semanticGraphTab.refreshCurrentView();
        });

        communityDetectionWorker.setFailedCallback(error -> {
            semanticGraphTab.hideProgress();
            semanticGraphTab.setCommunityDetectionRunning(false);
            Msg.showError(this, null, "Error", "Failed to run community detection: " + error);
        });

        // Start the worker
        semanticGraphTab.setCommunityDetectionRunning(true);
        semanticGraphTab.showProgress(0, "Starting community detection...");
        communityDetectionWorker.execute();
    }

    // ========================================
    // Analysis Chain Helpers (for ReIndex pipeline)
    // ========================================

    /**
     * Start the Security Analysis as part of the ReIndex chain.
     * On completion, chains to Network Flow Analysis.
     */
    private void startSecurityAnalysisChain() {
        if (plugin.getCurrentProgram() == null) {
            return;
        }

        securityAnalysisWorker = new SecurityAnalysisWorker(analysisDB, plugin.getCurrentProgram());

        securityAnalysisWorker.setProgressCallback(progress -> {
            semanticGraphTab.showProgress(progress.getPercentage(), "Security: " + progress.message);
        });

        securityAnalysisWorker.setCompletedCallback(result -> {
            semanticGraphTab.hideProgress();
            semanticGraphTab.setSecurityAnalysisRunning(false);
            Msg.info(this, String.format("Security Analysis complete: %d taint paths, %d VULNERABLE_VIA edges. Starting Network Flow Analysis...",
                    result.pathCount, result.vulnerableViaEdges));
            startNetworkFlowAnalysisChain();
        });

        securityAnalysisWorker.setFailedCallback(error -> {
            semanticGraphTab.hideProgress();
            semanticGraphTab.setSecurityAnalysisRunning(false);
            Msg.warn(this, "Security Analysis failed: " + error + ". Continuing with Network Flow Analysis...");
            startNetworkFlowAnalysisChain();
        });

        securityAnalysisWorker.setCancelledCallback(() -> {
            semanticGraphTab.hideProgress();
            semanticGraphTab.setSecurityAnalysisRunning(false);
            // Don't continue chain if cancelled
        });

        semanticGraphTab.setSecurityAnalysisRunning(true);
        securityAnalysisWorker.execute();
    }

    /**
     * Start Network Flow Analysis as part of the ReIndex chain.
     * On completion, chains to Community Detection.
     */
    private void startNetworkFlowAnalysisChain() {
        if (plugin.getCurrentProgram() == null) {
            return;
        }

        networkFlowWorker = new NetworkFlowAnalysisWorker(analysisDB, plugin.getCurrentProgram());

        networkFlowWorker.setProgressCallback(progress -> {
            semanticGraphTab.showProgress(progress.getPercentage(), "Network: " + progress.message);
        });

        networkFlowWorker.setCompletedCallback(result -> {
            semanticGraphTab.hideProgress();
            semanticGraphTab.setNetworkFlowRunning(false);
            Msg.info(this, String.format("Network Flow Analysis complete: %d send edges, %d recv edges. Starting Community Detection...",
                    result.sendPathEdges, result.recvPathEdges));
            startCommunityDetectionChain();
        });

        networkFlowWorker.setFailedCallback(error -> {
            semanticGraphTab.hideProgress();
            semanticGraphTab.setNetworkFlowRunning(false);
            Msg.warn(this, "Network Flow Analysis failed: " + error + ". Continuing with Community Detection...");
            startCommunityDetectionChain();
        });

        networkFlowWorker.setCancelledCallback(() -> {
            semanticGraphTab.hideProgress();
            semanticGraphTab.setNetworkFlowRunning(false);
            // Don't continue chain if cancelled
        });

        semanticGraphTab.setNetworkFlowRunning(true);
        networkFlowWorker.execute();
    }

    /**
     * Start Community Detection as the final step of the ReIndex chain.
     * Shows completion dialog when done.
     */
    private void startCommunityDetectionChain() {
        if (plugin.getCurrentProgram() == null) {
            return;
        }

        communityDetectionWorker = new CommunityDetectionWorker(analysisDB, plugin.getCurrentProgram());

        communityDetectionWorker.setProgressCallback(progress -> {
            semanticGraphTab.showProgress(progress.getPercentage(), "Community: " + progress.message);
        });

        communityDetectionWorker.setCompletedCallback(result -> {
            semanticGraphTab.hideProgress();
            semanticGraphTab.setCommunityDetectionRunning(false);
            semanticGraphTab.refreshCurrentView();
            Msg.showInfo(this, null, "Full Pipeline Complete",
                    String.format("ReIndex pipeline completed:\n" +
                            "• Structure extraction\n" +
                            "• Security analysis\n" +
                            "• Network flow analysis\n" +
                            "• Community detection (%d communities)", result.communityCount));
        });

        communityDetectionWorker.setFailedCallback(error -> {
            semanticGraphTab.hideProgress();
            semanticGraphTab.setCommunityDetectionRunning(false);
            semanticGraphTab.refreshCurrentView();
            Msg.warn(this, "Community Detection failed: " + error);
            Msg.showInfo(this, null, "Pipeline Complete (with errors)",
                    "ReIndex pipeline completed with some errors.\nCheck console for details.");
        });

        communityDetectionWorker.setCancelledCallback(() -> {
            semanticGraphTab.hideProgress();
            semanticGraphTab.setCommunityDetectionRunning(false);
            semanticGraphTab.refreshCurrentView();
        });

        semanticGraphTab.setCommunityDetectionRunning(true);
        communityDetectionWorker.execute();
    }

    /**
     * Handle semantic analysis button - LLM summarization of stale nodes.
     * Uses SwingWorker for non-blocking operation.
     */
    public void handleSemanticGraphSemanticAnalysis() {
        if (plugin.getCurrentProgram() == null) {
            Msg.showWarn(this, null, "No Program", "No program loaded");
            return;
        }

        // If already running, cancel it
        if (semanticAnalysisWorker != null && !semanticAnalysisWorker.isDone()) {
            semanticAnalysisWorker.requestCancel();
            return;
        }

        // Create and configure the worker
        semanticAnalysisWorker = new SemanticAnalysisWorker(analysisDB, plugin.getCurrentProgram());

        semanticAnalysisWorker.setProgressCallback(progress -> {
            semanticGraphTab.showProgress(progress.getPercentage(), progress.message);
        });

        semanticAnalysisWorker.setCompletedCallback(result -> {
            semanticGraphTab.hideProgress();
            semanticGraphTab.setSemanticAnalysisRunning(false);
            semanticGraphTab.refreshCurrentView();
            Msg.showInfo(this, null, "Semantic Analysis Complete",
                    String.format("Summarized %d nodes (%d errors) in %.1fs",
                            result.summarized, result.errors, result.elapsedMs / 1000.0));
        });

        semanticAnalysisWorker.setCancelledCallback(() -> {
            semanticGraphTab.hideProgress();
            semanticGraphTab.setSemanticAnalysisRunning(false);
            semanticGraphTab.refreshCurrentView();
        });

        semanticAnalysisWorker.setFailedCallback(error -> {
            semanticGraphTab.hideProgress();
            semanticGraphTab.setSemanticAnalysisRunning(false);
            Msg.showError(this, null, "Error", "Failed to run semantic analysis: " + error);
        });

        // Start the worker
        semanticGraphTab.setSemanticAnalysisRunning(true);
        semanticGraphTab.showProgress(0, "Starting semantic analysis...");
        semanticAnalysisWorker.execute();
    }

    /**
     * Handle security analysis button - taint analysis + VULNERABLE_VIA edges.
     * Uses SwingWorker for non-blocking operation.
     */
    public void handleSemanticGraphSecurityAnalysis() {
        if (plugin.getCurrentProgram() == null) {
            Msg.showWarn(this, null, "No Program", "No program loaded");
            return;
        }

        // If already running, cancel it
        if (securityAnalysisWorker != null && !securityAnalysisWorker.isDone()) {
            securityAnalysisWorker.requestCancel();
            return;
        }

        // Create and configure the worker
        securityAnalysisWorker = new SecurityAnalysisWorker(analysisDB, plugin.getCurrentProgram());

        securityAnalysisWorker.setProgressCallback(progress -> {
            semanticGraphTab.showProgress(progress.getPercentage(), progress.message);
        });

        securityAnalysisWorker.setCompletedCallback(result -> {
            semanticGraphTab.hideProgress();
            semanticGraphTab.setSecurityAnalysisRunning(false);
            semanticGraphTab.refreshCurrentView();
            Msg.showInfo(this, null, "Security Analysis Complete",
                    String.format("Found %d taint paths\nCreated %d VULNERABLE_VIA edges",
                            result.pathCount, result.vulnerableViaEdges));
        });

        securityAnalysisWorker.setCancelledCallback(() -> {
            semanticGraphTab.hideProgress();
            semanticGraphTab.setSecurityAnalysisRunning(false);
            semanticGraphTab.refreshCurrentView();
        });

        securityAnalysisWorker.setFailedCallback(error -> {
            semanticGraphTab.hideProgress();
            semanticGraphTab.setSecurityAnalysisRunning(false);
            Msg.showError(this, null, "Error", "Failed to run security analysis: " + error);
        });

        // Start the worker
        semanticGraphTab.setSecurityAnalysisRunning(true);
        semanticGraphTab.showProgress(0, "Starting security analysis...");
        securityAnalysisWorker.execute();
    }

    /**
     * Handle network flow analysis button - trace send/recv data flow paths.
     * Uses SwingWorker for non-blocking operation.
     */
    public void handleSemanticGraphNetworkFlowAnalysis() {
        if (plugin.getCurrentProgram() == null) {
            Msg.showWarn(this, null, "No Program", "No program loaded");
            return;
        }

        // If already running, cancel it
        if (networkFlowWorker != null && !networkFlowWorker.isDone()) {
            networkFlowWorker.requestCancel();
            return;
        }

        // Create and configure the worker
        networkFlowWorker = new NetworkFlowAnalysisWorker(analysisDB, plugin.getCurrentProgram());

        networkFlowWorker.setProgressCallback(progress -> {
            semanticGraphTab.showProgress(progress.getPercentage(), progress.message);
        });

        networkFlowWorker.setCompletedCallback(result -> {
            semanticGraphTab.hideProgress();
            semanticGraphTab.setNetworkFlowRunning(false);
            semanticGraphTab.refreshCurrentView();
            Msg.showInfo(this, null, "Network Flow Analysis Complete",
                    String.format("Found %d functions calling send APIs\n" +
                            "Found %d functions calling recv APIs\n" +
                            "Created %d NETWORK_SEND_PATH edges\n" +
                            "Created %d NETWORK_RECV_PATH edges",
                            result.sendFunctionsFound, result.recvFunctionsFound,
                            result.sendPathEdges, result.recvPathEdges));
        });

        networkFlowWorker.setCancelledCallback(() -> {
            semanticGraphTab.hideProgress();
            semanticGraphTab.setNetworkFlowRunning(false);
            semanticGraphTab.refreshCurrentView();
        });

        networkFlowWorker.setFailedCallback(error -> {
            semanticGraphTab.hideProgress();
            semanticGraphTab.setNetworkFlowRunning(false);
            Msg.showError(this, null, "Error", "Failed to run network flow analysis: " + error);
        });

        // Start the worker
        semanticGraphTab.setNetworkFlowRunning(true);
        semanticGraphTab.showProgress(0, "Starting network flow analysis...");
        networkFlowWorker.execute();
    }

    /**
     * Handle index single function button.
     */
    public void handleSemanticGraphIndexFunction(long address) {
        if (plugin.getCurrentProgram() == null) {
            return;
        }

        Task task = new Task("Index Function", true, true, true) {
            @Override
            public void run(TaskMonitor monitor) throws ghidra.util.exception.CancelledException {
                try {
                    Address addr = plugin.getCurrentProgram().getAddressFactory()
                            .getDefaultAddressSpace().getAddress(address);
                    Function function = plugin.getCurrentProgram().getFunctionManager()
                            .getFunctionContaining(addr);

                    if (function == null) {
                        Msg.showWarn(this, null, "No Function", "No function at this address");
                        return;
                    }

                    ghidrassist.graphrag.GraphRAGService service =
                            ghidrassist.graphrag.GraphRAGService.getInstance(analysisDB);
                    service.setCurrentProgram(plugin.getCurrentProgram());

                    // Index just this function
                    ghidrassist.graphrag.BinaryKnowledgeGraph graph =
                            analysisDB.getKnowledgeGraph(plugin.getCurrentProgram().getExecutableSHA256());
                    ghidrassist.graphrag.extraction.StructureExtractor extractor =
                            new ghidrassist.graphrag.extraction.StructureExtractor(
                                    plugin.getCurrentProgram(), graph, monitor);
                    try {
                        extractor.extractFunction(function);
                    } finally {
                        extractor.dispose();
                    }

                    SwingUtilities.invokeLater(() -> {
                        semanticGraphTab.refreshCurrentView();
                        Msg.showInfo(this, null, "Function Indexed",
                                "Function " + function.getName() + " has been indexed.");
                    });
                } catch (Exception e) {
                    Msg.showError(this, null, "Error", "Failed to index function: " + e.getMessage());
                }
            }
        };
        TaskLauncher.launch(task);
    }

    /**
     * Handle list view refresh.
     */
    public void handleSemanticGraphListViewRefresh(
            ghidrassist.ui.tabs.semanticgraph.ListViewPanel listView, long address) {
        if (plugin.getCurrentProgram() == null) {
            listView.showNotIndexed();
            return;
        }

        SwingUtilities.invokeLater(() -> {
            try {
                ghidrassist.graphrag.BinaryKnowledgeGraph graph =
                        analysisDB.getKnowledgeGraph(plugin.getCurrentProgram().getExecutableSHA256());

                ghidrassist.graphrag.nodes.KnowledgeNode node = graph.getNodeByAddress(address);

                if (node == null) {
                    listView.showNotIndexed();
                    semanticGraphTab.updateStatus(false, 0, 0, 0);
                    return;
                }

                listView.showContent();

                // Get callers and callees
                java.util.List<ghidrassist.graphrag.nodes.KnowledgeNode> callers = graph.getCallers(node.getId());
                java.util.List<ghidrassist.graphrag.nodes.KnowledgeNode> callees = graph.getCallees(node.getId());
                java.util.List<ghidrassist.graphrag.BinaryKnowledgeGraph.GraphEdge> outgoing = graph.getOutgoingEdges(node.getId());
                java.util.List<ghidrassist.graphrag.BinaryKnowledgeGraph.GraphEdge> incoming = graph.getIncomingEdges(node.getId());

                // Combine all edges
                java.util.List<ghidrassist.graphrag.BinaryKnowledgeGraph.GraphEdge> allEdges = new java.util.ArrayList<>();
                allEdges.addAll(outgoing);
                allEdges.addAll(incoming);

                listView.setCallers(callers);
                listView.setCallees(callees);
                listView.setEdges(allEdges);
                listView.setSecurityFlags(node.getSecurityFlags());
                listView.setSummary(node.getLlmSummary());

                semanticGraphTab.setCurrentNodeId(node.getId());
                semanticGraphTab.updateStatus(true, callers.size(), callees.size(),
                        node.getSecurityFlags().size());

                // Update stats
                int nodeCount = graph.getNodeCount();
                int edgeCount = graph.getEdgeCount();
                Long lastIndexed = analysisDB.getKnowledgeGraphLastIndexed(
                        plugin.getCurrentProgram().getExecutableSHA256());
                semanticGraphTab.updateStats(nodeCount, edgeCount, 0, formatIndexedTimestamp(lastIndexed));

            } catch (Exception e) {
                Msg.error(this, "Failed to refresh list view: " + e.getMessage(), e);
                listView.showNotIndexed();
            }
        });
    }

    /**
     * Handle visual graph refresh.
     */
    public void handleSemanticGraphVisualRefresh(
            ghidrassist.ui.tabs.semanticgraph.GraphViewPanel graphView,
            long address, int nHops, java.util.Set<ghidrassist.graphrag.nodes.EdgeType> edgeTypes) {
        if (plugin.getCurrentProgram() == null) {
            graphView.showNotIndexed();
            return;
        }

        SwingUtilities.invokeLater(() -> {
            try {
                ghidrassist.graphrag.BinaryKnowledgeGraph graph =
                        analysisDB.getKnowledgeGraph(plugin.getCurrentProgram().getExecutableSHA256());

                ghidrassist.graphrag.nodes.KnowledgeNode centerNode = graph.getNodeByAddress(address);

                if (centerNode == null) {
                    graphView.showNotIndexed();
                    return;
                }

                graphView.showContent();

                // Get N-hop neighborhood (only follows outgoing edges due to BFS on directed graph)
                java.util.List<ghidrassist.graphrag.nodes.KnowledgeNode> neighbors =
                        graph.getNeighborsBatch(centerNode.getId(), nHops);

                // Include center node in the list
                java.util.List<ghidrassist.graphrag.nodes.KnowledgeNode> allNodes = new java.util.ArrayList<>();
                allNodes.add(centerNode);
                allNodes.addAll(neighbors);

                // Find and add direct callers of the center node (incoming CALLS edges)
                // getNeighborsBatch uses BFS which only follows outgoing edges, so callers are missed
                java.util.Set<String> existingNodeIds = new java.util.HashSet<>();
                for (ghidrassist.graphrag.nodes.KnowledgeNode node : allNodes) {
                    existingNodeIds.add(node.getId());
                }

                // Track caller nodes separately - we only want their edges TO the root, not their other callees
                java.util.Set<String> callerNodeIds = new java.util.HashSet<>();
                java.util.List<ghidrassist.graphrag.BinaryKnowledgeGraph.GraphEdge> callerEdges = new java.util.ArrayList<>();

                for (ghidrassist.graphrag.BinaryKnowledgeGraph.GraphEdge edge : graph.getIncomingEdges(centerNode.getId())) {
                    if (edge.getType() == ghidrassist.graphrag.nodes.EdgeType.CALLS &&
                        !existingNodeIds.contains(edge.getSourceId())) {
                        ghidrassist.graphrag.nodes.KnowledgeNode callerNode = graph.getNode(edge.getSourceId());
                        if (callerNode != null) {
                            allNodes.add(callerNode);
                            existingNodeIds.add(callerNode.getId());
                            callerNodeIds.add(callerNode.getId());
                            callerEdges.add(edge);  // Only add the caller→root edge
                        }
                    }
                }

                // Collect all edges between non-caller nodes (center + descendants)
                java.util.Set<String> nodeIds = new java.util.HashSet<>();
                for (ghidrassist.graphrag.nodes.KnowledgeNode node : allNodes) {
                    nodeIds.add(node.getId());
                }

                java.util.List<ghidrassist.graphrag.BinaryKnowledgeGraph.GraphEdge> allEdges = new java.util.ArrayList<>();

                // Add the caller→root edges first
                allEdges.addAll(callerEdges);

                // For non-caller nodes, collect their edges normally
                for (ghidrassist.graphrag.nodes.KnowledgeNode node : allNodes) {
                    // Skip caller nodes - we already added their specific edges to root
                    if (callerNodeIds.contains(node.getId())) {
                        continue;
                    }
                    // Include outgoing edges (this node calls others)
                    for (ghidrassist.graphrag.BinaryKnowledgeGraph.GraphEdge edge : graph.getOutgoingEdges(node.getId())) {
                        if (nodeIds.contains(edge.getTargetId()) && edgeTypes.contains(edge.getType())) {
                            allEdges.add(edge);
                        }
                    }
                }

                graphView.buildGraph(centerNode, allNodes, allEdges);

            } catch (Exception e) {
                Msg.error(this, "Failed to refresh visual graph: " + e.getMessage(), e);
                graphView.showNotIndexed();
            }
        });
    }

    /**
     * Handle adding a security flag.
     */
    public void handleSemanticGraphAddFlag(long address, String flag) {
        if (plugin.getCurrentProgram() == null) {
            return;
        }

        try {
            ghidrassist.graphrag.BinaryKnowledgeGraph graph =
                    analysisDB.getKnowledgeGraph(plugin.getCurrentProgram().getExecutableSHA256());
            ghidrassist.graphrag.nodes.KnowledgeNode node = graph.getNodeByAddress(address);

            if (node != null) {
                node.addSecurityFlag(flag);
                graph.upsertNode(node);
            }
        } catch (Exception e) {
            Msg.error(this, "Failed to add security flag: " + e.getMessage(), e);
        }
    }

    /**
     * Handle removing a security flag.
     */
    public void handleSemanticGraphRemoveFlag(long address, String flag) {
        if (plugin.getCurrentProgram() == null) {
            return;
        }

        try {
            ghidrassist.graphrag.BinaryKnowledgeGraph graph =
                    analysisDB.getKnowledgeGraph(plugin.getCurrentProgram().getExecutableSHA256());
            ghidrassist.graphrag.nodes.KnowledgeNode node = graph.getNodeByAddress(address);

            if (node != null) {
                java.util.List<String> flags = new java.util.ArrayList<>(node.getSecurityFlags());
                flags.remove(flag);
                node.setSecurityFlags(flags);
                graph.upsertNode(node);
            }
        } catch (Exception e) {
            Msg.error(this, "Failed to remove security flag: " + e.getMessage(), e);
        }
    }

    /**
     * Handle saving LLM summary.
     */
    public void handleSemanticGraphSaveSummary(long address, String summary) {
        if (plugin.getCurrentProgram() == null) {
            return;
        }

        try {
            ghidrassist.graphrag.BinaryKnowledgeGraph graph =
                    analysisDB.getKnowledgeGraph(plugin.getCurrentProgram().getExecutableSHA256());
            ghidrassist.graphrag.nodes.KnowledgeNode node = graph.getNodeByAddress(address);

            if (node != null) {
                node.setLlmSummary(summary);
                graph.upsertNode(node);
                Msg.info(this, "Summary saved for node at 0x" + Long.toHexString(address));
            }
        } catch (Exception e) {
            Msg.error(this, "Failed to save summary: " + e.getMessage(), e);
        }
    }

    /**
     * Handle edge click in list view.
     */
    public void handleSemanticGraphEdgeClick(String targetId) {
        if (plugin.getCurrentProgram() == null) {
            return;
        }

        try {
            ghidrassist.graphrag.BinaryKnowledgeGraph graph =
                    analysisDB.getKnowledgeGraph(plugin.getCurrentProgram().getExecutableSHA256());
            ghidrassist.graphrag.nodes.KnowledgeNode node = graph.getNode(targetId);

            if (node != null) {
                handleSemanticGraphNavigate(node.getAddress());
            }
        } catch (Exception e) {
            Msg.error(this, "Failed to navigate to edge target: " + e.getMessage(), e);
        }
    }

    /**
     * Handle semantic graph search query.
     * Executes a semantic query tool and returns the result via callback.
     *
     * @param queryType The tool name (e.g., "ga_search_semantic")
     * @param args The query arguments as JsonObject
     * @param resultCallback Callback to receive the JSON result string
     */
    public void handleSemanticGraphSearchQuery(String queryType, com.google.gson.JsonObject args,
                                                java.util.function.Consumer<String> resultCallback) {
        if (plugin.getCurrentProgram() == null) {
            resultCallback.accept("{\"error\": \"No program loaded\"}");
            return;
        }

        Task task = new Task("Semantic Query", true, true, true) {
            @Override
            public void run(TaskMonitor monitor) throws ghidra.util.exception.CancelledException {
                try {
                    monitor.setMessage("Executing " + queryType + "...");

                    // Create query tools instance
                    ghidrassist.graphrag.query.SemanticQueryTools tools =
                            new ghidrassist.graphrag.query.SemanticQueryTools(analysisDB);
                    tools.setCurrentProgram(plugin.getCurrentProgram());

                    // Execute the query
                    ghidrassist.mcp2.tools.MCPToolResult result = tools.executeTool(queryType, args).join();

                    // Return result via callback on EDT
                    final String resultJson;
                    if (!result.isSuccess()) {
                        resultJson = "{\"error\": \"" + escapeJsonString(result.getError()) + "\"}";
                    } else {
                        resultJson = result.getContent();
                    }

                    SwingUtilities.invokeLater(() -> resultCallback.accept(resultJson));

                } catch (Exception e) {
                    Msg.error(this, "Failed to execute semantic query: " + e.getMessage(), e);
                    final String errorJson = "{\"error\": \"" + escapeJsonString(e.getMessage()) + "\"}";
                    SwingUtilities.invokeLater(() -> resultCallback.accept(errorJson));
                }
            }
        };
        TaskLauncher.launch(task);
    }

    /**
     * Escape a string for safe inclusion in JSON.
     */
    private String escapeJsonString(String input) {
        if (input == null) {
            return "";
        }
        return input
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    // ==== SymGraph Operations ====

    /**
     * Handle SymGraph query request.
     */
    public void handleSymGraphQuery() {
        if (symGraphTab == null || symGraphService == null) {
            Msg.showError(this, null, "Error", "SymGraph tab not initialized");
            return;
        }

        String sha256 = getProgramSHA256();
        if (sha256 == null) {
            Msg.showInfo(this, symGraphTab, "No Binary", "No binary loaded or unable to compute hash.");
            return;
        }

        symGraphTab.setQueryStatus("Checking...", false);
        symGraphTab.hideStats();
        symGraphTab.setButtonsEnabled(false);

        Task task = new Task("Query SymGraph", true, true, false) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    QueryResult result = symGraphService.queryBinary(sha256);

                    SwingUtilities.invokeLater(() -> {
                        symGraphTab.setButtonsEnabled(true);
                        if (result.getError() != null) {
                            symGraphTab.setQueryStatus("Error: " + result.getError(), false);
                        } else if (result.isExists()) {
                            symGraphTab.setQueryStatus("Found in SymGraph", true);
                            if (result.getStats() != null) {
                                BinaryStats stats = result.getStats();
                                symGraphTab.setStats(
                                    stats.getSymbolCount(),
                                    stats.getFunctionCount(),
                                    stats.getGraphNodeCount(),
                                    stats.getLastQueriedAt()
                                );
                            }
                        } else {
                            symGraphTab.setQueryStatus("Not found in SymGraph", false);
                            symGraphTab.hideStats();
                        }
                    });
                } catch (Exception e) {
                    Msg.error(this, "Query error: " + e.getMessage(), e);
                    SwingUtilities.invokeLater(() -> {
                        symGraphTab.setButtonsEnabled(true);
                        symGraphTab.setQueryStatus("Error: " + e.getMessage(), false);
                    });
                }
            }
        };
        TaskLauncher.launch(task);
    }

    /**
     * Handle SymGraph push request.
     */
    public void handleSymGraphPush(String scope, boolean pushSymbols, boolean pushGraph) {
        if (symGraphTab == null || symGraphService == null) {
            Msg.showError(this, null, "Error", "SymGraph tab not initialized");
            return;
        }

        String sha256 = getProgramSHA256();
        if (sha256 == null) {
            Msg.showInfo(this, symGraphTab, "No Binary", "No binary loaded or unable to compute hash.");
            return;
        }

        if (!symGraphService.hasApiKey()) {
            Msg.showError(this, symGraphTab, "API Key Required",
                "Push requires a SymGraph API key.\n\nAdd your API key in Settings > General > SymGraph");
            return;
        }

        // Use atomic boolean for cancellation
        final java.util.concurrent.atomic.AtomicBoolean cancelled = new java.util.concurrent.atomic.AtomicBoolean(false);

        // Show progress bar with cancel callback
        symGraphTab.setPushStatus("Preparing...", null);
        symGraphTab.showPushProgress(() -> cancelled.set(true));

        // Create progress callback that updates the UI
        SymGraphService.ProgressCallback progressCallback = new SymGraphService.ProgressCallback() {
            @Override
            public void onProgress(int current, int total, String message) {
                SwingUtilities.invokeLater(() -> {
                    symGraphTab.updatePushProgress(current, total, message);
                });
            }

            @Override
            public boolean isCancelled() {
                return cancelled.get();
            }
        };

        // Run in background thread (no modal dialog)
        Thread pushThread = new Thread(() -> {
            try {
                List<Map<String, Object>> symbols = new ArrayList<>();
                Map<String, Object> graphData = null;

                if (pushSymbols) {
                    SwingUtilities.invokeLater(() -> symGraphTab.updatePushProgress(0, 100, "Collecting symbols..."));
                    symbols = collectLocalSymbols(scope);
                    Msg.info(this, "Collected " + symbols.size() + " symbols to push");
                }

                if (cancelled.get()) {
                    handlePushCancelled();
                    return;
                }

                if (pushGraph) {
                    SwingUtilities.invokeLater(() -> symGraphTab.updatePushProgress(0, 100, "Collecting graph data..."));
                    graphData = collectLocalGraph(scope);
                }

                if (cancelled.get()) {
                    handlePushCancelled();
                    return;
                }

                if (symbols.isEmpty() && graphData == null) {
                    SwingUtilities.invokeLater(() -> {
                        symGraphTab.hidePushProgress();
                        symGraphTab.setButtonsEnabled(true);
                        symGraphTab.setPushStatus("No data to push", false);
                    });
                    return;
                }

                PushResult totalResult = PushResult.success(0, 0, 0);

                // Push symbols in chunks with progress
                if (!symbols.isEmpty()) {
                    PushResult symbolResult = symGraphService.pushSymbolsChunked(sha256, symbols, progressCallback);
                    if (!symbolResult.isSuccess()) {
                        throw new Exception(symbolResult.getError());
                    }
                    totalResult.setSymbolsPushed(symbolResult.getSymbolsPushed());
                }

                if (cancelled.get()) {
                    handlePushCancelled();
                    return;
                }

                // Push graph in chunks with progress
                if (graphData != null) {
                    PushResult graphResult = symGraphService.importGraphChunked(sha256, graphData, progressCallback);
                    if (!graphResult.isSuccess()) {
                        throw new Exception(graphResult.getError());
                    }
                    totalResult.setNodesPushed(graphResult.getNodesPushed());
                    totalResult.setEdgesPushed(graphResult.getEdgesPushed());
                }

                if (cancelled.get()) {
                    handlePushCancelled();
                    return;
                }

                // Add fingerprints for debug symbol matching (BuildID for ELF, etc.)
                SwingUtilities.invokeLater(() -> symGraphTab.updatePushProgress(100, 100, "Adding fingerprints..."));
                addBinaryFingerprints(sha256);

                final PushResult result = totalResult;
                SwingUtilities.invokeLater(() -> {
                    symGraphTab.hidePushProgress();
                    symGraphTab.setButtonsEnabled(true);
                    StringBuilder msg = new StringBuilder("Pushed: ");
                    List<String> parts = new ArrayList<>();
                    if (result.getSymbolsPushed() > 0) parts.add(result.getSymbolsPushed() + " symbols");
                    if (result.getNodesPushed() > 0) parts.add(result.getNodesPushed() + " nodes");
                    if (result.getEdgesPushed() > 0) parts.add(result.getEdgesPushed() + " edges");
                    msg.append(parts.isEmpty() ? "complete" : String.join(", ", parts));
                    symGraphTab.setPushStatus(msg.toString(), true);
                });
            } catch (Exception e) {
                Msg.error(this, "Push error: " + e.getMessage(), e);
                SwingUtilities.invokeLater(() -> {
                    symGraphTab.hidePushProgress();
                    symGraphTab.setButtonsEnabled(true);
                    symGraphTab.setPushStatus("Error: " + e.getMessage(), false);
                });
            }
        }, "SymGraph-Push-Worker");
        pushThread.setDaemon(true);
        pushThread.start();
    }

    private void handlePushCancelled() {
        SwingUtilities.invokeLater(() -> {
            symGraphTab.hidePushProgress();
            symGraphTab.setButtonsEnabled(true);
            symGraphTab.setPushStatus("Cancelled", false);
        });
    }

    /**
     * Handle SymGraph pull preview request.
     */
    public void handleSymGraphPullPreview() {
        if (symGraphTab == null || symGraphService == null) {
            Msg.showError(this, null, "Error", "SymGraph tab not initialized");
            return;
        }

        String sha256 = getProgramSHA256();
        if (sha256 == null) {
            Msg.showInfo(this, symGraphTab, "No Binary", "No binary loaded or unable to compute hash.");
            return;
        }

        if (!symGraphService.hasApiKey()) {
            Msg.showError(this, symGraphTab, "API Key Required",
                "Pull requires a SymGraph API key.\n\nAdd your API key in Settings > General > SymGraph");
            return;
        }

        // Get pull configuration from the tab
        ghidrassist.ui.tabs.SymGraphTab.PullConfig pullConfig = symGraphTab.getPullConfig();
        List<String> symbolTypes = pullConfig.getSymbolTypes();
        double minConfidence = pullConfig.getMinConfidence();
        boolean includeGraph = pullConfig.isIncludeGraph();

        if (symbolTypes.isEmpty()) {
            Msg.showInfo(this, symGraphTab, "No Types Selected", "Select at least one symbol type to pull.");
            return;
        }

        Msg.info(this, "Fetching symbols from SymGraph: " + sha256 + " (types: " + symbolTypes + ")");
        symGraphTab.setPullStatus("Fetching...", null);
        symGraphTab.clearConflicts();
        symGraphTab.setGraphPreviewData(null, 0, 0, 0);
        symGraphTab.setButtonsEnabled(false);

        Task task = new Task("Pull from SymGraph", true, true, false) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    // Fetch symbols for each selected type
                    List<Symbol> allRemoteSymbols = new ArrayList<>();

                    for (String symType : symbolTypes) {
                        if (monitor.isCancelled()) {
                            return;
                        }
                        monitor.setMessage("Fetching " + symType + " symbols...");
                        List<Symbol> remoteSymbols = symGraphService.getSymbols(sha256, symType);
                        allRemoteSymbols.addAll(remoteSymbols);
                        Msg.info(this, "Fetched " + remoteSymbols.size() + " " + symType + " symbols from API");
                    }

                    GraphExport graphExport = null;
                    int graphNodes = 0;
                    int graphEdges = 0;
                    int graphCommunities = 0;

                    if (includeGraph) {
                        monitor.setMessage("Fetching graph data...");
                        graphExport = symGraphService.exportGraph(sha256);
                        if (graphExport != null) {
                            graphNodes = graphExport.getNodes().size();
                            graphEdges = graphExport.getEdges().size();
                            graphCommunities = getGraphCommunityCount(graphExport);
                        }
                    }

                    if (allRemoteSymbols.isEmpty() && graphExport == null) {
                        SwingUtilities.invokeLater(() -> {
                            symGraphTab.setButtonsEnabled(true);
                            symGraphTab.setPullStatus("No symbols found", false);
                        });
                        return;
                    }

                    monitor.setMessage("Building conflict list...");
                    Map<Long, String> localSymbols = getLocalSymbolMap();
                    // Use the overloaded method with minConfidence
                    List<ConflictEntry> conflicts = symGraphService.buildConflictEntries(
                        localSymbols, allRemoteSymbols, minConfidence);

                    final GraphExport finalGraphExport = graphExport;
                    final int finalGraphNodes = graphNodes;
                    final int finalGraphEdges = graphEdges;
                    final int finalGraphCommunities = graphCommunities;

                    SwingUtilities.invokeLater(() -> {
                        symGraphTab.setButtonsEnabled(true);
                        symGraphTab.setGraphPreviewData(finalGraphExport, finalGraphNodes, finalGraphEdges, finalGraphCommunities);
                        symGraphTab.populateConflicts(conflicts);
                        int conflictCount = (int) conflicts.stream()
                            .filter(c -> c.getAction() == ConflictAction.CONFLICT).count();
                        int newCount = (int) conflicts.stream()
                            .filter(c -> c.getAction() == ConflictAction.NEW).count();
                        String status = String.format("Found %d symbols (%d conflicts, %d new)",
                            conflicts.size(), conflictCount, newCount);
                        if (conflicts.isEmpty() && finalGraphExport != null) {
                            status = "No symbols found (graph data available)";
                        } else if (finalGraphExport != null) {
                            status += String.format(" | Graph: %d nodes, %d edges, %d communities",
                                finalGraphNodes, finalGraphEdges, finalGraphCommunities);
                        }
                        symGraphTab.setPullStatus(status, true);
                    });
                } catch (Exception e) {
                    Msg.error(this, "Pull preview error: " + e.getMessage(), e);
                    SwingUtilities.invokeLater(() -> {
                        symGraphTab.setButtonsEnabled(true);
                        symGraphTab.setGraphPreviewData(null, 0, 0, 0);
                        symGraphTab.setPullStatus("Error: " + e.getMessage(), false);
                    });
                }
            }
        };
        TaskLauncher.launch(task);
    }

    /**
     * Handle applying selected symbols from SymGraph.
     */
    private int getGraphCommunityCount(GraphExport export) {
        if (export == null || export.getMetadata() == null) {
            return 0;
        }
        Object countValue = export.getMetadata().get("community_count");
        if (countValue instanceof Number) {
            return ((Number) countValue).intValue();
        }
        Object communitiesValue = export.getMetadata().get("communities");
        if (communitiesValue instanceof List) {
            return ((List<?>) communitiesValue).size();
        }
        return 0;
    }

    private List<String> getListProperty(Map<String, Object> props, String key) {
        if (props == null) {
            return new ArrayList<>();
        }
        Object value = props.get(key);
        if (value instanceof List) {
            List<String> list = new ArrayList<>();
            for (Object item : (List<?>) value) {
                if (item != null) {
                    list.add(item.toString());
                }
            }
            return list;
        }
        return new ArrayList<>();
    }

    private double getDoubleProperty(Map<String, Object> props, String key, double defaultValue) {
        if (props == null) {
            return defaultValue;
        }
        Object value = props.get(key);
        if (value instanceof Number) {
            return ((Number) value).doubleValue();
        }
        return defaultValue;
    }

    private void mergeGraphData(GraphExport export, String programHash, String mergePolicy) {
        if (export == null) {
            return;
        }
        BinaryKnowledgeGraph graph = analysisDB.getKnowledgeGraph(programHash);
        if ("replace".equals(mergePolicy)) {
            graph.clearGraph();
        }

        Map<Long, String> addressToId = new HashMap<>();
        for (GraphNode node : export.getNodes()) {
            NodeType nodeType = NodeType.fromString(node.getNodeType());
            if (nodeType == null) {
                nodeType = NodeType.FUNCTION;
            }

            KnowledgeNode existing = graph.getNodeByAddress(node.getAddress());
            if ("prefer_local".equals(mergePolicy) && existing != null) {
                addressToId.put(node.getAddress(), existing.getId());
                continue;
            }

            KnowledgeNode localNode = node.getId() != null
                    ? new KnowledgeNode(node.getId(), nodeType, programHash)
                    : new KnowledgeNode(nodeType, programHash);
            if (existing != null) {
                localNode.setId(existing.getId());
            }

            localNode.setAddress(node.getAddress());
            localNode.setName(node.getName());

            Map<String, Object> props = node.getProperties();
            String rawContent = props != null ? (String) props.get("raw_content") : null;
            if (rawContent == null && props != null) {
                rawContent = (String) props.get("raw_code");
            }
            String summary = node.getSummary();
            if (summary == null && props != null) {
                summary = (String) props.get("llm_summary");
            }

            localNode.setRawContent(rawContent);
            localNode.setLlmSummary(summary);
            localNode.setConfidence((float) getDoubleProperty(props, "confidence", 0.0));
            localNode.setSecurityFlags(getListProperty(props, "security_flags"));
            localNode.setNetworkAPIs(getListProperty(props, "network_apis"));
            localNode.setFileIOAPIs(getListProperty(props, "file_io_apis"));
            localNode.setIPAddresses(getListProperty(props, "ip_addresses"));
            localNode.setURLs(getListProperty(props, "urls"));
            localNode.setFilePaths(getListProperty(props, "file_paths"));
            localNode.setDomains(getListProperty(props, "domains"));
            localNode.setRegistryKeys(getListProperty(props, "registry_keys"));
            if (props != null) {
                localNode.setRiskLevel((String) props.get("risk_level"));
                localNode.setActivityProfile((String) props.get("activity_profile"));
                Object depth = props.get("analysis_depth");
                if (depth instanceof Number) {
                    localNode.setAnalysisDepth(((Number) depth).intValue());
                }
                Object isStale = props.get("is_stale");
                if (isStale instanceof Boolean) {
                    localNode.setStale((Boolean) isStale);
                }
                Object userEdited = props.get("user_edited");
                if (userEdited instanceof Boolean) {
                    localNode.setUserEdited((Boolean) userEdited);
                }
            }

            graph.upsertNode(localNode);
            addressToId.put(node.getAddress(), localNode.getId());
        }

        Gson gson = new Gson();
        for (GraphEdge edge : export.getEdges()) {
            String sourceId = addressToId.get(edge.getSourceAddress());
            String targetId = addressToId.get(edge.getTargetAddress());
            if (sourceId == null || targetId == null) {
                continue;
            }
            EdgeType edgeType = EdgeType.fromString(edge.getEdgeType());
            if (edgeType == null) {
                edgeType = EdgeType.CALLS;
            }
            Map<String, Object> props = edge.getProperties();
            double weight = getDoubleProperty(props, "weight", 1.0);
            String metadata = props != null ? gson.toJson(props) : null;
            graph.addEdge(sourceId, targetId, edgeType, weight, metadata);
        }
    }

    private boolean applyVariableSymbol(Function func,
            ghidrassist.services.symgraph.SymGraphModels.Symbol remoteSymbol) {
        if (remoteSymbol == null || remoteSymbol.getName() == null) {
            return false;
        }

        Map<String, Object> metadata = remoteSymbol.getMetadata();
        if (metadata == null) {
            return false;
        }

        String storageClass = (String) metadata.get("storage_class");
        String targetName = remoteSymbol.getName();

        try {
            if ("parameter".equals(storageClass)) {
                Object paramIdxObj = metadata.get("parameter_index");
                if (paramIdxObj != null) {
                    int paramIdx = ((Number) paramIdxObj).intValue();
                    ghidra.program.model.listing.Parameter[] params = func.getParameters();
                    if (paramIdx < params.length) {
                        params[paramIdx].setName(targetName,
                            ghidra.program.model.symbol.SourceType.USER_DEFINED);
                        return true;
                    }
                }
            } else if ("stack".equals(storageClass)) {
                Object stackOffsetObj = metadata.get("stack_offset");
                if (stackOffsetObj != null) {
                    int stackOffset = ((Number) stackOffsetObj).intValue();
                    for (ghidra.program.model.listing.Variable var : func.getLocalVariables()) {
                        if (var.isStackVariable()) {
                            try {
                                if (var.getStackOffset() == stackOffset) {
                                    var.setName(targetName,
                                        ghidra.program.model.symbol.SourceType.USER_DEFINED);
                                    return true;
                                }
                            } catch (UnsupportedOperationException e) {
                                // Not a simple stack var
                            }
                        }
                    }
                }
            } else if ("register".equals(storageClass)) {
                String regName = (String) metadata.get("register");
                if (regName != null) {
                    for (ghidra.program.model.listing.Variable var : func.getLocalVariables()) {
                        if (var.isRegisterVariable()) {
                            ghidra.program.model.lang.Register reg = var.getRegister();
                            if (reg != null && regName.equals(reg.getName())) {
                                var.setName(targetName,
                                    ghidra.program.model.symbol.SourceType.USER_DEFINED);
                                return true;
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            Msg.error(this, "Error applying variable: " + e.getMessage());
        }

        return false;
    }

    public void handleSymGraphApplySelected(List<ConflictEntry> selectedConflicts) {
        if (symGraphTab == null || plugin.getCurrentProgram() == null) {
            return;
        }

        GraphExport graphExport = symGraphTab.getGraphPreviewData();
        if (selectedConflicts.isEmpty() && graphExport == null) {
            symGraphTab.setPullStatus("No items selected", false);
            return;
        }

        String programHash = getProgramSHA256();
        if (graphExport != null && programHash == null) {
            symGraphTab.setPullStatus("Unable to resolve program hash", false);
            return;
        }

        Task task = new Task("Apply SymGraph Symbols", true, true, false) {
            @Override
            public void run(TaskMonitor monitor) {
                int appliedCount = 0;
                int transactionId = plugin.getCurrentProgram().startTransaction("Apply SymGraph Symbols");

                try {
                    if (graphExport != null) {
                        mergeGraphData(graphExport, programHash, symGraphTab.getGraphMergePolicy());
                    }

                    for (ConflictEntry conflict : selectedConflicts) {
                        if (conflict.getRemoteSymbol() == null || conflict.getRemoteSymbol().getName() == null) {
                            continue;
                        }

                        try {
                            long addr = conflict.getAddress();
                            Address address = plugin.getCurrentProgram().getAddressFactory()
                                .getDefaultAddressSpace().getAddress(addr);

                            String symbolType = conflict.getRemoteSymbol().getSymbolType();

                            if ("variable".equals(symbolType)) {
                                // Variable - use storage-aware application
                                Function func = plugin.getCurrentProgram().getFunctionManager()
                                    .getFunctionContaining(address);
                                if (func != null && func.getEntryPoint().getOffset() == addr) {
                                    if (applyVariableSymbol(func, conflict.getRemoteSymbol())) {
                                        appliedCount++;
                                    }
                                }
                            } else {
                                // Function or other symbol
                                Function func = plugin.getCurrentProgram().getFunctionManager()
                                    .getFunctionAt(address);

                                if (func != null) {
                                    func.setName(conflict.getRemoteSymbol().getName(),
                                        ghidra.program.model.symbol.SourceType.USER_DEFINED);
                                    appliedCount++;
                                }
                            }
                        } catch (Exception e) {
                            Msg.error(this, "Error applying symbol at 0x" +
                                Long.toHexString(conflict.getAddress()) + ": " + e.getMessage());
                        }
                    }

                    plugin.getCurrentProgram().endTransaction(transactionId, true);

                    final int count = appliedCount;
                    SwingUtilities.invokeLater(() -> {
                        symGraphTab.setPullStatus("Applied " + count + " symbols", true);
                        if (count > 0) {
                            Msg.showInfo(this, symGraphTab, "Success",
                                "Applied " + count + " symbols to binary.");
                        }
                    });
                } catch (Exception e) {
                    plugin.getCurrentProgram().endTransaction(transactionId, false);
                    throw e;
                }
            }
        };
        TaskLauncher.launch(task);
    }

    /**
     * Handle applying all NEW symbols from SymGraph (wizard shortcut).
     */
    public void handleSymGraphApplyAllNew() {
        if (symGraphTab == null || plugin.getCurrentProgram() == null) {
            return;
        }

        List<ConflictEntry> newConflicts = symGraphTab.getAllNewConflicts();
        GraphExport graphExport = symGraphTab.getGraphPreviewData();
        if (newConflicts.isEmpty() && graphExport == null) {
            symGraphTab.setPullStatus("No new symbols to apply", false);
            return;
        }

        String programHash = getProgramSHA256();
        if (graphExport != null && programHash == null) {
            symGraphTab.setPullStatus("Unable to resolve program hash", false);
            return;
        }

        final int total = newConflicts.size();
        String applyingMessage = "Applying " + total + " new symbols...";
        if (total == 0 && graphExport != null) {
            applyingMessage = "Applying graph data...";
        }
        symGraphTab.showApplyingPage(applyingMessage);

        Task task = new Task("Apply New SymGraph Symbols", true, true, false) {
            @Override
            public void run(TaskMonitor monitor) {
                int appliedCount = 0;
                int transactionId = plugin.getCurrentProgram().startTransaction("Apply SymGraph Symbols");

                try {
                    if (graphExport != null) {
                        mergeGraphData(graphExport, programHash, symGraphTab.getGraphMergePolicy());
                    }

                    for (int i = 0; i < newConflicts.size(); i++) {
                        ConflictEntry conflict = newConflicts.get(i);
                        if (conflict.getRemoteSymbol() == null || conflict.getRemoteSymbol().getName() == null) {
                            continue;
                        }

                        // Update progress on EDT
                        final int current = i + 1;
                        final String progressMsg = "Applying symbol " + current + " of " + total;
                        SwingUtilities.invokeLater(() -> {
                            symGraphTab.updateApplyProgress(current, total, progressMsg);
                        });

                        try {
                            long addrVal = conflict.getAddress();
                            Address address = plugin.getCurrentProgram().getAddressFactory()
                                .getDefaultAddressSpace().getAddress(addrVal);

                            String symbolType = conflict.getRemoteSymbol().getSymbolType();

                            if ("variable".equals(symbolType)) {
                                // Variable - use storage-aware application
                                Function func = plugin.getCurrentProgram().getFunctionManager()
                                    .getFunctionContaining(address);
                                if (func != null && func.getEntryPoint().getOffset() == addrVal) {
                                    if (applyVariableSymbol(func, conflict.getRemoteSymbol())) {
                                        appliedCount++;
                                    }
                                }
                            } else {
                                // Function or other symbol
                                Function func = plugin.getCurrentProgram().getFunctionManager()
                                    .getFunctionAt(address);

                                if (func != null) {
                                    func.setName(conflict.getRemoteSymbol().getName(),
                                        ghidra.program.model.symbol.SourceType.USER_DEFINED);
                                    appliedCount++;
                                }
                            }
                        } catch (Exception e) {
                            Msg.error(this, "Error applying symbol at 0x" +
                                Long.toHexString(conflict.getAddress()) + ": " + e.getMessage());
                        }

                        // Check for cancellation
                        if (monitor.isCancelled()) {
                            break;
                        }
                    }

                    plugin.getCurrentProgram().endTransaction(transactionId, true);

                    final int count = appliedCount;
                    final boolean cancelled = monitor.isCancelled();
                    SwingUtilities.invokeLater(() -> {
                        if (cancelled) {
                            symGraphTab.showCompletePage("Cancelled after applying " + count + " symbols", false);
                        } else {
                            symGraphTab.showCompletePage("Applied " + count + " new symbols", true);
                        }
                    });
                } catch (Exception e) {
                    plugin.getCurrentProgram().endTransaction(transactionId, false);
                    SwingUtilities.invokeLater(() -> {
                        symGraphTab.showCompletePage("Error: " + e.getMessage(), false);
                    });
                }
            }
        };
        TaskLauncher.launch(task);
    }

    // SymGraph helper methods

    private String getProgramSHA256() {
        try {
            if (plugin.getCurrentProgram() != null) {
                return plugin.getCurrentProgram().getExecutableSHA256();
            }
        } catch (Exception e) {
            Msg.error(this, "Error getting SHA256: " + e.getMessage());
        }
        return null;
    }

    /**
     * Add fingerprints to the binary for debug symbol matching.
     * Extracts BuildID (for ELF) or other identifiers and adds them as fingerprints.
     */
    private void addBinaryFingerprints(String sha256) {
        if (plugin.getCurrentProgram() == null || symGraphService == null) {
            return;
        }

        Program program = plugin.getCurrentProgram();

        try {
            // Check executable format
            String format = program.getExecutableFormat();

            if ("Executable and Linking Format (ELF)".equals(format) ||
                (format != null && format.contains("ELF"))) {
                // Extract BuildID from ELF
                String buildId = extractElfBuildId(program);
                if (buildId != null && !buildId.isEmpty()) {
                    Msg.info(this, "Extracted ELF BuildID: " + buildId);
                    try {
                        symGraphService.addFingerprint(sha256, "build_id", buildId);
                    } catch (Exception e) {
                        Msg.warn(this, "Failed to add BuildID fingerprint: " + e.getMessage());
                    }
                }
            }
            // PE/PDB GUID extraction would go here if needed
            // Currently Ghidra doesn't expose PDB GUID directly via simple API

        } catch (Exception e) {
            Msg.warn(this, "Error extracting fingerprints: " + e.getMessage());
        }
    }

    /**
     * Extract GNU BuildID from an ELF binary.
     */
    private String extractElfBuildId(Program program) {
        try {
            // Look for .note.gnu.build-id section
            ghidra.program.model.mem.MemoryBlock buildIdBlock = null;
            for (ghidra.program.model.mem.MemoryBlock block : program.getMemory().getBlocks()) {
                if (".note.gnu.build-id".equals(block.getName())) {
                    buildIdBlock = block;
                    break;
                }
            }

            if (buildIdBlock == null) {
                // Try alternative names
                for (ghidra.program.model.mem.MemoryBlock block : program.getMemory().getBlocks()) {
                    String name = block.getName();
                    if (name != null && name.contains("build") && name.contains("id")) {
                        buildIdBlock = block;
                        break;
                    }
                }
            }

            if (buildIdBlock != null) {
                // Read the note section
                int size = (int) buildIdBlock.getSize();
                if (size > 256) size = 256; // Sanity limit

                byte[] data = new byte[size];
                buildIdBlock.getBytes(buildIdBlock.getStart(), data);

                if (data.length >= 16) {
                    // GNU note format: namesz (4), descsz (4), type (4), name, desc
                    int namesz = readLittleEndianInt(data, 0);
                    int descsz = readLittleEndianInt(data, 4);
                    int noteType = readLittleEndianInt(data, 8);

                    if (noteType == 3) { // NT_GNU_BUILD_ID
                        // Name is padded to 4-byte boundary
                        int nameEnd = 12 + ((namesz + 3) & ~3);
                        if (data.length >= nameEnd + descsz) {
                            StringBuilder sb = new StringBuilder();
                            for (int i = nameEnd; i < nameEnd + descsz; i++) {
                                sb.append(String.format("%02x", data[i] & 0xff));
                            }
                            return sb.toString();
                        }
                    }
                }
            }
        } catch (Exception e) {
            Msg.debug(this, "Error extracting ELF BuildID: " + e.getMessage());
        }
        return null;
    }

    private int readLittleEndianInt(byte[] data, int offset) {
        return (data[offset] & 0xff) |
               ((data[offset + 1] & 0xff) << 8) |
               ((data[offset + 2] & 0xff) << 16) |
               ((data[offset + 3] & 0xff) << 24);
    }

    private List<Map<String, Object>> collectLocalSymbols(String scope) {
        List<Map<String, Object>> symbols = new ArrayList<>();

        if (plugin.getCurrentProgram() == null) {
            return symbols;
        }

        Program program = plugin.getCurrentProgram();

        try {
            if ("function".equals(scope)) {
                Function currentFunc = plugin.getCurrentFunction();
                if (currentFunc != null) {
                    symbols.add(functionToSymbolMap(currentFunc));
                    // Collect function comments and local variables
                    symbols.addAll(collectFunctionComments(currentFunc));
                    symbols.addAll(collectFunctionVariables(currentFunc));
                }
            } else {
                // Full binary - all symbol types

                // 1. Functions
                for (Function func : program.getFunctionManager().getFunctions(true)) {
                    symbols.add(functionToSymbolMap(func));
                }

                // 2. Data (global variables)
                symbols.addAll(collectDataSymbols(program));

                // 3. Types and enums
                symbols.addAll(collectTypesAndEnums(program));

                // 4. Comments
                symbols.addAll(collectAllComments(program));
            }
        } catch (Exception e) {
            Msg.error(this, "Error collecting symbols: " + e.getMessage());
        }

        return symbols;
    }

    private Map<String, Object> functionToSymbolMap(Function func) {
        Map<String, Object> map = new java.util.HashMap<>();
        map.put("address", String.format("0x%x", func.getEntryPoint().getOffset()));
        map.put("symbol_type", "function");
        map.put("name", func.getName());
        // Include function signature as data_type
        if (func.getSignature() != null) {
            map.put("data_type", func.getSignature().getPrototypeString());
        }
        // Use unified default name detection for cross-tool compatibility
        boolean isAuto = ghidrassist.services.symgraph.SymGraphUtils.isDefaultName(func.getName());
        map.put("confidence", isAuto ? 0.5 : 0.9);
        map.put("provenance", isAuto ? "decompiler" : "user");
        return map;
    }

    private List<Map<String, Object>> collectDataSymbols(Program program) {
        List<Map<String, Object>> symbols = new ArrayList<>();
        try {
            ghidra.program.model.listing.Listing listing = program.getListing();
            ghidra.program.model.listing.DataIterator dataIter = listing.getDefinedData(true);

            while (dataIter.hasNext()) {
                ghidra.program.model.listing.Data data = dataIter.next();
                if (data != null) {
                    ghidra.program.model.address.Address addr = data.getAddress();
                    ghidra.program.model.symbol.Symbol sym = program.getSymbolTable().getPrimarySymbol(addr);
                    String name = (sym != null) ? sym.getName() : null;

                    // Skip variables without names
                    if (name == null || name.isEmpty()) {
                        continue;
                    }

                    // Use unified default name detection for cross-tool compatibility
                    boolean isAutoNamed = ghidrassist.services.symgraph.SymGraphUtils.isDefaultName(name);

                    Map<String, Object> map = new java.util.HashMap<>();
                    map.put("address", String.format("0x%x", addr.getOffset()));
                    map.put("symbol_type", "variable");
                    map.put("name", name);
                    if (data.getDataType() != null) {
                        map.put("data_type", data.getDataType().getName());
                    }
                    map.put("confidence", isAutoNamed ? 0.3 : 0.85);
                    map.put("provenance", isAutoNamed ? "decompiler" : "user");
                    symbols.add(map);
                }
            }
        } catch (Exception e) {
            Msg.error(this, "Error collecting data symbols: " + e.getMessage());
        }
        return symbols;
    }

    private List<Map<String, Object>> collectFunctionVariables(Function func) {
        List<Map<String, Object>> symbols = new ArrayList<>();
        try {
            // Parameters - use ordinal for index
            ghidra.program.model.listing.Parameter[] params = func.getParameters();
            for (int i = 0; i < params.length; i++) {
                ghidra.program.model.listing.Parameter param = params[i];
                if (param.getName() != null) {
                    // Use unified default name detection for cross-tool compatibility
                    boolean isAuto = ghidrassist.services.symgraph.SymGraphUtils.isDefaultName(param.getName());
                    Map<String, Object> map = new java.util.HashMap<>();
                    map.put("address", String.format("0x%x", func.getEntryPoint().getOffset()));
                    map.put("symbol_type", "variable");
                    map.put("name", param.getName());
                    if (param.getDataType() != null) {
                        map.put("data_type", param.getDataType().getName());
                    }
                    map.put("confidence", isAuto ? 0.3 : 0.8);
                    map.put("provenance", isAuto ? "decompiler" : "user");

                    Map<String, Object> metadata = new java.util.HashMap<>();
                    metadata.put("scope", "parameter");
                    metadata.put("function", func.getName());
                    metadata.put("storage_class", "parameter");
                    metadata.put("parameter_index", param.getOrdinal());

                    // Also capture actual storage location
                    try {
                        if (param.isRegisterVariable()) {
                            ghidra.program.model.lang.Register reg = param.getRegister();
                            if (reg != null) {
                                metadata.put("register", reg.getName());
                            }
                        } else if (param.isStackVariable()) {
                            metadata.put("stack_offset", param.getStackOffset());
                        }
                    } catch (Exception e) {
                        // Storage info optional
                    }

                    map.put("metadata", metadata);
                    symbols.add(map);
                }
            }

            // Local variables
            for (ghidra.program.model.listing.Variable var : func.getLocalVariables()) {
                if (var.getName() != null) {
                    // Use unified default name detection for cross-tool compatibility
                    boolean isAuto = ghidrassist.services.symgraph.SymGraphUtils.isDefaultName(var.getName());
                    Map<String, Object> map = new java.util.HashMap<>();
                    map.put("address", String.format("0x%x", func.getEntryPoint().getOffset()));
                    map.put("symbol_type", "variable");
                    map.put("name", var.getName());
                    if (var.getDataType() != null) {
                        map.put("data_type", var.getDataType().getName());
                    }
                    map.put("confidence", isAuto ? 0.3 : 0.75);
                    map.put("provenance", isAuto ? "decompiler" : "user");

                    Map<String, Object> metadata = new java.util.HashMap<>();
                    metadata.put("scope", "local");
                    metadata.put("function", func.getName());

                    try {
                        if (var.isStackVariable()) {
                            metadata.put("storage_class", "stack");
                            metadata.put("stack_offset", var.getStackOffset());
                        } else if (var.isRegisterVariable()) {
                            metadata.put("storage_class", "register");
                            ghidra.program.model.lang.Register reg = var.getRegister();
                            if (reg != null) {
                                metadata.put("register", reg.getName());
                            }
                        } else {
                            metadata.put("storage_class", "compound");
                            metadata.put("storage_string", var.getVariableStorage().toString());
                        }
                    } catch (UnsupportedOperationException e) {
                        metadata.put("storage_class", "compound");
                        metadata.put("storage_string", var.getVariableStorage().toString());
                    }

                    map.put("metadata", metadata);
                    symbols.add(map);
                }
            }
        } catch (Exception e) {
            Msg.error(this, "Error collecting function variables: " + e.getMessage());
        }
        return symbols;
    }

    private List<Map<String, Object>> collectTypesAndEnums(Program program) {
        List<Map<String, Object>> symbols = new ArrayList<>();
        try {
            ghidra.program.model.data.DataTypeManager dtm = program.getDataTypeManager();

            // Iterate through all user-defined types
            java.util.Iterator<ghidra.program.model.data.DataType> iter = dtm.getAllDataTypes();
            while (iter.hasNext()) {
                ghidra.program.model.data.DataType dt = iter.next();
                // Skip built-in types (only collect user-defined)
                // Built-in types have no source archive or are from the BuiltIn category
                ghidra.program.model.data.SourceArchive srcArchive = dt.getSourceArchive();
                if (srcArchive == null) {
                    continue;
                }
                // Skip types from built-in archives (check by archive type)
                if (srcArchive.getArchiveType() == ghidra.program.model.data.ArchiveType.BUILT_IN) {
                    continue;
                }

                Map<String, Object> map = new java.util.HashMap<>();
                map.put("address", "0x0"); // Types don't have addresses
                map.put("name", dt.getName());
                map.put("data_type", dt.getDisplayName());
                map.put("confidence", 0.9);
                map.put("provenance", "user");

                if (dt instanceof ghidra.program.model.data.Enum) {
                    ghidra.program.model.data.Enum enumType = (ghidra.program.model.data.Enum) dt;
                    map.put("symbol_type", "enum");
                    // Collect enum members
                    Map<String, Object> metadata = new java.util.HashMap<>();
                    Map<String, Long> members = new java.util.HashMap<>();
                    StringBuilder contentBuilder = new StringBuilder();
                    contentBuilder.append("enum ").append(dt.getName()).append(" {\n");
                    for (String name : enumType.getNames()) {
                        long value = enumType.getValue(name);
                        members.put(name, value);
                        contentBuilder.append(String.format("    %s = 0x%x,\n", name, value));
                    }
                    contentBuilder.append("}");
                    metadata.put("members", members);
                    map.put("metadata", metadata);
                    map.put("content", contentBuilder.toString());
                    map.put("data_type", contentBuilder.toString());
                } else if (dt instanceof ghidra.program.model.data.Structure) {
                    ghidra.program.model.data.Structure struct = (ghidra.program.model.data.Structure) dt;
                    map.put("symbol_type", "struct");
                    // Collect struct fields
                    List<Map<String, Object>> fields = new ArrayList<>();
                    StringBuilder contentBuilder = new StringBuilder();
                    contentBuilder.append("struct ").append(dt.getName()).append(" {\n");
                    for (ghidra.program.model.data.DataTypeComponent comp : struct.getComponents()) {
                        Map<String, Object> field = new java.util.HashMap<>();
                        String fieldName = comp.getFieldName();
                        String fieldType = comp.getDataType().getName();
                        int offset = comp.getOffset();
                        field.put("name", fieldName);
                        field.put("type", fieldType);
                        field.put("offset", offset);
                        fields.add(field);
                        contentBuilder.append(String.format("    /* 0x%02x */ %s %s;\n",
                            offset, fieldType, fieldName != null ? fieldName : "field_" + offset));
                    }
                    contentBuilder.append("}");
                    Map<String, Object> metadata = new java.util.HashMap<>();
                    metadata.put("fields", fields);
                    map.put("metadata", metadata);
                    map.put("content", contentBuilder.toString());
                    map.put("data_type", contentBuilder.toString());
                } else {
                    map.put("symbol_type", "type");
                }

                symbols.add(map);
            }
        } catch (Exception e) {
            Msg.error(this, "Error collecting types and enums: " + e.getMessage());
        }
        return symbols;
    }

    private List<Map<String, Object>> collectAllComments(Program program) {
        List<Map<String, Object>> symbols = new ArrayList<>();
        try {
            // Collect function-level and address comments
            for (Function func : program.getFunctionManager().getFunctions(true)) {
                symbols.addAll(collectFunctionComments(func));
            }
        } catch (Exception e) {
            Msg.error(this, "Error collecting comments: " + e.getMessage());
        }
        return symbols;
    }

    private List<Map<String, Object>> collectFunctionComments(Function func) {
        List<Map<String, Object>> symbols = new ArrayList<>();
        Program program = func.getProgram();

        try {
            // Function comment (plate comment)
            String funcComment = func.getComment();
            if (funcComment != null && !funcComment.isEmpty()) {
                Map<String, Object> map = new java.util.HashMap<>();
                map.put("address", String.format("0x%x", func.getEntryPoint().getOffset()));
                map.put("symbol_type", "comment");
                map.put("content", funcComment);
                map.put("confidence", 1.0);
                map.put("provenance", "user");
                Map<String, Object> metadata = new java.util.HashMap<>();
                metadata.put("type", "function");
                map.put("metadata", metadata);
                symbols.add(map);
            }

            // EOL and PRE comments within the function
            ghidra.program.model.listing.Listing listing = program.getListing();
            ghidra.program.model.address.AddressSetView body = func.getBody();

            for (ghidra.program.model.address.Address addr : body.getAddresses(true)) {
                ghidra.program.model.listing.CodeUnit codeUnit = listing.getCodeUnitAt(addr);
                if (codeUnit == null) continue;

                String eolComment = codeUnit.getComment(ghidra.program.model.listing.CommentType.EOL);
                if (eolComment != null && !eolComment.isEmpty()) {
                    Map<String, Object> map = new java.util.HashMap<>();
                    map.put("address", String.format("0x%x", addr.getOffset()));
                    map.put("symbol_type", "comment");
                    map.put("content", eolComment);
                    map.put("confidence", 1.0);
                    map.put("provenance", "user");
                    Map<String, Object> metadata = new java.util.HashMap<>();
                    metadata.put("type", "eol");
                    metadata.put("function", func.getName());
                    map.put("metadata", metadata);
                    symbols.add(map);
                }

                String preComment = codeUnit.getComment(ghidra.program.model.listing.CommentType.PRE);
                if (preComment != null && !preComment.isEmpty()) {
                    Map<String, Object> map = new java.util.HashMap<>();
                    map.put("address", String.format("0x%x", addr.getOffset()));
                    map.put("symbol_type", "comment");
                    map.put("content", preComment);
                    map.put("confidence", 1.0);
                    map.put("provenance", "user");
                    Map<String, Object> metadata = new java.util.HashMap<>();
                    metadata.put("type", "pre");
                    metadata.put("function", func.getName());
                    map.put("metadata", metadata);
                    symbols.add(map);
                }
            }
        } catch (Exception e) {
            Msg.error(this, "Error collecting function comments: " + e.getMessage());
        }
        return symbols;
    }

    private Map<String, Object> collectLocalGraph(String scope) {
        if (plugin.getCurrentProgram() == null || analysisDB == null) {
            return null;
        }

        List<Map<String, Object>> nodes = new ArrayList<>();
        List<Map<String, Object>> edges = new ArrayList<>();

        try {
            String programHash = plugin.getCurrentProgram().getExecutableSHA256();
            ghidrassist.graphrag.BinaryKnowledgeGraph graph = analysisDB.getKnowledgeGraph(programHash);

            if (graph == null || graph.getNodeCount() == 0) {
                Msg.warn(this, "No graph data found. Please index the binary first using the Semantic Graph tab.");
                return null;
            }

            // Step 1: Collect all node IDs to export
            java.util.Set<String> nodeIdsToExport = new java.util.HashSet<>();

            if ("function".equals(scope)) {
                // Just the current function and its immediate neighbors
                Function currentFunc = plugin.getCurrentFunction();
                if (currentFunc != null) {
                    ghidrassist.graphrag.nodes.KnowledgeNode funcNode =
                        graph.getNodeByAddress(currentFunc.getEntryPoint().getOffset());
                    if (funcNode != null) {
                        nodeIdsToExport.add(funcNode.getId());
                        // Add 1-hop neighbors (uses batch loading internally)
                        for (ghidrassist.graphrag.nodes.KnowledgeNode neighbor : graph.getNeighborsBatch(funcNode.getId(), 1)) {
                            nodeIdsToExport.add(neighbor.getId());
                        }
                    }
                }
            } else {
                // Full binary - export all nodes
                for (ghidrassist.graphrag.nodes.NodeType nodeType : ghidrassist.graphrag.nodes.NodeType.values()) {
                    for (ghidrassist.graphrag.nodes.KnowledgeNode node : graph.getNodesByType(nodeType)) {
                        nodeIdsToExport.add(node.getId());
                    }
                }
            }

            // Step 2: BATCH fetch all nodes in ONE query (instead of N queries)
            java.util.Map<String, ghidrassist.graphrag.nodes.KnowledgeNode> nodeCache = graph.getNodes(nodeIdsToExport);

            // Step 3: BATCH fetch all edges in ONE query (instead of N queries)
            java.util.List<ghidrassist.graphrag.BinaryKnowledgeGraph.GraphEdge> allEdges = graph.getEdgesForNodes(nodeIdsToExport);

            // Step 4: Process nodes from cache (no DB queries needed)
            for (ghidrassist.graphrag.nodes.KnowledgeNode node : nodeCache.values()) {
                nodes.add(nodeToExportMap(node));
            }

            // Step 5: Process edges using cache (no DB queries needed)
            for (ghidrassist.graphrag.BinaryKnowledgeGraph.GraphEdge edge : allEdges) {
                // Only include edges where both endpoints are in our export set
                if (nodeIdsToExport.contains(edge.getTargetId())) {
                    // Look up nodes from cache (no DB query)
                    ghidrassist.graphrag.nodes.KnowledgeNode sourceNode = nodeCache.get(edge.getSourceId());
                    ghidrassist.graphrag.nodes.KnowledgeNode targetNode = nodeCache.get(edge.getTargetId());

                    if (sourceNode != null && targetNode != null) {
                        Map<String, Object> edgeMap = new java.util.HashMap<>();
                        edgeMap.put("source_address", sourceNode.getAddress() != null ?
                            String.format("0x%x", sourceNode.getAddress()) : "0x0");
                        edgeMap.put("target_address", targetNode.getAddress() != null ?
                            String.format("0x%x", targetNode.getAddress()) : "0x0");
                        edgeMap.put("edge_type", edge.getType().name().toLowerCase());
                        edgeMap.put("weight", edge.getWeight());
                        edges.add(edgeMap);
                    }
                }
            }

            Msg.info(this, String.format("Collected %d nodes and %d edges for export", nodes.size(), edges.size()));

        } catch (Exception e) {
            Msg.error(this, "Error collecting graph: " + e.getMessage(), e);
        }

        if (nodes.isEmpty()) {
            return null;
        }

        Map<String, Object> graphData = new java.util.HashMap<>();
        graphData.put("nodes", nodes);
        graphData.put("edges", edges);
        return graphData;
    }

    /**
     * Convert a KnowledgeNode to a Map for export.
     * Helper method to reduce code duplication.
     */
    private Map<String, Object> nodeToExportMap(ghidrassist.graphrag.nodes.KnowledgeNode node) {
        Map<String, Object> nodeMap = new java.util.HashMap<>();
        nodeMap.put("address", node.getAddress() != null ?
            String.format("0x%x", node.getAddress()) : "0x0");
        nodeMap.put("node_type", node.getType().name().toLowerCase());
        nodeMap.put("name", node.getName());
        nodeMap.put("raw_content", node.getRawContent());
        nodeMap.put("llm_summary", node.getLlmSummary());
        nodeMap.put("confidence", node.getConfidence());
        nodeMap.put("provenance", "user");

        // Add security-related fields if present
        if (node.getSecurityFlags() != null && !node.getSecurityFlags().isEmpty()) {
            nodeMap.put("security_flags", new ArrayList<>(node.getSecurityFlags()));
        }
        if (node.getNetworkAPIs() != null && !node.getNetworkAPIs().isEmpty()) {
            nodeMap.put("network_apis", new ArrayList<>(node.getNetworkAPIs()));
        }
        if (node.getFileIOAPIs() != null && !node.getFileIOAPIs().isEmpty()) {
            nodeMap.put("file_io_apis", new ArrayList<>(node.getFileIOAPIs()));
        }
        if (node.getIPAddresses() != null && !node.getIPAddresses().isEmpty()) {
            nodeMap.put("ip_addresses", new ArrayList<>(node.getIPAddresses()));
        }
        if (node.getURLs() != null && !node.getURLs().isEmpty()) {
            nodeMap.put("urls", new ArrayList<>(node.getURLs()));
        }
        if (node.getFilePaths() != null && !node.getFilePaths().isEmpty()) {
            nodeMap.put("file_paths", new ArrayList<>(node.getFilePaths()));
        }
        if (node.getDomains() != null && !node.getDomains().isEmpty()) {
            nodeMap.put("domains", new ArrayList<>(node.getDomains()));
        }
        if (node.getRegistryKeys() != null && !node.getRegistryKeys().isEmpty()) {
            nodeMap.put("registry_keys", new ArrayList<>(node.getRegistryKeys()));
        }

        return nodeMap;
    }

    private Map<Long, String> getLocalSymbolMap() {
        Map<Long, String> symbolMap = new java.util.HashMap<>();

        if (plugin.getCurrentProgram() == null) {
            return symbolMap;
        }

        try {
            for (Function func : plugin.getCurrentProgram().getFunctionManager().getFunctions(true)) {
                if (func.getName() != null && !func.getName().startsWith("FUN_")) {
                    symbolMap.put(func.getEntryPoint().getOffset(), func.getName());
                }
            }
        } catch (Exception e) {
            Msg.error(this, "Error getting local symbols: " + e.getMessage());
        }

        return symbolMap;
    }

    /**
     * Update SymGraph tab binary info when program changes.
     */
    public void updateSymGraphBinaryInfo() {
        if (symGraphTab == null) {
            return;
        }

        if (plugin.getCurrentProgram() != null) {
            String name = plugin.getCurrentProgram().getName();
            String sha256 = getProgramSHA256();
            symGraphTab.setBinaryInfo(name, sha256);
        } else {
            symGraphTab.setBinaryInfo(null, null);
        }
    }




    // ==== Cleanup ====


    public void dispose() {
        codeAnalysisService.close();
        analysisDataService.close();
        feedbackService.close();

        // Shutdown safety scheduler
        if (safetyScheduler != null) {
            safetyScheduler.shutdown();
        }
    }
}
