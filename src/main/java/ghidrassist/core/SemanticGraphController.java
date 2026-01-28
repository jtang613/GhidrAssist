package ghidrassist.core;

import ghidra.app.services.GoToService;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import ghidrassist.AnalysisDB;
import ghidrassist.GhidrAssistPlugin;
import ghidrassist.graphrag.BinaryKnowledgeGraph;
import ghidrassist.graphrag.nodes.EdgeType;
import ghidrassist.graphrag.nodes.KnowledgeNode;
import ghidrassist.ui.tabs.SemanticGraphTab;
import ghidrassist.ui.tabs.semanticgraph.GraphViewPanel;
import ghidrassist.ui.tabs.semanticgraph.ListViewPanel;
import ghidrassist.workers.*;

import javax.swing.*;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Controller for Semantic Graph operations.
 * Handles indexing, analysis, navigation, and visualization of the knowledge graph.
 *
 * Extracted from TabController as part of decomposition refactoring.
 */
public class SemanticGraphController {

    private final GhidrAssistPlugin plugin;
    private final AnalysisDB analysisDB;
    private SemanticGraphTab semanticGraphTab;

    // Background workers for non-blocking analysis
    private volatile ReindexWorker reindexWorker;
    private volatile SemanticAnalysisWorker semanticAnalysisWorker;
    private volatile SecurityAnalysisWorker securityAnalysisWorker;
    private volatile RefreshNamesWorker refreshNamesWorker;
    private volatile NetworkFlowAnalysisWorker networkFlowWorker;
    private volatile CommunityDetectionWorker communityDetectionWorker;

    public SemanticGraphController(GhidrAssistPlugin plugin, AnalysisDB analysisDB) {
        this.plugin = plugin;
        this.analysisDB = analysisDB;
    }

    // ==== Tab Registration ====

    public void setSemanticGraphTab(SemanticGraphTab tab) {
        this.semanticGraphTab = tab;
    }

    // ==== Navigation Operations ====

    /**
     * Handle navigation to a function/address in the semantic graph tab.
     */
    public void handleGo(String text) {
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
    public void handleNavigate(long address) {
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

    // ==== Graph Management Operations ====

    /**
     * Handle reset graph button.
     */
    public void handleReset() {
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
    public void handleReindex() {
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
    public void handleRefreshNames() {
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

    // ==== Analysis Operations ====

    /**
     * Handle community detection - group related functions.
     */
    public void handleCommunityDetection() {
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

    /**
     * Handle semantic analysis button - LLM summarization of stale nodes.
     * Uses SwingWorker for non-blocking operation.
     */
    public void handleSemanticAnalysis() {
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
    public void handleSecurityAnalysis() {
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
    public void handleNetworkFlowAnalysis() {
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

    // ==== Analysis Chain Helpers (for ReIndex pipeline) ====

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

    // ==== Single Function Operations ====

    /**
     * Handle index single function button.
     */
    public void handleIndexFunction(long address) {
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
                    BinaryKnowledgeGraph graph =
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

    // ==== View Refresh Operations ====

    /**
     * Handle list view refresh.
     */
    public void handleListViewRefresh(ListViewPanel listView, long address) {
        if (plugin.getCurrentProgram() == null) {
            listView.showNotIndexed();
            return;
        }

        SwingUtilities.invokeLater(() -> {
            try {
                BinaryKnowledgeGraph graph =
                        analysisDB.getKnowledgeGraph(plugin.getCurrentProgram().getExecutableSHA256());

                KnowledgeNode node = graph.getNodeByAddress(address);

                if (node == null) {
                    listView.showNotIndexed();
                    semanticGraphTab.updateStatus(false, 0, 0, 0);
                    return;
                }

                listView.showContent();

                // Get callers and callees
                List<KnowledgeNode> callers = graph.getCallers(node.getId());
                List<KnowledgeNode> callees = graph.getCallees(node.getId());
                List<BinaryKnowledgeGraph.GraphEdge> outgoing = graph.getOutgoingEdges(node.getId());
                List<BinaryKnowledgeGraph.GraphEdge> incoming = graph.getIncomingEdges(node.getId());

                // Combine all edges
                List<BinaryKnowledgeGraph.GraphEdge> allEdges = new ArrayList<>();
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
    public void handleVisualRefresh(GraphViewPanel graphView, long address, int nHops, Set<EdgeType> edgeTypes) {
        if (plugin.getCurrentProgram() == null) {
            graphView.showNotIndexed();
            return;
        }

        SwingUtilities.invokeLater(() -> {
            try {
                BinaryKnowledgeGraph graph =
                        analysisDB.getKnowledgeGraph(plugin.getCurrentProgram().getExecutableSHA256());

                KnowledgeNode centerNode = graph.getNodeByAddress(address);

                if (centerNode == null) {
                    graphView.showNotIndexed();
                    return;
                }

                graphView.showContent();

                // Get N-hop neighborhood
                List<KnowledgeNode> neighbors = graph.getNeighborsBatch(centerNode.getId(), nHops);

                // Include center node in the list
                List<KnowledgeNode> allNodes = new ArrayList<>();
                allNodes.add(centerNode);
                allNodes.addAll(neighbors);

                // Find and add direct callers of the center node
                Set<String> existingNodeIds = new HashSet<>();
                for (KnowledgeNode node : allNodes) {
                    existingNodeIds.add(node.getId());
                }

                // Track caller nodes separately
                Set<String> callerNodeIds = new HashSet<>();
                List<BinaryKnowledgeGraph.GraphEdge> callerEdges = new ArrayList<>();

                for (BinaryKnowledgeGraph.GraphEdge edge : graph.getIncomingEdges(centerNode.getId())) {
                    if (edge.getType() == EdgeType.CALLS &&
                        !existingNodeIds.contains(edge.getSourceId())) {
                        KnowledgeNode callerNode = graph.getNode(edge.getSourceId());
                        if (callerNode != null) {
                            allNodes.add(callerNode);
                            existingNodeIds.add(callerNode.getId());
                            callerNodeIds.add(callerNode.getId());
                            callerEdges.add(edge);
                        }
                    }
                }

                // Collect all edges between non-caller nodes
                Set<String> nodeIds = new HashSet<>();
                for (KnowledgeNode node : allNodes) {
                    nodeIds.add(node.getId());
                }

                List<BinaryKnowledgeGraph.GraphEdge> allEdges = new ArrayList<>();

                // Add the caller→root edges first
                allEdges.addAll(callerEdges);

                // For non-caller nodes, collect their edges normally
                for (KnowledgeNode node : allNodes) {
                    // Skip caller nodes
                    if (callerNodeIds.contains(node.getId())) {
                        continue;
                    }
                    // Include outgoing edges
                    for (BinaryKnowledgeGraph.GraphEdge edge : graph.getOutgoingEdges(node.getId())) {
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

    // ==== Node Editing Operations ====

    /**
     * Handle adding a security flag.
     */
    public void handleAddFlag(long address, String flag) {
        if (plugin.getCurrentProgram() == null) {
            return;
        }

        try {
            BinaryKnowledgeGraph graph =
                    analysisDB.getKnowledgeGraph(plugin.getCurrentProgram().getExecutableSHA256());
            KnowledgeNode node = graph.getNodeByAddress(address);

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
    public void handleRemoveFlag(long address, String flag) {
        if (plugin.getCurrentProgram() == null) {
            return;
        }

        try {
            BinaryKnowledgeGraph graph =
                    analysisDB.getKnowledgeGraph(plugin.getCurrentProgram().getExecutableSHA256());
            KnowledgeNode node = graph.getNodeByAddress(address);

            if (node != null) {
                List<String> flags = new ArrayList<>(node.getSecurityFlags());
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
    public void handleSaveSummary(long address, String summary) {
        if (plugin.getCurrentProgram() == null) {
            return;
        }

        try {
            BinaryKnowledgeGraph graph =
                    analysisDB.getKnowledgeGraph(plugin.getCurrentProgram().getExecutableSHA256());
            KnowledgeNode node = graph.getNodeByAddress(address);

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
    public void handleEdgeClick(String targetId) {
        if (plugin.getCurrentProgram() == null) {
            return;
        }

        try {
            BinaryKnowledgeGraph graph =
                    analysisDB.getKnowledgeGraph(plugin.getCurrentProgram().getExecutableSHA256());
            KnowledgeNode node = graph.getNode(targetId);

            if (node != null) {
                handleNavigate(node.getAddress());
            }
        } catch (Exception e) {
            Msg.error(this, "Failed to navigate to edge target: " + e.getMessage(), e);
        }
    }

    // ==== Search Query Operations ====

    /**
     * Handle semantic graph search query.
     * Executes a semantic query tool and returns the result via callback.
     *
     * @param queryType The tool name (e.g., "ga_search_semantic")
     * @param args The query arguments as JsonObject
     * @param resultCallback Callback to receive the JSON result string
     */
    public void handleSearchQuery(String queryType, com.google.gson.JsonObject args,
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

    // ==== Helper Methods ====

    private String formatIndexedTimestamp(Long epochMs) {
        if (epochMs == null || epochMs <= 0) {
            return "unknown";
        }
        DateTimeFormatter formatter =
                DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());
        return formatter.format(Instant.ofEpochMilli(epochMs));
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
}
