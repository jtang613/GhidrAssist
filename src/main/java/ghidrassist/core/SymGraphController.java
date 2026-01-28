package ghidrassist.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import ghidrassist.AnalysisDB;
import ghidrassist.GhidrAssistPlugin;
import ghidrassist.graphrag.BinaryKnowledgeGraph;
import ghidrassist.graphrag.nodes.EdgeType;
import ghidrassist.graphrag.nodes.KnowledgeNode;
import ghidrassist.graphrag.nodes.NodeType;
import ghidrassist.services.symgraph.SymGraphService;
import ghidrassist.services.symgraph.SymGraphModels.*;
import ghidrassist.ui.tabs.SymGraphTab;

import com.google.gson.Gson;

import javax.swing.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Controller for SymGraph operations.
 * Handles query, push, pull, and apply operations for symbol sharing.
 *
 * Extracted from TabController as part of decomposition refactoring.
 */
public class SymGraphController {

    private final GhidrAssistPlugin plugin;
    private final AnalysisDB analysisDB;
    private SymGraphService symGraphService;
    private SymGraphTab symGraphTab;

    public SymGraphController(GhidrAssistPlugin plugin, AnalysisDB analysisDB) {
        this.plugin = plugin;
        this.analysisDB = analysisDB;
    }

    // ==== Tab Registration ====

    public void setSymGraphTab(SymGraphTab tab) {
        this.symGraphTab = tab;
        if (this.symGraphService == null) {
            this.symGraphService = new SymGraphService();
        }
    }

    // ==== Query Operations ====

    /**
     * Handle SymGraph query request.
     */
    public void handleQuery() {
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

    // ==== Push Operations ====

    /**
     * Handle SymGraph push request.
     */
    public void handlePush(String scope, boolean pushSymbols, boolean pushGraph) {
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

    // ==== Pull Operations ====

    /**
     * Handle SymGraph pull preview request.
     */
    public void handlePullPreview() {
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
        SymGraphTab.PullConfig pullConfig = symGraphTab.getPullConfig();
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

    // ==== Apply Operations ====

    /**
     * Handle applying selected symbols from SymGraph.
     */
    public void handleApplySelected(List<ConflictEntry> selectedConflicts) {
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
    public void handleApplyAllNew() {
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

    // ==== Binary Info ====

    /**
     * Update SymGraph tab binary info when program changes.
     */
    public void updateBinaryInfo() {
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

    // ==== Helper Methods ====

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
        Map<String, Object> map = new HashMap<>();
        map.put("address", String.format("0x%x", func.getEntryPoint().getOffset()));
        map.put("symbol_type", "function");
        map.put("name", getQualifiedFunctionName(func));
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

                    Map<String, Object> map = new HashMap<>();
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
                    Map<String, Object> map = new HashMap<>();
                    map.put("address", String.format("0x%x", func.getEntryPoint().getOffset()));
                    map.put("symbol_type", "variable");
                    map.put("name", param.getName());
                    if (param.getDataType() != null) {
                        map.put("data_type", param.getDataType().getName());
                    }
                    map.put("confidence", isAuto ? 0.3 : 0.8);
                    map.put("provenance", isAuto ? "decompiler" : "user");

                    Map<String, Object> metadata = new HashMap<>();
                    metadata.put("scope", "parameter");
                    metadata.put("function", getQualifiedFunctionName(func));
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
                    Map<String, Object> map = new HashMap<>();
                    map.put("address", String.format("0x%x", func.getEntryPoint().getOffset()));
                    map.put("symbol_type", "variable");
                    map.put("name", var.getName());
                    if (var.getDataType() != null) {
                        map.put("data_type", var.getDataType().getName());
                    }
                    map.put("confidence", isAuto ? 0.3 : 0.75);
                    map.put("provenance", isAuto ? "decompiler" : "user");

                    Map<String, Object> metadata = new HashMap<>();
                    metadata.put("scope", "local");
                    metadata.put("function", getQualifiedFunctionName(func));

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
                ghidra.program.model.data.SourceArchive srcArchive = dt.getSourceArchive();
                if (srcArchive == null) {
                    continue;
                }
                // Skip types from built-in archives
                if (srcArchive.getArchiveType() == ghidra.program.model.data.ArchiveType.BUILT_IN) {
                    continue;
                }

                Map<String, Object> map = new HashMap<>();
                map.put("address", "0x0"); // Types don't have addresses
                map.put("name", dt.getName());
                map.put("data_type", dt.getDisplayName());
                map.put("confidence", 0.9);
                map.put("provenance", "user");

                if (dt instanceof ghidra.program.model.data.Enum) {
                    ghidra.program.model.data.Enum enumType = (ghidra.program.model.data.Enum) dt;
                    map.put("symbol_type", "enum");
                    // Collect enum members
                    Map<String, Object> metadata = new HashMap<>();
                    Map<String, Long> members = new HashMap<>();
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
                        Map<String, Object> field = new HashMap<>();
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
                    Map<String, Object> metadata = new HashMap<>();
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
                Map<String, Object> map = new HashMap<>();
                map.put("address", String.format("0x%x", func.getEntryPoint().getOffset()));
                map.put("symbol_type", "comment");
                map.put("content", funcComment);
                map.put("confidence", 1.0);
                map.put("provenance", "user");
                Map<String, Object> metadata = new HashMap<>();
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
                    Map<String, Object> map = new HashMap<>();
                    map.put("address", String.format("0x%x", addr.getOffset()));
                    map.put("symbol_type", "comment");
                    map.put("content", eolComment);
                    map.put("confidence", 1.0);
                    map.put("provenance", "user");
                    Map<String, Object> metadata = new HashMap<>();
                    metadata.put("type", "eol");
                    metadata.put("function", getQualifiedFunctionName(func));
                    map.put("metadata", metadata);
                    symbols.add(map);
                }

                String preComment = codeUnit.getComment(ghidra.program.model.listing.CommentType.PRE);
                if (preComment != null && !preComment.isEmpty()) {
                    Map<String, Object> map = new HashMap<>();
                    map.put("address", String.format("0x%x", addr.getOffset()));
                    map.put("symbol_type", "comment");
                    map.put("content", preComment);
                    map.put("confidence", 1.0);
                    map.put("provenance", "user");
                    Map<String, Object> metadata = new HashMap<>();
                    metadata.put("type", "pre");
                    metadata.put("function", getQualifiedFunctionName(func));
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
            BinaryKnowledgeGraph graph = analysisDB.getKnowledgeGraph(programHash);

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
                    KnowledgeNode funcNode = graph.getNodeByAddress(currentFunc.getEntryPoint().getOffset());
                    if (funcNode != null) {
                        nodeIdsToExport.add(funcNode.getId());
                        // Add 1-hop neighbors
                        for (KnowledgeNode neighbor : graph.getNeighborsBatch(funcNode.getId(), 1)) {
                            nodeIdsToExport.add(neighbor.getId());
                        }
                    }
                }
            } else {
                // Full binary - export all nodes
                for (NodeType nodeType : NodeType.values()) {
                    for (KnowledgeNode node : graph.getNodesByType(nodeType)) {
                        nodeIdsToExport.add(node.getId());
                    }
                }
            }

            // Step 2: BATCH fetch all nodes in ONE query
            java.util.Map<String, KnowledgeNode> nodeCache = graph.getNodes(nodeIdsToExport);

            // Step 3: BATCH fetch all edges in ONE query
            java.util.List<BinaryKnowledgeGraph.GraphEdge> allEdges = graph.getEdgesForNodes(nodeIdsToExport);

            // Step 4: Process nodes from cache
            for (KnowledgeNode node : nodeCache.values()) {
                nodes.add(nodeToExportMap(node));
            }

            // Step 5: Process edges using cache
            for (BinaryKnowledgeGraph.GraphEdge edge : allEdges) {
                // Only include edges where both endpoints are in our export set
                if (nodeIdsToExport.contains(edge.getTargetId())) {
                    KnowledgeNode sourceNode = nodeCache.get(edge.getSourceId());
                    KnowledgeNode targetNode = nodeCache.get(edge.getTargetId());

                    if (sourceNode != null && targetNode != null) {
                        Map<String, Object> edgeMap = new HashMap<>();
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

        Map<String, Object> graphData = new HashMap<>();
        graphData.put("nodes", nodes);
        graphData.put("edges", edges);
        return graphData;
    }

    /**
     * Convert a KnowledgeNode to a Map for export.
     */
    private Map<String, Object> nodeToExportMap(KnowledgeNode node) {
        Map<String, Object> nodeMap = new HashMap<>();
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
        Map<Long, String> symbolMap = new HashMap<>();

        if (plugin.getCurrentProgram() == null) {
            return symbolMap;
        }

        try {
            for (Function func : plugin.getCurrentProgram().getFunctionManager().getFunctions(true)) {
                String qualifiedName = getQualifiedFunctionName(func);
                // Use unified default name detection for cross-tool compatibility
                if (!ghidrassist.services.symgraph.SymGraphUtils.isDefaultName(qualifiedName)) {
                    symbolMap.put(func.getEntryPoint().getOffset(), qualifiedName);
                }
            }
        } catch (Exception e) {
            Msg.error(this, "Error getting local symbols: " + e.getMessage());
        }

        return symbolMap;
    }

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

    private boolean applyVariableSymbol(Function func, Symbol remoteSymbol) {
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

    /**
     * Get the fully qualified name of a function including its namespace.
     * Delegates to shared utility in SymGraphUtils.
     */
    private String getQualifiedFunctionName(Function func) {
        return ghidrassist.services.symgraph.SymGraphUtils.getQualifiedFunctionName(func);
    }
}
