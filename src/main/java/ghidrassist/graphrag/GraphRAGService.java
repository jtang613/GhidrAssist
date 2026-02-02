package ghidrassist.graphrag;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import ghidrassist.AnalysisDB;
import ghidrassist.apiprovider.APIProvider;
import ghidrassist.graphrag.extraction.BackgroundIndexer;
import ghidrassist.graphrag.extraction.SemanticExtractor;
import ghidrassist.graphrag.extraction.StructureExtractor;
import ghidrassist.graphrag.nodes.KnowledgeNode;
import ghidrassist.graphrag.nodes.NodeType;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Main service facade for the Graph-RAG knowledge system.
 *
 * Provides high-level APIs for:
 * - Cached decompilation (primary use case to avoid redundant decompile calls)
 * - Graph population and indexing
 * - Semantic search and traversal
 * - Context building for LLM queries
 *
 * This is the main entry point for other components to interact with the Graph-RAG system.
 */
public class GraphRAGService {

    private static GraphRAGService instance;

    private final AnalysisDB analysisDB;
    private final Map<String, BackgroundIndexer> activeIndexers = new ConcurrentHashMap<>();

    // Optional LLM provider for semantic extraction
    private APIProvider llmProvider;

    // Background semantic analysis queue
    private final ScheduledExecutorService semanticWorker = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "GraphRAG-SemanticWorker");
        t.setDaemon(true);
        return t;
    });
    private final ConcurrentLinkedQueue<SemanticQueueEntry> semanticQueue = new ConcurrentLinkedQueue<>();
    private volatile boolean semanticWorkerRunning = false;
    private volatile Program currentProgram;  // For background processing
    private volatile SemanticExtractor currentExtractor;  // For cancellation support

    /**
     * Entry in the semantic analysis queue.
     */
    private static class SemanticQueueEntry {
        final long address;
        final String programHash;
        int retryCount;

        SemanticQueueEntry(long address, String programHash) {
            this.address = address;
            this.programHash = programHash;
            this.retryCount = 0;
        }
    }

    private GraphRAGService(AnalysisDB analysisDB) {
        this.analysisDB = analysisDB;
    }

    /**
     * Get the singleton instance.
     */
    public static synchronized GraphRAGService getInstance(AnalysisDB analysisDB) {
        if (instance == null) {
            instance = new GraphRAGService(analysisDB);
        }
        return instance;
    }

    /**
     * Set the LLM provider for semantic extraction.
     * Required for LLM summarization; if not set, only structural extraction works.
     */
    public void setLLMProvider(APIProvider provider) {
        this.llmProvider = provider;
        if (provider != null) {
            Msg.info(this, "LLM provider set for background semantic analysis: " + provider.getType());
        } else {
            Msg.warn(this, "LLM provider set to null - background semantic analysis disabled");
        }
        // Start background worker if provider is now available and queue has items
        if (provider != null && !semanticQueue.isEmpty()) {
            ensureSemanticWorkerRunning();
        }
    }

    /**
     * Check if an LLM provider is configured.
     */
    public boolean hasLlmProvider() {
        return llmProvider != null;
    }

    /**
     * Set the current program for background processing.
     * This should be called when the program changes in the UI.
     */
    public void setCurrentProgram(Program program) {
        this.currentProgram = program;
    }

    // ========================================
    // Background Semantic Analysis Queue
    // ========================================

    /**
     * Queue a function for background LLM semantic analysis.
     * This method returns immediately; analysis happens asynchronously.
     *
     * @param address Function entry point address
     * @param programHash SHA256 hash of the program binary
     */
    public void queueForSemanticAnalysis(long address, String programHash) {
        if (programHash == null) {
            Msg.warn(this, "Cannot queue for semantic analysis: no program hash");
            return;
        }

        // Check if already in queue (simple O(n) check, acceptable for typical queue sizes)
        boolean alreadyQueued = semanticQueue.stream()
                .anyMatch(e -> e.address == address && e.programHash.equals(programHash));

        if (!alreadyQueued) {
            semanticQueue.offer(new SemanticQueueEntry(address, programHash));
            Msg.info(this, String.format("Queued function 0x%x for background semantic analysis (%d in queue)",
                    address, semanticQueue.size()));
            ensureSemanticWorkerRunning();
        }
    }

    /**
     * Queue a function for background LLM semantic analysis using current program.
     *
     * @param address Function entry point address
     */
    public void queueForSemanticAnalysis(long address) {
        if (currentProgram != null) {
            queueForSemanticAnalysis(address, currentProgram.getExecutableSHA256());
        } else {
            Msg.warn(this, "Cannot queue for semantic analysis: no current program set");
        }
    }

    /**
     * Get the current size of the semantic analysis queue.
     */
    public int getSemanticQueueSize() {
        return semanticQueue.size();
    }

    /**
     * Ensure the background semantic worker is running.
     */
    private void ensureSemanticWorkerRunning() {
        if (semanticWorkerRunning) {
            Msg.debug(this, "Semantic worker already running");
            return;
        }
        if (llmProvider == null) {
            Msg.warn(this, "Cannot start semantic worker: no LLM provider configured");
            return;
        }
        semanticWorkerRunning = true;
        // Start worker: initial delay 2 seconds, then every 5 seconds
        semanticWorker.scheduleWithFixedDelay(this::processSemanticQueue, 2, 5, TimeUnit.SECONDS);
        Msg.info(this, "Started background semantic analysis worker");
    }

    /**
     * Background worker method: processes the semantic analysis queue.
     * Runs periodically and respects rate limits.
     */
    private void processSemanticQueue() {
        if (llmProvider == null) {
            Msg.debug(this, "processSemanticQueue: no LLM provider");
            return;
        }
        if (semanticQueue.isEmpty()) {
            return; // Normal case, don't log
        }

        Msg.info(this, "processSemanticQueue: processing " + semanticQueue.size() + " queued functions");

        // Determine batch size based on provider type
        int batchSize = isLocalProvider() ? 10 : 3;
        List<SemanticQueueEntry> batch = new ArrayList<>();

        // Poll batch from queue
        for (int i = 0; i < batchSize && !semanticQueue.isEmpty(); i++) {
            SemanticQueueEntry entry = semanticQueue.poll();
            if (entry != null) {
                batch.add(entry);
            }
        }

        if (batch.isEmpty()) {
            return;
        }

        Msg.info(this, String.format("Processing semantic analysis batch: %d functions", batch.size()));

        for (SemanticQueueEntry entry : batch) {
            try {
                processSemanticEntry(entry);
            } catch (Exception e) {
                Msg.error(this, "Failed to process semantic entry: " + e.getMessage(), e);
                // Re-queue with retry limit
                if (entry.retryCount < 3) {
                    entry.retryCount++;
                    semanticQueue.offer(entry);
                } else {
                    Msg.warn(this, String.format("Giving up on function 0x%x after %d retries",
                            entry.address, entry.retryCount));
                }
            }
        }

        // Rebuild FTS to reflect newly-summarized nodes
        analysisDB.rebuildFts();
    }

    /**
     * Process a single semantic queue entry.
     */
    private void processSemanticEntry(SemanticQueueEntry entry) {
        BinaryKnowledgeGraph graph = analysisDB.getKnowledgeGraph(entry.programHash);
        if (graph == null) {
            Msg.warn(this, "No graph found for program hash: " + entry.programHash);
            return;
        }

        // Check if node exists and needs summarization
        KnowledgeNode node = graph.getNodeByAddress(entry.address);
        if (node == null) {
            Msg.debug(this, String.format("Node not found for 0x%x, skipping semantic analysis", entry.address));
            return;
        }

        // Skip if already has a summary and is not stale
        if (node.getLlmSummary() != null && !node.getLlmSummary().isEmpty() && !node.isStale()) {
            Msg.debug(this, String.format("Node 0x%x already has summary, skipping", entry.address));
            return;
        }

        // Run semantic extraction
        SemanticExtractor extractor = new SemanticExtractor(llmProvider, graph);
        boolean success = extractor.summarizeNode(node);

        if (success) {
            Msg.info(this, String.format("Completed semantic analysis for 0x%x", entry.address));
        } else {
            Msg.warn(this, String.format("Semantic analysis failed for 0x%x", entry.address));
        }
    }

    /**
     * Check if the current LLM provider is local (faster rate limits).
     */
    private boolean isLocalProvider() {
        if (llmProvider == null) return false;
        APIProvider.ProviderType type = llmProvider.getType();
        return type == APIProvider.ProviderType.OLLAMA ||
               type == APIProvider.ProviderType.LMSTUDIO;
    }

    // ========================================
    // Cached Decompilation (Primary Use Case)
    // ========================================

    /**
     * Get decompiled code for a function, using cache if available.
     * This is the main method to replace direct decompilation calls.
     *
     * Falls back to live decompilation if not cached.
     *
     * @param function The function to decompile
     * @param monitor  Task monitor for decompilation
     * @return Decompiled code, or null if failed
     */
    public String getCachedDecompiledCode(Function function, TaskMonitor monitor) {
        if (function == null) {
            return null;
        }

        Program program = function.getProgram();
        String programHash = program.getExecutableSHA256();
        BinaryKnowledgeGraph graph = analysisDB.getKnowledgeGraph(programHash);

        // Check cache first
        String cached = graph.getCachedDecompiledCode(function.getEntryPoint().getOffset());
        if (cached != null) {
            Msg.debug(this, "GraphRAG cache hit: " + function.getName());
            return cached;
        }

        // Cache miss - decompile and cache
        Msg.debug(this, "GraphRAG cache miss: " + function.getName() + " - decompiling...");
        StructureExtractor extractor = new StructureExtractor(program, graph, monitor);
        try {
            return extractor.getDecompiledCode(function);
        } finally {
            extractor.dispose();
        }
    }

    /**
     * Get decompiled code by address.
     */
    public String getCachedDecompiledCode(Program program, Address address, TaskMonitor monitor) {
        if (program == null || address == null) {
            return null;
        }

        Function function = program.getFunctionManager().getFunctionContaining(address);
        if (function == null) {
            return null;
        }

        return getCachedDecompiledCode(function, monitor);
    }

    /**
     * Check if a function is already cached.
     */
    public boolean isFunctionCached(Function function) {
        if (function == null) {
            return false;
        }

        String programHash = function.getProgram().getExecutableSHA256();
        BinaryKnowledgeGraph graph = analysisDB.getKnowledgeGraph(programHash);
        return graph.hasFunctionCached(function.getEntryPoint().getOffset());
    }

    // ========================================
    // Graph Population / Indexing
    // ========================================

    /**
     * Start background indexing of a program.
     *
     * @param program       The program to index
     * @param monitor       Task monitor
     * @param includeBlocks Whether to extract basic blocks (increases size)
     * @param runSemantic   Whether to run LLM summarization
     * @param callback      Optional callback for status updates
     * @return The BackgroundIndexer instance for tracking progress
     */
    public BackgroundIndexer startIndexing(Program program, TaskMonitor monitor,
                                            boolean includeBlocks, boolean runSemantic,
                                            BackgroundIndexer.IndexingCallback callback) {
        String programHash = program.getExecutableSHA256();

        // Check if already indexing
        BackgroundIndexer existing = activeIndexers.get(programHash);
        if (existing != null && existing.isRunning()) {
            Msg.warn(this, "Indexing already in progress for: " + program.getName());
            return existing;
        }

        BinaryKnowledgeGraph graph = analysisDB.getKnowledgeGraph(programHash);
        BackgroundIndexer indexer = new BackgroundIndexer(program, graph, monitor);

        if (llmProvider != null) {
            indexer.setProvider(llmProvider);
        }

        if (callback != null) {
            indexer.setCallback(callback);
        }

        activeIndexers.put(programHash, indexer);

        int summarizeLimit = runSemantic ? 500 : 0; // Limit initial summarization
        indexer.start(includeBlocks, runSemantic, summarizeLimit);

        return indexer;
    }

    /**
     * Run structure extraction synchronously (blocking).
     * Use when you need immediate results.
     */
    public StructureExtractor.ExtractionResult indexStructureSync(Program program,
                                                                    TaskMonitor monitor,
                                                                    boolean includeBlocks) {
        return indexStructureSync(program, monitor, includeBlocks, false);
    }

    /**
     * Run structure extraction synchronously with optional incremental mode.
     *
     * @param program       The program to index
     * @param monitor       Task monitor for progress/cancellation
     * @param includeBlocks Whether to extract basic blocks
     * @param incremental   If true, preserves existing semantic data (summaries, embeddings, flags)
     * @return Extraction result with statistics
     */
    public StructureExtractor.ExtractionResult indexStructureSync(Program program,
                                                                    TaskMonitor monitor,
                                                                    boolean includeBlocks,
                                                                    boolean incremental) {
        String programHash = program.getExecutableSHA256();
        BinaryKnowledgeGraph graph = analysisDB.getKnowledgeGraph(programHash);

        return BackgroundIndexer.runStructureSync(program, graph, monitor, includeBlocks, incremental);
    }

    /**
     * Run semantic extraction (LLM summarization) on stale nodes.
     *
     * @param program  The program
     * @param limit    Max nodes to summarize (0 = all)
     * @param callback Progress callback
     * @return Extraction result
     */
    public SemanticExtractor.ExtractionResult summarizeStaleNodes(Program program,
                                                                    int limit,
                                                                    SemanticExtractor.ProgressCallback callback) {
        if (llmProvider == null) {
            Msg.warn(this, "No LLM provider configured for semantic extraction");
            return new SemanticExtractor.ExtractionResult(0, 0, 0, 0);
        }

        String programHash = program.getExecutableSHA256();
        BinaryKnowledgeGraph graph = analysisDB.getKnowledgeGraph(programHash);

        currentExtractor = new SemanticExtractor(llmProvider, graph);
        try {
            return currentExtractor.summarizeStaleNodes(limit, callback);
        } finally {
            currentExtractor = null;  // Clear when done
        }
    }

    /**
     * Cancel any running semantic extraction.
     */
    public void cancelSemanticExtraction() {
        SemanticExtractor extractor = currentExtractor;
        if (extractor != null) {
            extractor.cancel();
        }
    }

    // ========================================
    // Security Flags Update
    // ========================================

    /**
     * Update security flags for a specific function.
     * Re-extracts security features and updates the node's security_flags field.
     *
     * @param function The function to update
     * @param monitor  Task monitor
     * @return true if updated successfully
     */
    public boolean updateSecurityFlags(Function function, TaskMonitor monitor) {
        if (function == null || function.isThunk() || function.isExternal()) {
            return false;
        }

        Program program = function.getProgram();
        String programHash = program.getExecutableSHA256();
        BinaryKnowledgeGraph graph = analysisDB.getKnowledgeGraph(programHash);

        KnowledgeNode node = graph.getNodeByAddress(function.getEntryPoint().getOffset());
        if (node == null) {
            Msg.debug(this, "No node found for function: " + function.getName());
            return false;
        }

        try {
            ghidrassist.graphrag.extraction.SecurityFeatureExtractor extractor =
                    new ghidrassist.graphrag.extraction.SecurityFeatureExtractor(program, monitor);
            // Pass decompiled code for additional API detection via regex parsing
            String decompiledCode = node.getRawContent();
            ghidrassist.graphrag.extraction.SecurityFeatures features = extractor.extractFeatures(function, decompiledCode);

            if (!features.isEmpty()) {
                node.applySecurityFeatures(features);
                java.util.List<String> securityFlags = features.generateSecurityFlags();
                node.setSecurityFlags(securityFlags);
                graph.upsertNode(node);

                Msg.debug(this, String.format("Updated security flags for %s: %s",
                        function.getName(), securityFlags));
                return true;
            }
        } catch (Exception e) {
            Msg.error(this, "Failed to update security flags for " + function.getName() + ": " + e.getMessage());
        }

        return false;
    }

    /**
     * Update security flags for all function nodes in a program.
     * Useful for populating flags on existing nodes that were indexed before this feature.
     *
     * @param program The program to update
     * @param monitor Task monitor
     * @return Number of nodes updated
     */
    public int updateAllSecurityFlags(Program program, TaskMonitor monitor) {
        if (program == null) {
            return 0;
        }

        String programHash = program.getExecutableSHA256();
        BinaryKnowledgeGraph graph = analysisDB.getKnowledgeGraph(programHash);
        java.util.List<KnowledgeNode> functionNodes = graph.getNodesByType(NodeType.FUNCTION);

        int updated = 0;
        int total = functionNodes.size();

        monitor.setMessage("Updating security flags...");
        monitor.setMaximum(total);

        ghidrassist.graphrag.extraction.SecurityFeatureExtractor extractor =
                new ghidrassist.graphrag.extraction.SecurityFeatureExtractor(program, monitor);

        for (int i = 0; i < total; i++) {
            if (monitor.isCancelled()) {
                break;
            }

            KnowledgeNode node = functionNodes.get(i);
            monitor.setProgress(i);

            // Skip if node already has security flags
            java.util.List<String> existingFlags = node.getSecurityFlags();
            if (existingFlags != null && !existingFlags.isEmpty()) {
                continue;
            }

            // Get function by address
            Long address = node.getAddress();
            if (address == null || address == 0) {
                continue;
            }

            Function function = program.getFunctionManager().getFunctionAt(
                    program.getAddressFactory().getDefaultAddressSpace().getAddress(address));

            if (function == null || function.isThunk() || function.isExternal()) {
                continue;
            }

            try {
                // Pass decompiled code for additional API detection via regex parsing
                String decompiledCode = node.getRawContent();
                ghidrassist.graphrag.extraction.SecurityFeatures features = extractor.extractFeatures(function, decompiledCode);
                if (!features.isEmpty()) {
                    node.applySecurityFeatures(features);
                    java.util.List<String> securityFlags = features.generateSecurityFlags();
                    node.setSecurityFlags(securityFlags);
                    graph.upsertNode(node);
                    updated++;
                }
            } catch (Exception e) {
                Msg.debug(this, "Failed to update flags for " + node.getName() + ": " + e.getMessage());
            }
        }

        Msg.info(this, String.format("Updated security flags for %d/%d functions", updated, total));
        return updated;
    }

    /**
     * Check if a node needs security flags update.
     * Returns true if the node exists but has no security flags.
     *
     * @param function The function to check
     * @return true if security flags need to be updated
     */
    public boolean needsSecurityFlagsUpdate(Function function) {
        if (function == null) {
            return false;
        }

        String programHash = function.getProgram().getExecutableSHA256();
        BinaryKnowledgeGraph graph = analysisDB.getKnowledgeGraph(programHash);
        KnowledgeNode node = graph.getNodeByAddress(function.getEntryPoint().getOffset());

        if (node == null) {
            return false;  // Node doesn't exist yet
        }

        java.util.List<String> flags = node.getSecurityFlags();
        return flags == null || flags.isEmpty();
    }

    // ========================================
    // Graph Queries
    // ========================================

    /**
     * Get a knowledge node by function.
     */
    public KnowledgeNode getNode(Function function) {
        if (function == null) {
            return null;
        }

        String programHash = function.getProgram().getExecutableSHA256();
        BinaryKnowledgeGraph graph = analysisDB.getKnowledgeGraph(programHash);
        return graph.getNodeByAddress(function.getEntryPoint().getOffset());
    }

    /**
     * Get callers of a function.
     */
    public List<KnowledgeNode> getCallers(Function function) {
        KnowledgeNode node = getNode(function);
        if (node == null) {
            return List.of();
        }

        String programHash = function.getProgram().getExecutableSHA256();
        BinaryKnowledgeGraph graph = analysisDB.getKnowledgeGraph(programHash);
        return graph.getCallers(node.getId());
    }

    /**
     * Get callees of a function.
     */
    public List<KnowledgeNode> getCallees(Function function) {
        KnowledgeNode node = getNode(function);
        if (node == null) {
            return List.of();
        }

        String programHash = function.getProgram().getExecutableSHA256();
        BinaryKnowledgeGraph graph = analysisDB.getKnowledgeGraph(programHash);
        return graph.getCallees(node.getId());
    }

    /**
     * Full-text search on node summaries.
     */
    public List<KnowledgeNode> searchNodes(Program program, String query, int limit) {
        String programHash = program.getExecutableSHA256();
        BinaryKnowledgeGraph graph = analysisDB.getKnowledgeGraph(programHash);
        return graph.ftsSearch(query, limit);
    }

    /**
     * Get neighboring nodes within N hops.
     */
    public List<KnowledgeNode> getNeighborhood(Function function, int depth) {
        KnowledgeNode node = getNode(function);
        if (node == null) {
            return List.of();
        }

        String programHash = function.getProgram().getExecutableSHA256();
        BinaryKnowledgeGraph graph = analysisDB.getKnowledgeGraph(programHash);
        return graph.getNeighborsBatch(node.getId(), depth);
    }

    // ========================================
    // Context Building for LLM
    // ========================================

    /**
     * Build context for a function query (local search).
     * Includes the function's decompiled code, summary, callers, and callees.
     *
     * @param function The function to build context for
     * @param depth    How many hops to include (1 = direct callers/callees)
     * @return Formatted context string for LLM
     */
    public String buildFunctionContext(Function function, int depth) {
        if (function == null) {
            return "";
        }

        KnowledgeNode node = getNode(function);
        if (node == null) {
            return "Function not yet indexed: " + function.getName();
        }

        StringBuilder context = new StringBuilder();

        // Function info
        context.append("## Function: ").append(function.getName()).append("\n\n");

        // Summary if available
        if (node.getLlmSummary() != null && !node.getLlmSummary().isEmpty()) {
            context.append("**Summary:** ").append(node.getLlmSummary()).append("\n\n");
        }

        // Security flags
        if (node.hasSecurityFlags()) {
            context.append("**Security Flags:** ").append(String.join(", ", node.getSecurityFlags())).append("\n\n");
        }

        // Callers
        List<KnowledgeNode> callers = getCallers(function);
        if (!callers.isEmpty()) {
            context.append("**Called by:** ");
            context.append(formatNodeList(callers, 5));
            context.append("\n\n");
        }

        // Callees
        List<KnowledgeNode> callees = getCallees(function);
        if (!callees.isEmpty()) {
            context.append("**Calls:** ");
            context.append(formatNodeList(callees, 5));
            context.append("\n\n");
        }

        // Decompiled code (truncated)
        if (node.getRawContent() != null) {
            String code = node.getRawContent();
            if (code.length() > 3000) {
                code = code.substring(0, 3000) + "\n// ... (truncated)";
            }
            context.append("**Decompiled Code:**\n```c\n").append(code).append("\n```\n");
        }

        return context.toString();
    }

    /**
     * Build global context for a program (binary-level summary).
     */
    public String buildProgramContext(Program program) {
        String programHash = program.getExecutableSHA256();
        BinaryKnowledgeGraph graph = analysisDB.getKnowledgeGraph(programHash);

        // Get binary node
        List<KnowledgeNode> binaryNodes = graph.getNodesByType(NodeType.BINARY);
        if (binaryNodes.isEmpty()) {
            return "Program not yet indexed: " + program.getName();
        }

        KnowledgeNode binaryNode = binaryNodes.get(0);

        StringBuilder context = new StringBuilder();
        context.append("## Binary: ").append(program.getName()).append("\n\n");

        if (binaryNode.getLlmSummary() != null) {
            context.append(binaryNode.getLlmSummary()).append("\n\n");
        } else if (binaryNode.getRawContent() != null) {
            context.append(binaryNode.getRawContent()).append("\n\n");
        }

        // Add graph stats
        Map<String, Integer> stats = analysisDB.getKnowledgeGraphStats(programHash);
        context.append("**Graph Statistics:**\n");
        context.append("- Nodes: ").append(stats.get("nodes")).append("\n");
        context.append("- Edges: ").append(stats.get("edges")).append("\n");
        context.append("- Stale nodes: ").append(stats.get("stale_nodes")).append("\n");

        return context.toString();
    }

    // ========================================
    // Status and Utilities
    // ========================================

    /**
     * Check if a program has been indexed.
     */
    public boolean isProgramIndexed(Program program) {
        return analysisDB.hasKnowledgeGraph(program.getExecutableSHA256());
    }

    /**
     * Get indexing status for a program.
     */
    public String getIndexingStatus(Program program) {
        String programHash = program.getExecutableSHA256();

        BackgroundIndexer indexer = activeIndexers.get(programHash);
        if (indexer != null && indexer.isRunning()) {
            return String.format("Indexing: %s (%d%%)",
                    indexer.getCurrentPhase(), (int) indexer.getProgressPercent());
        }

        if (analysisDB.hasKnowledgeGraph(programHash)) {
            Map<String, Integer> stats = analysisDB.getKnowledgeGraphStats(programHash);
            return String.format("Indexed: %d nodes, %d edges (%d stale)",
                    stats.get("nodes"), stats.get("edges"), stats.get("stale_nodes"));
        }

        return "Not indexed";
    }

    /**
     * Get graph statistics for a program.
     */
    public Map<String, Integer> getGraphStats(Program program) {
        return analysisDB.getKnowledgeGraphStats(program.getExecutableSHA256());
    }

    /**
     * Clear graph data for a program.
     */
    public void clearGraph(Program program) {
        String programHash = program.getExecutableSHA256();
        BinaryKnowledgeGraph graph = analysisDB.getKnowledgeGraph(programHash);
        graph.clearGraph();
        analysisDB.rebuildFts();
        analysisDB.invalidateKnowledgeGraphCache(programHash);
    }

    // ========================================
    // Helper Methods
    // ========================================

    private String formatNodeList(List<KnowledgeNode> nodes, int limit) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(nodes.size(), limit); i++) {
            if (i > 0) sb.append(", ");
            KnowledgeNode n = nodes.get(i);
            sb.append(n.getName() != null ? n.getName() : String.format("0x%x", n.getAddress()));
        }
        if (nodes.size() > limit) {
            sb.append(String.format(" (+%d more)", nodes.size() - limit));
        }
        return sb.toString();
    }
}
