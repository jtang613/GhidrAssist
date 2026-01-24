package ghidrassist.graphrag.extraction;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import ghidrassist.apiprovider.APIProvider;
import ghidrassist.graphrag.BinaryKnowledgeGraph;

import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Background indexer for populating the knowledge graph asynchronously.
 *
 * Manages the two-phase extraction process:
 * 1. Structure extraction (fast, no LLM) - runs immediately
 * 2. Semantic extraction (LLM summarization) - runs in background
 *
 * Provides status tracking and cancellation support.
 */
public class BackgroundIndexer {

    // Thread pool for background work
    private static final ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "GraphRAG-Indexer");
        t.setDaemon(true);
        return t;
    });

    // Current indexing state
    private final AtomicBoolean isRunning = new AtomicBoolean(false);
    private final AtomicBoolean isCancelled = new AtomicBoolean(false);
    private final AtomicInteger progress = new AtomicInteger(0);
    private final AtomicInteger total = new AtomicInteger(0);

    private volatile String statusMessage = "Idle";
    private volatile Phase currentPhase = Phase.IDLE;
    private Future<?> currentTask;

    // References
    private final Program program;
    private final BinaryKnowledgeGraph graph;
    private final TaskMonitor monitor;
    private APIProvider provider;

    // Callbacks
    private IndexingCallback callback;

    /**
     * Indexing phases.
     */
    public enum Phase {
        IDLE,
        STRUCTURE_EXTRACTION,
        SEMANTIC_EXTRACTION,
        COMPLETED,
        ERROR,
        CANCELLED
    }

    /**
     * Create a BackgroundIndexer for a program.
     *
     * @param program The Ghidra program to index
     * @param graph   The knowledge graph to populate
     * @param monitor Task monitor for the Ghidra UI
     */
    public BackgroundIndexer(Program program, BinaryKnowledgeGraph graph, TaskMonitor monitor) {
        this.program = program;
        this.graph = graph;
        this.monitor = monitor;
    }

    /**
     * Set the LLM provider for semantic extraction.
     * If not set, only structure extraction will run.
     */
    public void setProvider(APIProvider provider) {
        this.provider = provider;
    }

    /**
     * Set a callback for status updates.
     */
    public void setCallback(IndexingCallback callback) {
        this.callback = callback;
    }

    /**
     * Start the indexing process.
     *
     * @param includeBlocks   Whether to extract basic blocks (increases graph size)
     * @param runSemantic     Whether to run LLM summarization
     * @param summarizeLimit  Max nodes to summarize (0 = all)
     */
    public void start(boolean includeBlocks, boolean runSemantic, int summarizeLimit) {
        if (isRunning.get()) {
            Msg.warn(this, "Indexer is already running");
            return;
        }

        isRunning.set(true);
        isCancelled.set(false);
        progress.set(0);
        total.set(0);

        currentTask = executor.submit(() -> {
            try {
                runIndexing(includeBlocks, runSemantic, summarizeLimit);
            } catch (Exception e) {
                Msg.error(this, "Indexing failed: " + e.getMessage(), e);
                setPhase(Phase.ERROR, "Error: " + e.getMessage());
            } finally {
                isRunning.set(false);
            }
        });
    }

    /**
     * Start structure extraction only (no LLM).
     * Fast operation suitable for immediate use.
     */
    public void startStructureOnly(boolean includeBlocks) {
        start(includeBlocks, false, 0);
    }

    /**
     * Start full indexing with LLM summarization.
     */
    public void startFull(boolean includeBlocks, int summarizeLimit) {
        start(includeBlocks, true, summarizeLimit);
    }

    /**
     * Cancel the current indexing operation.
     */
    public void cancel() {
        isCancelled.set(true);
        if (currentTask != null) {
            currentTask.cancel(false);
        }
        setPhase(Phase.CANCELLED, "Indexing cancelled");
    }

    /**
     * Wait for indexing to complete.
     *
     * @param timeoutSeconds Maximum time to wait
     * @return true if completed, false if timeout or error
     */
    public boolean waitForCompletion(int timeoutSeconds) {
        if (currentTask == null) {
            return true;
        }

        try {
            currentTask.get(timeoutSeconds, TimeUnit.SECONDS);
            return true;
        } catch (TimeoutException e) {
            Msg.warn(this, "Indexing timeout after " + timeoutSeconds + " seconds");
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        } catch (ExecutionException e) {
            Msg.error(this, "Indexing error: " + e.getCause().getMessage());
            return false;
        }
    }

    // ========================================
    // Status Getters
    // ========================================

    public boolean isRunning() {
        return isRunning.get();
    }

    public Phase getCurrentPhase() {
        return currentPhase;
    }

    public String getStatusMessage() {
        return statusMessage;
    }

    public int getProgress() {
        return progress.get();
    }

    public int getTotal() {
        return total.get();
    }

    public float getProgressPercent() {
        int t = total.get();
        return t > 0 ? (float) progress.get() / t * 100 : 0;
    }

    // ========================================
    // Internal Processing
    // ========================================

    private void runIndexing(boolean includeBlocks, boolean runSemantic, int summarizeLimit) {
        // Phase 1: Structure Extraction
        setPhase(Phase.STRUCTURE_EXTRACTION, "Extracting program structure...");

        StructureExtractor structureExtractor = new StructureExtractor(program, graph, monitor);
        try {
            StructureExtractor.ExtractionResult structResult = structureExtractor.extractAll(includeBlocks);

            total.set(structResult.functionsExtracted);
            progress.set(structResult.functionsExtracted);

            setPhase(Phase.STRUCTURE_EXTRACTION,
                    String.format("Extracted %d functions, %d call edges",
                            structResult.functionsExtracted, structResult.callEdgesCreated));

            notifyCallback(Phase.STRUCTURE_EXTRACTION, structResult.toString());

        } finally {
            structureExtractor.dispose();
        }

        if (isCancelled.get()) {
            setPhase(Phase.CANCELLED, "Cancelled during structure extraction");
            return;
        }

        // Phase 2: Semantic Extraction (optional)
        if (runSemantic && provider != null) {
            setPhase(Phase.SEMANTIC_EXTRACTION, "Running LLM summarization...");

            SemanticExtractor semanticExtractor = new SemanticExtractor(provider, graph);

            // Configure based on provider type (slower for cloud, faster for local)
            if (isLocalProvider()) {
                semanticExtractor.setBatchConfig(10, 100); // Faster for local
            } else {
                semanticExtractor.setBatchConfig(3, 1000); // Slower for cloud (rate limits)
            }

            SemanticExtractor.ExtractionResult semResult = semanticExtractor.summarizeStaleNodes(
                    summarizeLimit,
                    (processed, total, summarized, errors) -> {
                        this.progress.set(processed);
                        this.total.set(total);
                        setPhase(Phase.SEMANTIC_EXTRACTION,
                                String.format("Summarizing: %d/%d (%d errors)", summarized, total, errors));
                    }
            );

            if (isCancelled.get()) {
                setPhase(Phase.CANCELLED, "Cancelled during semantic extraction");
                graph.rebuildFts();
                return;
            }

            notifyCallback(Phase.SEMANTIC_EXTRACTION, semResult.toString());
        }

        // Rebuild FTS index after all extraction is complete
        graph.rebuildFts();

        // Done
        setPhase(Phase.COMPLETED, "Indexing complete");
        notifyCallback(Phase.COMPLETED, "Indexing complete: " + graph.getNodeCount() + " nodes");
    }

    private void setPhase(Phase phase, String message) {
        this.currentPhase = phase;
        this.statusMessage = message;
        Msg.info(this, "GraphRAG Indexer: [" + phase + "] " + message);
    }

    private void notifyCallback(Phase phase, String message) {
        if (callback != null) {
            callback.onStatusUpdate(phase, message, progress.get(), total.get());
        }
    }

    private boolean isLocalProvider() {
        if (provider == null) return false;
        APIProvider.ProviderType type = provider.getType();
        return type == APIProvider.ProviderType.OLLAMA ||
               type == APIProvider.ProviderType.LMSTUDIO;
    }

    // ========================================
    // Callback Interface
    // ========================================

    /**
     * Callback interface for indexing status updates.
     */
    public interface IndexingCallback {
        void onStatusUpdate(Phase phase, String message, int progress, int total);
    }

    // ========================================
    // Static Factory Methods
    // ========================================

    /**
     * Create an indexer and immediately start structure extraction.
     * Returns quickly - extraction runs in background.
     */
    public static BackgroundIndexer createAndStart(Program program, BinaryKnowledgeGraph graph,
                                                    TaskMonitor monitor, boolean includeBlocks) {
        BackgroundIndexer indexer = new BackgroundIndexer(program, graph, monitor);
        indexer.startStructureOnly(includeBlocks);
        return indexer;
    }

    /**
     * Run structure extraction synchronously (blocking).
     * Use this when you need immediate results.
     */
    public static StructureExtractor.ExtractionResult runStructureSync(
            Program program, BinaryKnowledgeGraph graph, TaskMonitor monitor, boolean includeBlocks) {

        StructureExtractor extractor = new StructureExtractor(program, graph, monitor);
        try {
            return extractor.extractAll(includeBlocks);
        } finally {
            extractor.dispose();
        }
    }
}
