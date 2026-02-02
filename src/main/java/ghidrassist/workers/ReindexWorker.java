package ghidrassist.workers;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidrassist.AnalysisDB;
import ghidrassist.graphrag.BinaryKnowledgeGraph;
import ghidrassist.graphrag.GraphRAGService;
import ghidrassist.graphrag.extraction.StructureExtractor;

/**
 * Background worker for reindexing a binary's knowledge graph.
 *
 * This worker performs a NON-DESTRUCTIVE reindex that:
 * - Preserves existing LLM summaries, security flags, and embeddings
 * - Updates structural data (function names, addresses, call edges)
 * - Marks changed nodes as stale for re-summarization
 *
 * The upsertNode() method uses COALESCE to preserve semantic data fields
 * when they are null in the new node but exist in the database.
 */
public class ReindexWorker extends AnalysisWorker<ReindexWorker.Result> {

    private final AnalysisDB analysisDB;
    private final Program program;

    public static class Result {
        public final int functionsExtracted;
        public final int callEdgesCreated;
        public final int nodesMarkedStale;

        public Result(int functionsExtracted, int callEdgesCreated) {
            this(functionsExtracted, callEdgesCreated, 0);
        }

        public Result(int functionsExtracted, int callEdgesCreated, int nodesMarkedStale) {
            this.functionsExtracted = functionsExtracted;
            this.callEdgesCreated = callEdgesCreated;
            this.nodesMarkedStale = nodesMarkedStale;
        }
    }

    public ReindexWorker(AnalysisDB analysisDB, Program program) {
        this.analysisDB = analysisDB;
        this.program = program;
    }

    @Override
    protected Result doInBackground() throws Exception {
        GraphRAGService service = GraphRAGService.getInstance(analysisDB);
        service.setCurrentProgram(program);

        // NON-DESTRUCTIVE: Mark existing nodes as stale instead of deleting
        publishProgress(0, 100, "Marking nodes for update...");
        BinaryKnowledgeGraph graph = analysisDB.getKnowledgeGraph(program.getExecutableSHA256());
        int markedStale = graph.markAllStale();
        Msg.info(this, "Marked " + markedStale + " nodes as stale for non-destructive reindex");

        if (isCancelRequested()) {
            return new Result(0, 0, markedStale);
        }

        // Create a TaskMonitor that bridges to our SwingWorker
        SwingWorkerTaskMonitor monitor = new SwingWorkerTaskMonitor(
                (current, total, message) -> {
                    // Scale progress to 10-95 range (0-10 is marking, 95-100 is finalizing)
                    int scaledProgress = total > 0 ? 10 + (int) ((current * 85L) / total) : 10;
                    publishProgress(scaledProgress, 100, message);
                },
                this::isCancelRequested
        );

        // Index structure with incremental mode enabled
        // Incremental mode preserves semantic data via COALESCE in upsertNode
        publishProgress(10, 100, "Updating binary structure...");
        StructureExtractor.ExtractionResult result = service.indexStructureSync(program, monitor, false, true);

        if (isCancelRequested()) {
            return new Result(result.functionsExtracted, result.callEdgesCreated, markedStale);
        }

        // Rebuild FTS index to reflect newly-indexed nodes
        publishProgress(95, 100, "Rebuilding search index...");
        analysisDB.rebuildFts();

        // Invalidate cache to ensure fresh data is loaded
        publishProgress(98, 100, "Finalizing...");
        analysisDB.invalidateKnowledgeGraphCache(program.getExecutableSHA256());

        publishProgress(100, 100, "Complete");
        Msg.info(this, String.format("ReIndex complete: %d functions, %d edges (non-destructive, %d nodes marked stale)",
                result.functionsExtracted, result.callEdgesCreated, markedStale));
        return new Result(result.functionsExtracted, result.callEdgesCreated, markedStale);
    }
}
