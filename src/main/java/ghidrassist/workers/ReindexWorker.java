package ghidrassist.workers;

import ghidra.program.model.listing.Program;
import ghidrassist.AnalysisDB;
import ghidrassist.graphrag.GraphRAGService;
import ghidrassist.graphrag.extraction.StructureExtractor;

/**
 * Background worker for reindexing a binary's knowledge graph.
 */
public class ReindexWorker extends AnalysisWorker<ReindexWorker.Result> {

    private final AnalysisDB analysisDB;
    private final Program program;

    public static class Result {
        public final int functionsExtracted;
        public final int callEdgesCreated;

        public Result(int functionsExtracted, int callEdgesCreated) {
            this.functionsExtracted = functionsExtracted;
            this.callEdgesCreated = callEdgesCreated;
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

        // Clear existing graph data
        publishProgress(0, 100, "Clearing existing graph data...");
        service.clearGraph(program);

        if (isCancelRequested()) {
            return new Result(0, 0);
        }

        // Create a TaskMonitor that bridges to our SwingWorker
        SwingWorkerTaskMonitor monitor = new SwingWorkerTaskMonitor(
                (current, total, message) -> {
                    // Scale progress to 10-95 range (0-10 is clearing, 95-100 is finalizing)
                    int scaledProgress = total > 0 ? 10 + (int) ((current * 85L) / total) : 10;
                    publishProgress(scaledProgress, 100, message);
                },
                this::isCancelRequested
        );

        // Index the binary structure
        publishProgress(10, 100, "Indexing binary structure...");
        StructureExtractor.ExtractionResult result = service.indexStructureSync(program, monitor, false);

        if (isCancelRequested()) {
            return new Result(result.functionsExtracted, result.callEdgesCreated);
        }

        // Invalidate cache
        publishProgress(95, 100, "Finalizing...");
        analysisDB.invalidateKnowledgeGraphCache(program.getExecutableSHA256());

        publishProgress(100, 100, "Complete");
        return new Result(result.functionsExtracted, result.callEdgesCreated);
    }
}
