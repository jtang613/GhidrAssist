package ghidrassist.workers;

import ghidra.program.model.listing.Program;
import ghidrassist.AnalysisDB;
import ghidrassist.graphrag.GraphRAGService;
import ghidrassist.graphrag.extraction.SemanticExtractor;

/**
 * Background worker for LLM semantic analysis (summarization of stale nodes).
 */
public class SemanticAnalysisWorker extends AnalysisWorker<SemanticAnalysisWorker.Result> {

    private final AnalysisDB analysisDB;
    private final Program program;
    private volatile SemanticExtractor extractor;

    public static class Result {
        public final int summarized;
        public final int errors;
        public final long elapsedMs;

        public Result(int summarized, int errors, long elapsedMs) {
            this.summarized = summarized;
            this.errors = errors;
            this.elapsedMs = elapsedMs;
        }
    }

    public SemanticAnalysisWorker(AnalysisDB analysisDB, Program program) {
        this.analysisDB = analysisDB;
        this.program = program;
    }

    @Override
    public void requestCancel() {
        super.requestCancel();
        // Also cancel the extractor if it's running
        if (extractor != null) {
            extractor.cancel();
        }
    }

    @Override
    protected Result doInBackground() throws Exception {
        GraphRAGService service = GraphRAGService.getInstance(analysisDB);
        service.setCurrentProgram(program);

        // Check if LLM provider is configured
        if (!service.hasLlmProvider()) {
            throw new Exception("No LLM provider configured. Please configure an API provider in Analysis Options.");
        }

        publishProgress(0, 100, "Running semantic analysis...");

        // Run semantic extraction with progress callback
        SemanticExtractor.ExtractionResult result = service.summarizeStaleNodes(
                program,
                0, // no limit
                (processed, total, summarized, errors) -> {
                    int pct = total > 0 ? (int) ((processed * 100L) / total) : 0;
                    publishProgress(pct, 100, String.format("Summarizing... %d/%d (%d errors)", processed, total, errors));

                    // Check for cancellation
                    if (isCancelRequested()) {
                        throw new RuntimeException("Cancelled");
                    }
                }
        );

        // Store extractor reference for cancellation
        // Note: The actual extractor is managed internally by GraphRAGService

        if (isCancelRequested()) {
            return new Result(result.summarized, result.errors, result.elapsedMs);
        }

        // Invalidate cache
        analysisDB.invalidateKnowledgeGraphCache(program.getExecutableSHA256());

        return new Result(result.summarized, result.errors, result.elapsedMs);
    }
}
