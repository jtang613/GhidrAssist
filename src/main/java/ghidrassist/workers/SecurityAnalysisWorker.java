package ghidrassist.workers;

import ghidra.program.model.listing.Program;
import ghidrassist.AnalysisDB;
import ghidrassist.graphrag.BinaryKnowledgeGraph;
import ghidrassist.graphrag.analysis.TaintAnalyzer;

import java.util.List;

/**
 * Background worker for security/taint analysis.
 */
public class SecurityAnalysisWorker extends AnalysisWorker<SecurityAnalysisWorker.Result> {

    private final AnalysisDB analysisDB;
    private final Program program;
    private volatile TaintAnalyzer taintAnalyzer;

    public static class Result {
        public final int pathCount;
        public final int vulnerableViaEdges;

        public Result(int pathCount, int vulnerableViaEdges) {
            this.pathCount = pathCount;
            this.vulnerableViaEdges = vulnerableViaEdges;
        }
    }

    public SecurityAnalysisWorker(AnalysisDB analysisDB, Program program) {
        this.analysisDB = analysisDB;
        this.program = program;
    }

    @Override
    public void requestCancel() {
        super.requestCancel();
        // TaintAnalyzer will check isCancelRequested during analysis
    }

    @Override
    protected Result doInBackground() throws Exception {
        String programHash = program.getExecutableSHA256();
        BinaryKnowledgeGraph graph = analysisDB.getKnowledgeGraph(programHash);

        if (graph == null) {
            throw new Exception("Binary is not indexed. Please run ReIndex first.");
        }

        publishProgress(0, 100, "Running taint analysis...");

        // Create taint analyzer
        taintAnalyzer = new TaintAnalyzer(graph);

        if (isCancelRequested()) {
            return new Result(0, 0);
        }

        // Find taint paths and create TAINT_FLOWS_TO edges
        List<TaintAnalyzer.TaintPath> taintPaths = taintAnalyzer.findTaintPaths(100, true);

        if (isCancelRequested()) {
            return new Result(taintPaths.size(), 0);
        }

        publishProgress(70, 100, "Creating VULNERABLE_VIA edges...");

        // Create VULNERABLE_VIA edges from entry points to vulnerable sinks
        int vulnerableViaEdges = taintAnalyzer.createVulnerableViaEdges();

        if (isCancelRequested()) {
            return new Result(taintPaths.size(), vulnerableViaEdges);
        }

        publishProgress(90, 100, "Finalizing...");

        // Invalidate cache
        analysisDB.invalidateKnowledgeGraphCache(programHash);

        publishProgress(100, 100, "Complete");
        return new Result(taintPaths.size(), vulnerableViaEdges);
    }
}
