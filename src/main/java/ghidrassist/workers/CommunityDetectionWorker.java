package ghidrassist.workers;

import ghidra.program.model.listing.Program;
import ghidrassist.AnalysisDB;
import ghidrassist.graphrag.BinaryKnowledgeGraph;
import ghidrassist.graphrag.community.CommunityDetector;

/**
 * Background worker for community detection using Label Propagation.
 */
public class CommunityDetectionWorker extends AnalysisWorker<CommunityDetectionWorker.Result> {

    private final AnalysisDB analysisDB;
    private final Program program;

    public static class Result {
        public final int communityCount;

        public Result(int communityCount) {
            this.communityCount = communityCount;
        }
    }

    public CommunityDetectionWorker(AnalysisDB analysisDB, Program program) {
        this.analysisDB = analysisDB;
        this.program = program;
    }

    @Override
    protected Result doInBackground() throws Exception {
        String programHash = program.getExecutableSHA256();
        BinaryKnowledgeGraph graph = analysisDB.getKnowledgeGraph(programHash);

        if (graph == null) {
            throw new Exception("Binary is not indexed. Please run ReIndex first.");
        }

        publishProgress(0, 100, "Detecting communities...");

        // Create task monitor that respects cancellation
        SwingWorkerTaskMonitor monitor = new SwingWorkerTaskMonitor(
            (current, total, msg) -> publishProgress(current, total, msg),
            this::isCancelRequested
        );

        // Create community detector
        CommunityDetector detector = new CommunityDetector(graph, monitor);

        if (isCancelRequested()) {
            return new Result(0);
        }

        publishProgress(10, 100, "Running Label Propagation algorithm...");

        // Run community detection
        int communityCount = detector.detectCommunities();

        if (isCancelRequested()) {
            return new Result(communityCount);
        }

        publishProgress(90, 100, "Finalizing...");

        // Invalidate cache
        analysisDB.invalidateKnowledgeGraphCache(programHash);

        publishProgress(100, 100, "Complete");
        return new Result(communityCount);
    }
}
