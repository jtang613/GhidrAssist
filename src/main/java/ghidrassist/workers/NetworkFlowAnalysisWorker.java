package ghidrassist.workers;

import ghidra.program.model.listing.Program;
import ghidrassist.AnalysisDB;
import ghidrassist.graphrag.BinaryKnowledgeGraph;
import ghidrassist.graphrag.analysis.TaintAnalyzer;

/**
 * Background worker for network flow analysis.
 * Creates NETWORK_SEND_PATH and NETWORK_RECV_PATH edges to trace
 * network data flow through the call graph.
 */
public class NetworkFlowAnalysisWorker extends AnalysisWorker<NetworkFlowAnalysisWorker.Result> {

    private final AnalysisDB analysisDB;
    private final Program program;
    private volatile TaintAnalyzer taintAnalyzer;

    public static class Result {
        public final int sendPathEdges;
        public final int recvPathEdges;
        public final int sendFunctionsFound;
        public final int recvFunctionsFound;

        public Result(int sendPathEdges, int recvPathEdges, int sendFunctionsFound, int recvFunctionsFound) {
            this.sendPathEdges = sendPathEdges;
            this.recvPathEdges = recvPathEdges;
            this.sendFunctionsFound = sendFunctionsFound;
            this.recvFunctionsFound = recvFunctionsFound;
        }
    }

    public NetworkFlowAnalysisWorker(AnalysisDB analysisDB, Program program) {
        this.analysisDB = analysisDB;
        this.program = program;
    }

    @Override
    public void requestCancel() {
        super.requestCancel();
        // Propagate cancellation to the TaintAnalyzer
        TaintAnalyzer analyzer = taintAnalyzer;
        if (analyzer != null) {
            analyzer.requestCancel();
        }
    }

    @Override
    protected Result doInBackground() throws Exception {
        String programHash = program.getExecutableSHA256();
        BinaryKnowledgeGraph graph = analysisDB.getKnowledgeGraph(programHash);

        if (graph == null) {
            throw new Exception("Binary is not indexed. Please run ReIndex first.");
        }

        publishProgress(0, 100, "Initializing network flow analysis...");

        // Create taint analyzer (reuses the same class for graph traversal)
        taintAnalyzer = new TaintAnalyzer(graph);

        // Set up progress callback to forward to worker progress
        taintAnalyzer.setProgressCallback((current, total, message) -> {
            // The message from TaintAnalyzer already contains percentage info
            // Parse the percentage from the message or use 0-100 scale
            // The TaintAnalyzer reports overall percentage in its messages
            publishProgress(current, total, message);
        });

        if (isCancelRequested()) {
            return new Result(0, 0, 0, 0);
        }

        // Run network flow analysis (progress is reported via callback)
        TaintAnalyzer.NetworkFlowResult flowResult = taintAnalyzer.analyzeNetworkFlow();

        if (isCancelRequested()) {
            return new Result(0, 0, 0, 0);
        }

        publishProgress(98, 100, "Finalizing...");

        // Invalidate cache to ensure new edges are visible
        analysisDB.invalidateKnowledgeGraphCache(programHash);

        publishProgress(100, 100, "Complete");
        return new Result(
            flowResult.getSendPathEdges(),
            flowResult.getRecvPathEdges(),
            flowResult.getSendFunctions().size(),
            flowResult.getRecvFunctions().size()
        );
    }
}
