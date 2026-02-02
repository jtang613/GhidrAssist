package ghidrassist.workers;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidrassist.services.symgraph.SymGraphService;
import ghidrassist.services.symgraph.SymGraphModels.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Background worker for pulling symbols and graph data from SymGraph.
 * Uses SwingWorker to run in the background without blocking the UI.
 */
public class SymGraphPullWorker extends AnalysisWorker<SymGraphPullWorker.Result> {

    /**
     * Result of the pull operation.
     */
    public static class Result {
        public final List<ConflictEntry> conflicts;
        public final GraphExport graphExport;
        public final int graphNodes;
        public final int graphEdges;
        public final int graphCommunities;
        public final long elapsedMs;
        public final boolean cancelled;
        public final String error;

        public Result(List<ConflictEntry> conflicts, GraphExport graphExport,
                      int graphNodes, int graphEdges, int graphCommunities,
                      long elapsedMs, boolean cancelled) {
            this.conflicts = conflicts;
            this.graphExport = graphExport;
            this.graphNodes = graphNodes;
            this.graphEdges = graphEdges;
            this.graphCommunities = graphCommunities;
            this.elapsedMs = elapsedMs;
            this.cancelled = cancelled;
            this.error = null;
        }

        public Result(String error) {
            this.conflicts = new ArrayList<>();
            this.graphExport = null;
            this.graphNodes = 0;
            this.graphEdges = 0;
            this.graphCommunities = 0;
            this.elapsedMs = 0;
            this.cancelled = false;
            this.error = error;
        }

        public Result(long elapsedMs, boolean cancelled) {
            this.conflicts = new ArrayList<>();
            this.graphExport = null;
            this.graphNodes = 0;
            this.graphEdges = 0;
            this.graphCommunities = 0;
            this.elapsedMs = elapsedMs;
            this.cancelled = cancelled;
            this.error = null;
        }
    }

    private final Program program;
    private final SymGraphService symGraphService;
    private final String sha256;
    private final List<String> symbolTypes;
    private final double minConfidence;
    private final boolean includeGraph;

    /**
     * Create a new SymGraphPullWorker.
     *
     * @param program        The Ghidra program (for local symbol lookup)
     * @param symGraphService The SymGraph service for API calls
     * @param sha256         SHA256 hash of the binary
     * @param symbolTypes    List of symbol types to fetch (function, variable, etc.)
     * @param minConfidence  Minimum confidence threshold for symbols
     * @param includeGraph   Whether to fetch graph data
     */
    public SymGraphPullWorker(Program program, SymGraphService symGraphService,
                               String sha256, List<String> symbolTypes,
                               double minConfidence, boolean includeGraph) {
        this.program = program;
        this.symGraphService = symGraphService;
        this.sha256 = sha256;
        this.symbolTypes = symbolTypes != null ? symbolTypes : new ArrayList<>();
        this.minConfidence = minConfidence;
        this.includeGraph = includeGraph;
    }

    @Override
    protected Result doInBackground() throws Exception {
        long startTime = System.currentTimeMillis();

        try {
            // Phase 1: Fetch symbols (0-60%)
            List<Symbol> allRemoteSymbols = new ArrayList<>();
            int totalTypes = symbolTypes.size();

            for (int i = 0; i < totalTypes; i++) {
                if (isCancelRequested()) {
                    long elapsed = System.currentTimeMillis() - startTime;
                    return new Result(elapsed, true);
                }

                String symType = symbolTypes.get(i);
                int progress = (int) ((i * 60L) / Math.max(totalTypes, 1));
                publishProgress(progress, 100, "Fetching " + symType + " symbols...");

                List<Symbol> remoteSymbols = symGraphService.getSymbols(sha256, symType);
                allRemoteSymbols.addAll(remoteSymbols);
                Msg.info(this, "Fetched " + remoteSymbols.size() + " " + symType + " symbols from API");
            }

            if (isCancelRequested()) {
                long elapsed = System.currentTimeMillis() - startTime;
                return new Result(elapsed, true);
            }

            // Phase 2: Fetch graph data (60-80%)
            GraphExport graphExport = null;
            int graphNodes = 0;
            int graphEdges = 0;
            int graphCommunities = 0;

            if (includeGraph) {
                publishProgress(60, 100, "Fetching graph data...");
                graphExport = symGraphService.exportGraph(sha256);
                if (graphExport != null) {
                    graphNodes = graphExport.getNodes().size();
                    graphEdges = graphExport.getEdges().size();
                    graphCommunities = getGraphCommunityCount(graphExport);
                }
            }

            if (isCancelRequested()) {
                long elapsed = System.currentTimeMillis() - startTime;
                return new Result(elapsed, true);
            }

            // Phase 3: Build conflict list (80-100%)
            publishProgress(80, 100, "Building conflict list...");

            Map<Long, String> localSymbols = getLocalSymbolMap();
            List<ConflictEntry> conflicts = symGraphService.buildConflictEntries(
                localSymbols, allRemoteSymbols, minConfidence);

            publishProgress(100, 100, "Complete");

            long elapsed = System.currentTimeMillis() - startTime;
            return new Result(conflicts, graphExport, graphNodes, graphEdges, graphCommunities, elapsed, false);

        } catch (Exception e) {
            Msg.error(this, "Pull preview error: " + e.getMessage(), e);
            return new Result(e.getMessage());
        }
    }

    /**
     * Get local symbol map for conflict detection.
     */
    private Map<Long, String> getLocalSymbolMap() {
        Map<Long, String> symbolMap = new HashMap<>();

        if (program == null) {
            return symbolMap;
        }

        try {
            for (Function func : program.getFunctionManager().getFunctions(true)) {
                String qualifiedName = ghidrassist.services.symgraph.SymGraphUtils.getQualifiedFunctionName(func);
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

    /**
     * Get the number of communities from graph export metadata.
     */
    private int getGraphCommunityCount(GraphExport export) {
        if (export == null || export.getMetadata() == null) {
            return 0;
        }
        Object countValue = export.getMetadata().get("community_count");
        if (countValue instanceof Number) {
            return ((Number) countValue).intValue();
        }
        Object communitiesValue = export.getMetadata().get("communities");
        if (communitiesValue instanceof java.util.List) {
            return ((java.util.List<?>) communitiesValue).size();
        }
        return 0;
    }
}
