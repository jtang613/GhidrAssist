package ghidrassist.workers;

import ghidra.program.model.listing.Program;
import ghidrassist.AnalysisDB;
import ghidrassist.graphrag.query.SemanticQueryTools;
import com.google.gson.JsonObject;

/**
 * Background worker for refreshing function names in the knowledge graph.
 */
public class RefreshNamesWorker extends AnalysisWorker<Boolean> {

    private final AnalysisDB analysisDB;
    private final Program program;

    public RefreshNamesWorker(AnalysisDB analysisDB, Program program) {
        this.analysisDB = analysisDB;
        this.program = program;
    }

    @Override
    protected Boolean doInBackground() throws Exception {
        publishProgress(0, 100, "Refreshing function names...");

        // Use the ga_refresh_names tool via SemanticQueryTools
        SemanticQueryTools tools = new SemanticQueryTools(analysisDB);
        tools.setCurrentProgram(program);

        JsonObject args = new JsonObject();
        tools.executeTool("ga_refresh_names", args).join();

        publishProgress(100, 100, "Complete");
        return true;
    }
}
