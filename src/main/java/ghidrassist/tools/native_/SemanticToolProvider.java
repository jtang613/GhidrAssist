package ghidrassist.tools.native_;

import com.google.gson.JsonObject;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidrassist.AnalysisDB;
import ghidrassist.graphrag.query.SemanticQueryTools;
import ghidrassist.mcp2.tools.MCPTool;
import ghidrassist.mcp2.tools.MCPToolResult;
import ghidrassist.tools.api.Tool;
import ghidrassist.tools.api.ToolProvider;
import ghidrassist.tools.api.ToolResult;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

/**
 * Tool provider for Graph-RAG semantic query tools.
 * Wraps SemanticQueryTools to provide LLM-free semantic analysis capabilities.
 *
 * Tools provided:
 * - get_semantic_analysis: Get pre-computed semantic analysis for a function
 * - get_similar_functions: Find similar functions based on graph structure
 * - get_call_context: Get caller/callee context with semantic summaries
 * - get_security_analysis: Get security analysis for function or binary
 * - search_semantic: Search for functions by semantic keywords
 * - get_module_summary: Get community/module summary
 */
public class SemanticToolProvider implements ToolProvider {

    private static final String PROVIDER_NAME = "GraphRAG-Semantic";

    private final SemanticQueryTools queryTools;

    /**
     * Create a SemanticToolProvider with the given AnalysisDB.
     * @param analysisDB Database containing the knowledge graph
     */
    public SemanticToolProvider(AnalysisDB analysisDB) {
        this.queryTools = new SemanticQueryTools(analysisDB);
        Msg.info(this, "SemanticToolProvider initialized");
    }

    @Override
    public String getProviderName() {
        return PROVIDER_NAME;
    }

    @Override
    public List<Tool> getTools() {
        if (!queryTools.isAvailable()) {
            Msg.debug(this, "Semantic tools not available (no program context)");
            return Collections.emptyList();
        }

        List<MCPTool> mcpTools = queryTools.getToolDefinitions();
        Msg.debug(this, "Returning " + mcpTools.size() + " semantic tools");

        return mcpTools.stream()
                .map(mcp -> new NativeTool(mcp, PROVIDER_NAME))
                .collect(Collectors.toList());
    }

    @Override
    public CompletableFuture<ToolResult> executeTool(String name, JsonObject args) {
        Msg.info(this, "Executing semantic tool: " + name);

        return queryTools.executeTool(name, args)
                .thenApply(mcpResult -> {
                    if (!mcpResult.isSuccess()) {
                        Msg.debug(this, "Tool " + name + " returned error: " + mcpResult.getError());
                        return ToolResult.error(mcpResult.getError());
                    } else {
                        Msg.debug(this, "Tool " + name + " succeeded");
                        return ToolResult.success(mcpResult.getContent());
                    }
                });
    }

    @Override
    public boolean handlesTool(String name) {
        return queryTools.handlesTool(name);
    }

    @Override
    public void setContext(Program program) {
        queryTools.setCurrentProgram(program);
        if (program != null) {
            Msg.debug(this, "Set program context: " + program.getName());
        } else {
            Msg.debug(this, "Cleared program context");
        }
    }

    /**
     * Check if tools are available (requires program context).
     */
    public boolean isAvailable() {
        return queryTools.isAvailable();
    }
}
