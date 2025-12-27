package ghidrassist.graphrag.query;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import ghidrassist.AnalysisDB;
import ghidrassist.graphrag.BinaryKnowledgeGraph;
import ghidrassist.graphrag.GraphRAGEngine;
import ghidrassist.graphrag.GraphRAGService;
import ghidrassist.graphrag.extraction.SecurityFeatureExtractor;
import ghidrassist.graphrag.extraction.SecurityFeatures;
import ghidrassist.graphrag.extraction.StructureExtractor;
import ghidrassist.graphrag.nodes.KnowledgeNode;
import ghidrassist.mcp2.tools.MCPTool;
import ghidrassist.mcp2.tools.MCPToolResult;

import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * Provides built-in LLM-free semantic query tools for the Graph-RAG system.
 *
 * These tools are executed locally (no MCP server required) and return
 * pre-computed semantic analysis from the knowledge graph.
 *
 * All tool executions are LLM-free - they only perform graph traversal
 * and database lookups.
 */
public class SemanticQueryTools {

    private static final String SERVER_NAME = "GraphRAG-BuiltIn";
    private static final String TOOL_PREFIX = "ga_";
    private static final Gson gson = new Gson();

    private final AnalysisDB analysisDB;
    private Program currentProgram;
    private BinaryKnowledgeGraph graph;
    private GraphRAGEngine engine;

    public SemanticQueryTools(AnalysisDB analysisDB) {
        this.analysisDB = analysisDB;
    }

    /**
     * Set the current program for tool execution.
     */
    public void setCurrentProgram(Program program) {
        this.currentProgram = program;
        if (program != null) {
            String programHash = program.getExecutableSHA256();
            this.graph = analysisDB.getKnowledgeGraph(programHash);
            this.engine = new GraphRAGEngine(graph);
        } else {
            this.graph = null;
            this.engine = null;
        }
    }

    /**
     * Check if tools are available (program must be set).
     */
    public boolean isAvailable() {
        return engine != null && currentProgram != null;
    }

    // ========================================
    // Tool Definitions
    // ========================================

    /**
     * Get all semantic query tools as MCPTool objects.
     * These can be registered with the tool manager.
     */
    public List<MCPTool> getToolDefinitions() {
        List<MCPTool> tools = new ArrayList<>();

        // 1. ga.get_semantic_analysis
        tools.add(createTool(
                TOOL_PREFIX + "get_semantic_analysis",
                "Get pre-computed semantic analysis for a function. Returns LLM-generated summary, " +
                "security flags, caller/callee relationships, and decompiled code. NO LLM call at query time.",
                createSchema(
                        Map.of(
                                "address", Map.of("type", "string", "description", "Function address (hex, e.g., '0x401000')"),
                                "function_name", Map.of("type", "string", "description", "Function name (alternative to address)")
                        ),
                        List.of() // Neither is strictly required, but one should be provided
                )
        ));

        // 2. ga.get_similar_functions
        tools.add(createTool(
                TOOL_PREFIX + "get_similar_functions",
                "Find functions similar to the specified function based on graph structure " +
                "(shared callers, shared callees, community membership, keyword matching). NO LLM call.",
                createSchema(
                        Map.of(
                                "address", Map.of("type", "string", "description", "Function address (hex)"),
                                "limit", Map.of("type", "integer", "description", "Maximum results (default: 10)")
                        ),
                        List.of("address")
                )
        ));

        // 3. ga.get_call_context
        tools.add(createTool(
                TOOL_PREFIX + "get_call_context",
                "Get caller and callee functions with their semantic summaries. " +
                "Useful for understanding function relationships. NO LLM call.",
                createSchema(
                        Map.of(
                                "address", Map.of("type", "string", "description", "Function address (hex)"),
                                "depth", Map.of("type", "integer", "description", "How many levels deep (default: 1)"),
                                "direction", Map.of("type", "string", "description", "callers, callees, or both (default: both)")
                        ),
                        List.of("address")
                )
        ));

        // 4. ga.get_security_analysis
        tools.add(createTool(
                TOOL_PREFIX + "get_security_analysis",
                "Get security analysis including vulnerability flags, taint paths, and attack surface. " +
                "Can analyze a single function or the entire binary. NO LLM call.",
                createSchema(
                        Map.of(
                                "address", Map.of("type", "string", "description", "Function address (hex, optional)"),
                                "scope", Map.of("type", "string", "description", "function or binary (default: function)")
                        ),
                        List.of()
                )
        ));

        // 5. ga.search_semantic
        tools.add(createTool(
                TOOL_PREFIX + "search_semantic",
                "Search for functions by semantic keywords in their pre-computed summaries. " +
                "Uses full-text search (FTS5) on cached LLM analysis. NO LLM call at query time.",
                createSchema(
                        Map.of(
                                "query", Map.of("type", "string", "description", "Search query (keywords, phrases)"),
                                "limit", Map.of("type", "integer", "description", "Maximum results (default: 20)")
                        ),
                        List.of("query")
                )
        ));

        // 6. ga.get_module_summary
        tools.add(createTool(
                TOOL_PREFIX + "get_module_summary",
                "Get the community/module summary for a function's containing subsystem. " +
                "Returns module-level semantic analysis. NO LLM call.",
                createSchema(
                        Map.of(
                                "address", Map.of("type", "string", "description", "Function address (hex)")
                        ),
                        List.of("address")
                )
        ));

        // 7. ga.get_activity_analysis
        tools.add(createTool(
                TOOL_PREFIX + "get_activity_analysis",
                "Get network and file I/O activity analysis for a function. " +
                "Returns detected API calls (socket, send, recv, fopen, etc.), " +
                "string references (IPs, URLs, file paths, domains), " +
                "activity profile (NETWORK_CLIENT, FILE_WRITER, etc.), and risk level. NO LLM call.",
                createSchema(
                        Map.of(
                                "address", Map.of("type", "string", "description", "Function address (hex)"),
                                "function_name", Map.of("type", "string", "description", "Function name (alternative to address)")
                        ),
                        List.of() // Neither required, but one should be provided
                )
        ));

        // 8. ga.update_security_flags
        tools.add(createTool(
                TOOL_PREFIX + "update_security_flags",
                "Update security vulnerability flags for functions. Analyzes functions to detect " +
                "dangerous function calls (strcpy, sprintf, system, etc.) and potential vulnerabilities " +
                "(buffer overflow, command injection, format string). Can update a single function or all functions. " +
                "NO LLM call - uses static analysis only.",
                createSchema(
                        Map.of(
                                "address", Map.of("type", "string", "description", "Function address (hex, optional - if omitted updates all)"),
                                "function_name", Map.of("type", "string", "description", "Function name (alternative to address)"),
                                "force", Map.of("type", "boolean", "description", "Force re-analysis even if flags exist (default: false)")
                        ),
                        List.of() // None required - omitting all updates entire binary
                )
        ));

        return tools;
    }

    // ========================================
    // Tool Execution
    // ========================================

    /**
     * Execute a semantic query tool.
     *
     * @param toolName Name of the tool
     * @param arguments Tool arguments as JSON object
     * @return Tool result
     */
    public CompletableFuture<MCPToolResult> executeTool(String toolName, JsonObject arguments) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                if (!isAvailable()) {
                    return MCPToolResult.error("No program loaded or Graph-RAG not initialized");
                }

                // Switch on the full prefixed name (case-insensitive)
                String lowerName = toolName.toLowerCase();
                switch (lowerName) {
                    case "ga_get_semantic_analysis":
                        return executeGetSemanticAnalysis(arguments);
                    case "ga_get_similar_functions":
                        return executeGetSimilarFunctions(arguments);
                    case "ga_get_call_context":
                        return executeGetCallContext(arguments);
                    case "ga_get_security_analysis":
                        return executeGetSecurityAnalysis(arguments);
                    case "ga_search_semantic":
                        return executeSearchSemantic(arguments);
                    case "ga_get_module_summary":
                        return executeGetModuleSummary(arguments);
                    case "ga_get_activity_analysis":
                        return executeGetActivityAnalysis(arguments);
                    case "ga_update_security_flags":
                        return executeUpdateSecurityFlags(arguments);
                    default:
                        return MCPToolResult.error("Unknown tool: " + toolName);
                }
            } catch (Exception e) {
                Msg.error(this, "Tool execution failed: " + e.getMessage(), e);
                return MCPToolResult.error("Tool execution failed: " + e.getMessage());
            }
        });
    }

    /**
     * Check if this class handles the given tool.
     */
    public boolean handlesTool(String toolName) {
        if (toolName == null) return false;
        String lowerName = toolName.toLowerCase();
        return lowerName.equals("ga_get_semantic_analysis") ||
               lowerName.equals("ga_get_similar_functions") ||
               lowerName.equals("ga_get_call_context") ||
               lowerName.equals("ga_get_security_analysis") ||
               lowerName.equals("ga_search_semantic") ||
               lowerName.equals("ga_get_module_summary") ||
               lowerName.equals("ga_get_activity_analysis") ||
               lowerName.equals("ga_update_security_flags");
    }

    // ========================================
    // Individual Tool Implementations
    // ========================================

    private MCPToolResult executeGetSemanticAnalysis(JsonObject arguments) {
        SemanticAnalysis result;
        long address = 0;
        String functionName = null;

        if (arguments.has("address")) {
            address = parseAddress(arguments.get("address").getAsString());
            Msg.info(this, "get_semantic_analysis: Looking up address 0x" + Long.toHexString(address));
            result = engine.getSemanticAnalysis(address);
        } else if (arguments.has("function_name")) {
            functionName = arguments.get("function_name").getAsString();
            Msg.info(this, "get_semantic_analysis: Looking up function name: " + functionName);
            result = engine.getSemanticAnalysis(functionName);
        } else {
            return MCPToolResult.error("Either 'address' or 'function_name' is required");
        }

        Msg.info(this, "get_semantic_analysis: Initial result - indexed=" + result.isIndexed() +
                ", hasData=" + result.hasData() + ", hasSemantic=" + result.hasSemanticAnalysis() +
                ", name=" + result.getName());

        // Determine what actions are needed
        boolean needsStructureIndexing = !result.isIndexed();
        boolean needsSemanticAnalysis = !result.hasSemanticAnalysis();

        Function func = null;
        if (needsStructureIndexing || needsSemanticAnalysis) {
            func = lookupFunction(address, functionName);
        }

        // If not indexed at all, trigger structure extraction first
        if (needsStructureIndexing) {
            Msg.info(this, "Function not indexed, triggering lazy indexing...");
            if (func != null) {
                Msg.info(this, "Found function in Ghidra: " + func.getName() + " at 0x" +
                        Long.toHexString(func.getEntryPoint().getOffset()));
                boolean indexed = indexFunctionOnDemand(func);
                if (indexed) {
                    // Retry the query after indexing
                    long funcAddress = func.getEntryPoint().getOffset();
                    result = engine.getSemanticAnalysis(funcAddress);
                    Msg.info(this, "Lazy indexing complete for: " + func.getName() +
                            " - result indexed=" + result.isIndexed() +
                            ", hasData=" + result.hasData() +
                            ", rawCode=" + (result.getRawCode() != null ? "present" : "null"));
                }
            } else {
                Msg.warn(this, "Could not find function in Ghidra for address 0x" +
                        Long.toHexString(address) + " or name: " + functionName);
            }
        }
        // If indexed but missing semantic analysis, queue for background LLM processing
        else if (needsSemanticAnalysis && func != null) {
            Msg.info(this, "Function indexed but missing LLM summary, queueing for semantic analysis...");
            queueFunctionForSemanticAnalysis(func);
        }

        // Auto-detect and update missing security flags
        if (func == null) {
            func = lookupFunction(address, functionName);
        }
        if (func != null) {
            ensureSecurityFlags(func);
        }

        String output = result.toToolOutput();
        Msg.debug(this, "get_semantic_analysis: Returning output length=" + output.length());
        return MCPToolResult.success(output);
    }

    /**
     * Look up a function by address or name.
     */
    private Function lookupFunction(long address, String functionName) {
        if (currentProgram == null) {
            return null;
        }

        FunctionManager funcMgr = currentProgram.getFunctionManager();

        // Try by address first
        if (address != 0) {
            Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(address);
            Function func = funcMgr.getFunctionAt(addr);
            if (func == null) {
                func = funcMgr.getFunctionContaining(addr);
            }
            if (func != null) {
                return func;
            }
        }

        // Try by name
        if (functionName != null && !functionName.isEmpty()) {
            for (Function func : funcMgr.getFunctions(true)) {
                if (functionName.equals(func.getName())) {
                    return func;
                }
            }
        }

        return null;
    }

    /**
     * Index a single function on-demand (lazy indexing).
     * This performs structure extraction and queues the function for background LLM summarization.
     * Also queues neighbor functions (callers/callees) for background indexing (depth=1).
     *
     * @param function The function to index
     * @return true if indexing succeeded
     */
    private boolean indexFunctionOnDemand(Function function) {
        if (function == null || graph == null || currentProgram == null) {
            return false;
        }

        try {
            StructureExtractor extractor = new StructureExtractor(currentProgram, graph, TaskMonitor.DUMMY);
            try {
                // Extract just this one function - returns KnowledgeNode or null
                ghidrassist.graphrag.nodes.KnowledgeNode node = extractor.extractFunction(function);
                if (node != null) {
                    long address = function.getEntryPoint().getOffset();
                    String programHash = currentProgram.getExecutableSHA256();

                    Msg.info(this, String.format("On-demand indexed function %s at 0x%x",
                            function.getName(), address));

                    // Queue this function for background LLM summarization
                    GraphRAGService service = GraphRAGService.getInstance(analysisDB);
                    service.setCurrentProgram(currentProgram);
                    service.queueForSemanticAnalysis(address, programHash);

                    // Queue neighbors (callers/callees) for background indexing (depth=1)
                    queueNeighbors(function, programHash, service);

                    return true;
                }
                return false;
            } finally {
                extractor.dispose();
            }
        } catch (Exception e) {
            Msg.error(this, "Failed to index function on-demand: " + e.getMessage(), e);
            return false;
        }
    }

    /**
     * Queue neighbor functions (callers and callees) for background indexing.
     * This implements depth=1 neighbor propagation.
     *
     * @param function The function whose neighbors to queue
     * @param programHash SHA256 hash of the program
     * @param service The GraphRAGService instance
     */
    private void queueNeighbors(Function function, String programHash, GraphRAGService service) {
        if (function == null || currentProgram == null) {
            return;
        }

        int neighborsQueued = 0;

        // Queue callers (functions that call this one)
        try {
            if (function.getSymbol() != null) {
                ReferenceIterator refIter = currentProgram.getReferenceManager()
                        .getReferencesTo(function.getEntryPoint());
                while (refIter.hasNext()) {
                    Reference ref = refIter.next();
                    if (ref.getReferenceType().isCall()) {
                        Function caller = currentProgram.getFunctionManager()
                                .getFunctionContaining(ref.getFromAddress());
                        if (caller != null) {
                            long callerAddr = caller.getEntryPoint().getOffset();
                            if (!graph.hasFunctionCached(callerAddr)) {
                                service.queueForSemanticAnalysis(callerAddr, programHash);
                                neighborsQueued++;
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            Msg.warn(this, "Error queueing callers: " + e.getMessage());
        }

        // Queue callees (functions this one calls)
        try {
            for (Function callee : function.getCalledFunctions(TaskMonitor.DUMMY)) {
                long calleeAddr = callee.getEntryPoint().getOffset();
                if (!graph.hasFunctionCached(calleeAddr)) {
                    service.queueForSemanticAnalysis(calleeAddr, programHash);
                    neighborsQueued++;
                }
            }
        } catch (Exception e) {
            Msg.warn(this, "Error queueing callees: " + e.getMessage());
        }

        if (neighborsQueued > 0) {
            Msg.info(this, String.format("Queued %d neighbor functions for background analysis", neighborsQueued));
        }
    }

    /**
     * Queue a function for background semantic (LLM) analysis.
     * Used when a function is already indexed structurally but missing LLM summary.
     * Also queues neighbors that are missing semantic analysis.
     *
     * @param function The function to queue for semantic analysis
     */
    private void queueFunctionForSemanticAnalysis(Function function) {
        if (function == null || currentProgram == null) {
            return;
        }

        try {
            String programHash = currentProgram.getExecutableSHA256();
            long address = function.getEntryPoint().getOffset();

            GraphRAGService service = GraphRAGService.getInstance(analysisDB);
            service.setCurrentProgram(currentProgram);

            // Queue this function for LLM semantic analysis
            service.queueForSemanticAnalysis(address, programHash);
            Msg.info(this, String.format("Queued function %s (0x%x) for semantic analysis",
                    function.getName(), address));

            // Also queue neighbors that are missing semantic analysis
            queueNeighborsForSemanticAnalysis(function, programHash, service);
        } catch (Exception e) {
            Msg.error(this, "Failed to queue function for semantic analysis: " + e.getMessage(), e);
        }
    }

    /**
     * Queue neighbor functions (callers and callees) for semantic analysis
     * if they exist in the graph but are missing LLM summaries.
     *
     * @param function The function whose neighbors to check
     * @param programHash SHA256 hash of the program
     * @param service The GraphRAGService instance
     */
    private void queueNeighborsForSemanticAnalysis(Function function, String programHash, GraphRAGService service) {
        if (function == null || currentProgram == null || graph == null) {
            return;
        }

        int neighborsQueued = 0;

        // Check callers (functions that call this one)
        try {
            if (function.getSymbol() != null) {
                ReferenceIterator refIter = currentProgram.getReferenceManager()
                        .getReferencesTo(function.getEntryPoint());
                while (refIter.hasNext()) {
                    Reference ref = refIter.next();
                    if (ref.getReferenceType().isCall()) {
                        Function caller = currentProgram.getFunctionManager()
                                .getFunctionContaining(ref.getFromAddress());
                        if (caller != null) {
                            long callerAddr = caller.getEntryPoint().getOffset();
                            // Check if node exists but lacks semantic analysis
                            KnowledgeNode node = graph.getNodeByAddress(callerAddr);
                            if (node != null && !hasSemanticAnalysis(node)) {
                                service.queueForSemanticAnalysis(callerAddr, programHash);
                                neighborsQueued++;
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            Msg.warn(this, "Error checking callers for semantic analysis: " + e.getMessage());
        }

        // Check callees (functions this one calls)
        try {
            for (Function callee : function.getCalledFunctions(TaskMonitor.DUMMY)) {
                long calleeAddr = callee.getEntryPoint().getOffset();
                // Check if node exists but lacks semantic analysis
                KnowledgeNode node = graph.getNodeByAddress(calleeAddr);
                if (node != null && !hasSemanticAnalysis(node)) {
                    service.queueForSemanticAnalysis(calleeAddr, programHash);
                    neighborsQueued++;
                }
            }
        } catch (Exception e) {
            Msg.warn(this, "Error checking callees for semantic analysis: " + e.getMessage());
        }

        if (neighborsQueued > 0) {
            Msg.info(this, String.format("Queued %d neighbors for semantic analysis", neighborsQueued));
        }
    }

    /**
     * Check if a node has semantic (LLM) analysis completed.
     *
     * @param node The knowledge node to check
     * @return true if the node has semantic analysis
     */
    private boolean hasSemanticAnalysis(KnowledgeNode node) {
        if (node == null) {
            return false;
        }
        // Check if the node has an LLM-generated summary
        String summary = node.getLlmSummary();
        return summary != null && !summary.isEmpty() && !summary.equals("pending");
    }

    /**
     * Ensure security flags are populated for a function.
     * If the function node exists but has no security flags, triggers security analysis.
     *
     * @param function The function to check and update
     */
    private void ensureSecurityFlags(Function function) {
        if (function == null || graph == null || currentProgram == null) {
            return;
        }

        try {
            GraphRAGService service = GraphRAGService.getInstance(analysisDB);
            service.setCurrentProgram(currentProgram);

            if (service.needsSecurityFlagsUpdate(function)) {
                Msg.debug(this, "Auto-updating security flags for: " + function.getName());
                service.updateSecurityFlags(function, TaskMonitor.DUMMY);
            }
        } catch (Exception e) {
            Msg.debug(this, "Failed to auto-update security flags: " + e.getMessage());
        }
    }

    private MCPToolResult executeGetSimilarFunctions(JsonObject arguments) {
        if (!arguments.has("address")) {
            return MCPToolResult.error("'address' is required");
        }

        long address = parseAddress(arguments.get("address").getAsString());
        int limit = arguments.has("limit") ? arguments.get("limit").getAsInt() : 10;

        List<SimilarFunction> results = engine.getSimilarFunctions(address, limit);

        // Format output
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"count\": ").append(results.size()).append(",\n");
        sb.append("  \"similar_functions\": [\n");
        for (int i = 0; i < results.size(); i++) {
            if (i > 0) sb.append(",\n");
            String resultOutput = results.get(i).toToolOutput();
            String indented = resultOutput.replace("\n", "\n    ");
            sb.append("    ").append(indented);
        }
        sb.append("\n  ]\n");
        sb.append("}");

        return MCPToolResult.success(sb.toString());
    }

    private MCPToolResult executeGetCallContext(JsonObject arguments) {
        if (!arguments.has("address")) {
            return MCPToolResult.error("'address' is required");
        }

        long address = parseAddress(arguments.get("address").getAsString());
        int depth = arguments.has("depth") ? arguments.get("depth").getAsInt() : 1;

        CallContext.Direction direction = CallContext.Direction.BOTH;
        if (arguments.has("direction")) {
            String dir = arguments.get("direction").getAsString().toLowerCase();
            if (dir.equals("callers")) {
                direction = CallContext.Direction.CALLERS;
            } else if (dir.equals("callees")) {
                direction = CallContext.Direction.CALLEES;
            }
        }

        CallContext result = engine.getCallContext(address, depth, direction);
        return MCPToolResult.success(result.toToolOutput());
    }

    private MCPToolResult executeGetSecurityAnalysis(JsonObject arguments) {
        String scope = arguments.has("scope") ?
                arguments.get("scope").getAsString().toLowerCase() : "function";

        SecurityAnalysis result;
        if (scope.equals("binary")) {
            String binaryId = currentProgram.getExecutableSHA256();
            result = engine.getBinarySecurityAnalysis(binaryId);
        } else if (arguments.has("address")) {
            long address = parseAddress(arguments.get("address").getAsString());

            // Auto-detect and update missing security flags before querying
            Function func = lookupFunction(address, null);
            if (func != null) {
                ensureSecurityFlags(func);
            }

            result = engine.getSecurityAnalysis(address);
        } else {
            return MCPToolResult.error("'address' is required for function-level security analysis");
        }

        return MCPToolResult.success(result.toToolOutput());
    }

    private MCPToolResult executeSearchSemantic(JsonObject arguments) {
        if (!arguments.has("query")) {
            return MCPToolResult.error("'query' is required");
        }

        String query = arguments.get("query").getAsString();
        int limit = arguments.has("limit") ? arguments.get("limit").getAsInt() : 20;

        List<SearchResult> results = engine.searchSemantic(query, limit);
        return MCPToolResult.success(SearchResult.listToToolOutput(results));
    }

    private MCPToolResult executeGetModuleSummary(JsonObject arguments) {
        if (!arguments.has("address")) {
            return MCPToolResult.error("'address' is required");
        }

        long address = parseAddress(arguments.get("address").getAsString());
        ModuleSummary result = engine.getModuleSummary(address);
        return MCPToolResult.success(result.toToolOutput());
    }

    private MCPToolResult executeGetActivityAnalysis(JsonObject arguments) {
        long address = 0;
        String functionName = null;

        if (arguments.has("address")) {
            address = parseAddress(arguments.get("address").getAsString());
        } else if (arguments.has("function_name")) {
            functionName = arguments.get("function_name").getAsString();
        } else {
            return MCPToolResult.error("Either 'address' or 'function_name' is required");
        }

        // Look up function
        Function function = lookupFunction(address, functionName);
        if (function == null) {
            return MCPToolResult.error("Function not found for address 0x" +
                    Long.toHexString(address) + " or name: " + functionName);
        }

        // Ensure security flags are populated
        ensureSecurityFlags(function);

        // First, try to get cached activity analysis from the knowledge graph
        KnowledgeNode node = graph.getNodeByAddress(function.getEntryPoint().getOffset());

        SecurityFeatures features = null;

        if (node != null && node.getActivityProfile() != null) {
            // Use cached data from the graph
            features = buildFeaturesFromNode(node);
            Msg.info(this, "get_activity_analysis: Using cached features for " + function.getName());
        } else {
            // Extract fresh features
            Msg.info(this, "get_activity_analysis: Extracting fresh features for " + function.getName());
            SecurityFeatureExtractor extractor = new SecurityFeatureExtractor(currentProgram, TaskMonitor.DUMMY);
            features = extractor.extractFeatures(function);

            // Cache the features if we have a node
            if (node != null && !features.isEmpty()) {
                node.applySecurityFeatures(features);
                graph.upsertNode(node);
            }
        }

        // Build output JSON
        return MCPToolResult.success(buildActivityAnalysisOutput(function, features));
    }

    /**
     * Build SecurityFeatures from cached KnowledgeNode data.
     */
    private SecurityFeatures buildFeaturesFromNode(KnowledgeNode node) {
        SecurityFeatures features = new SecurityFeatures();

        // Add network APIs
        for (String api : node.getNetworkAPIs()) {
            features.addNetworkAPI(api);
        }

        // Add file I/O APIs
        for (String api : node.getFileIOAPIs()) {
            features.addFileIOAPI(api);
        }

        // Add IP addresses
        for (String ip : node.getIPAddresses()) {
            features.addIPAddress(ip);
        }

        // Add URLs
        for (String url : node.getURLs()) {
            features.addURL(url);
        }

        // Add file paths
        for (String path : node.getFilePaths()) {
            features.addFilePath(path);
        }

        // Add domains
        for (String domain : node.getDomains()) {
            features.addDomain(domain);
        }

        // Set computed fields if available
        features.calculateActivityProfile();
        features.calculateRiskLevel();

        return features;
    }

    /**
     * Build the JSON output for activity analysis.
     */
    private String buildActivityAnalysisOutput(Function function, SecurityFeatures features) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"function_name\": \"").append(escapeJson(function.getName())).append("\",\n");
        sb.append("  \"address\": \"0x").append(Long.toHexString(function.getEntryPoint().getOffset())).append("\",\n");

        if (features == null || features.isEmpty()) {
            sb.append("  \"has_activity\": false,\n");
            sb.append("  \"activity_profile\": \"NONE\",\n");
            sb.append("  \"risk_level\": \"LOW\"\n");
        } else {
            sb.append("  \"has_activity\": true,\n");
            sb.append("  \"activity_profile\": \"").append(escapeJson(features.getActivityProfile())).append("\",\n");
            sb.append("  \"risk_level\": \"").append(escapeJson(features.getRiskLevel())).append("\",\n");

            // Network APIs
            if (features.hasNetworkAPIs()) {
                sb.append("  \"network_apis\": ").append(toJsonArray(features.getNetworkAPIs())).append(",\n");
            }

            // File I/O APIs
            if (features.hasFileIOAPIs()) {
                sb.append("  \"file_io_apis\": ").append(toJsonArray(features.getFileIOAPIs())).append(",\n");
            }

            // Crypto APIs
            if (features.hasCryptoAPIs()) {
                sb.append("  \"crypto_apis\": ").append(toJsonArray(features.getCryptoAPIs())).append(",\n");
            }

            // Process APIs
            if (features.hasProcessAPIs()) {
                sb.append("  \"process_apis\": ").append(toJsonArray(features.getProcessAPIs())).append(",\n");
            }

            // String references
            if (features.hasIPAddresses()) {
                sb.append("  \"ip_addresses\": ").append(toJsonArray(features.getIPAddresses())).append(",\n");
            }

            if (features.hasURLs()) {
                sb.append("  \"urls\": ").append(toJsonArray(features.getURLs())).append(",\n");
            }

            if (features.hasFilePaths()) {
                sb.append("  \"file_paths\": ").append(toJsonArray(features.getFilePaths())).append(",\n");
            }

            if (features.hasDomains()) {
                sb.append("  \"domains\": ").append(toJsonArray(features.getDomains())).append(",\n");
            }

            if (features.hasRegistryKeys()) {
                sb.append("  \"registry_keys\": ").append(toJsonArray(features.getRegistryKeys())).append(",\n");
            }

            // Remove trailing comma if present
            String result = sb.toString();
            if (result.endsWith(",\n")) {
                result = result.substring(0, result.length() - 2) + "\n";
            }
            sb = new StringBuilder(result);
        }

        sb.append("}");
        return sb.toString();
    }

    /**
     * Execute the ga_update_security_flags tool.
     * Updates security vulnerability flags for functions by analyzing dangerous function calls.
     */
    private MCPToolResult executeUpdateSecurityFlags(JsonObject arguments) {
        long address = 0;
        String functionName = null;
        boolean force = arguments.has("force") && arguments.get("force").getAsBoolean();

        if (arguments.has("address")) {
            address = parseAddress(arguments.get("address").getAsString());
        } else if (arguments.has("function_name")) {
            functionName = arguments.get("function_name").getAsString();
        }

        GraphRAGService service = GraphRAGService.getInstance(analysisDB);
        service.setCurrentProgram(currentProgram);

        // Single function update
        if (address != 0 || functionName != null) {
            Function function = lookupFunction(address, functionName);
            if (function == null) {
                return MCPToolResult.error("Function not found for address 0x" +
                        Long.toHexString(address) + " or name: " + functionName);
            }

            // Check if already has flags (unless force)
            if (!force && !service.needsSecurityFlagsUpdate(function)) {
                KnowledgeNode node = graph.getNodeByAddress(function.getEntryPoint().getOffset());
                List<String> existingFlags = node != null ? node.getSecurityFlags() : List.of();
                return MCPToolResult.success(buildSecurityFlagsOutput(function.getName(),
                        function.getEntryPoint().getOffset(), existingFlags, false));
            }

            // Update security flags
            boolean success = service.updateSecurityFlags(function, TaskMonitor.DUMMY);
            if (success) {
                KnowledgeNode node = graph.getNodeByAddress(function.getEntryPoint().getOffset());
                List<String> flags = node != null ? node.getSecurityFlags() : List.of();
                return MCPToolResult.success(buildSecurityFlagsOutput(function.getName(),
                        function.getEntryPoint().getOffset(), flags, true));
            } else {
                return MCPToolResult.success(buildSecurityFlagsOutput(function.getName(),
                        function.getEntryPoint().getOffset(), List.of(), true));
            }
        }

        // Batch update all functions
        int updated = service.updateAllSecurityFlags(currentProgram, TaskMonitor.DUMMY);
        return MCPToolResult.success(buildBatchSecurityFlagsOutput(updated));
    }

    /**
     * Build JSON output for single function security flags update.
     */
    private String buildSecurityFlagsOutput(String functionName, long address, List<String> flags, boolean wasUpdated) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"function_name\": \"").append(escapeJson(functionName)).append("\",\n");
        sb.append("  \"address\": \"0x").append(Long.toHexString(address)).append("\",\n");
        sb.append("  \"updated\": ").append(wasUpdated).append(",\n");
        sb.append("  \"security_flags\": ").append(toJsonArray(flags)).append("\n");
        sb.append("}");
        return sb.toString();
    }

    /**
     * Build JSON output for batch security flags update.
     */
    private String buildBatchSecurityFlagsOutput(int updatedCount) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"scope\": \"binary\",\n");
        sb.append("  \"functions_updated\": ").append(updatedCount).append(",\n");
        sb.append("  \"message\": \"Updated security flags for ").append(updatedCount).append(" functions\"\n");
        sb.append("}");
        return sb.toString();
    }

    /**
     * Convert a list of strings to JSON array.
     */
    private String toJsonArray(List<String> list) {
        if (list == null || list.isEmpty()) {
            return "[]";
        }
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (String item : list) {
            if (!first) sb.append(", ");
            sb.append("\"").append(escapeJson(item)).append("\"");
            first = false;
        }
        sb.append("]");
        return sb.toString();
    }

    private String escapeJson(String str) {
        if (str == null) return "";
        return str.replace("\\", "\\\\")
                  .replace("\"", "\\\"")
                  .replace("\n", "\\n")
                  .replace("\r", "\\r")
                  .replace("\t", "\\t");
    }

    private String toJsonArray(java.util.Set<String> set) {
        if (set == null || set.isEmpty()) {
            return "[]";
        }
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (String item : set) {
            if (!first) sb.append(", ");
            sb.append("\"").append(escapeJson(item)).append("\"");
            first = false;
        }
        sb.append("]");
        return sb.toString();
    }

    // ========================================
    // Helper Methods
    // ========================================

    private long parseAddress(String addressStr) {
        if (addressStr == null || addressStr.isEmpty()) {
            return 0;
        }

        String cleaned = addressStr.trim().toLowerCase();
        if (cleaned.startsWith("0x")) {
            cleaned = cleaned.substring(2);
        }

        try {
            return Long.parseLong(cleaned, 16);
        } catch (NumberFormatException e) {
            Msg.warn(this, "Invalid address format: " + addressStr);
            return 0;
        }
    }

    private MCPTool createTool(String name, String description, JsonObject inputSchema) {
        return new MCPTool(name, description, inputSchema, SERVER_NAME);
    }

    private JsonObject createSchema(Map<String, Map<String, String>> properties, List<String> required) {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");

        JsonObject propsJson = new JsonObject();
        for (Map.Entry<String, Map<String, String>> entry : properties.entrySet()) {
            JsonObject prop = new JsonObject();
            for (Map.Entry<String, String> propEntry : entry.getValue().entrySet()) {
                prop.addProperty(propEntry.getKey(), propEntry.getValue());
            }
            propsJson.add(entry.getKey(), prop);
        }
        schema.add("properties", propsJson);

        if (!required.isEmpty()) {
            com.google.gson.JsonArray requiredArray = new com.google.gson.JsonArray();
            for (String req : required) {
                requiredArray.add(req);
            }
            schema.add("required", requiredArray);
        }

        return schema;
    }
}
