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
import ghidrassist.graphrag.analysis.TaintAnalyzer;
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

        // 9. ga.index_binary
        tools.add(createTool(
                TOOL_PREFIX + "index_binary",
                "Trigger full binary indexing to populate the knowledge graph. Extracts all functions, " +
                "call graph, cross-references (REFERENCES edges), data dependencies (DATA_DEPENDS edges), " +
                "and vulnerable call edges (CALLS_VULNERABLE edges). This is required for comprehensive " +
                "graph queries. NO LLM call - uses Ghidra analysis only. May take time for large binaries.",
                createSchema(
                        Map.of(
                                "include_blocks", Map.of("type", "boolean", "description", "Include basic block extraction (increases graph size, default: false)"),
                                "force", Map.of("type", "boolean", "description", "Force re-indexing even if already indexed (default: false)")
                        ),
                        List.of() // None required
                )
        ));

        // 10. ga.record_vulnerability
        tools.add(createTool(
                TOOL_PREFIX + "record_vulnerability",
                "Record a discovered vulnerability or security finding for a function. " +
                "Use this when you identify potential security issues like buffer overflows, " +
                "command injection, format string bugs, use-after-free, etc. during analysis. " +
                "This persists findings to the knowledge graph and propagates vulnerability markers to callers.",
                createSchema(
                        Map.of(
                                "address", Map.of("type", "string", "description", "Function address (hex)"),
                                "function_name", Map.of("type", "string", "description", "Function name (alternative to address)"),
                                "vulnerability_type", Map.of("type", "string", "description",
                                        "Type: BUFFER_OVERFLOW, COMMAND_INJECTION, FORMAT_STRING, USE_AFTER_FREE, " +
                                        "INTEGER_OVERFLOW, PATH_TRAVERSAL, SQL_INJECTION, RACE_CONDITION, " +
                                        "MEMORY_LEAK, NULL_DEREF, INFO_DISCLOSURE, AUTH_BYPASS, CRYPTO_WEAKNESS, OTHER"),
                                "severity", Map.of("type", "string", "description", "Severity: LOW, MEDIUM, HIGH, CRITICAL"),
                                "description", Map.of("type", "string", "description", "Brief description of the vulnerability"),
                                "evidence", Map.of("type", "string", "description", "Code snippet or reasoning that supports this finding")
                        ),
                        List.of("vulnerability_type", "severity", "description") // Required fields
                )
        ));

        // 11. ga.add_security_flag
        tools.add(createTool(
                TOOL_PREFIX + "add_security_flag",
                "Add a security-relevant flag to a function's node in the knowledge graph. " +
                "Use this to mark functions with security-relevant properties you discover during analysis. " +
                "Common flags: HANDLES_USER_INPUT, PARSES_NETWORK_DATA, CRYPTO_OPERATION, " +
                "PRIVILEGE_CHECK, AUTHENTICATION, SENSITIVE_DATA, MEMORY_ALLOCATOR, ERROR_HANDLER",
                createSchema(
                        Map.of(
                                "address", Map.of("type", "string", "description", "Function address (hex)"),
                                "function_name", Map.of("type", "string", "description", "Function name (alternative to address)"),
                                "flag", Map.of("type", "string", "description", "Security flag to add (e.g., HANDLES_USER_INPUT)")
                        ),
                        List.of("flag") // flag is required
                )
        ));

        // 12. ga.detect_communities
        tools.add(createTool(
                TOOL_PREFIX + "detect_communities",
                "Run community detection on the function call graph to cluster related functions into modules. " +
                "Uses Label Propagation algorithm to identify communities based on call relationships. " +
                "Results are stored in the knowledge graph for use by ga_get_module_summary. NO LLM call.",
                createSchema(
                        Map.of(
                                "min_size", Map.of("type", "integer", "description", "Minimum community size (default: 2). Smaller communities are merged."),
                                "force", Map.of("type", "boolean", "description", "Force re-detection even if communities exist (default: false)")
                        ),
                        List.of() // None required
                )
        ));

        // 13. ga.global_query
        tools.add(createTool(
                TOOL_PREFIX + "global_query",
                "Get binary-wide analysis by aggregating insights across all detected communities. " +
                "Returns attack surface summary, security flag distribution across communities, " +
                "key functions per community, and cross-community patterns. " +
                "Requires community detection to have run first (use ga_detect_communities). NO LLM call.",
                createSchema(
                        Map.of(
                                "community_level", Map.of("type", "integer", "description", "Community level to query (default: 0 = function communities)"),
                                "include_members", Map.of("type", "boolean", "description", "Include full member function lists for each community (default: false)")
                        ),
                        List.of() // None required
                )
        ));

        // 14. ga.find_taint_paths
        tools.add(createTool(
                TOOL_PREFIX + "find_taint_paths",
                "Find data flow paths from taint sources (network input, file reads, user input) " +
                "to taint sinks (dangerous functions like strcpy, system, sprintf). " +
                "Identifies potential vulnerability chains where untrusted data flows to dangerous operations. " +
                "Can optionally create TAINT_FLOWS_TO edges in the graph. NO LLM call.",
                createSchema(
                        Map.of(
                                "source_address", Map.of("type", "string", "description", "Optional: Find paths from this specific source function (hex address)"),
                                "sink_address", Map.of("type", "string", "description", "Optional: Find paths to this specific sink function (hex address)"),
                                "max_paths", Map.of("type", "integer", "description", "Maximum number of paths to return (default: 20)"),
                                "create_edges", Map.of("type", "boolean", "description", "Create TAINT_FLOWS_TO edges along found paths (default: false)")
                        ),
                        List.of() // None required
                )
        ));

        // 15. ga.create_edge
        tools.add(createTool(
                TOOL_PREFIX + "create_edge",
                "Create a semantic relationship edge between two functions based on your analysis. " +
                "Use this to record relationships you discover during code review that aren't captured " +
                "by the structural call graph. Edge types: SIMILAR_PURPOSE (functions with similar behavior), " +
                "RELATED_TO (general semantic relationship), DEPENDS_ON (functional dependency), " +
                "IMPLEMENTS (implements a concept like 'authentication' or 'encryption'). " +
                "Edges are persisted to the knowledge graph. NO LLM call.",
                createSchema(
                        Map.of(
                                "source_address", Map.of("type", "string", "description", "Source function address (hex)"),
                                "source_name", Map.of("type", "string", "description", "Source function name (alternative to address)"),
                                "target_address", Map.of("type", "string", "description", "Target function address (hex)"),
                                "target_name", Map.of("type", "string", "description", "Target function name (alternative to address)"),
                                "edge_type", Map.of("type", "string", "description",
                                        "Edge type: SIMILAR_PURPOSE, RELATED_TO, DEPENDS_ON, IMPLEMENTS"),
                                "confidence", Map.of("type", "number", "description", "Confidence score 0.0-1.0 (default: 0.8)"),
                                "reason", Map.of("type", "string", "description", "Brief explanation of the relationship")
                        ),
                        List.of("edge_type") // edge_type is required
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
                    case "ga_index_binary":
                        return executeIndexBinary(arguments);
                    case "ga_record_vulnerability":
                        return executeRecordVulnerability(arguments);
                    case "ga_add_security_flag":
                        return executeAddSecurityFlag(arguments);
                    case "ga_detect_communities":
                        return executeDetectCommunities(arguments);
                    case "ga_global_query":
                        return executeGlobalQuery(arguments);
                    case "ga_find_taint_paths":
                        return executeFindTaintPaths(arguments);
                    case "ga_create_edge":
                        return executeCreateEdge(arguments);
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
               lowerName.equals("ga_update_security_flags") ||
               lowerName.equals("ga_index_binary") ||
               lowerName.equals("ga_record_vulnerability") ||
               lowerName.equals("ga_add_security_flag") ||
               lowerName.equals("ga_detect_communities") ||
               lowerName.equals("ga_global_query") ||
               lowerName.equals("ga_find_taint_paths") ||
               lowerName.equals("ga_create_edge");
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

        // Auto-detect and update missing security flags, edges, and stale names
        if (func == null) {
            func = lookupFunction(address, functionName);
        }
        if (func != null) {
            ensureNodeNameFresh(func);
            ensureSecurityFlags(func);
            ensureFunctionEdges(func);
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

    /**
     * Ensure all edge types are extracted for a function.
     * If the function node exists but is missing new edge types, triggers edge extraction.
     *
     * @param function The function to check and update
     */
    private void ensureFunctionEdges(Function function) {
        if (function == null || graph == null || currentProgram == null) {
            return;
        }

        try {
            KnowledgeNode node = graph.getNodeByAddress(function.getEntryPoint().getOffset());
            if (node == null) {
                return; // Node doesn't exist, will be created by indexFunctionOnDemand
            }

            // Check if any of the new edge types are missing
            boolean needsUpdate = !graph.hasEdgesOfType(node.getId(), ghidrassist.graphrag.nodes.EdgeType.REFERENCES) ||
                                  !graph.hasEdgesOfType(node.getId(), ghidrassist.graphrag.nodes.EdgeType.DATA_DEPENDS);

            // Also check for CALLS_VULNERABLE (either direction)
            if (!needsUpdate) {
                needsUpdate = !graph.hasEdgesOfType(node.getId(), ghidrassist.graphrag.nodes.EdgeType.CALLS_VULNERABLE) &&
                              !graph.hasIncomingEdgesOfType(node.getId(), ghidrassist.graphrag.nodes.EdgeType.CALLS_VULNERABLE);
            }

            if (needsUpdate) {
                Msg.debug(this, "Auto-updating edges for: " + function.getName());
                StructureExtractor extractor = new StructureExtractor(currentProgram, graph, TaskMonitor.DUMMY);
                try {
                    extractor.updateFunctionEdges(function, node);
                } finally {
                    extractor.dispose();
                }
            }
        } catch (Exception e) {
            Msg.debug(this, "Failed to auto-update edges: " + e.getMessage());
        }
    }

    /**
     * Ensure node name matches the current Ghidra function name.
     * If the user has renamed the function, update the node to reflect the new name.
     * The FTS index is automatically updated via database triggers.
     *
     * @param function The Ghidra function with the current name
     * @param node The knowledge node to check and update
     * @return true if the name was updated
     */
    private boolean ensureNodeNameFresh(Function function, KnowledgeNode node) {
        if (function == null || node == null || graph == null) {
            return false;
        }

        String currentName = function.getName();
        String storedName = node.getName();

        if (currentName != null && !currentName.equals(storedName)) {
            Msg.info(this, "Updating stale function name: " + storedName + " -> " + currentName);
            node.setName(currentName);
            graph.upsertNode(node);  // FTS index auto-updates via trigger
            return true;
        }
        return false;
    }

    /**
     * Ensure node name is fresh for a function, looking up the node if needed.
     *
     * @param function The Ghidra function
     */
    private void ensureNodeNameFresh(Function function) {
        if (function == null || graph == null) {
            return;
        }

        try {
            KnowledgeNode node = graph.getNodeByAddress(function.getEntryPoint().getOffset());
            if (node != null) {
                ensureNodeNameFresh(function, node);
            }
        } catch (Exception e) {
            Msg.debug(this, "Failed to check node name freshness: " + e.getMessage());
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

            // Auto-detect and update stale names, missing security flags and edges before querying
            Function func = lookupFunction(address, null);
            if (func != null) {
                ensureNodeNameFresh(func);
                ensureSecurityFlags(func);
                ensureFunctionEdges(func);
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

        // Ensure name is fresh, security flags and edges are populated
        ensureNodeNameFresh(function);
        ensureSecurityFlags(function);
        ensureFunctionEdges(function);

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
     * Execute the ga_index_binary tool.
     * Triggers full binary indexing to populate the knowledge graph with all edge types.
     */
    private MCPToolResult executeIndexBinary(JsonObject arguments) {
        boolean includeBlocks = arguments.has("include_blocks") && arguments.get("include_blocks").getAsBoolean();
        boolean force = arguments.has("force") && arguments.get("force").getAsBoolean();

        if (currentProgram == null) {
            return MCPToolResult.error("No program loaded");
        }

        String programHash = currentProgram.getExecutableSHA256();

        // Check if already indexed (unless force)
        if (!force && graph != null) {
            int existingFunctions = graph.getNodesByType(ghidrassist.graphrag.nodes.NodeType.FUNCTION).size();
            if (existingFunctions > 0) {
                return MCPToolResult.success(buildIndexSkippedOutput(existingFunctions));
            }
        }

        try {
            // Run synchronous structure extraction
            GraphRAGService service = GraphRAGService.getInstance(analysisDB);
            service.setCurrentProgram(currentProgram);

            StructureExtractor.ExtractionResult result = service.indexStructureSync(
                    currentProgram, TaskMonitor.DUMMY, includeBlocks);

            return MCPToolResult.success(buildIndexResultOutput(result));
        } catch (Exception e) {
            Msg.error(this, "Failed to index binary: " + e.getMessage(), e);
            return MCPToolResult.error("Failed to index binary: " + e.getMessage());
        }
    }

    /**
     * Build JSON output when indexing is skipped (already indexed).
     */
    private String buildIndexSkippedOutput(int existingFunctions) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"status\": \"skipped\",\n");
        sb.append("  \"reason\": \"Binary already indexed\",\n");
        sb.append("  \"existing_functions\": ").append(existingFunctions).append(",\n");
        sb.append("  \"hint\": \"Use force=true to re-index\"\n");
        sb.append("}");
        return sb.toString();
    }

    /**
     * Build JSON output for indexing result.
     */
    private String buildIndexResultOutput(StructureExtractor.ExtractionResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"status\": \"completed\",\n");
        sb.append("  \"functions_extracted\": ").append(result.functionsExtracted).append(",\n");
        sb.append("  \"call_edges\": ").append(result.callEdgesCreated).append(",\n");
        sb.append("  \"reference_edges\": ").append(result.refEdgesCreated).append(",\n");
        sb.append("  \"data_dependency_edges\": ").append(result.dataDepEdgesCreated).append(",\n");
        sb.append("  \"vulnerable_call_edges\": ").append(result.vulnEdgesCreated).append(",\n");
        sb.append("  \"elapsed_ms\": ").append(result.elapsedMs).append("\n");
        sb.append("}");
        return sb.toString();
    }

    /**
     * Execute the ga_record_vulnerability tool.
     * Records a vulnerability discovered by LLM analysis and propagates to callers.
     */
    private MCPToolResult executeRecordVulnerability(JsonObject arguments) {
        // Parse arguments
        long address = 0;
        String functionName = null;

        if (arguments.has("address")) {
            address = parseAddress(arguments.get("address").getAsString());
        }
        if (arguments.has("function_name")) {
            functionName = arguments.get("function_name").getAsString();
        }

        // Required fields
        if (!arguments.has("vulnerability_type")) {
            return MCPToolResult.error("'vulnerability_type' is required");
        }
        if (!arguments.has("severity")) {
            return MCPToolResult.error("'severity' is required");
        }
        if (!arguments.has("description")) {
            return MCPToolResult.error("'description' is required");
        }

        String vulnType = arguments.get("vulnerability_type").getAsString().toUpperCase();
        String severity = arguments.get("severity").getAsString().toUpperCase();
        String description = arguments.get("description").getAsString();
        String evidence = arguments.has("evidence") ? arguments.get("evidence").getAsString() : null;

        // Validate vulnerability type
        if (!isValidVulnerabilityType(vulnType)) {
            return MCPToolResult.error("Invalid vulnerability_type: " + vulnType +
                ". Valid types: BUFFER_OVERFLOW, COMMAND_INJECTION, FORMAT_STRING, USE_AFTER_FREE, " +
                "INTEGER_OVERFLOW, PATH_TRAVERSAL, SQL_INJECTION, RACE_CONDITION, " +
                "MEMORY_LEAK, NULL_DEREF, INFO_DISCLOSURE, AUTH_BYPASS, CRYPTO_WEAKNESS, OTHER");
        }

        // Validate severity
        if (!isValidSeverity(severity)) {
            return MCPToolResult.error("Invalid severity: " + severity +
                ". Valid values: LOW, MEDIUM, HIGH, CRITICAL");
        }

        // Look up function
        Function function = lookupFunction(address, functionName);
        if (function == null) {
            return MCPToolResult.error("Function not found. Provide valid 'address' or 'function_name'");
        }

        address = function.getEntryPoint().getOffset();

        // Get or create node
        KnowledgeNode node = graph.getNodeByAddress(address);
        if (node == null) {
            // Index the function first
            boolean indexed = indexFunctionOnDemand(function);
            if (!indexed) {
                return MCPToolResult.error("Failed to index function: " + function.getName());
            }
            node = graph.getNodeByAddress(address);
            if (node == null) {
                return MCPToolResult.error("Failed to create node for function: " + function.getName());
            }
        }

        // Add vulnerability as security flag (e.g., "VULN_BUFFER_OVERFLOW")
        String vulnFlag = "VULN_" + vulnType;
        node.addSecurityFlag(vulnFlag);

        // Add severity flag (e.g., "SEVERITY_HIGH")
        String severityFlag = "SEVERITY_" + severity;
        node.addSecurityFlag(severityFlag);

        // Mark as LLM-discovered vulnerability
        node.addSecurityFlag("LLM_DISCOVERED_VULN");

        // Store description in node metadata (append to existing llm_summary or create new)
        String existingSummary = node.getLlmSummary();
        String vulnNote = String.format("\n\n[VULNERABILITY] %s (%s): %s%s",
            vulnType, severity, description,
            evidence != null ? "\nEvidence: " + evidence : "");

        if (existingSummary != null && !existingSummary.isEmpty() && !existingSummary.equals("pending")) {
            node.setLlmSummary(existingSummary + vulnNote);
        } else {
            node.setLlmSummary(vulnNote.trim());
        }

        // Save the updated node
        graph.upsertNode(node);

        // Propagate vulnerability to callers (Phase B.2)
        int callersUpdated = propagateVulnerabilityToCallers(node, vulnType, severity);

        Msg.info(this, String.format("Recorded vulnerability %s (%s) for %s at 0x%x, propagated to %d callers",
            vulnType, severity, function.getName(), address, callersUpdated));

        return MCPToolResult.success(buildVulnerabilityRecordOutput(
            function.getName(), address, vulnType, severity, description, callersUpdated));
    }

    /**
     * Propagate vulnerability information to all functions that call the vulnerable function.
     * Creates CALLS_VULNERABLE edges and adds CALLS_VULNERABLE_FUNCTION flag to callers.
     *
     * @param vulnerableNode The node with the vulnerability
     * @param vulnType The type of vulnerability
     * @param severity The severity level
     * @return Number of callers updated
     */
    private int propagateVulnerabilityToCallers(KnowledgeNode vulnerableNode, String vulnType, String severity) {
        if (vulnerableNode == null || graph == null) {
            return 0;
        }

        int callersUpdated = 0;
        List<KnowledgeNode> callers = graph.getCallers(vulnerableNode.getId());

        for (KnowledgeNode caller : callers) {
            // Add CALLS_VULNERABLE edge from caller to vulnerable function
            // Check if edge already exists
            if (!graph.hasEdgesOfType(caller.getId(), ghidrassist.graphrag.nodes.EdgeType.CALLS_VULNERABLE)) {
                String metadata = String.format("{\"vuln_type\":\"%s\",\"severity\":\"%s\"}", vulnType, severity);
                graph.addEdge(caller.getId(), vulnerableNode.getId(),
                    ghidrassist.graphrag.nodes.EdgeType.CALLS_VULNERABLE, 1.0, metadata);
            }

            // Add flag to caller indicating it calls a vulnerable function
            String callerFlag = "CALLS_VULN_" + vulnType;
            if (!caller.getSecurityFlags().contains(callerFlag)) {
                caller.addSecurityFlag(callerFlag);
                caller.addSecurityFlag("CALLS_VULNERABLE_FUNCTION");
                graph.upsertNode(caller);
                callersUpdated++;
            }
        }

        return callersUpdated;
    }

    /**
     * Execute the ga_add_security_flag tool.
     * Adds a security-relevant flag to a function's knowledge graph node.
     */
    private MCPToolResult executeAddSecurityFlag(JsonObject arguments) {
        // Parse arguments
        long address = 0;
        String functionName = null;

        if (arguments.has("address")) {
            address = parseAddress(arguments.get("address").getAsString());
        }
        if (arguments.has("function_name")) {
            functionName = arguments.get("function_name").getAsString();
        }

        // Required field
        if (!arguments.has("flag")) {
            return MCPToolResult.error("'flag' is required");
        }

        String flag = arguments.get("flag").getAsString().toUpperCase().replace(" ", "_");

        // Look up function
        Function function = lookupFunction(address, functionName);
        if (function == null) {
            return MCPToolResult.error("Function not found. Provide valid 'address' or 'function_name'");
        }

        address = function.getEntryPoint().getOffset();

        // Get or create node
        KnowledgeNode node = graph.getNodeByAddress(address);
        if (node == null) {
            // Index the function first
            boolean indexed = indexFunctionOnDemand(function);
            if (!indexed) {
                return MCPToolResult.error("Failed to index function: " + function.getName());
            }
            node = graph.getNodeByAddress(address);
            if (node == null) {
                return MCPToolResult.error("Failed to create node for function: " + function.getName());
            }
        }

        // Check if flag already exists
        boolean alreadyExists = node.getSecurityFlags().contains(flag);

        if (!alreadyExists) {
            // Add the flag
            node.addSecurityFlag(flag);
            graph.upsertNode(node);
            Msg.info(this, String.format("Added security flag '%s' to %s at 0x%x",
                flag, function.getName(), address));
        }

        return MCPToolResult.success(buildSecurityFlagAddOutput(
            function.getName(), address, flag, !alreadyExists, node.getSecurityFlags()));
    }

    /**
     * Check if a vulnerability type is valid.
     */
    private boolean isValidVulnerabilityType(String type) {
        return type.equals("BUFFER_OVERFLOW") ||
               type.equals("COMMAND_INJECTION") ||
               type.equals("FORMAT_STRING") ||
               type.equals("USE_AFTER_FREE") ||
               type.equals("INTEGER_OVERFLOW") ||
               type.equals("PATH_TRAVERSAL") ||
               type.equals("SQL_INJECTION") ||
               type.equals("RACE_CONDITION") ||
               type.equals("MEMORY_LEAK") ||
               type.equals("NULL_DEREF") ||
               type.equals("INFO_DISCLOSURE") ||
               type.equals("AUTH_BYPASS") ||
               type.equals("CRYPTO_WEAKNESS") ||
               type.equals("OTHER");
    }

    /**
     * Check if a severity level is valid.
     */
    private boolean isValidSeverity(String severity) {
        return severity.equals("LOW") ||
               severity.equals("MEDIUM") ||
               severity.equals("HIGH") ||
               severity.equals("CRITICAL");
    }

    /**
     * Build JSON output for vulnerability record.
     */
    private String buildVulnerabilityRecordOutput(String functionName, long address,
            String vulnType, String severity, String description, int callersUpdated) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"status\": \"recorded\",\n");
        sb.append("  \"function_name\": \"").append(escapeJson(functionName)).append("\",\n");
        sb.append("  \"address\": \"0x").append(Long.toHexString(address)).append("\",\n");
        sb.append("  \"vulnerability_type\": \"").append(escapeJson(vulnType)).append("\",\n");
        sb.append("  \"severity\": \"").append(escapeJson(severity)).append("\",\n");
        sb.append("  \"description\": \"").append(escapeJson(description)).append("\",\n");
        sb.append("  \"callers_updated\": ").append(callersUpdated).append(",\n");
        sb.append("  \"message\": \"Vulnerability recorded and propagated to ").append(callersUpdated);
        sb.append(" caller(s)\"\n");
        sb.append("}");
        return sb.toString();
    }

    /**
     * Build JSON output for security flag add.
     */
    private String buildSecurityFlagAddOutput(String functionName, long address,
            String flag, boolean wasAdded, List<String> allFlags) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"status\": \"").append(wasAdded ? "added" : "already_exists").append("\",\n");
        sb.append("  \"function_name\": \"").append(escapeJson(functionName)).append("\",\n");
        sb.append("  \"address\": \"0x").append(Long.toHexString(address)).append("\",\n");
        sb.append("  \"flag\": \"").append(escapeJson(flag)).append("\",\n");
        sb.append("  \"all_flags\": ").append(toJsonArray(allFlags)).append("\n");
        sb.append("}");
        return sb.toString();
    }

    /**
     * Execute the ga_refresh_names tool.
     * Refreshes function names in the knowledge graph to match current Ghidra names.
     */
    private MCPToolResult executeRefreshNames(JsonObject arguments) {
        // Parse arguments
        long address = 0;
        String functionName = null;

        if (arguments.has("address")) {
            address = parseAddress(arguments.get("address").getAsString());
        }
        if (arguments.has("function_name")) {
            functionName = arguments.get("function_name").getAsString();
        }

        // Single function refresh
        if (address != 0 || functionName != null) {
            Function function = lookupFunction(address, functionName);
            if (function == null) {
                return MCPToolResult.error("Function not found. Provide valid 'address' or 'function_name'");
            }

            address = function.getEntryPoint().getOffset();
            KnowledgeNode node = graph.getNodeByAddress(address);
            if (node == null) {
                return MCPToolResult.error("Function not indexed in knowledge graph: " + function.getName());
            }

            String oldName = node.getName();
            boolean wasUpdated = ensureNodeNameFresh(function, node);

            return MCPToolResult.success(buildNameRefreshOutput(
                function.getName(), address, oldName, wasUpdated));
        }

        // Batch refresh all functions in binary
        int updated = refreshAllNames();
        return MCPToolResult.success(buildBatchNameRefreshOutput(updated));
    }

    /**
     * Refresh all function names in the knowledge graph.
     * Compares each indexed function's name with the current Ghidra name.
     *
     * @return Number of names updated
     */
    private int refreshAllNames() {
        if (graph == null || currentProgram == null) {
            return 0;
        }

        FunctionManager funcMgr = currentProgram.getFunctionManager();
        int updated = 0;

        // Get all function nodes from the graph
        List<KnowledgeNode> functionNodes = graph.getNodesByType(ghidrassist.graphrag.nodes.NodeType.FUNCTION);

        for (KnowledgeNode node : functionNodes) {
            try {
                // Look up the function in Ghidra by address
                Address addr = currentProgram.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(node.getAddress());
                Function func = funcMgr.getFunctionAt(addr);

                if (func != null) {
                    if (ensureNodeNameFresh(func, node)) {
                        updated++;
                    }
                }
            } catch (Exception e) {
                Msg.debug(this, "Failed to refresh name for node " + node.getId() + ": " + e.getMessage());
            }
        }

        Msg.info(this, String.format("Refreshed %d function names out of %d total", updated, functionNodes.size()));
        return updated;
    }

    /**
     * Build JSON output for single function name refresh.
     */
    private String buildNameRefreshOutput(String currentName, long address, String oldName, boolean wasUpdated) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"status\": \"").append(wasUpdated ? "updated" : "unchanged").append("\",\n");
        sb.append("  \"address\": \"0x").append(Long.toHexString(address)).append("\",\n");
        sb.append("  \"current_name\": \"").append(escapeJson(currentName)).append("\",\n");
        if (wasUpdated) {
            sb.append("  \"old_name\": \"").append(escapeJson(oldName)).append("\",\n");
        }
        sb.append("  \"message\": \"");
        if (wasUpdated) {
            sb.append("Name updated from '").append(escapeJson(oldName)).append("' to '").append(escapeJson(currentName)).append("'");
        } else {
            sb.append("Name is already current");
        }
        sb.append("\"\n");
        sb.append("}");
        return sb.toString();
    }

    /**
     * Build JSON output for batch name refresh.
     */
    private String buildBatchNameRefreshOutput(int updatedCount) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"status\": \"completed\",\n");
        sb.append("  \"scope\": \"binary\",\n");
        sb.append("  \"names_updated\": ").append(updatedCount).append(",\n");
        sb.append("  \"message\": \"Updated ").append(updatedCount).append(" stale function name(s)\"\n");
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

    /**
     * Execute the ga_detect_communities tool.
     * Runs community detection on the function call graph.
     */
    private MCPToolResult executeDetectCommunities(JsonObject arguments) {
        // Parse arguments
        int minSize = 2;
        boolean force = false;

        if (arguments.has("min_size")) {
            minSize = arguments.get("min_size").getAsInt();
        }
        if (arguments.has("force")) {
            force = arguments.get("force").getAsBoolean();
        }

        // Check if communities already exist
        int existingCount = graph.getCommunityCount();
        if (existingCount > 0 && !force) {
            return MCPToolResult.success(String.format(
                    "{\n  \"status\": \"skipped\",\n  \"message\": \"Communities already exist (%d communities). Use force=true to re-detect.\",\n  \"existing_count\": %d\n}",
                    existingCount, existingCount));
        }

        // Run community detection
        ghidrassist.graphrag.community.CommunityDetector detector =
                new ghidrassist.graphrag.community.CommunityDetector(graph, null);
        int communityCount = detector.detectCommunities(100, minSize);

        // Get statistics
        Map<String, Object> stats = detector.getCommunityStats();

        // Build result
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"status\": \"success\",\n");
        sb.append("  \"communities_detected\": ").append(communityCount).append(",\n");
        sb.append("  \"min_size_used\": ").append(minSize).append(",\n");

        if (stats.containsKey("total_members")) {
            sb.append("  \"total_members\": ").append(stats.get("total_members")).append(",\n");
        }
        if (stats.containsKey("avg_size")) {
            sb.append("  \"avg_community_size\": ").append(stats.get("avg_size")).append(",\n");
        }
        if (stats.containsKey("max_size")) {
            sb.append("  \"max_community_size\": ").append(stats.get("max_size")).append(",\n");
        }
        if (stats.containsKey("min_size")) {
            sb.append("  \"min_community_size\": ").append(stats.get("min_size")).append(",\n");
        }

        sb.append("  \"message\": \"Community detection complete. Use ga_get_module_summary to view community details.\"\n");
        sb.append("}");

        Msg.info(this, String.format("Community detection complete: %d communities", communityCount));

        return MCPToolResult.success(sb.toString());
    }

    /**
     * Execute the ga_global_query tool.
     * Aggregates insights across all detected communities for binary-wide analysis.
     */
    private MCPToolResult executeGlobalQuery(JsonObject arguments) {
        // Parse arguments
        int communityLevel = 0;
        boolean includeMembers = false;

        if (arguments.has("community_level")) {
            communityLevel = arguments.get("community_level").getAsInt();
        }
        if (arguments.has("include_members")) {
            includeMembers = arguments.get("include_members").getAsBoolean();
        }

        // Check if communities exist
        int existingCount = graph.getCommunityCount();
        if (existingCount == 0) {
            return MCPToolResult.success(
                "{\n  \"status\": \"error\",\n  \"message\": \"No communities detected. " +
                "Run ga_detect_communities first to cluster functions into communities.\"\n}");
        }

        // Execute global query
        GlobalQueryResult result = engine.globalQuery(communityLevel);

        Msg.info(this, String.format("Global query complete: %d communities, %d functions",
                result.getCommunityCount(), result.getTotalFunctions()));

        return MCPToolResult.success(result.toToolOutput(includeMembers));
    }

    /**
     * Execute the ga_find_taint_paths tool.
     * Finds data flow paths from taint sources to sinks.
     */
    private MCPToolResult executeFindTaintPaths(JsonObject arguments) {
        // Parse arguments
        long sourceAddress = 0;
        long sinkAddress = 0;
        int maxPaths = 20;
        boolean createEdges = false;

        if (arguments.has("source_address")) {
            sourceAddress = parseAddress(arguments.get("source_address").getAsString());
        }
        if (arguments.has("sink_address")) {
            sinkAddress = parseAddress(arguments.get("sink_address").getAsString());
        }
        if (arguments.has("max_paths")) {
            maxPaths = arguments.get("max_paths").getAsInt();
        }
        if (arguments.has("create_edges")) {
            createEdges = arguments.get("create_edges").getAsBoolean();
        }

        // Create taint analyzer
        TaintAnalyzer analyzer = new TaintAnalyzer(graph);

        // Execute appropriate search
        java.util.List<TaintAnalyzer.TaintPath> paths;

        if (sourceAddress != 0 && sinkAddress != 0) {
            // Both specified - not directly supported, find from source
            paths = analyzer.findTaintPathsFrom(sourceAddress, maxPaths, createEdges);
        } else if (sourceAddress != 0) {
            // Find paths from specific source
            paths = analyzer.findTaintPathsFrom(sourceAddress, maxPaths, createEdges);
        } else if (sinkAddress != 0) {
            // Find paths to specific sink
            paths = analyzer.findTaintPathsTo(sinkAddress, maxPaths, createEdges);
        } else {
            // Find all taint paths
            paths = analyzer.findTaintPaths(maxPaths, createEdges);
        }

        // Build result output
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"paths_found\": ").append(paths.size()).append(",\n");

        if (paths.isEmpty()) {
            // Get taint stats for additional context
            java.util.Map<String, Object> stats = analyzer.getTaintStats();
            sb.append("  \"source_count\": ").append(stats.get("source_count")).append(",\n");
            sb.append("  \"sink_count\": ").append(stats.get("sink_count")).append(",\n");
            sb.append("  \"message\": \"No taint paths found. Ensure the binary is indexed and has source/sink functions.\",\n");
            sb.append("  \"sample_sources\": ").append(toJsonArray((java.util.List<String>)stats.get("sample_sources"))).append(",\n");
            sb.append("  \"sample_sinks\": ").append(toJsonArray((java.util.List<String>)stats.get("sample_sinks"))).append("\n");
        } else {
            sb.append("  \"edges_created\": ").append(createEdges).append(",\n");
            sb.append("  \"paths\": [\n");

            for (int i = 0; i < paths.size(); i++) {
                TaintAnalyzer.TaintPath path = paths.get(i);
                String pathOutput = path.toToolOutput();
                // Indent the path output
                String indented = pathOutput.replace("\n", "\n    ");
                sb.append("    ").append(indented);
                if (i < paths.size() - 1) sb.append(",");
                sb.append("\n");
            }

            sb.append("  ]\n");
        }

        sb.append("}");

        Msg.info(this, String.format("Taint path analysis complete: %d paths found", paths.size()));

        return MCPToolResult.success(sb.toString());
    }

    /**
     * Execute the ga_create_edge tool.
     * Creates a semantic relationship edge between two functions.
     */
    private MCPToolResult executeCreateEdge(JsonObject arguments) {
        // Parse source function
        long sourceAddress = 0;
        String sourceName = null;
        if (arguments.has("source_address")) {
            sourceAddress = parseAddress(arguments.get("source_address").getAsString());
        }
        if (arguments.has("source_name")) {
            sourceName = arguments.get("source_name").getAsString();
        }

        // Parse target function
        long targetAddress = 0;
        String targetName = null;
        if (arguments.has("target_address")) {
            targetAddress = parseAddress(arguments.get("target_address").getAsString());
        }
        if (arguments.has("target_name")) {
            targetName = arguments.get("target_name").getAsString();
        }

        // Required field: edge_type
        if (!arguments.has("edge_type")) {
            return MCPToolResult.error("'edge_type' is required");
        }
        String edgeTypeStr = arguments.get("edge_type").getAsString().toUpperCase();

        // Optional fields
        double confidence = 0.8; // Default confidence
        if (arguments.has("confidence")) {
            confidence = arguments.get("confidence").getAsDouble();
            confidence = Math.max(0.0, Math.min(1.0, confidence)); // Clamp to 0-1
        }
        String reason = arguments.has("reason") ? arguments.get("reason").getAsString() : null;

        // Validate edge type
        ghidrassist.graphrag.nodes.EdgeType edgeType;
        try {
            edgeType = ghidrassist.graphrag.nodes.EdgeType.valueOf(edgeTypeStr);
        } catch (IllegalArgumentException e) {
            return MCPToolResult.error("Invalid edge_type: " + edgeTypeStr +
                ". Valid types: SIMILAR_PURPOSE, RELATED_TO, DEPENDS_ON, IMPLEMENTS");
        }

        // Validate that this is a semantic edge type (not structural)
        if (!isSemanticEdgeType(edgeType)) {
            return MCPToolResult.error("Edge type " + edgeTypeStr + " is not a semantic edge type. " +
                "Use: SIMILAR_PURPOSE, RELATED_TO, DEPENDS_ON, IMPLEMENTS");
        }

        // Look up source function
        Function sourceFunc = lookupFunction(sourceAddress, sourceName);
        if (sourceFunc == null) {
            return MCPToolResult.error("Source function not found. Provide valid 'source_address' or 'source_name'");
        }

        // Look up target function
        Function targetFunc = lookupFunction(targetAddress, targetName);
        if (targetFunc == null) {
            return MCPToolResult.error("Target function not found. Provide valid 'target_address' or 'target_name'");
        }

        sourceAddress = sourceFunc.getEntryPoint().getOffset();
        targetAddress = targetFunc.getEntryPoint().getOffset();

        // Get or create source node
        KnowledgeNode sourceNode = graph.getNodeByAddress(sourceAddress);
        if (sourceNode == null) {
            boolean indexed = indexFunctionOnDemand(sourceFunc);
            if (!indexed) {
                return MCPToolResult.error("Failed to index source function: " + sourceFunc.getName());
            }
            sourceNode = graph.getNodeByAddress(sourceAddress);
        }

        // Get or create target node
        KnowledgeNode targetNode = graph.getNodeByAddress(targetAddress);
        if (targetNode == null) {
            boolean indexed = indexFunctionOnDemand(targetFunc);
            if (!indexed) {
                return MCPToolResult.error("Failed to index target function: " + targetFunc.getName());
            }
            targetNode = graph.getNodeByAddress(targetAddress);
        }

        if (sourceNode == null || targetNode == null) {
            return MCPToolResult.error("Failed to get nodes for source or target function");
        }

        // Check if edge already exists
        if (graph.hasEdgeBetween(sourceNode.getId(), targetNode.getId(), edgeType)) {
            return MCPToolResult.success(buildEdgeExistsOutput(
                sourceFunc.getName(), targetFunc.getName(), edgeTypeStr));
        }

        // Create the edge with metadata
        String metadata = reason != null ?
            String.format("{\"reason\":\"%s\",\"source\":\"llm_analysis\"}", escapeJson(reason)) :
            "{\"source\":\"llm_analysis\"}";

        graph.addEdge(sourceNode.getId(), targetNode.getId(), edgeType, confidence, metadata);

        Msg.info(this, String.format("Created %s edge from %s to %s (confidence: %.2f)",
            edgeTypeStr, sourceFunc.getName(), targetFunc.getName(), confidence));

        return MCPToolResult.success(buildEdgeCreatedOutput(
            sourceFunc.getName(), sourceAddress, targetFunc.getName(), targetAddress,
            edgeTypeStr, confidence, reason));
    }

    /**
     * Check if an edge type is a semantic (LLM-creatable) edge type.
     */
    private boolean isSemanticEdgeType(ghidrassist.graphrag.nodes.EdgeType edgeType) {
        return edgeType == ghidrassist.graphrag.nodes.EdgeType.SIMILAR_PURPOSE ||
               edgeType == ghidrassist.graphrag.nodes.EdgeType.RELATED_TO ||
               edgeType == ghidrassist.graphrag.nodes.EdgeType.DEPENDS_ON ||
               edgeType == ghidrassist.graphrag.nodes.EdgeType.IMPLEMENTS;
    }

    /**
     * Build output for edge already exists case.
     */
    private String buildEdgeExistsOutput(String sourceName, String targetName, String edgeType) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"status\": \"exists\",\n");
        sb.append("  \"message\": \"Edge already exists\",\n");
        sb.append("  \"source\": \"").append(escapeJson(sourceName)).append("\",\n");
        sb.append("  \"target\": \"").append(escapeJson(targetName)).append("\",\n");
        sb.append("  \"edge_type\": \"").append(edgeType).append("\"\n");
        sb.append("}");
        return sb.toString();
    }

    /**
     * Build output for successfully created edge.
     */
    private String buildEdgeCreatedOutput(String sourceName, long sourceAddr,
                                           String targetName, long targetAddr,
                                           String edgeType, double confidence, String reason) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"status\": \"created\",\n");
        sb.append("  \"source\": \"").append(escapeJson(sourceName)).append("\",\n");
        sb.append("  \"source_address\": \"0x").append(Long.toHexString(sourceAddr)).append("\",\n");
        sb.append("  \"target\": \"").append(escapeJson(targetName)).append("\",\n");
        sb.append("  \"target_address\": \"0x").append(Long.toHexString(targetAddr)).append("\",\n");
        sb.append("  \"edge_type\": \"").append(edgeType).append("\",\n");
        sb.append("  \"confidence\": ").append(String.format("%.2f", confidence));
        if (reason != null) {
            sb.append(",\n  \"reason\": \"").append(escapeJson(reason)).append("\"");
        }
        sb.append("\n}");
        return sb.toString();
    }

    /**
     * Execute the ga_cleanup_graph tool.
     * Performs maintenance operations like removing duplicate edges.
     */
    private MCPToolResult executeCleanupGraph(JsonObject arguments) {
        boolean removeDuplicates = true; // Default to true

        if (arguments.has("remove_duplicates")) {
            removeDuplicates = arguments.get("remove_duplicates").getAsBoolean();
        }

        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"status\": \"success\",\n");

        int totalCleaned = 0;

        if (removeDuplicates) {
            int duplicatesRemoved = graph.removeDuplicateEdges();
            totalCleaned += duplicatesRemoved;
            sb.append("  \"duplicates_removed\": ").append(duplicatesRemoved).append(",\n");
        }

        // Get updated stats
        sb.append("  \"current_node_count\": ").append(graph.getNodeCount()).append(",\n");
        sb.append("  \"current_edge_count\": ").append(graph.getEdgeCount()).append(",\n");
        sb.append("  \"message\": \"Graph cleanup complete. ").append(totalCleaned).append(" issues fixed.\"\n");
        sb.append("}");

        Msg.info(this, String.format("Graph cleanup complete: %d issues fixed", totalCleaned));

        return MCPToolResult.success(sb.toString());
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
