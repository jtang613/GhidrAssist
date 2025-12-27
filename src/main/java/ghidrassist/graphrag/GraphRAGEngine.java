package ghidrassist.graphrag;

import ghidra.util.Msg;

import ghidrassist.graphrag.nodes.EdgeType;
import ghidrassist.graphrag.nodes.KnowledgeNode;
import ghidrassist.graphrag.nodes.NodeType;
import ghidrassist.graphrag.query.*;

import java.util.*;
import java.util.stream.Collectors;

/**
 * LLM-Free Query Engine for Graph-RAG semantic queries.
 *
 * CRITICAL: All query methods in this class are LLM-free. They only perform:
 * - Graph traversal
 * - SQLite queries
 * - Full-text search (FTS5)
 *
 * LLM calls happen ONLY during indexing (via SemanticExtractor), not here.
 *
 * This engine provides MCP-style tools that return pre-computed semantic analysis:
 * - get_semantic_analysis() - Returns cached LLM summary and metadata
 * - get_similar_functions() - Graph-based similarity search
 * - get_call_context() - Caller/callee context with summaries
 * - get_security_analysis() - Security flags and taint paths
 * - search_semantic() - FTS search on cached summaries
 * - get_module_summary() - Community/module summary
 */
public class GraphRAGEngine {

    private final BinaryKnowledgeGraph graph;
    // NOTE: No LLMClient field - queries don't use LLM!

    public GraphRAGEngine(BinaryKnowledgeGraph graph) {
        this.graph = graph;
    }

    // ========================================
    // LLM-FREE Query Tools (MCP-style)
    // ========================================

    /**
     * Get semantic analysis for a function by address.
     * Returns pre-computed LLM summary (NO LLM call at query time).
     *
     * @param address Function entry point address
     * @return SemanticAnalysis with cached summary, or "not indexed" if not found
     */
    public SemanticAnalysis getSemanticAnalysis(long address) {
        Msg.info(this, "getSemanticAnalysis: Looking up address 0x" + Long.toHexString(address));
        KnowledgeNode node = graph.getNodeByAddress(address);
        Msg.info(this, "getSemanticAnalysis: Graph lookup returned node=" + (node != null ? node.getName() : "null"));
        return buildSemanticAnalysis(node, address);
    }

    /**
     * Get semantic analysis for a function by name.
     * Returns pre-computed LLM summary (NO LLM call at query time).
     *
     * @param functionName Function name
     * @return SemanticAnalysis with cached summary, or "not indexed" if not found
     */
    public SemanticAnalysis getSemanticAnalysis(String functionName) {
        Msg.info(this, "getSemanticAnalysis: Looking up function name: " + functionName);
        KnowledgeNode node = graph.getNodeByName(functionName);
        Msg.info(this, "getSemanticAnalysis: Graph lookup returned node=" + (node != null ? node.getName() : "null"));
        return buildSemanticAnalysis(node, node != null ? node.getAddress() : 0);
    }

    private SemanticAnalysis buildSemanticAnalysis(KnowledgeNode node, long address) {
        if (node == null) {
            Msg.info(this, "buildSemanticAnalysis: Node is null for address 0x" + Long.toHexString(address));
            return SemanticAnalysis.notIndexed("unknown", address);
        }

        // Check if we have any useful data
        boolean hasRawContent = node.getRawContent() != null && !node.getRawContent().isEmpty();
        boolean hasLlmSummary = node.getLlmSummary() != null && !node.getLlmSummary().isEmpty();
        Msg.info(this, "buildSemanticAnalysis: Node found - name=" + node.getName() +
                ", hasRawContent=" + hasRawContent + ", hasLlmSummary=" + hasLlmSummary +
                ", rawContentLen=" + (node.getRawContent() != null ? node.getRawContent().length() : 0));

        // If no data at all, return not indexed
        if (!hasRawContent && !hasLlmSummary) {
            return SemanticAnalysis.notIndexed(node.getName(), address);
        }

        // Get callers and callees
        List<String> callers = graph.getCallers(node.getId()).stream()
                .map(n -> n.getName() != null ? n.getName() : String.format("sub_%x", n.getAddress()))
                .collect(Collectors.toList());

        List<String> callees = graph.getCallees(node.getId()).stream()
                .map(n -> n.getName() != null ? n.getName() : String.format("sub_%x", n.getAddress()))
                .collect(Collectors.toList());

        // Get community if available
        String community = null; // TODO: Implement community lookup

        // Extract category from summary if present
        String category = extractCategory(node.getLlmSummary());

        // indexed=true means we have SOME useful data (structure or semantic)
        // The SemanticAnalysis.hasSemanticAnalysis() method checks for LLM summary specifically
        boolean indexed = hasRawContent || hasLlmSummary;

        return new SemanticAnalysis(
                node.getName(),
                node.getAddress(),
                node.getLlmSummary(),
                node.getSecurityFlags() != null ? node.getSecurityFlags() : List.of(),
                category,
                node.getConfidence(),
                callers,
                callees,
                community,
                node.getRawContent(),
                indexed
        );
    }

    /**
     * Get similar functions based on graph structure.
     * NO LLM call - uses graph traversal and FTS matching.
     *
     * @param address Function address
     * @param limit Maximum results to return
     * @return List of similar functions with similarity scores
     */
    public List<SimilarFunction> getSimilarFunctions(long address, int limit) {
        List<SimilarFunction> results = new ArrayList<>();
        KnowledgeNode sourceNode = graph.getNodeByAddress(address);

        if (sourceNode == null) {
            return results;
        }

        Set<String> addedIds = new HashSet<>();
        addedIds.add(sourceNode.getId()); // Exclude self

        // Strategy 1: Functions in same community (highest similarity)
        // TODO: Implement when community detection is ready

        // Strategy 2: Functions that share callers (similar role)
        List<KnowledgeNode> callers = graph.getCallers(sourceNode.getId());
        for (KnowledgeNode caller : callers) {
            for (KnowledgeNode sibling : graph.getCallees(caller.getId())) {
                if (!addedIds.contains(sibling.getId()) && sibling.getType() == NodeType.FUNCTION) {
                    addedIds.add(sibling.getId());
                    results.add(new SimilarFunction(
                            sibling.getName(),
                            sibling.getAddress(),
                            sibling.getLlmSummary(),
                            0.7f,
                            SimilarFunction.SimilarityType.SHARED_CALLERS
                    ));
                    if (results.size() >= limit) break;
                }
            }
            if (results.size() >= limit) break;
        }

        // Strategy 3: Functions that share callees (similar dependencies)
        if (results.size() < limit) {
            List<KnowledgeNode> callees = graph.getCallees(sourceNode.getId());
            for (KnowledgeNode callee : callees) {
                for (KnowledgeNode sibling : graph.getCallers(callee.getId())) {
                    if (!addedIds.contains(sibling.getId()) && sibling.getType() == NodeType.FUNCTION) {
                        addedIds.add(sibling.getId());
                        results.add(new SimilarFunction(
                                sibling.getName(),
                                sibling.getAddress(),
                                sibling.getLlmSummary(),
                                0.6f,
                                SimilarFunction.SimilarityType.SHARED_CALLEES
                        ));
                        if (results.size() >= limit) break;
                    }
                }
                if (results.size() >= limit) break;
            }
        }

        // Strategy 4: FTS search on summary keywords
        if (results.size() < limit && sourceNode.getLlmSummary() != null) {
            // Extract keywords from summary
            String[] keywords = extractKeywords(sourceNode.getLlmSummary());
            if (keywords.length > 0) {
                String query = String.join(" OR ", keywords);
                List<KnowledgeNode> ftsResults = graph.ftsSearch(query, limit - results.size() + 5);
                for (KnowledgeNode match : ftsResults) {
                    if (!addedIds.contains(match.getId()) && match.getType() == NodeType.FUNCTION) {
                        addedIds.add(match.getId());
                        results.add(new SimilarFunction(
                                match.getName(),
                                match.getAddress(),
                                match.getLlmSummary(),
                                0.5f,
                                SimilarFunction.SimilarityType.FTS_MATCH
                        ));
                        if (results.size() >= limit) break;
                    }
                }
            }
        }

        // Sort by similarity score descending
        results.sort((a, b) -> Float.compare(b.getSimilarityScore(), a.getSimilarityScore()));

        return results.subList(0, Math.min(results.size(), limit));
    }

    /**
     * Get call context for a function with semantic summaries.
     * NO LLM call - retrieves pre-computed summaries from graph.
     *
     * @param address Function address
     * @param depth How many levels of callers/callees to include
     * @param direction CALLERS, CALLEES, or BOTH
     * @return CallContext with caller/callee summaries
     */
    public CallContext getCallContext(long address, int depth, CallContext.Direction direction) {
        KnowledgeNode centerNode = graph.getNodeByAddress(address);

        if (centerNode == null) {
            return new CallContext(
                    new CallContext.FunctionSummary("unknown", address, "Function not found in graph", List.of()),
                    List.of(),
                    List.of()
            );
        }

        CallContext.FunctionSummary center = nodeToFunctionSummary(centerNode);

        List<CallContext.ContextEntry> callers = new ArrayList<>();
        List<CallContext.ContextEntry> callees = new ArrayList<>();

        if (direction == CallContext.Direction.CALLERS || direction == CallContext.Direction.BOTH) {
            collectCallContext(centerNode.getId(), depth, true, callers, new HashSet<>());
        }

        if (direction == CallContext.Direction.CALLEES || direction == CallContext.Direction.BOTH) {
            collectCallContext(centerNode.getId(), depth, false, callees, new HashSet<>());
        }

        return new CallContext(center, callers, callees);
    }

    private void collectCallContext(String nodeId, int maxDepth, boolean callers,
                                     List<CallContext.ContextEntry> results, Set<String> visited) {
        collectCallContextRecursive(nodeId, 1, maxDepth, callers, results, visited);
    }

    private void collectCallContextRecursive(String nodeId, int currentDepth, int maxDepth,
                                              boolean callers, List<CallContext.ContextEntry> results,
                                              Set<String> visited) {
        if (currentDepth > maxDepth) return;

        List<KnowledgeNode> neighbors = callers ?
                graph.getCallers(nodeId) : graph.getCallees(nodeId);

        for (KnowledgeNode neighbor : neighbors) {
            if (visited.contains(neighbor.getId())) continue;
            visited.add(neighbor.getId());

            CallContext.FunctionSummary summary = nodeToFunctionSummary(neighbor);
            results.add(new CallContext.ContextEntry(currentDepth, summary));

            // Recurse
            collectCallContextRecursive(neighbor.getId(), currentDepth + 1, maxDepth,
                    callers, results, visited);
        }
    }

    private CallContext.FunctionSummary nodeToFunctionSummary(KnowledgeNode node) {
        return new CallContext.FunctionSummary(
                node.getName() != null ? node.getName() : String.format("sub_%x", node.getAddress()),
                node.getAddress(),
                node.getLlmSummary(),
                node.getSecurityFlags() != null ? node.getSecurityFlags() : List.of()
        );
    }

    /**
     * Get security analysis for a function.
     * NO LLM call - retrieves pre-computed security flags from graph.
     *
     * @param address Function address
     * @return SecurityAnalysis with flags and taint paths
     */
    public SecurityAnalysis getSecurityAnalysis(long address) {
        KnowledgeNode node = graph.getNodeByAddress(address);

        if (node == null) {
            return new SecurityAnalysis("function", "unknown", List.of(), List.of(), List.of(), List.of());
        }

        // Get security flags for this function
        List<String> flags = node.getSecurityFlags() != null ?
                node.getSecurityFlags() : List.of();

        // Find callers of this function that might propagate vulnerabilities
        List<String> vulnerableCallers = new ArrayList<>();
        for (KnowledgeNode caller : graph.getCallers(node.getId())) {
            if (caller.hasSecurityFlags()) {
                vulnerableCallers.add(caller.getName() != null ? caller.getName() :
                        String.format("sub_%x", caller.getAddress()));
            }
        }

        // TODO: Implement taint path finding
        List<SecurityAnalysis.TaintPath> taintPaths = List.of();

        // TODO: Implement attack surface detection
        List<String> attackSurface = List.of();

        return new SecurityAnalysis(
                "function",
                node.getName() != null ? node.getName() : String.format("sub_%x", node.getAddress()),
                flags,
                taintPaths,
                attackSurface,
                vulnerableCallers
        );
    }

    /**
     * Get security analysis for entire binary.
     * NO LLM call - aggregates pre-computed security flags from graph.
     *
     * @param binaryId Program hash
     * @return SecurityAnalysis with binary-wide security information
     */
    public SecurityAnalysis getBinarySecurityAnalysis(String binaryId) {
        // Get all nodes with security flags
        List<KnowledgeNode> allNodes = graph.getNodesByType(NodeType.FUNCTION);

        Set<String> allFlags = new HashSet<>();
        List<String> flaggedFunctions = new ArrayList<>();

        for (KnowledgeNode node : allNodes) {
            if (node.hasSecurityFlags()) {
                allFlags.addAll(node.getSecurityFlags());
                flaggedFunctions.add(node.getName() != null ? node.getName() :
                        String.format("sub_%x", node.getAddress()));
            }
        }

        // Get attack surface (entry points, external-facing functions)
        List<String> attackSurface = new ArrayList<>();
        List<KnowledgeNode> binaryNodes = graph.getNodesByType(NodeType.BINARY);
        if (!binaryNodes.isEmpty()) {
            // TODO: Extract entry points from binary node
        }

        return new SecurityAnalysis(
                "binary",
                binaryId,
                new ArrayList<>(allFlags),
                List.of(), // TODO: Binary-wide taint paths
                attackSurface,
                flaggedFunctions
        );
    }

    /**
     * Search for functions by semantic query.
     * NO LLM call - uses SQLite FTS5 on pre-computed summaries.
     *
     * @param query Search query (keywords, phrases)
     * @param limit Maximum results
     * @return List of matching functions with relevance scores
     */
    public List<SearchResult> searchSemantic(String query, int limit) {
        List<KnowledgeNode> ftsResults = graph.ftsSearch(query, limit);

        return ftsResults.stream()
                .filter(node -> node.getType() == NodeType.FUNCTION)
                .map(node -> new SearchResult(
                        node.getName() != null ? node.getName() : String.format("sub_%x", node.getAddress()),
                        node.getAddress(),
                        node.getLlmSummary(),
                        1.0f, // TODO: Get actual FTS rank
                        "fts_match",
                        null // TODO: Extract matched text
                ))
                .collect(Collectors.toList());
    }

    /**
     * Get module/community summary for a function.
     * NO LLM call - retrieves pre-computed community summary from graph.
     *
     * @param functionAddress Address of function to get community for
     * @return ModuleSummary with community information
     */
    public ModuleSummary getModuleSummary(long functionAddress) {
        KnowledgeNode node = graph.getNodeByAddress(functionAddress);

        if (node == null) {
            return ModuleSummary.notFound(String.format("sub_%x", functionAddress));
        }

        // TODO: Implement community lookup when community detection is ready
        // For now, return a placeholder indicating community detection hasn't run
        return ModuleSummary.notFound(node.getName() != null ? node.getName() :
                String.format("sub_%x", functionAddress));
    }

    // ========================================
    // Context Building (LLM-free, for LLM input)
    // ========================================

    /**
     * Build rich context string from graph for LLM input.
     * NO LLM call - just formats pre-computed data.
     *
     * @param address Function address
     * @param depth How many levels of context to include
     * @return Formatted context string
     */
    public String buildLocalContext(long address, int depth) {
        SemanticAnalysis analysis = getSemanticAnalysis(address);
        CallContext context = getCallContext(address, depth, CallContext.Direction.BOTH);

        StringBuilder sb = new StringBuilder();
        sb.append("## Function Context\n\n");

        // Function info
        sb.append("### ").append(analysis.getName()).append(" (0x")
                .append(Long.toHexString(analysis.getAddress())).append(")\n\n");

        if (analysis.isIndexed()) {
            if (analysis.getSummary() != null) {
                sb.append("**Summary:** ").append(analysis.getSummary()).append("\n\n");
            }
            if (analysis.hasSecurityConcerns()) {
                sb.append("**Security Flags:** ").append(String.join(", ", analysis.getSecurityFlags())).append("\n\n");
            }
        } else {
            sb.append("*Function not yet indexed - summary unavailable*\n\n");
        }

        // Callers
        if (!context.getCallers().isEmpty()) {
            sb.append("**Called by:**\n");
            for (CallContext.ContextEntry entry : context.getCallers()) {
                sb.append("- ").append(entry.getFunction().getName());
                if (entry.getFunction().getSummary() != null) {
                    sb.append(": ").append(truncate(entry.getFunction().getSummary(), 100));
                }
                sb.append("\n");
            }
            sb.append("\n");
        }

        // Callees
        if (!context.getCallees().isEmpty()) {
            sb.append("**Calls:**\n");
            for (CallContext.ContextEntry entry : context.getCallees()) {
                sb.append("- ").append(entry.getFunction().getName());
                if (entry.getFunction().getSummary() != null) {
                    sb.append(": ").append(truncate(entry.getFunction().getSummary(), 100));
                }
                sb.append("\n");
            }
            sb.append("\n");
        }

        // Raw code (truncated)
        if (analysis.getRawCode() != null) {
            sb.append("**Decompiled Code:**\n```c\n");
            sb.append(truncate(analysis.getRawCode(), 2000));
            sb.append("\n```\n");
        }

        return sb.toString();
    }

    /**
     * Build global context for binary.
     * NO LLM call - aggregates pre-computed data.
     */
    public String buildGlobalContext(String binaryId) {
        StringBuilder sb = new StringBuilder();
        sb.append("## Binary Context\n\n");

        // Get binary node
        List<KnowledgeNode> binaryNodes = graph.getNodesByType(NodeType.BINARY);
        if (!binaryNodes.isEmpty()) {
            KnowledgeNode binaryNode = binaryNodes.get(0);
            if (binaryNode.getLlmSummary() != null) {
                sb.append("**Summary:** ").append(binaryNode.getLlmSummary()).append("\n\n");
            }
            if (binaryNode.getRawContent() != null) {
                sb.append(binaryNode.getRawContent()).append("\n\n");
            }
        }

        // Get security overview
        SecurityAnalysis security = getBinarySecurityAnalysis(binaryId);
        if (security.hasSecurityIssues()) {
            sb.append("**Security Flags:** ").append(String.join(", ", security.getSecurityFlags())).append("\n\n");
        }

        // Graph stats
        sb.append("**Graph Statistics:**\n");
        sb.append("- Functions: ").append(graph.getNodesByType(NodeType.FUNCTION).size()).append("\n");
        sb.append("- Total nodes: ").append(graph.getNodeCount()).append("\n");
        sb.append("- Total edges: ").append(graph.getEdgeCount()).append("\n");

        return sb.toString();
    }

    // ========================================
    // Helper Methods
    // ========================================

    private String extractCategory(String summary) {
        if (summary == null) return null;

        String lower = summary.toLowerCase();
        if (lower.contains("crypto") || lower.contains("encrypt") || lower.contains("decrypt")) {
            return "crypto";
        } else if (lower.contains("network") || lower.contains("socket") || lower.contains("connect")) {
            return "network";
        } else if (lower.contains("auth") || lower.contains("login") || lower.contains("password")) {
            return "authentication";
        } else if (lower.contains("file") || lower.contains("read") || lower.contains("write")) {
            return "io_operations";
        } else if (lower.contains("init") || lower.contains("setup") || lower.contains("constructor")) {
            return "initialization";
        } else if (lower.contains("error") || lower.contains("exception") || lower.contains("handler")) {
            return "error_handling";
        }
        return "utility";
    }

    private String[] extractKeywords(String summary) {
        if (summary == null || summary.isEmpty()) {
            return new String[0];
        }

        // Extract significant words (skip common words)
        Set<String> stopWords = Set.of("the", "a", "an", "is", "are", "was", "were", "be", "been",
                "being", "have", "has", "had", "do", "does", "did", "will", "would", "could", "should",
                "may", "might", "must", "shall", "can", "this", "that", "these", "those", "and", "or",
                "but", "if", "then", "else", "when", "where", "which", "who", "what", "how", "why",
                "to", "from", "for", "with", "without", "in", "on", "at", "by", "of", "as", "it");

        return Arrays.stream(summary.toLowerCase().split("\\W+"))
                .filter(word -> word.length() > 3 && !stopWords.contains(word))
                .limit(5)
                .toArray(String[]::new);
    }

    private String truncate(String text, int maxLength) {
        if (text == null || text.length() <= maxLength) {
            return text;
        }
        return text.substring(0, maxLength) + "...";
    }
}
