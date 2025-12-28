package ghidrassist.graphrag.analysis;

import java.util.*;
import java.util.stream.Collectors;

import org.jgrapht.Graph;
import org.jgrapht.GraphPath;
import org.jgrapht.alg.shortestpath.AllDirectedPaths;

import ghidra.util.Msg;

import ghidrassist.graphrag.BinaryKnowledgeGraph;
import ghidrassist.graphrag.BinaryKnowledgeGraph.LabeledEdge;
import ghidrassist.graphrag.nodes.EdgeType;
import ghidrassist.graphrag.nodes.KnowledgeNode;
import ghidrassist.graphrag.nodes.NodeType;

/**
 * Taint analysis for finding data flow paths from sources to sinks.
 *
 * Taint sources are functions that introduce external/untrusted data:
 * - Network input (recv, recvfrom, read from socket)
 * - File input (fread, fgets, ReadFile)
 * - User input (scanf, gets, getenv)
 * - IPC input (recv from pipes, shared memory)
 *
 * Taint sinks are dangerous functions where tainted data can cause harm:
 * - Buffer operations (strcpy, strcat, sprintf, gets)
 * - Command execution (system, popen, exec*, CreateProcess)
 * - File operations (fopen, WriteFile with user-controlled paths)
 * - Format strings (printf with non-constant format)
 */
public class TaintAnalyzer {

    // Maximum path length to prevent explosion
    private static final int MAX_PATH_LENGTH = 10;

    // Taint sources - functions that introduce external/untrusted data
    private static final Set<String> TAINT_SOURCES = new HashSet<>(Arrays.asList(
            // Network input
            "recv", "recvfrom", "recvmsg", "read", "WSARecv", "WSARecvFrom",
            "InternetReadFile", "HttpQueryInfo", "WinHttpReadData",
            // File input
            "fread", "fgets", "fgetc", "getc", "ReadFile", "ReadFileEx",
            "NtReadFile", "ZwReadFile",
            // User input
            "scanf", "fscanf", "sscanf", "gets", "getline", "getdelim",
            "getenv", "GetEnvironmentVariable",
            // IPC input
            "msgrcv", "mq_receive", "ReadEventLog", "PeekNamedPipe",
            // Memory mapped
            "MapViewOfFile", "mmap"
    ));

    // Taint sinks - dangerous functions where tainted data causes harm
    private static final Set<String> TAINT_SINKS = new HashSet<>(Arrays.asList(
            // Buffer overflow risks
            "strcpy", "strcat", "sprintf", "vsprintf", "gets", "wcscpy", "wcscat",
            "lstrcpy", "lstrcpyA", "lstrcpyW", "lstrcat",
            // Format string risks
            "printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf",
            "wprintf", "fwprintf", "swprintf",
            // Command injection risks
            "system", "popen", "_popen", "exec", "execl", "execle", "execlp",
            "execv", "execve", "execvp", "CreateProcess", "CreateProcessA",
            "CreateProcessW", "ShellExecute", "ShellExecuteA", "ShellExecuteW",
            "WinExec",
            // Path traversal risks
            "fopen", "open", "CreateFile", "CreateFileA", "CreateFileW",
            "DeleteFile", "RemoveDirectory", "MoveFile", "CopyFile",
            // SQL injection (if detected)
            "mysql_query", "sqlite3_exec", "PQexec",
            // Memory operations
            "memcpy", "memmove", "memset", "RtlCopyMemory"
    ));

    // Functions that indicate security-relevant flags for sources/sinks
    private static final Set<String> SOURCE_FLAGS = new HashSet<>(Arrays.asList(
            "NETWORK_CAPABLE", "HANDLES_USER_INPUT", "PARSES_NETWORK_DATA",
            "FILE_READER", "ACCEPTS_CONNECTIONS"
    ));

    private static final Set<String> SINK_FLAGS = new HashSet<>(Arrays.asList(
            "BUFFER_OVERFLOW_RISK", "COMMAND_INJECTION_RISK", "FORMAT_STRING_RISK",
            "PATH_TRAVERSAL_RISK", "SQL_INJECTION_RISK", "CALLS_VULNERABLE_FUNCTION"
    ));

    private final BinaryKnowledgeGraph graph;

    public TaintAnalyzer(BinaryKnowledgeGraph graph) {
        this.graph = graph;
    }

    /**
     * Find all taint paths in the binary.
     *
     * @param maxPaths Maximum number of paths to return
     * @param createEdges If true, create TAINT_FLOWS_TO edges along found paths
     * @return List of taint paths from sources to sinks
     */
    public List<TaintPath> findTaintPaths(int maxPaths, boolean createEdges) {
        Msg.info(this, "Starting taint path analysis...");

        List<TaintPath> allPaths = new ArrayList<>();

        // Find source nodes (functions that call taint sources or have source flags)
        List<KnowledgeNode> sourceNodes = findSourceNodes();
        Msg.info(this, String.format("Found %d potential taint source nodes", sourceNodes.size()));

        // Find sink nodes (functions that call taint sinks or have sink flags)
        List<KnowledgeNode> sinkNodes = findSinkNodes();
        Msg.info(this, String.format("Found %d potential taint sink nodes", sinkNodes.size()));

        if (sourceNodes.isEmpty() || sinkNodes.isEmpty()) {
            Msg.info(this, "No sources or sinks found - no taint paths possible");
            return allPaths;
        }

        // Use JGraphT to find paths
        Graph<String, LabeledEdge> memGraph = graph.getMemoryGraph();
        AllDirectedPaths<String, LabeledEdge> pathFinder = new AllDirectedPaths<>(memGraph);

        for (KnowledgeNode source : sourceNodes) {
            if (allPaths.size() >= maxPaths) break;

            for (KnowledgeNode sink : sinkNodes) {
                if (allPaths.size() >= maxPaths) break;
                if (source.getId().equals(sink.getId())) continue;

                // Check if both vertices exist in memory graph
                if (!memGraph.containsVertex(source.getId()) ||
                    !memGraph.containsVertex(sink.getId())) {
                    continue;
                }

                try {
                    // Find all paths up to MAX_PATH_LENGTH
                    List<GraphPath<String, LabeledEdge>> paths = pathFinder.getAllPaths(
                            source.getId(), sink.getId(), true, MAX_PATH_LENGTH);

                    for (GraphPath<String, LabeledEdge> path : paths) {
                        if (allPaths.size() >= maxPaths) break;

                        TaintPath taintPath = buildTaintPath(source, sink, path);
                        allPaths.add(taintPath);

                        // Optionally create TAINT_FLOWS_TO edges
                        if (createEdges) {
                            createTaintEdges(path);
                        }
                    }
                } catch (Exception e) {
                    // Path finding can throw on disconnected graphs
                    Msg.debug(this, "No path from " + source.getName() + " to " + sink.getName());
                }
            }
        }

        Msg.info(this, String.format("Found %d taint paths", allPaths.size()));
        return allPaths;
    }

    /**
     * Find taint paths from a specific source function.
     */
    public List<TaintPath> findTaintPathsFrom(long sourceAddress, int maxPaths, boolean createEdges) {
        KnowledgeNode sourceNode = graph.getNodeByAddress(sourceAddress);
        if (sourceNode == null) {
            return List.of();
        }

        List<TaintPath> allPaths = new ArrayList<>();
        List<KnowledgeNode> sinkNodes = findSinkNodes();
        Graph<String, LabeledEdge> memGraph = graph.getMemoryGraph();
        AllDirectedPaths<String, LabeledEdge> pathFinder = new AllDirectedPaths<>(memGraph);

        for (KnowledgeNode sink : sinkNodes) {
            if (allPaths.size() >= maxPaths) break;
            if (sourceNode.getId().equals(sink.getId())) continue;

            if (!memGraph.containsVertex(sourceNode.getId()) ||
                !memGraph.containsVertex(sink.getId())) {
                continue;
            }

            try {
                List<GraphPath<String, LabeledEdge>> paths = pathFinder.getAllPaths(
                        sourceNode.getId(), sink.getId(), true, MAX_PATH_LENGTH);

                for (GraphPath<String, LabeledEdge> path : paths) {
                    if (allPaths.size() >= maxPaths) break;
                    TaintPath taintPath = buildTaintPath(sourceNode, sink, path);
                    allPaths.add(taintPath);

                    if (createEdges) {
                        createTaintEdges(path);
                    }
                }
            } catch (Exception e) {
                // Ignore path-finding failures
            }
        }

        return allPaths;
    }

    /**
     * Find taint paths to a specific sink function.
     */
    public List<TaintPath> findTaintPathsTo(long sinkAddress, int maxPaths, boolean createEdges) {
        KnowledgeNode sinkNode = graph.getNodeByAddress(sinkAddress);
        if (sinkNode == null) {
            return List.of();
        }

        List<TaintPath> allPaths = new ArrayList<>();
        List<KnowledgeNode> sourceNodes = findSourceNodes();
        Graph<String, LabeledEdge> memGraph = graph.getMemoryGraph();
        AllDirectedPaths<String, LabeledEdge> pathFinder = new AllDirectedPaths<>(memGraph);

        for (KnowledgeNode source : sourceNodes) {
            if (allPaths.size() >= maxPaths) break;
            if (source.getId().equals(sinkNode.getId())) continue;

            if (!memGraph.containsVertex(source.getId()) ||
                !memGraph.containsVertex(sinkNode.getId())) {
                continue;
            }

            try {
                List<GraphPath<String, LabeledEdge>> paths = pathFinder.getAllPaths(
                        source.getId(), sinkNode.getId(), true, MAX_PATH_LENGTH);

                for (GraphPath<String, LabeledEdge> path : paths) {
                    if (allPaths.size() >= maxPaths) break;
                    TaintPath taintPath = buildTaintPath(source, sinkNode, path);
                    allPaths.add(taintPath);

                    if (createEdges) {
                        createTaintEdges(path);
                    }
                }
            } catch (Exception e) {
                // Ignore path-finding failures
            }
        }

        return allPaths;
    }

    /**
     * Find nodes that are potential taint sources.
     * A node is a source if:
     * - It calls a known taint source function, OR
     * - It has source-related security flags
     */
    private List<KnowledgeNode> findSourceNodes() {
        List<KnowledgeNode> sources = new ArrayList<>();

        for (KnowledgeNode node : graph.getNodesByType(NodeType.FUNCTION)) {
            // Check security flags
            List<String> flags = node.getSecurityFlags();
            if (flags != null) {
                for (String flag : flags) {
                    if (SOURCE_FLAGS.contains(flag)) {
                        sources.add(node);
                        break;
                    }
                }
            }

            // Check if function name is a known source
            String name = node.getName();
            if (name != null && TAINT_SOURCES.contains(name)) {
                if (!sources.contains(node)) {
                    sources.add(node);
                }
            }

            // Check callees for taint source functions
            if (!sources.contains(node)) {
                for (KnowledgeNode callee : graph.getCallees(node.getId())) {
                    if (callee.getName() != null && TAINT_SOURCES.contains(callee.getName())) {
                        sources.add(node);
                        break;
                    }
                }
            }
        }

        return sources;
    }

    /**
     * Find nodes that are potential taint sinks.
     */
    private List<KnowledgeNode> findSinkNodes() {
        List<KnowledgeNode> sinks = new ArrayList<>();

        for (KnowledgeNode node : graph.getNodesByType(NodeType.FUNCTION)) {
            // Check security flags
            List<String> flags = node.getSecurityFlags();
            if (flags != null) {
                for (String flag : flags) {
                    if (SINK_FLAGS.contains(flag)) {
                        sinks.add(node);
                        break;
                    }
                }
            }

            // Check if function name is a known sink
            String name = node.getName();
            if (name != null && TAINT_SINKS.contains(name)) {
                if (!sinks.contains(node)) {
                    sinks.add(node);
                }
            }

            // Check callees for taint sink functions
            if (!sinks.contains(node)) {
                for (KnowledgeNode callee : graph.getCallees(node.getId())) {
                    if (callee.getName() != null && TAINT_SINKS.contains(callee.getName())) {
                        sinks.add(node);
                        break;
                    }
                }
            }
        }

        return sinks;
    }

    /**
     * Build a TaintPath object from a JGraphT path.
     */
    private TaintPath buildTaintPath(KnowledgeNode source, KnowledgeNode sink,
                                      GraphPath<String, LabeledEdge> graphPath) {
        List<String> pathNodeIds = graphPath.getVertexList();
        List<TaintPath.PathNode> pathNodes = new ArrayList<>();

        for (String nodeId : pathNodeIds) {
            KnowledgeNode node = graph.getNode(nodeId);
            if (node != null) {
                String funcName = node.getName() != null ? node.getName() :
                        String.format("sub_%x", node.getAddress());
                pathNodes.add(new TaintPath.PathNode(
                        nodeId, funcName, node.getAddress(), node.getSecurityFlags()));
            }
        }

        // Determine severity based on sink type
        String severity = determineSeverity(sink);

        return new TaintPath(
                source.getName() != null ? source.getName() : String.format("sub_%x", source.getAddress()),
                source.getAddress(),
                sink.getName() != null ? sink.getName() : String.format("sub_%x", sink.getAddress()),
                sink.getAddress(),
                pathNodes,
                severity,
                graphPath.getLength()
        );
    }

    /**
     * Determine severity based on sink's security flags.
     */
    private String determineSeverity(KnowledgeNode sink) {
        List<String> flags = sink.getSecurityFlags();
        if (flags == null || flags.isEmpty()) {
            return "MEDIUM";
        }

        // Critical sinks
        if (flags.contains("COMMAND_INJECTION_RISK") ||
            flags.contains("VULN_COMMAND_INJECTION") ||
            flags.contains("SQL_INJECTION_RISK")) {
            return "CRITICAL";
        }

        // High severity sinks
        if (flags.contains("BUFFER_OVERFLOW_RISK") ||
            flags.contains("VULN_BUFFER_OVERFLOW") ||
            flags.contains("FORMAT_STRING_RISK")) {
            return "HIGH";
        }

        // Medium severity
        if (flags.contains("PATH_TRAVERSAL_RISK") ||
            flags.contains("CALLS_VULNERABLE_FUNCTION")) {
            return "MEDIUM";
        }

        return "LOW";
    }

    /**
     * Create TAINT_FLOWS_TO edges along a path.
     */
    private void createTaintEdges(GraphPath<String, LabeledEdge> path) {
        List<String> vertices = path.getVertexList();

        for (int i = 0; i < vertices.size() - 1; i++) {
            String from = vertices.get(i);
            String to = vertices.get(i + 1);

            // Check if edge already exists
            if (!graph.hasEdgeBetween(from, to, EdgeType.TAINT_FLOWS_TO)) {
                graph.addEdge(from, to, EdgeType.TAINT_FLOWS_TO);
            }
        }
    }

    /**
     * Create VULNERABLE_VIA edges from entry points to vulnerable sinks.
     * Entry points are functions that are:
     * - Exported
     * - Named "main", "WinMain", "DllMain", etc.
     * - Have the ENTRY_POINT security flag
     *
     * Vulnerable sinks are functions with *_RISK or VULN_* security flags.
     *
     * @return Number of VULNERABLE_VIA edges created
     */
    public int createVulnerableViaEdges() {
        Msg.info(this, "Creating VULNERABLE_VIA edges from entry points to vulnerable sinks...");

        int edgesCreated = 0;

        // Find entry points
        List<KnowledgeNode> entryPoints = findEntryPoints();
        Msg.info(this, String.format("Found %d entry points", entryPoints.size()));

        // Find vulnerable nodes (nodes with vulnerability flags)
        List<KnowledgeNode> vulnerableNodes = findVulnerableNodes();
        Msg.info(this, String.format("Found %d vulnerable nodes", vulnerableNodes.size()));

        if (entryPoints.isEmpty() || vulnerableNodes.isEmpty()) {
            Msg.info(this, "No entry points or vulnerable nodes found - no VULNERABLE_VIA edges to create");
            return 0;
        }

        // Use JGraphT to check path existence
        Graph<String, LabeledEdge> memGraph = graph.getMemoryGraph();

        for (KnowledgeNode entry : entryPoints) {
            for (KnowledgeNode vulnerable : vulnerableNodes) {
                if (entry.getId().equals(vulnerable.getId())) {
                    continue; // Skip self
                }

                // Check if both vertices exist in memory graph
                if (!memGraph.containsVertex(entry.getId()) ||
                    !memGraph.containsVertex(vulnerable.getId())) {
                    continue;
                }

                // Check if there's a path from entry to vulnerable
                try {
                    AllDirectedPaths<String, LabeledEdge> pathFinder = new AllDirectedPaths<>(memGraph);
                    List<GraphPath<String, LabeledEdge>> paths = pathFinder.getAllPaths(
                            entry.getId(), vulnerable.getId(), true, MAX_PATH_LENGTH);

                    if (!paths.isEmpty()) {
                        // Path exists - create VULNERABLE_VIA edge
                        if (!graph.hasEdgeBetween(entry.getId(), vulnerable.getId(), EdgeType.VULNERABLE_VIA)) {
                            // Get the vulnerability type from the vulnerable node's flags
                            String vulnType = getVulnerabilityType(vulnerable);
                            String metadata = String.format("{\"path_length\":%d,\"vuln_type\":\"%s\"}",
                                    paths.get(0).getLength(), vulnType);

                            graph.addEdge(entry.getId(), vulnerable.getId(),
                                    EdgeType.VULNERABLE_VIA, 1.0, metadata);
                            edgesCreated++;
                        }
                    }
                } catch (Exception e) {
                    // Path finding can throw on disconnected graphs - ignore
                    Msg.debug(this, "No path from " + entry.getName() + " to " + vulnerable.getName());
                }
            }
        }

        Msg.info(this, String.format("Created %d VULNERABLE_VIA edges", edgesCreated));
        return edgesCreated;
    }

    /**
     * Find entry point nodes (exported functions, main, etc.)
     */
    private List<KnowledgeNode> findEntryPoints() {
        List<KnowledgeNode> entryPoints = new ArrayList<>();

        // Common entry point names
        Set<String> entryPointNames = new HashSet<>(Arrays.asList(
                "main", "_main", "wmain", "_wmain",
                "WinMain", "wWinMain", "_WinMain@16", "_wWinMain@16",
                "DllMain", "_DllMain@12", "DllEntryPoint",
                "start", "_start", "entry", "_entry",
                "mainCRTStartup", "wmainCRTStartup",
                "WinMainCRTStartup", "wWinMainCRTStartup"
        ));

        for (KnowledgeNode node : graph.getNodesByType(NodeType.FUNCTION)) {
            boolean isEntryPoint = false;

            // Check security flags for ENTRY_POINT
            List<String> flags = node.getSecurityFlags();
            if (flags != null && flags.contains("ENTRY_POINT")) {
                isEntryPoint = true;
            }

            // Check for known entry point names
            String name = node.getName();
            if (name != null && entryPointNames.contains(name)) {
                isEntryPoint = true;
            }

            // Check if function is exported (has EXPORTED flag or is in symbol table as exported)
            if (flags != null && flags.contains("EXPORTED")) {
                isEntryPoint = true;
            }

            if (isEntryPoint && !entryPoints.contains(node)) {
                entryPoints.add(node);
            }
        }

        return entryPoints;
    }

    /**
     * Find nodes with vulnerability flags (*_RISK, VULN_*, etc.)
     */
    private List<KnowledgeNode> findVulnerableNodes() {
        List<KnowledgeNode> vulnerableNodes = new ArrayList<>();

        for (KnowledgeNode node : graph.getNodesByType(NodeType.FUNCTION)) {
            List<String> flags = node.getSecurityFlags();
            if (flags == null || flags.isEmpty()) {
                continue;
            }

            // Check for vulnerability-indicating flags
            for (String flag : flags) {
                if (flag.endsWith("_RISK") || flag.startsWith("VULN_")) {
                    if (!vulnerableNodes.contains(node)) {
                        vulnerableNodes.add(node);
                    }
                    break;
                }
            }
        }

        return vulnerableNodes;
    }

    /**
     * Extract the primary vulnerability type from a node's security flags.
     */
    private String getVulnerabilityType(KnowledgeNode node) {
        List<String> flags = node.getSecurityFlags();
        if (flags == null || flags.isEmpty()) {
            return "UNKNOWN";
        }

        // Prefer VULN_* flags, then *_RISK flags
        for (String flag : flags) {
            if (flag.startsWith("VULN_")) {
                return flag.substring(5); // Remove "VULN_" prefix
            }
        }
        for (String flag : flags) {
            if (flag.endsWith("_RISK")) {
                return flag.replace("_RISK", "");
            }
        }

        return "UNKNOWN";
    }

    /**
     * Get statistics about taint sources and sinks.
     */
    public Map<String, Object> getTaintStats() {
        Map<String, Object> stats = new HashMap<>();

        List<KnowledgeNode> sources = findSourceNodes();
        List<KnowledgeNode> sinks = findSinkNodes();

        stats.put("source_count", sources.size());
        stats.put("sink_count", sinks.size());

        // List source names
        List<String> sourceNames = sources.stream()
                .map(n -> n.getName() != null ? n.getName() : String.format("sub_%x", n.getAddress()))
                .limit(10)
                .collect(Collectors.toList());
        stats.put("sample_sources", sourceNames);

        // List sink names
        List<String> sinkNames = sinks.stream()
                .map(n -> n.getName() != null ? n.getName() : String.format("sub_%x", n.getAddress()))
                .limit(10)
                .collect(Collectors.toList());
        stats.put("sample_sinks", sinkNames);

        return stats;
    }

    /**
     * Represents a taint path from source to sink.
     */
    public static class TaintPath {
        private final String sourceName;
        private final long sourceAddress;
        private final String sinkName;
        private final long sinkAddress;
        private final List<PathNode> path;
        private final String severity;
        private final int pathLength;

        public TaintPath(String sourceName, long sourceAddress,
                         String sinkName, long sinkAddress,
                         List<PathNode> path, String severity, int pathLength) {
            this.sourceName = sourceName;
            this.sourceAddress = sourceAddress;
            this.sinkName = sinkName;
            this.sinkAddress = sinkAddress;
            this.path = path;
            this.severity = severity;
            this.pathLength = pathLength;
        }

        public String getSourceName() { return sourceName; }
        public long getSourceAddress() { return sourceAddress; }
        public String getSinkName() { return sinkName; }
        public long getSinkAddress() { return sinkAddress; }
        public List<PathNode> getPath() { return path; }
        public String getSeverity() { return severity; }
        public int getPathLength() { return pathLength; }

        /**
         * Format as tool output.
         */
        public String toToolOutput() {
            StringBuilder sb = new StringBuilder();
            sb.append("{\n");
            sb.append("  \"source\": \"").append(sourceName).append("\",\n");
            sb.append("  \"source_address\": \"0x").append(Long.toHexString(sourceAddress)).append("\",\n");
            sb.append("  \"sink\": \"").append(sinkName).append("\",\n");
            sb.append("  \"sink_address\": \"0x").append(Long.toHexString(sinkAddress)).append("\",\n");
            sb.append("  \"severity\": \"").append(severity).append("\",\n");
            sb.append("  \"path_length\": ").append(pathLength).append(",\n");
            sb.append("  \"path\": [\n");

            for (int i = 0; i < path.size(); i++) {
                PathNode node = path.get(i);
                sb.append("    {\"name\": \"").append(node.name)
                  .append("\", \"address\": \"0x").append(Long.toHexString(node.address)).append("\"}");
                if (i < path.size() - 1) sb.append(",");
                sb.append("\n");
            }

            sb.append("  ]\n");
            sb.append("}");
            return sb.toString();
        }

        /**
         * A node in the taint path.
         */
        public static class PathNode {
            private final String id;
            private final String name;
            private final long address;
            private final List<String> flags;

            public PathNode(String id, String name, long address, List<String> flags) {
                this.id = id;
                this.name = name;
                this.address = address;
                this.flags = flags != null ? flags : List.of();
            }

            public String getId() { return id; }
            public String getName() { return name; }
            public long getAddress() { return address; }
            public List<String> getFlags() { return flags; }
        }
    }
}
