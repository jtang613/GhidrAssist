package ghidrassist.graphrag.analysis;

import java.util.*;
import java.util.stream.Collectors;

import org.jgrapht.Graph;
import org.jgrapht.GraphPath;
import org.jgrapht.alg.shortestpath.BFSShortestPath;

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

    // Network send APIs - functions that send data over the network
    private static final Set<String> NETWORK_SEND_APIS = new HashSet<>(Arrays.asList(
            // POSIX
            "send", "sendto", "sendmsg", "write",
            // WinSock
            "WSASend", "WSASendTo", "WSASendMsg", "WSASendDisconnect",
            // SSL/TLS
            "SSL_write",
            // WinHTTP
            "WinHttpWriteData", "WinHttpSendRequest",
            // WinINet
            "InternetWriteFile", "HttpSendRequest", "HttpSendRequestA", "HttpSendRequestW",
            "HttpSendRequestEx", "HttpSendRequestExA", "HttpSendRequestExW",
            // libcurl
            "curl_easy_send"
    ));

    // Network recv APIs - functions that receive data from the network
    private static final Set<String> NETWORK_RECV_APIS = new HashSet<>(Arrays.asList(
            // POSIX
            "recv", "recvfrom", "recvmsg", "read",
            // WinSock
            "WSARecv", "WSARecvFrom", "WSARecvMsg", "WSARecvDisconnect",
            // SSL/TLS
            "SSL_read",
            // WinHTTP
            "WinHttpReadData", "WinHttpReceiveResponse",
            // WinINet
            "InternetReadFile", "InternetReadFileEx", "HttpQueryInfo", "HttpQueryInfoA", "HttpQueryInfoW",
            // libcurl
            "curl_easy_recv"
    ));

    private final BinaryKnowledgeGraph graph;

    // Cancellation support
    private volatile boolean cancelRequested = false;

    // Progress callback for reporting analysis progress
    private volatile ProgressCallback progressCallback;

    /**
     * Callback interface for reporting analysis progress.
     */
    @FunctionalInterface
    public interface ProgressCallback {
        /**
         * Called to report progress.
         * @param current Current item being processed
         * @param total Total items to process
         * @param message Description of current phase
         */
        void onProgress(int current, int total, String message);
    }

    public TaintAnalyzer(BinaryKnowledgeGraph graph) {
        this.graph = graph;
    }

    /**
     * Set the progress callback for reporting analysis progress.
     */
    public void setProgressCallback(ProgressCallback callback) {
        this.progressCallback = callback;
    }

    /**
     * Report progress if a callback is set.
     */
    private void reportProgress(int current, int total, String message) {
        ProgressCallback callback = progressCallback;
        if (callback != null) {
            callback.onProgress(current, total, message);
        }
    }

    /**
     * Request cancellation of ongoing analysis.
     * Analysis methods will check this flag and exit early.
     */
    public void requestCancel() {
        this.cancelRequested = true;
    }

    /**
     * Check if cancellation has been requested.
     */
    public boolean isCancelRequested() {
        return cancelRequested;
    }

    /**
     * Reset cancellation flag (call before starting new analysis).
     */
    public void resetCancel() {
        this.cancelRequested = false;
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

        // Use BFS for fast shortest path finding (linear time vs exponential for AllDirectedPaths)
        Graph<String, LabeledEdge> memGraph = graph.getMemoryGraph();
        BFSShortestPath<String, LabeledEdge> bfs = new BFSShortestPath<>(memGraph);

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
                    // Find shortest path only (BFS is O(V+E) vs O(k^n) for all paths)
                    GraphPath<String, LabeledEdge> path = bfs.getPath(source.getId(), sink.getId());

                    if (path != null && path.getLength() <= MAX_PATH_LENGTH) {
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
        BFSShortestPath<String, LabeledEdge> bfs = new BFSShortestPath<>(memGraph);

        for (KnowledgeNode sink : sinkNodes) {
            if (allPaths.size() >= maxPaths) break;
            if (sourceNode.getId().equals(sink.getId())) continue;

            if (!memGraph.containsVertex(sourceNode.getId()) ||
                !memGraph.containsVertex(sink.getId())) {
                continue;
            }

            try {
                GraphPath<String, LabeledEdge> path = bfs.getPath(sourceNode.getId(), sink.getId());

                if (path != null && path.getLength() <= MAX_PATH_LENGTH) {
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
        BFSShortestPath<String, LabeledEdge> bfs = new BFSShortestPath<>(memGraph);

        for (KnowledgeNode source : sourceNodes) {
            if (allPaths.size() >= maxPaths) break;
            if (source.getId().equals(sinkNode.getId())) continue;

            if (!memGraph.containsVertex(source.getId()) ||
                !memGraph.containsVertex(sinkNode.getId())) {
                continue;
            }

            try {
                GraphPath<String, LabeledEdge> path = bfs.getPath(source.getId(), sinkNode.getId());

                if (path != null && path.getLength() <= MAX_PATH_LENGTH) {
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

        // Use JGraphT to check path existence - BFS is O(V+E) per query vs exponential for AllDirectedPaths
        Graph<String, LabeledEdge> memGraph = graph.getMemoryGraph();
        BFSShortestPath<String, LabeledEdge> bfs = new BFSShortestPath<>(memGraph);

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
                    GraphPath<String, LabeledEdge> path = bfs.getPath(entry.getId(), vulnerable.getId());

                    if (path != null && path.getLength() <= MAX_PATH_LENGTH) {
                        // Path exists - create VULNERABLE_VIA edge
                        if (!graph.hasEdgeBetween(entry.getId(), vulnerable.getId(), EdgeType.VULNERABLE_VIA)) {
                            // Get the vulnerability type from the vulnerable node's flags
                            String vulnType = getVulnerabilityType(vulnerable);
                            String metadata = String.format("{\"path_length\":%d,\"vuln_type\":\"%s\"}",
                                    path.getLength(), vulnType);

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

    // ========================================
    // Network Flow Analysis
    // ========================================

    /**
     * Analyze network data flow and create NETWORK_SEND_PATH and NETWORK_RECV_PATH edges.
     *
     * @return NetworkFlowResult with statistics about edges created
     */
    public NetworkFlowResult analyzeNetworkFlow() {
        Msg.info(this, "Starting network flow analysis...");
        resetCancel();  // Reset cancellation flag at start

        // Debug: Log memory graph statistics
        Graph<String, LabeledEdge> memGraph = graph.getMemoryGraph();
        int totalVertices = memGraph.vertexSet().size();
        int totalEdges = memGraph.edgeSet().size();
        long callEdges = memGraph.edgeSet().stream().filter(e -> e.getType() == EdgeType.CALLS).count();
        Msg.debug(this, String.format("Memory graph stats: %d vertices, %d edges (%d CALLS edges)",
                totalVertices, totalEdges, callEdges));

        reportProgress(0, 100, "Finding network send functions...");

        // Find network send/recv nodes
        List<KnowledgeNode> sendNodes = findNetworkSendNodes();
        if (cancelRequested) {
            Msg.info(this, "Network flow analysis cancelled during send node discovery");
            return new NetworkFlowResult(0, 0, 0, 0, Collections.emptyList(), Collections.emptyList());
        }

        reportProgress(2, 100, "Finding network recv functions...");

        List<KnowledgeNode> recvNodes = findNetworkRecvNodes();
        if (cancelRequested) {
            Msg.info(this, "Network flow analysis cancelled during recv node discovery");
            return new NetworkFlowResult(0, 0, 0, 0, Collections.emptyList(), Collections.emptyList());
        }

        Msg.info(this, String.format("Found %d functions that send network data", sendNodes.size()));
        Msg.info(this, String.format("Found %d functions that receive network data", recvNodes.size()));

        reportProgress(5, 100, String.format("Found %d send, %d recv functions. Creating send edges...",
                sendNodes.size(), recvNodes.size()));

        // Create edges (these methods check cancelRequested internally and report progress)
        // Returns int[]{created, existing}
        int[] sendResult = createNetworkSendEdges(sendNodes);
        int sendEdgesCreated = sendResult[0];
        int sendEdgesExisting = sendResult[1];

        if (cancelRequested) {
            Msg.info(this, "Network flow analysis cancelled during send edge creation");
            return new NetworkFlowResult(sendEdgesCreated, 0, sendEdgesExisting, 0,
                    sendNodes.stream().map(n -> n.getName() != null ? n.getName() : String.format("sub_%x", n.getAddress())).collect(Collectors.toList()),
                    Collections.emptyList());
        }

        int[] recvResult = createNetworkRecvEdges(recvNodes);
        int recvEdgesCreated = recvResult[0];
        int recvEdgesExisting = recvResult[1];

        // Collect function names for the result
        List<String> sendFunctionNames = sendNodes.stream()
                .map(n -> n.getName() != null ? n.getName() : String.format("sub_%x", n.getAddress()))
                .collect(Collectors.toList());

        List<String> recvFunctionNames = recvNodes.stream()
                .map(n -> n.getName() != null ? n.getName() : String.format("sub_%x", n.getAddress()))
                .collect(Collectors.toList());

        int totalSendEdges = sendEdgesCreated + sendEdgesExisting;
        int totalRecvEdges = recvEdgesCreated + recvEdgesExisting;

        if (cancelRequested) {
            Msg.info(this, "Network flow analysis cancelled");
        } else {
            reportProgress(100, 100, String.format("Complete: %d send edges (%d new), %d recv edges (%d new)",
                    totalSendEdges, sendEdgesCreated, totalRecvEdges, recvEdgesCreated));
            Msg.info(this, String.format("Network flow analysis complete: %d send edges (%d new, %d existing), %d recv edges (%d new, %d existing)",
                    totalSendEdges, sendEdgesCreated, sendEdgesExisting,
                    totalRecvEdges, recvEdgesCreated, recvEdgesExisting));
        }

        return new NetworkFlowResult(sendEdgesCreated, recvEdgesCreated, sendEdgesExisting, recvEdgesExisting,
                sendFunctionNames, recvFunctionNames);
    }

    /**
     * Find functions that call network send APIs.
     * Uses Set for O(1) deduplication.
     */
    public List<KnowledgeNode> findNetworkSendNodes() {
        Set<String> seenIds = new HashSet<>();
        List<KnowledgeNode> sendNodes = new ArrayList<>();

        for (KnowledgeNode node : graph.getNodesByType(NodeType.FUNCTION)) {
            // Check if function name is a known send API (for external function nodes)
            String name = node.getName();
            if (name != null && isNetworkSendAPI(name)) {
                if (seenIds.add(node.getId())) {
                    sendNodes.add(node);
                }
                continue;
            }

            // Check callees for network send functions
            for (KnowledgeNode callee : graph.getCallees(node.getId())) {
                if (callee.getName() != null && isNetworkSendAPI(callee.getName())) {
                    if (seenIds.add(node.getId())) {
                        sendNodes.add(node);
                    }
                    break;
                }
            }
        }

        return sendNodes;
    }

    /**
     * Find functions that call network recv APIs.
     * Uses Set for O(1) deduplication.
     */
    public List<KnowledgeNode> findNetworkRecvNodes() {
        Set<String> seenIds = new HashSet<>();
        List<KnowledgeNode> recvNodes = new ArrayList<>();
        int foundByName = 0;
        int foundByCallee = 0;

        for (KnowledgeNode node : graph.getNodesByType(NodeType.FUNCTION)) {
            // Check if function name is a known recv API (for external function nodes)
            String name = node.getName();
            if (name != null && isNetworkRecvAPI(name)) {
                if (seenIds.add(node.getId())) {
                    recvNodes.add(node);
                    foundByName++;
                    Msg.debug(this, String.format("Found recv API by name: %s (id=%s)", name, node.getId()));
                }
                continue;
            }

            // Check callees for network recv functions
            for (KnowledgeNode callee : graph.getCallees(node.getId())) {
                if (callee.getName() != null && isNetworkRecvAPI(callee.getName())) {
                    if (seenIds.add(node.getId())) {
                        recvNodes.add(node);
                        foundByCallee++;
                        Msg.debug(this, String.format("Found function calling recv API: %s calls %s",
                                name != null ? name : "sub_" + Long.toHexString(node.getAddress()),
                                callee.getName()));
                    }
                    break;
                }
            }
        }

        Msg.info(this, String.format("Recv nodes breakdown: %d by API name, %d by callee match", foundByName, foundByCallee));
        return recvNodes;
    }

    /**
     * Check if a function name is a network send API.
     */
    private boolean isNetworkSendAPI(String name) {
        if (name == null) return false;
        // Normalize name (remove __imp_, leading _, trailing @N)
        String normalized = normalizeFunctionName(name);
        return NETWORK_SEND_APIS.contains(name) || NETWORK_SEND_APIS.contains(normalized);
    }

    /**
     * Check if a function name is a network recv API.
     */
    private boolean isNetworkRecvAPI(String name) {
        if (name == null) return false;
        // Normalize name (remove __imp_, leading _, trailing @N)
        String normalized = normalizeFunctionName(name);
        return NETWORK_RECV_APIS.contains(name) || NETWORK_RECV_APIS.contains(normalized);
    }

    /**
     * Normalize a function name by removing common decorations.
     */
    private String normalizeFunctionName(String name) {
        if (name == null) return null;

        String normalized = name;

        // Remove __imp_ prefix (import thunk)
        if (normalized.startsWith("__imp_")) {
            normalized = normalized.substring(6);
        }

        // Remove leading underscores (one or two)
        while (normalized.startsWith("_") && normalized.length() > 1) {
            normalized = normalized.substring(1);
        }

        // Remove trailing @N (stdcall decoration)
        int atIndex = normalized.lastIndexOf('@');
        if (atIndex > 0) {
            String suffix = normalized.substring(atIndex + 1);
            if (suffix.matches("\\d+")) {
                normalized = normalized.substring(0, atIndex);
            }
        }

        return normalized;
    }

    /**
     * Create NETWORK_SEND_PATH edges from entry points to send functions.
     * Also creates edges from direct callers.
     * @return int array: [0] = edges created, [1] = edges already existing
     */
    private int[] createNetworkSendEdges(List<KnowledgeNode> sendNodes) {
        if (sendNodes.isEmpty()) {
            return new int[]{0, 0};
        }

        // Find entry points
        List<KnowledgeNode> entryPoints = findEntryPoints();
        Graph<String, LabeledEdge> memGraph = graph.getMemoryGraph();

        final int totalEntryPoints = entryPoints.size();
        final int totalSendNodes = sendNodes.size();
        Msg.info(this, String.format("Processing %d entry points × %d send nodes...",
                totalEntryPoints, totalSendNodes));

        // Debug: Log entry points and send nodes
        for (KnowledgeNode entry : entryPoints) {
            String name = entry.getName() != null ? entry.getName() : "sub_" + Long.toHexString(entry.getAddress());
            boolean inGraph = memGraph.containsVertex(entry.getId());
            int outEdges = inGraph ? memGraph.outgoingEdgesOf(entry.getId()).size() : 0;
            Msg.debug(this, String.format("Entry point '%s': inMemGraph=%b, outgoingEdges=%d",
                    name, inGraph, outEdges));
        }
        for (KnowledgeNode send : sendNodes) {
            String name = send.getName() != null ? send.getName() : "sub_" + Long.toHexString(send.getAddress());
            boolean inGraph = memGraph.containsVertex(send.getId());
            int inEdges = inGraph ? memGraph.incomingEdgesOf(send.getId()).size() : 0;
            Msg.debug(this, String.format("Send node '%s': inMemGraph=%b, incomingEdges=%d",
                    name, inGraph, inEdges));
        }

        // Use atomic counters for thread-safe counting
        java.util.concurrent.atomic.AtomicInteger edgesCreated = new java.util.concurrent.atomic.AtomicInteger(0);
        java.util.concurrent.atomic.AtomicInteger edgesExisting = new java.util.concurrent.atomic.AtomicInteger(0);
        java.util.concurrent.atomic.AtomicInteger entryPointsProcessed = new java.util.concurrent.atomic.AtomicInteger(0);

        // Progress reporting: send edges phase is 5-80% of total (75% range)
        final int PROGRESS_START = 5;
        final int PROGRESS_END = 80;

        // Process entry→send pairs sequentially for debugging
        org.jgrapht.alg.shortestpath.BFSShortestPath<String, LabeledEdge> bfs =
                new org.jgrapht.alg.shortestpath.BFSShortestPath<>(memGraph);

        for (KnowledgeNode entry : entryPoints) {
            if (cancelRequested) {
                break;
            }

            String entryName = entry.getName() != null ? entry.getName() : "sub_" + Long.toHexString(entry.getAddress());

            for (KnowledgeNode sendNode : sendNodes) {
                if (cancelRequested) {
                    break;
                }

                String sendName = sendNode.getName() != null ? sendNode.getName() : "sub_" + Long.toHexString(sendNode.getAddress());

                if (entry.getId().equals(sendNode.getId())) {
                    continue;
                }

                if (!memGraph.containsVertex(entry.getId()) ||
                    !memGraph.containsVertex(sendNode.getId())) {
                    Msg.debug(this, String.format("Skipping %s -> %s: vertex not in graph", entryName, sendName));
                    continue;
                }

                // Skip if edge already exists
                if (graph.hasEdgeBetween(entry.getId(), sendNode.getId(), EdgeType.NETWORK_SEND_PATH)) {
                    Msg.debug(this, String.format("SEND edge already exists: %s -> %s", entryName, sendName));
                    edgesExisting.incrementAndGet();
                    continue;
                }

                try {
                    // BFS finds shortest path only - much faster than AllDirectedPaths
                    GraphPath<String, LabeledEdge> path = bfs.getPath(entry.getId(), sendNode.getId());

                    if (path != null) {
                        if (path.getLength() <= MAX_PATH_LENGTH) {
                            String sendAPI = getSendAPIName(sendNode);
                            String metadata = String.format(
                                    "{\"path_length\":%d,\"send_api\":\"%s\",\"entry_point\":\"%s\"}",
                                    path.getLength(), sendAPI, entry.getName());

                            graph.addEdge(entry.getId(), sendNode.getId(),
                                    EdgeType.NETWORK_SEND_PATH, 1.0, metadata);
                            edgesCreated.incrementAndGet();
                            Msg.info(this, String.format("Created SEND edge: %s -> %s (path length %d)",
                                    entryName, sendName, path.getLength()));
                        } else {
                            Msg.debug(this, String.format("Path too long %s -> %s: %d > %d",
                                    entryName, sendName, path.getLength(), MAX_PATH_LENGTH));
                        }
                    } else {
                        Msg.debug(this, String.format("No path found: %s -> %s", entryName, sendName));
                    }
                } catch (Exception e) {
                    Msg.debug(this, String.format("Path finding error %s -> %s: %s", entryName, sendName, e.getMessage()));
                }
            }

            // Update progress after completing each entry point
            int completed = entryPointsProcessed.incrementAndGet();
            if (totalEntryPoints > 0) {
                int percent = PROGRESS_START + (completed * (PROGRESS_END - PROGRESS_START) / totalEntryPoints);
                reportProgress(completed, totalEntryPoints,
                        String.format("Send paths: %d/%d entry points (%d%%), %d edges",
                                completed, totalEntryPoints, percent, edgesCreated.get()));
            }
        }

        // Check cancellation before direct caller processing
        if (cancelRequested) {
            return new int[]{edgesCreated.get(), edgesExisting.get()};
        }

        // Also add direct caller edges for completeness (sequential - usually small)
        for (KnowledgeNode sendNode : sendNodes) {
            if (cancelRequested) {
                break;
            }
            for (KnowledgeNode caller : graph.getCallers(sendNode.getId())) {
                if (!graph.hasEdgeBetween(caller.getId(), sendNode.getId(), EdgeType.NETWORK_SEND_PATH)) {
                    String sendAPI = getSendAPIName(sendNode);
                    String metadata = String.format(
                            "{\"direct_caller\":true,\"send_api\":\"%s\"}", sendAPI);

                    graph.addEdge(caller.getId(), sendNode.getId(),
                            EdgeType.NETWORK_SEND_PATH, 0.5, metadata);
                    edgesCreated.incrementAndGet();
                } else {
                    edgesExisting.incrementAndGet();
                }
            }
        }

        return new int[]{edgesCreated.get(), edgesExisting.get()};
    }

    /**
     * Create NETWORK_RECV_PATH edges from recv functions to their callers.
     * Shows where received network data flows.
     * @return int array: [0] = edges created, [1] = edges already existing
     */
    private int[] createNetworkRecvEdges(List<KnowledgeNode> recvNodes) {
        if (recvNodes.isEmpty()) {
            return new int[]{0, 0};
        }

        final int totalRecvNodes = recvNodes.size();
        Msg.info(this, String.format("Processing %d recv nodes for caller tracing...", totalRecvNodes));

        // Debug: Check if recv nodes exist in memory graph and have callers
        Graph<String, LabeledEdge> memGraph = graph.getMemoryGraph();
        for (KnowledgeNode recvNode : recvNodes) {
            boolean inGraph = memGraph.containsVertex(recvNode.getId());
            int incomingEdgeCount = inGraph ? memGraph.incomingEdgesOf(recvNode.getId()).size() : 0;
            List<KnowledgeNode> callers = graph.getCallers(recvNode.getId());
            Msg.debug(this, String.format("Recv node '%s': inMemGraph=%b, incomingEdges=%d, callers=%d",
                    recvNode.getName() != null ? recvNode.getName() : "sub_" + Long.toHexString(recvNode.getAddress()),
                    inGraph, incomingEdgeCount, callers.size()));
        }

        // Use atomic counters for thread-safe counting
        java.util.concurrent.atomic.AtomicInteger edgesCreated = new java.util.concurrent.atomic.AtomicInteger(0);
        java.util.concurrent.atomic.AtomicInteger edgesExisting = new java.util.concurrent.atomic.AtomicInteger(0);
        java.util.concurrent.atomic.AtomicInteger recvNodesProcessed = new java.util.concurrent.atomic.AtomicInteger(0);

        // Progress reporting: recv edges phase is 80-98% of total (18% range)
        final int PROGRESS_START = 80;
        final int PROGRESS_END = 98;

        // Process recv nodes
        for (KnowledgeNode recvNode : recvNodes) {
            // Check for cancellation at start of each recv node processing
            if (cancelRequested) {
                break;
            }

            String recvAPI = getRecvAPIName(recvNode);
            String recvNodeName = recvNode.getName() != null ? recvNode.getName() : "sub_" + Long.toHexString(recvNode.getAddress());

            // Get direct callers (1-hop)
            List<KnowledgeNode> callers = graph.getCallers(recvNode.getId());
            Msg.debug(this, String.format("Processing recv node '%s': found %d callers", recvNodeName, callers.size()));

            for (KnowledgeNode caller : callers) {
                // Check for cancellation periodically
                if (cancelRequested) {
                    break;
                }

                String callerName = caller.getName() != null ? caller.getName() : "sub_" + Long.toHexString(caller.getAddress());

                // Edge: recv -> caller (showing data flow direction)
                try {
                    boolean alreadyExists = graph.hasEdgeBetween(recvNode.getId(), caller.getId(), EdgeType.NETWORK_RECV_PATH);
                    if (!alreadyExists) {
                        String metadata = String.format(
                                "{\"recv_api\":\"%s\",\"hop\":1}", recvAPI);

                        graph.addEdge(recvNode.getId(), caller.getId(),
                                EdgeType.NETWORK_RECV_PATH, 1.0, metadata);
                        edgesCreated.incrementAndGet();
                        Msg.debug(this, String.format("Created NETWORK_RECV_PATH edge: %s -> %s", recvNodeName, callerName));
                    } else {
                        edgesExisting.incrementAndGet();
                        Msg.debug(this, String.format("Edge already exists: %s -> %s", recvNodeName, callerName));
                    }
                } catch (Exception e) {
                    Msg.error(this, String.format("Failed to create edge %s -> %s: %s", recvNodeName, callerName, e.getMessage()));
                }

                // Also trace 2-hop callers (for data propagation tracking)
                for (KnowledgeNode grandCaller : graph.getCallers(caller.getId())) {
                    try {
                        if (!graph.hasEdgeBetween(recvNode.getId(), grandCaller.getId(), EdgeType.NETWORK_RECV_PATH)) {
                            String metadata2 = String.format(
                                    "{\"recv_api\":\"%s\",\"hop\":2,\"via\":\"%s\"}",
                                    recvAPI, caller.getName());

                            graph.addEdge(recvNode.getId(), grandCaller.getId(),
                                    EdgeType.NETWORK_RECV_PATH, 0.5, metadata2);
                            edgesCreated.incrementAndGet();
                        } else {
                            edgesExisting.incrementAndGet();
                        }
                    } catch (Exception e) {
                        Msg.debug(this, "Failed to create 2-hop edge: " + e.getMessage());
                    }
                }
            }

            // Update progress after completing each recv node
            int completed = recvNodesProcessed.incrementAndGet();
            if (totalRecvNodes > 0) {
                int percent = PROGRESS_START + (completed * (PROGRESS_END - PROGRESS_START) / totalRecvNodes);
                reportProgress(completed, totalRecvNodes,
                        String.format("Recv paths: %d/%d recv nodes (%d%%), %d edges",
                                completed, totalRecvNodes, percent, edgesCreated.get()));
            }
        }

        return new int[]{edgesCreated.get(), edgesExisting.get()};
    }

    /**
     * Get the name of the send API called by a node.
     */
    private String getSendAPIName(KnowledgeNode node) {
        // If the node itself is a send API
        if (node.getName() != null && isNetworkSendAPI(node.getName())) {
            return normalizeFunctionName(node.getName());
        }

        // Check callees
        for (KnowledgeNode callee : graph.getCallees(node.getId())) {
            if (callee.getName() != null && isNetworkSendAPI(callee.getName())) {
                return normalizeFunctionName(callee.getName());
            }
        }

        return "unknown";
    }

    /**
     * Get the name of the recv API called by a node.
     */
    private String getRecvAPIName(KnowledgeNode node) {
        // If the node itself is a recv API
        if (node.getName() != null && isNetworkRecvAPI(node.getName())) {
            return normalizeFunctionName(node.getName());
        }

        // Check callees
        for (KnowledgeNode callee : graph.getCallees(node.getId())) {
            if (callee.getName() != null && isNetworkRecvAPI(callee.getName())) {
                return normalizeFunctionName(callee.getName());
            }
        }

        return "unknown";
    }

    /**
     * Result of network flow analysis.
     */
    public static class NetworkFlowResult {
        private final int sendPathEdgesCreated;
        private final int recvPathEdgesCreated;
        private final int sendPathEdgesExisting;
        private final int recvPathEdgesExisting;
        private final List<String> sendFunctions;
        private final List<String> recvFunctions;

        public NetworkFlowResult(int sendPathEdgesCreated, int recvPathEdgesCreated,
                                  int sendPathEdgesExisting, int recvPathEdgesExisting,
                                  List<String> sendFunctions, List<String> recvFunctions) {
            this.sendPathEdgesCreated = sendPathEdgesCreated;
            this.recvPathEdgesCreated = recvPathEdgesCreated;
            this.sendPathEdgesExisting = sendPathEdgesExisting;
            this.recvPathEdgesExisting = recvPathEdgesExisting;
            this.sendFunctions = sendFunctions;
            this.recvFunctions = recvFunctions;
        }

        public int getSendPathEdges() { return sendPathEdgesCreated + sendPathEdgesExisting; }
        public int getRecvPathEdges() { return recvPathEdgesCreated + recvPathEdgesExisting; }
        public int getSendPathEdgesCreated() { return sendPathEdgesCreated; }
        public int getRecvPathEdgesCreated() { return recvPathEdgesCreated; }
        public List<String> getSendFunctions() { return sendFunctions; }
        public List<String> getRecvFunctions() { return recvFunctions; }

        public String toSummary() {
            int totalSend = sendPathEdgesCreated + sendPathEdgesExisting;
            int totalRecv = recvPathEdgesCreated + recvPathEdgesExisting;
            return String.format(
                    "Network Flow Analysis Complete:\n" +
                    "- Found %d functions calling send APIs\n" +
                    "- NETWORK_SEND_PATH edges: %d total (%d new, %d existing)\n" +
                    "- Found %d functions calling recv APIs\n" +
                    "- NETWORK_RECV_PATH edges: %d total (%d new, %d existing)",
                    sendFunctions.size(), totalSend, sendPathEdgesCreated, sendPathEdgesExisting,
                    recvFunctions.size(), totalRecv, recvPathEdgesCreated, recvPathEdgesExisting);
        }
    }
}
