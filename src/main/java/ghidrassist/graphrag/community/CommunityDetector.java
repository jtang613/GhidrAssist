package ghidrassist.graphrag.community;

import java.util.*;
import java.util.stream.Collectors;

import org.jgrapht.Graph;
import org.jgrapht.Graphs;

import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidrassist.graphrag.BinaryKnowledgeGraph;
import ghidrassist.graphrag.BinaryKnowledgeGraph.LabeledEdge;
import ghidrassist.graphrag.nodes.EdgeType;
import ghidrassist.graphrag.nodes.KnowledgeNode;
import ghidrassist.graphrag.nodes.NodeType;

/**
 * Detects communities (clusters) of related functions in a binary's call graph
 * using the Label Propagation algorithm.
 *
 * Label Propagation is an efficient O(E) algorithm that:
 * 1. Initializes each node with a unique label
 * 2. Iteratively updates labels to match the most frequent neighbor label
 * 3. Converges when no labels change
 *
 * The algorithm naturally groups densely connected functions into communities.
 */
public class CommunityDetector {

    private static final int DEFAULT_MAX_ITERATIONS = 100;
    private static final int DEFAULT_MIN_COMMUNITY_SIZE = 2;

    private final BinaryKnowledgeGraph graph;
    private final TaskMonitor monitor;
    private final Random random;

    public CommunityDetector(BinaryKnowledgeGraph graph, TaskMonitor monitor) {
        this.graph = graph;
        this.monitor = monitor;
        this.random = new Random();
    }

    /**
     * Detect communities in the call graph using Label Propagation.
     *
     * @param maxIterations Maximum iterations before stopping
     * @param minCommunitySize Minimum members for a community (smaller ones are merged)
     * @return Number of communities detected
     */
    public int detectCommunities(int maxIterations, int minCommunitySize) {
        Msg.info(this, "Starting community detection...");

        // Get the in-memory graph
        Graph<String, LabeledEdge> memGraph = graph.getMemoryGraph();
        if (memGraph == null || memGraph.vertexSet().isEmpty()) {
            Msg.warn(this, "No graph data available for community detection");
            return 0;
        }

        // Get only FUNCTION nodes (exclude BINARY, BLOCK, etc.)
        Set<String> functionNodeIds = getFunctionNodeIds();
        if (functionNodeIds.isEmpty()) {
            Msg.warn(this, "No function nodes found for community detection");
            return 0;
        }

        Msg.info(this, String.format("Detecting communities among %d functions", functionNodeIds.size()));

        // Run label propagation
        Map<String, Integer> nodeToLabel = runLabelPropagation(
                memGraph, functionNodeIds, maxIterations);

        // Group nodes by label
        Map<Integer, List<String>> communities = groupByLabel(nodeToLabel);

        // Merge small communities
        communities = mergeSmallCommunities(communities, minCommunitySize);

        Msg.info(this, String.format("Detected %d communities", communities.size()));

        // Clear existing communities for this binary
        graph.clearCommunitiesForBinary();

        // Create community records
        int communityCount = createCommunityRecords(communities);

        return communityCount;
    }

    /**
     * Detect communities with default parameters.
     */
    public int detectCommunities() {
        return detectCommunities(DEFAULT_MAX_ITERATIONS, DEFAULT_MIN_COMMUNITY_SIZE);
    }

    /**
     * Get IDs of all FUNCTION type nodes in the graph.
     */
    private Set<String> getFunctionNodeIds() {
        Set<String> ids = new HashSet<>();
        for (KnowledgeNode node : graph.getNodesByType(NodeType.FUNCTION)) {
            ids.add(node.getId());
        }
        return ids;
    }

    /**
     * Run Label Propagation algorithm on the graph.
     *
     * Algorithm:
     * 1. Initialize each node with unique label (0, 1, 2, ...)
     * 2. Shuffle nodes and iterate:
     *    - For each node, find most common label among neighbors
     *    - Update node's label to that most common label
     * 3. Stop when no labels change or max iterations reached
     */
    private Map<String, Integer> runLabelPropagation(
            Graph<String, LabeledEdge> memGraph,
            Set<String> nodeIds,
            int maxIterations) {

        // Initialize labels
        Map<String, Integer> labels = new HashMap<>();
        int labelCounter = 0;
        for (String nodeId : nodeIds) {
            labels.put(nodeId, labelCounter++);
        }

        // Convert to list for shuffling
        List<String> nodeList = new ArrayList<>(nodeIds);

        // Iterate until convergence
        for (int iteration = 0; iteration < maxIterations; iteration++) {
            if (monitor != null && monitor.isCancelled()) {
                break;
            }

            // Shuffle to avoid ordering bias
            Collections.shuffle(nodeList, random);

            boolean changed = false;

            for (String nodeId : nodeList) {
                if (!memGraph.containsVertex(nodeId)) {
                    continue;
                }

                // Get neighbor labels (considering only CALLS edges for call graph clustering)
                Map<Integer, Integer> labelCounts = new HashMap<>();

                // Outgoing edges (functions this node calls)
                for (LabeledEdge edge : memGraph.outgoingEdgesOf(nodeId)) {
                    if (isCallEdge(edge)) {
                        String targetId = memGraph.getEdgeTarget(edge);
                        if (labels.containsKey(targetId)) {
                            int targetLabel = labels.get(targetId);
                            labelCounts.merge(targetLabel, 1, Integer::sum);
                        }
                    }
                }

                // Incoming edges (functions that call this node)
                for (LabeledEdge edge : memGraph.incomingEdgesOf(nodeId)) {
                    if (isCallEdge(edge)) {
                        String sourceId = memGraph.getEdgeSource(edge);
                        if (labels.containsKey(sourceId)) {
                            int sourceLabel = labels.get(sourceId);
                            labelCounts.merge(sourceLabel, 1, Integer::sum);
                        }
                    }
                }

                // Find most common label
                if (!labelCounts.isEmpty()) {
                    int currentLabel = labels.get(nodeId);
                    int bestLabel = currentLabel;
                    int bestCount = labelCounts.getOrDefault(currentLabel, 0);

                    for (Map.Entry<Integer, Integer> entry : labelCounts.entrySet()) {
                        if (entry.getValue() > bestCount) {
                            bestLabel = entry.getKey();
                            bestCount = entry.getValue();
                        } else if (entry.getValue() == bestCount && entry.getKey() < bestLabel) {
                            // Tie-breaker: prefer smaller label for determinism
                            bestLabel = entry.getKey();
                        }
                    }

                    if (bestLabel != currentLabel) {
                        labels.put(nodeId, bestLabel);
                        changed = true;
                    }
                }
            }

            // Converged
            if (!changed) {
                Msg.debug(this, String.format("Label propagation converged after %d iterations", iteration + 1));
                break;
            }
        }

        return labels;
    }

    /**
     * Check if an edge represents a function call relationship.
     */
    private boolean isCallEdge(LabeledEdge edge) {
        EdgeType type = edge.getType();
        return type == EdgeType.CALLS || type == EdgeType.CALLS_VULNERABLE;
    }

    /**
     * Group node IDs by their community label.
     */
    private Map<Integer, List<String>> groupByLabel(Map<String, Integer> nodeToLabel) {
        Map<Integer, List<String>> communities = new HashMap<>();

        for (Map.Entry<String, Integer> entry : nodeToLabel.entrySet()) {
            communities.computeIfAbsent(entry.getValue(), k -> new ArrayList<>())
                    .add(entry.getKey());
        }

        return communities;
    }

    /**
     * Merge communities smaller than minSize into the nearest larger community.
     */
    private Map<Integer, List<String>> mergeSmallCommunities(
            Map<Integer, List<String>> communities,
            int minSize) {

        // Find small communities
        List<Integer> smallCommunityIds = communities.entrySet().stream()
                .filter(e -> e.getValue().size() < minSize)
                .map(Map.Entry::getKey)
                .collect(Collectors.toList());

        if (smallCommunityIds.isEmpty()) {
            return communities;
        }

        // Find the largest community to merge orphans into
        int largestCommunityId = communities.entrySet().stream()
                .max(Comparator.comparingInt(e -> e.getValue().size()))
                .map(Map.Entry::getKey)
                .orElse(-1);

        if (largestCommunityId == -1) {
            return communities;
        }

        // Merge small communities
        for (Integer smallId : smallCommunityIds) {
            if (!smallId.equals(largestCommunityId)) {
                List<String> members = communities.remove(smallId);
                if (members != null) {
                    communities.get(largestCommunityId).addAll(members);
                }
            }
        }

        // Re-number communities to be contiguous
        Map<Integer, List<String>> renumbered = new HashMap<>();
        int newId = 0;
        for (List<String> members : communities.values()) {
            renumbered.put(newId++, members);
        }

        return renumbered;
    }

    /**
     * Create Community and membership records in the database.
     */
    private int createCommunityRecords(Map<Integer, List<String>> communities) {
        String binaryId = graph.getBinaryId();
        int count = 0;

        for (Map.Entry<Integer, List<String>> entry : communities.entrySet()) {
            List<String> memberIds = entry.getValue();

            // Create community
            Community community = new Community(binaryId, 0); // level 0 = function communities
            community.setMemberCount(memberIds.size());

            // Generate name based on prominent functions
            String name = generateCommunityName(memberIds, entry.getKey());
            community.setName(name);

            // Generate summary based on member analysis
            String summary = generateCommunitySummary(memberIds);
            community.setSummary(summary);

            // Store community
            graph.upsertCommunity(community);

            // Add members
            for (String nodeId : memberIds) {
                graph.addCommunityMember(community.getId(), nodeId, 1.0);
            }

            // Create BELONGS_TO_COMMUNITY edges
            for (String nodeId : memberIds) {
                graph.addEdge(nodeId, community.getId(), EdgeType.BELONGS_TO_COMMUNITY);
            }

            count++;

            if (monitor != null && monitor.isCancelled()) {
                break;
            }
        }

        Msg.info(this, String.format("Created %d community records", count));
        return count;
    }

    /**
     * Generate a descriptive name for a community based on its members.
     */
    private String generateCommunityName(List<String> memberIds, int communityIndex) {
        // Try to find a representative function name
        List<String> functionNames = new ArrayList<>();

        for (String nodeId : memberIds) {
            KnowledgeNode node = graph.getNode(nodeId);
            if (node != null && node.getName() != null) {
                String name = node.getName();
                // Skip generic names
                if (!name.startsWith("FUN_") && !name.startsWith("sub_")) {
                    functionNames.add(name);
                }
            }
        }

        if (!functionNames.isEmpty()) {
            // Use shortest meaningful name as representative
            functionNames.sort(Comparator.comparingInt(String::length));
            String representative = functionNames.get(0);
            return String.format("%s_group (%d)", representative, memberIds.size());
        }

        // Fallback to generic name
        return String.format("community_%d (%d functions)", communityIndex, memberIds.size());
    }

    /**
     * Generate a structural summary for a community based on its members.
     * This is LLM-free - aggregates data from member nodes.
     */
    private String generateCommunitySummary(List<String> memberIds) {
        StringBuilder summary = new StringBuilder();

        // Collect data from members
        List<String> namedFunctions = new ArrayList<>();
        Set<String> allSecurityFlags = new HashSet<>();
        int totalWithFlags = 0;

        for (String nodeId : memberIds) {
            KnowledgeNode node = graph.getNode(nodeId);
            if (node == null) continue;

            // Collect named functions (skip generic names)
            String name = node.getName();
            if (name != null && !name.startsWith("FUN_") && !name.startsWith("sub_")) {
                namedFunctions.add(name);
            }

            // Collect security flags
            List<String> flags = node.getSecurityFlags();
            if (flags != null && !flags.isEmpty()) {
                allSecurityFlags.addAll(flags);
                totalWithFlags++;
            }
        }

        // Build summary
        summary.append("Community of ").append(memberIds.size()).append(" functions. ");

        // Named functions
        if (!namedFunctions.isEmpty()) {
            int showCount = Math.min(5, namedFunctions.size());
            summary.append("Key functions: ");
            for (int i = 0; i < showCount; i++) {
                if (i > 0) summary.append(", ");
                summary.append(namedFunctions.get(i));
            }
            if (namedFunctions.size() > showCount) {
                summary.append(" (+").append(namedFunctions.size() - showCount).append(" more)");
            }
            summary.append(". ");
        }

        // Security flags
        if (!allSecurityFlags.isEmpty()) {
            summary.append("Security-relevant: ").append(totalWithFlags)
                   .append(" functions with flags [");

            List<String> flagList = new ArrayList<>(allSecurityFlags);
            Collections.sort(flagList);
            int showFlags = Math.min(5, flagList.size());
            for (int i = 0; i < showFlags; i++) {
                if (i > 0) summary.append(", ");
                summary.append(flagList.get(i));
            }
            if (flagList.size() > showFlags) {
                summary.append(", +").append(flagList.size() - showFlags).append(" more");
            }
            summary.append("]. ");
        }

        // Infer purpose from common patterns
        String inferredPurpose = inferCommunityPurpose(namedFunctions, allSecurityFlags);
        if (inferredPurpose != null) {
            summary.append("Likely purpose: ").append(inferredPurpose).append(".");
        }

        return summary.toString();
    }

    /**
     * Attempt to infer community purpose from function names and flags.
     */
    private String inferCommunityPurpose(List<String> functionNames, Set<String> flags) {
        String namesLower = String.join(" ", functionNames).toLowerCase();

        // Network-related
        if (namesLower.contains("recv") || namesLower.contains("send") ||
            namesLower.contains("socket") || namesLower.contains("connect") ||
            namesLower.contains("http") || namesLower.contains("network") ||
            flags.contains("NETWORK_CAPABLE")) {
            return "network I/O";
        }

        // File operations
        if (namesLower.contains("file") || namesLower.contains("read") ||
            namesLower.contains("write") || namesLower.contains("open") ||
            namesLower.contains("fopen") || namesLower.contains("fclose") ||
            flags.contains("FILE_READER") || flags.contains("FILE_WRITER")) {
            return "file operations";
        }

        // Crypto
        if (namesLower.contains("crypt") || namesLower.contains("encrypt") ||
            namesLower.contains("decrypt") || namesLower.contains("hash") ||
            namesLower.contains("aes") || namesLower.contains("sha") ||
            flags.contains("USES_CRYPTO")) {
            return "cryptographic operations";
        }

        // String handling
        if (namesLower.contains("str") || namesLower.contains("string") ||
            namesLower.contains("parse") || namesLower.contains("format")) {
            return "string processing";
        }

        // Memory management
        if (namesLower.contains("alloc") || namesLower.contains("malloc") ||
            namesLower.contains("free") || namesLower.contains("memory") ||
            namesLower.contains("heap")) {
            return "memory management";
        }

        // UI/Window
        if (namesLower.contains("window") || namesLower.contains("dialog") ||
            namesLower.contains("button") || namesLower.contains("menu") ||
            namesLower.contains("draw") || namesLower.contains("paint")) {
            return "UI/graphics";
        }

        // Process/thread
        if (namesLower.contains("thread") || namesLower.contains("process") ||
            namesLower.contains("create") || namesLower.contains("spawn") ||
            flags.contains("SPAWNS_PROCESSES")) {
            return "process/thread management";
        }

        // Registry (Windows)
        if (namesLower.contains("reg") || namesLower.contains("registry") ||
            namesLower.contains("hkey")) {
            return "registry operations";
        }

        // Initialization
        if (namesLower.contains("init") || namesLower.contains("setup") ||
            namesLower.contains("start") || namesLower.contains("main")) {
            return "initialization/entry";
        }

        return null;
    }

    /**
     * Get statistics about detected communities.
     */
    public Map<String, Object> getCommunityStats() {
        Map<String, Object> stats = new HashMap<>();

        List<Community> communities = graph.getCommunitiesForBinary(0);
        stats.put("total_communities", communities.size());

        if (!communities.isEmpty()) {
            int totalMembers = communities.stream()
                    .mapToInt(Community::getMemberCount)
                    .sum();
            int avgSize = totalMembers / communities.size();
            int maxSize = communities.stream()
                    .mapToInt(Community::getMemberCount)
                    .max()
                    .orElse(0);
            int minSize = communities.stream()
                    .mapToInt(Community::getMemberCount)
                    .min()
                    .orElse(0);

            stats.put("total_members", totalMembers);
            stats.put("avg_size", avgSize);
            stats.put("max_size", maxSize);
            stats.put("min_size", minSize);
        }

        return stats;
    }
}
