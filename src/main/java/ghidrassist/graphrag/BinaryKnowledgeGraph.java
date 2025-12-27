package ghidrassist.graphrag;

import ghidra.util.Msg;
import ghidrassist.AnalysisDB;
import ghidrassist.graphrag.nodes.EdgeType;
import ghidrassist.graphrag.nodes.KnowledgeNode;
import ghidrassist.graphrag.nodes.NodeType;

import org.jgrapht.Graph;
import org.jgrapht.graph.DefaultDirectedGraph;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.traverse.BreadthFirstIterator;

import java.sql.*;
import java.time.Instant;
import java.util.*;

/**
 * Core storage layer for the Binary Knowledge Graph.
 *
 * Combines SQLite for persistent storage with JGraphT for in-memory graph algorithms.
 * Provides CRUD operations for nodes and edges, graph traversal, and search capabilities.
 *
 * Architecture:
 * - SQLite stores all nodes/edges persistently
 * - JGraphT provides efficient in-memory graph operations for algorithms
 * - LRU cache for hot nodes (TODO: implement in MultiTierCache)
 */
public class BinaryKnowledgeGraph {

    private final Connection connection;
    private final AnalysisDB analysisDB;
    private Graph<String, LabeledEdge> memoryGraph;
    private final String binaryId;

    // Statistics
    private int nodeCount = 0;
    private int edgeCount = 0;

    // FTS repair attempted flag to prevent infinite retry loops
    private boolean ftsRepairAttempted = false;

    /**
     * Create a BinaryKnowledgeGraph for a specific binary.
     *
     * @param connection SQLite database connection (shared with AnalysisDB)
     * @param binaryId   Program hash identifying the binary
     * @deprecated Use the constructor with AnalysisDB parameter for FTS repair support
     */
    @Deprecated
    public BinaryKnowledgeGraph(Connection connection, String binaryId) {
        this(connection, binaryId, null);
    }

    /**
     * Create a BinaryKnowledgeGraph for a specific binary with FTS repair support.
     *
     * @param connection SQLite database connection (shared with AnalysisDB)
     * @param binaryId   Program hash identifying the binary
     * @param analysisDB AnalysisDB instance for FTS table repair
     */
    public BinaryKnowledgeGraph(Connection connection, String binaryId, AnalysisDB analysisDB) {
        this.connection = connection;
        this.binaryId = binaryId;
        this.analysisDB = analysisDB;
        this.memoryGraph = new DefaultDirectedGraph<>(LabeledEdge.class);
        loadGraphIntoMemory();
    }

    // ========================================
    // Node Operations
    // ========================================

    /**
     * Get a node by its unique ID.
     */
    public KnowledgeNode getNode(String id) {
        String sql = "SELECT * FROM graph_nodes WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, id);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return resultSetToNode(rs);
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to get node: " + e.getMessage(), e);
        }
        return null;
    }

    /**
     * Get a node by its Ghidra address within this binary.
     */
    public KnowledgeNode getNodeByAddress(long address) {
        String sql = "SELECT * FROM graph_nodes WHERE binary_id = ? AND address = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, binaryId);
            stmt.setLong(2, address);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return resultSetToNode(rs);
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to get node by address: " + e.getMessage(), e);
        }
        return null;
    }

    /**
     * Get a function node by name.
     */
    public KnowledgeNode getNodeByName(String name) {
        String sql = "SELECT * FROM graph_nodes WHERE binary_id = ? AND name = ? AND type = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, binaryId);
            stmt.setString(2, name);
            stmt.setString(3, NodeType.FUNCTION.name());
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return resultSetToNode(rs);
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to get node by name: " + e.getMessage(), e);
        }
        return null;
    }

    /**
     * Get all nodes of a specific type for this binary.
     */
    public List<KnowledgeNode> getNodesByType(NodeType type) {
        List<KnowledgeNode> nodes = new ArrayList<>();
        String sql = "SELECT * FROM graph_nodes WHERE binary_id = ? AND type = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, binaryId);
            stmt.setString(2, type.name());
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                nodes.add(resultSetToNode(rs));
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to get nodes by type: " + e.getMessage(), e);
        }
        return nodes;
    }

    /**
     * Insert or update a node.
     */
    public void upsertNode(KnowledgeNode node) {
        upsertNodeInternal(node, false);
    }

    /**
     * Internal upsert implementation with retry support for FTS corruption.
     */
    private void upsertNodeInternal(KnowledgeNode node, boolean isRetry) {
        String sql = "INSERT INTO graph_nodes "
                + "(id, type, address, binary_id, name, raw_content, llm_summary, confidence, "
                + "embedding, security_flags, analysis_depth, created_at, updated_at, is_stale) "
                + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                + "ON CONFLICT(id) DO UPDATE SET "
                + "type = excluded.type, address = excluded.address, name = excluded.name, "
                + "raw_content = excluded.raw_content, llm_summary = excluded.llm_summary, "
                + "confidence = excluded.confidence, embedding = excluded.embedding, "
                + "security_flags = excluded.security_flags, analysis_depth = excluded.analysis_depth, "
                + "updated_at = excluded.updated_at, is_stale = excluded.is_stale";

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, node.getId());
            stmt.setString(2, node.getType().name());
            if (node.getAddress() != null) {
                stmt.setLong(3, node.getAddress());
            } else {
                stmt.setNull(3, Types.INTEGER);
            }
            stmt.setString(4, node.getBinaryId());
            stmt.setString(5, node.getName());
            stmt.setString(6, node.getRawContent());
            stmt.setString(7, node.getLlmSummary());
            stmt.setFloat(8, node.getConfidence());
            stmt.setBytes(9, node.serializeEmbedding());
            stmt.setString(10, node.serializeSecurityFlags());
            stmt.setInt(11, node.getAnalysisDepth());
            stmt.setLong(12, node.getCreatedAt().toEpochMilli());
            stmt.setLong(13, node.getUpdatedAt().toEpochMilli());
            stmt.setInt(14, node.isStale() ? 1 : 0);

            stmt.executeUpdate();

            // Add to in-memory graph if not present
            if (!memoryGraph.containsVertex(node.getId())) {
                memoryGraph.addVertex(node.getId());
                nodeCount++;
            }
        } catch (SQLException e) {
            // Check if this is an FTS corruption error
            if (!isRetry && !ftsRepairAttempted && AnalysisDB.isFtsCorruptionError(e)) {
                Msg.warn(this, "FTS corruption detected, attempting repair...");
                ftsRepairAttempted = true;

                if (analysisDB != null && analysisDB.repairFtsTable()) {
                    Msg.info(this, "FTS repair successful, retrying upsert...");
                    upsertNodeInternal(node, true);
                    return;
                } else {
                    Msg.error(this, "FTS repair failed");
                }
            }
            Msg.error(this, "Failed to upsert node: " + e.getMessage(), e);
        }
    }

    /**
     * Delete a node and all its edges.
     */
    public boolean deleteNode(String id) {
        // Edges will be deleted via CASCADE
        String sql = "DELETE FROM graph_nodes WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, id);
            int affected = stmt.executeUpdate();
            if (affected > 0) {
                memoryGraph.removeVertex(id);
                nodeCount--;
                return true;
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to delete node: " + e.getMessage(), e);
        }
        return false;
    }

    // ========================================
    // Edge Operations
    // ========================================

    /**
     * Add an edge between two nodes.
     */
    public void addEdge(String sourceId, String targetId, EdgeType type) {
        addEdge(sourceId, targetId, type, 1.0, null);
    }

    /**
     * Add an edge with weight and metadata.
     */
    public void addEdge(String sourceId, String targetId, EdgeType type, double weight, String metadata) {
        String edgeId = UUID.randomUUID().toString();
        String sql = "INSERT INTO graph_edges (id, source_id, target_id, type, weight, metadata, created_at) "
                + "VALUES (?, ?, ?, ?, ?, ?, ?) "
                + "ON CONFLICT DO NOTHING";

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, edgeId);
            stmt.setString(2, sourceId);
            stmt.setString(3, targetId);
            stmt.setString(4, type.name());
            stmt.setDouble(5, weight);
            stmt.setString(6, metadata);
            stmt.setLong(7, Instant.now().toEpochMilli());

            int affected = stmt.executeUpdate();
            if (affected > 0) {
                // Add to in-memory graph
                if (!memoryGraph.containsVertex(sourceId)) {
                    memoryGraph.addVertex(sourceId);
                }
                if (!memoryGraph.containsVertex(targetId)) {
                    memoryGraph.addVertex(targetId);
                }
                LabeledEdge edge = new LabeledEdge(type);
                memoryGraph.addEdge(sourceId, targetId, edge);
                edgeCount++;
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to add edge: " + e.getMessage(), e);
        }
    }

    /**
     * Get all edges from a source node.
     */
    public List<GraphEdge> getOutgoingEdges(String nodeId) {
        return getEdges(nodeId, true);
    }

    /**
     * Get all edges to a target node.
     */
    public List<GraphEdge> getIncomingEdges(String nodeId) {
        return getEdges(nodeId, false);
    }

    private List<GraphEdge> getEdges(String nodeId, boolean outgoing) {
        List<GraphEdge> edges = new ArrayList<>();
        String sql = outgoing
                ? "SELECT * FROM graph_edges WHERE source_id = ?"
                : "SELECT * FROM graph_edges WHERE target_id = ?";

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, nodeId);
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                edges.add(new GraphEdge(
                        rs.getString("id"),
                        rs.getString("source_id"),
                        rs.getString("target_id"),
                        EdgeType.fromString(rs.getString("type")),
                        rs.getDouble("weight"),
                        rs.getString("metadata")
                ));
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to get edges: " + e.getMessage(), e);
        }
        return edges;
    }

    /**
     * Delete an edge by ID.
     */
    public boolean deleteEdge(String edgeId) {
        // First get the edge details for memory graph removal
        String selectSql = "SELECT source_id, target_id FROM graph_edges WHERE id = ?";
        String sourceId = null, targetId = null;

        try (PreparedStatement stmt = connection.prepareStatement(selectSql)) {
            stmt.setString(1, edgeId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                sourceId = rs.getString("source_id");
                targetId = rs.getString("target_id");
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to get edge details: " + e.getMessage(), e);
        }

        String deleteSql = "DELETE FROM graph_edges WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(deleteSql)) {
            stmt.setString(1, edgeId);
            int affected = stmt.executeUpdate();
            if (affected > 0 && sourceId != null && targetId != null) {
                memoryGraph.removeEdge(sourceId, targetId);
                edgeCount--;
                return true;
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to delete edge: " + e.getMessage(), e);
        }
        return false;
    }

    // ========================================
    // Graph Traversal Operations
    // ========================================

    /**
     * Get neighboring nodes within N hops.
     */
    public List<KnowledgeNode> getNeighbors(String nodeId, int depth) {
        Set<String> visited = new HashSet<>();
        List<KnowledgeNode> neighbors = new ArrayList<>();

        if (!memoryGraph.containsVertex(nodeId)) {
            return neighbors;
        }

        BreadthFirstIterator<String, LabeledEdge> iterator =
                new BreadthFirstIterator<>(memoryGraph, nodeId);

        int currentDepth = 0;
        String lastVertex = nodeId;

        while (iterator.hasNext() && currentDepth <= depth) {
            String vertexId = iterator.next();
            if (vertexId.equals(nodeId)) {
                continue;
            }

            // Track depth (simplified - BFS naturally expands by level)
            if (!visited.contains(vertexId)) {
                visited.add(vertexId);
                KnowledgeNode node = getNode(vertexId);
                if (node != null) {
                    neighbors.add(node);
                }
            }

            // Check if we've exceeded depth (approximate via neighbor count)
            if (neighbors.size() > depth * 50) {
                break;
            }
        }

        return neighbors;
    }

    /**
     * Get all callers of a function (nodes that have CALLS edge to this function).
     */
    public List<KnowledgeNode> getCallers(String functionId) {
        List<KnowledgeNode> callers = new ArrayList<>();
        String sql = "SELECT source_id FROM graph_edges WHERE target_id = ? AND type = ?";

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, functionId);
            stmt.setString(2, EdgeType.CALLS.name());
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                KnowledgeNode caller = getNode(rs.getString("source_id"));
                if (caller != null) {
                    callers.add(caller);
                }
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to get callers: " + e.getMessage(), e);
        }
        return callers;
    }

    /**
     * Get all callees of a function (nodes this function CALLS).
     */
    public List<KnowledgeNode> getCallees(String functionId) {
        List<KnowledgeNode> callees = new ArrayList<>();
        String sql = "SELECT target_id FROM graph_edges WHERE source_id = ? AND type = ?";

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, functionId);
            stmt.setString(2, EdgeType.CALLS.name());
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                KnowledgeNode callee = getNode(rs.getString("target_id"));
                if (callee != null) {
                    callees.add(callee);
                }
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to get callees: " + e.getMessage(), e);
        }
        return callees;
    }

    // ========================================
    // Search Operations
    // ========================================

    /**
     * Full-text search on node summaries and names.
     */
    public List<KnowledgeNode> ftsSearch(String query, int limit) {
        return ftsSearchInternal(query, limit, false);
    }

    /**
     * Internal FTS search with repair support for corruption.
     */
    private List<KnowledgeNode> ftsSearchInternal(String query, int limit, boolean isRetry) {
        List<KnowledgeNode> results = new ArrayList<>();
        String sql = "SELECT id FROM node_fts WHERE node_fts MATCH ? LIMIT ?";

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            // Escape special FTS5 characters and prepare query
            String ftsQuery = escapeFtsQuery(query);
            stmt.setString(1, ftsQuery);
            stmt.setInt(2, limit);

            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                KnowledgeNode node = getNode(rs.getString("id"));
                if (node != null && binaryId.equals(node.getBinaryId())) {
                    results.add(node);
                }
            }
        } catch (SQLException e) {
            // Check if this is an FTS corruption error
            if (!isRetry && !ftsRepairAttempted && AnalysisDB.isFtsCorruptionError(e)) {
                Msg.warn(this, "FTS corruption detected during search, attempting repair...");
                ftsRepairAttempted = true;

                if (analysisDB != null && analysisDB.repairFtsTable()) {
                    Msg.info(this, "FTS repair successful, retrying search...");
                    return ftsSearchInternal(query, limit, true);
                } else {
                    Msg.error(this, "FTS repair failed");
                }
            }
            Msg.error(this, "FTS search failed: " + e.getMessage(), e);
        }
        return results;
    }

    /**
     * Get stale nodes that need re-summarization.
     */
    public List<KnowledgeNode> getStaleNodes(int limit) {
        List<KnowledgeNode> nodes = new ArrayList<>();
        String sql = "SELECT * FROM graph_nodes WHERE binary_id = ? AND is_stale = 1 LIMIT ?";

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, binaryId);
            stmt.setInt(2, limit);
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                nodes.add(resultSetToNode(rs));
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to get stale nodes: " + e.getMessage(), e);
        }
        return nodes;
    }

    // ========================================
    // Bulk Operations
    // ========================================

    /**
     * Mark all nodes in the graph as stale.
     */
    public int markAllStale() {
        String sql = "UPDATE graph_nodes SET is_stale = 1 WHERE binary_id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, binaryId);
            return stmt.executeUpdate();
        } catch (SQLException e) {
            Msg.error(this, "Failed to mark nodes stale: " + e.getMessage(), e);
        }
        return 0;
    }

    /**
     * Delete all graph data for this binary.
     */
    public void clearGraph() {
        String deleteNodes = "DELETE FROM graph_nodes WHERE binary_id = ?";
        String deleteCommunities = "DELETE FROM graph_communities WHERE binary_id = ?";

        try (PreparedStatement stmt1 = connection.prepareStatement(deleteNodes);
             PreparedStatement stmt2 = connection.prepareStatement(deleteCommunities)) {

            stmt1.setString(1, binaryId);
            stmt2.setString(1, binaryId);

            stmt1.executeUpdate();
            stmt2.executeUpdate();

            // Clear in-memory graph
            memoryGraph = new DefaultDirectedGraph<>(LabeledEdge.class);
            nodeCount = 0;
            edgeCount = 0;

            Msg.info(this, "Cleared graph for binary: " + binaryId);
        } catch (SQLException e) {
            Msg.error(this, "Failed to clear graph: " + e.getMessage(), e);
        }
    }

    // ========================================
    // Statistics
    // ========================================

    public int getNodeCount() {
        return nodeCount;
    }

    public int getEdgeCount() {
        return edgeCount;
    }

    public String getBinaryId() {
        return binaryId;
    }

    /**
     * Check if a function is already cached in the graph.
     */
    public boolean hasFunctionCached(long address) {
        return getNodeByAddress(address) != null;
    }

    /**
     * Check if a function's decompiled content is cached.
     */
    public String getCachedDecompiledCode(long address) {
        KnowledgeNode node = getNodeByAddress(address);
        return node != null ? node.getRawContent() : null;
    }

    // ========================================
    // Internal Methods
    // ========================================

    /**
     * Load graph structure from SQLite into JGraphT for algorithm operations.
     */
    private void loadGraphIntoMemory() {
        memoryGraph = new DefaultDirectedGraph<>(LabeledEdge.class);
        nodeCount = 0;
        edgeCount = 0;

        // Load all node IDs for this binary
        String nodesSql = "SELECT id FROM graph_nodes WHERE binary_id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(nodesSql)) {
            stmt.setString(1, binaryId);
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                String nodeId = rs.getString("id");
                memoryGraph.addVertex(nodeId);
                nodeCount++;
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to load nodes into memory: " + e.getMessage(), e);
        }

        // Load all edges for nodes in this binary
        String edgesSql = "SELECT e.source_id, e.target_id, e.type FROM graph_edges e "
                + "INNER JOIN graph_nodes n ON e.source_id = n.id "
                + "WHERE n.binary_id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(edgesSql)) {
            stmt.setString(1, binaryId);
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                String sourceId = rs.getString("source_id");
                String targetId = rs.getString("target_id");
                EdgeType type = EdgeType.fromString(rs.getString("type"));

                if (memoryGraph.containsVertex(sourceId) && memoryGraph.containsVertex(targetId)) {
                    LabeledEdge edge = new LabeledEdge(type);
                    memoryGraph.addEdge(sourceId, targetId, edge);
                    edgeCount++;
                }
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to load edges into memory: " + e.getMessage(), e);
        }

        Msg.info(this, String.format("Loaded graph for %s: %d nodes, %d edges",
                binaryId, nodeCount, edgeCount));
    }

    private KnowledgeNode resultSetToNode(ResultSet rs) throws SQLException {
        NodeType type = NodeType.fromString(rs.getString("type"));
        KnowledgeNode node = new KnowledgeNode(
                rs.getString("id"),
                type,
                rs.getString("binary_id")
        );

        long address = rs.getLong("address");
        if (!rs.wasNull()) {
            node.setAddress(address);
        }

        node.setName(rs.getString("name"));
        node.setRawContent(rs.getString("raw_content"));
        node.setLlmSummary(rs.getString("llm_summary"));
        node.setConfidence(rs.getFloat("confidence"));
        node.setEmbedding(KnowledgeNode.deserializeEmbedding(rs.getBytes("embedding")));
        node.setSecurityFlags(KnowledgeNode.deserializeSecurityFlags(rs.getString("security_flags")));
        node.setAnalysisDepth(rs.getInt("analysis_depth"));

        long createdAt = rs.getLong("created_at");
        if (createdAt > 0) {
            node.setCreatedAt(Instant.ofEpochMilli(createdAt));
        }

        long updatedAt = rs.getLong("updated_at");
        if (updatedAt > 0) {
            node.setUpdatedAt(Instant.ofEpochMilli(updatedAt));
        }

        node.setStale(rs.getInt("is_stale") == 1);

        return node;
    }

    private String escapeFtsQuery(String query) {
        // Escape special FTS5 characters
        return query
                .replace("\"", "\"\"")
                .replace("*", "")
                .replace(":", " ");
    }

    // ========================================
    // Inner Classes
    // ========================================

    /**
     * Custom edge class that carries the edge type label.
     */
    public static class LabeledEdge extends DefaultEdge {
        private final EdgeType type;

        public LabeledEdge(EdgeType type) {
            this.type = type;
        }

        public EdgeType getType() {
            return type;
        }

        @Override
        public String toString() {
            return type != null ? type.getDisplayName() : "edge";
        }
    }

    /**
     * Data class representing a graph edge with full details.
     */
    public static class GraphEdge {
        private final String id;
        private final String sourceId;
        private final String targetId;
        private final EdgeType type;
        private final double weight;
        private final String metadata;

        public GraphEdge(String id, String sourceId, String targetId, EdgeType type,
                         double weight, String metadata) {
            this.id = id;
            this.sourceId = sourceId;
            this.targetId = targetId;
            this.type = type;
            this.weight = weight;
            this.metadata = metadata;
        }

        public String getId() { return id; }
        public String getSourceId() { return sourceId; }
        public String getTargetId() { return targetId; }
        public EdgeType getType() { return type; }
        public double getWeight() { return weight; }
        public String getMetadata() { return metadata; }
    }
}
