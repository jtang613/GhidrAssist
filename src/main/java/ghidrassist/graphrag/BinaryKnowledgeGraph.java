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
     * If a node with the same address already exists, updates it instead of creating a duplicate.
     */
    public void upsertNode(KnowledgeNode node) {
        // Check if a node with this address already exists (for FUNCTION, BLOCK types)
        if (node.getAddress() != null && node.getAddress() != 0) {
            KnowledgeNode existing = getNodeByAddress(node.getAddress());
            if (existing != null) {
                // Reuse the existing node's ID to update it instead of creating duplicate
                node.setId(existing.getId());
            }
        }
        upsertNodeInternal(node, false);
    }

    /**
     * Internal upsert implementation with retry support for FTS corruption.
     */
    private void upsertNodeInternal(KnowledgeNode node, boolean isRetry) {
        String sql = "INSERT INTO graph_nodes "
                + "(id, type, address, binary_id, name, raw_content, llm_summary, confidence, "
                + "embedding, security_flags, network_apis, file_io_apis, ip_addresses, urls, "
                + "file_paths, domains, registry_keys, risk_level, activity_profile, analysis_depth, "
                + "created_at, updated_at, is_stale, user_edited) "
                + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                + "ON CONFLICT(id) DO UPDATE SET "
                + "type = excluded.type, address = excluded.address, name = excluded.name, "
                + "raw_content = excluded.raw_content, llm_summary = excluded.llm_summary, "
                + "confidence = excluded.confidence, embedding = excluded.embedding, "
                + "security_flags = excluded.security_flags, "
                + "network_apis = excluded.network_apis, file_io_apis = excluded.file_io_apis, "
                + "ip_addresses = excluded.ip_addresses, urls = excluded.urls, "
                + "file_paths = excluded.file_paths, domains = excluded.domains, "
                + "registry_keys = excluded.registry_keys, "
                + "risk_level = excluded.risk_level, activity_profile = excluded.activity_profile, "
                + "analysis_depth = excluded.analysis_depth, "
                + "updated_at = excluded.updated_at, is_stale = excluded.is_stale, "
                + "user_edited = excluded.user_edited";

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
            stmt.setString(11, node.serializeNetworkAPIs());
            stmt.setString(12, node.serializeFileIOAPIs());
            stmt.setString(13, node.serializeIPAddresses());
            stmt.setString(14, node.serializeURLs());
            stmt.setString(15, node.serializeFilePaths());
            stmt.setString(16, node.serializeDomains());
            stmt.setString(17, node.serializeRegistryKeys());
            stmt.setString(18, node.getRiskLevel());
            stmt.setString(19, node.getActivityProfile());
            stmt.setInt(20, node.getAnalysisDepth());
            stmt.setLong(21, node.getCreatedAt().toEpochMilli());
            stmt.setLong(22, node.getUpdatedAt().toEpochMilli());
            stmt.setInt(23, node.isStale() ? 1 : 0);
            stmt.setInt(24, node.isUserEdited() ? 1 : 0);

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
     * Skips if an edge of the same type already exists between source and target.
     */
    public void addEdge(String sourceId, String targetId, EdgeType type, double weight, String metadata) {
        // Check for existing edge first to prevent duplicates
        if (hasEdgeBetween(sourceId, targetId, type)) {
            return; // Edge already exists
        }

        String edgeId = UUID.randomUUID().toString();
        String sql = "INSERT INTO graph_edges (id, source_id, target_id, type, weight, metadata, created_at) "
                + "VALUES (?, ?, ?, ?, ?, ?, ?)";

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
     * Remove duplicate edges from the database.
     * Keeps the oldest edge (by created_at) for each unique (source_id, target_id, type) combination.
     *
     * @return Number of duplicate edges removed
     */
    public int removeDuplicateEdges() {
        // SQL to find and delete duplicates, keeping the one with MIN(created_at)
        String sql = "DELETE FROM graph_edges WHERE id NOT IN (" +
                "SELECT MIN(id) FROM graph_edges " +
                "GROUP BY source_id, target_id, type)";

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            int deleted = stmt.executeUpdate();
            if (deleted > 0) {
                Msg.info(this, String.format("Removed %d duplicate edges", deleted));
                // Reload the in-memory graph to reflect changes
                loadGraphIntoMemory();
            }
            return deleted;
        } catch (SQLException e) {
            Msg.error(this, "Failed to remove duplicate edges: " + e.getMessage(), e);
        }
        return 0;
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
    public List<KnowledgeNode> getNeighbors(String nodeId, int maxDepth) {
        Set<String> visited = new HashSet<>();
        List<KnowledgeNode> neighbors = new ArrayList<>();

        if (!memoryGraph.containsVertex(nodeId)) {
            return neighbors;
        }

        BreadthFirstIterator<String, LabeledEdge> iterator =
                new BreadthFirstIterator<>(memoryGraph, nodeId);

        while (iterator.hasNext()) {
            String vertexId = iterator.next();

            // Skip the starting node
            if (vertexId.equals(nodeId)) {
                continue;
            }

            // Use BFS iterator's depth tracking - stop if beyond maxDepth
            int vertexDepth = iterator.getDepth(vertexId);
            if (vertexDepth > maxDepth) {
                // BFS visits nodes in order of increasing depth, so we can stop here
                break;
            }

            if (!visited.contains(vertexId)) {
                visited.add(vertexId);
                KnowledgeNode node = getNode(vertexId);
                if (node != null) {
                    neighbors.add(node);
                }
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

    /**
     * Check if a node has any edges of a specific type (outgoing).
     *
     * @param nodeId The node ID
     * @param edgeType The edge type to check for
     * @return true if the node has at least one edge of this type
     */
    public boolean hasEdgesOfType(String nodeId, EdgeType edgeType) {
        String sql = "SELECT 1 FROM graph_edges WHERE source_id = ? AND type = ? LIMIT 1";

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, nodeId);
            stmt.setString(2, edgeType.name());
            ResultSet rs = stmt.executeQuery();
            return rs.next();
        } catch (SQLException e) {
            Msg.error(this, "Failed to check edges of type: " + e.getMessage(), e);
        }
        return false;
    }

    /**
     * Check if a node has any incoming edges of a specific type.
     *
     * @param nodeId The node ID
     * @param edgeType The edge type to check for
     * @return true if the node has at least one incoming edge of this type
     */
    public boolean hasIncomingEdgesOfType(String nodeId, EdgeType edgeType) {
        String sql = "SELECT 1 FROM graph_edges WHERE target_id = ? AND type = ? LIMIT 1";

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, nodeId);
            stmt.setString(2, edgeType.name());
            ResultSet rs = stmt.executeQuery();
            return rs.next();
        } catch (SQLException e) {
            Msg.error(this, "Failed to check incoming edges of type: " + e.getMessage(), e);
        }
        return false;
    }

    /**
     * Check if an edge exists between two nodes with a specific type.
     *
     * @param sourceId The source node ID
     * @param targetId The target node ID
     * @param edgeType The edge type to check for
     * @return true if such an edge exists
     */
    public boolean hasEdgeBetween(String sourceId, String targetId, EdgeType edgeType) {
        String sql = "SELECT 1 FROM graph_edges WHERE source_id = ? AND target_id = ? AND type = ? LIMIT 1";

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, sourceId);
            stmt.setString(2, targetId);
            stmt.setString(3, edgeType.name());
            ResultSet rs = stmt.executeQuery();
            return rs.next();
        } catch (SQLException e) {
            Msg.error(this, "Failed to check edge between nodes: " + e.getMessage(), e);
        }
        return false;
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
     * Get nodes that need summarization: either marked stale OR have empty/null summary.
     * This ensures nodes with failed previous summarization attempts are re-processed.
     */
    public List<KnowledgeNode> getStaleNodes(int limit) {
        List<KnowledgeNode> nodes = new ArrayList<>();
        // Include nodes that are stale OR have no summary (null or empty)
        String sql = "SELECT * FROM graph_nodes WHERE binary_id = ? " +
                     "AND (is_stale = 1 OR llm_summary IS NULL OR llm_summary = '') LIMIT ?";

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

    /**
     * Get the in-memory JGraphT graph for algorithm operations.
     */
    public Graph<String, LabeledEdge> getMemoryGraph() {
        return memoryGraph;
    }

    // ========================================
    // Community Operations
    // ========================================

    /**
     * Insert or update a community record.
     */
    public void upsertCommunity(ghidrassist.graphrag.community.Community community) {
        String sql = "INSERT OR REPLACE INTO graph_communities " +
                "(id, level, binary_id, parent_community_id, name, summary, member_count, is_stale, created_at, updated_at) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, community.getId());
            stmt.setInt(2, community.getLevel());
            stmt.setString(3, community.getBinaryId());
            stmt.setString(4, community.getParentCommunityId());
            stmt.setString(5, community.getName());
            stmt.setString(6, community.getSummary());
            stmt.setInt(7, community.getMemberCount());
            stmt.setInt(8, community.isStale() ? 1 : 0);
            stmt.setLong(9, community.getCreatedAt());
            stmt.setLong(10, community.getUpdatedAt());

            stmt.executeUpdate();
        } catch (SQLException e) {
            Msg.error(this, "Failed to upsert community: " + e.getMessage(), e);
        }
    }

    /**
     * Get a community by ID.
     */
    public ghidrassist.graphrag.community.Community getCommunity(String communityId) {
        String sql = "SELECT * FROM graph_communities WHERE id = ?";

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, communityId);
            ResultSet rs = stmt.executeQuery();

            if (rs.next()) {
                return resultSetToCommunity(rs);
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to get community: " + e.getMessage(), e);
        }
        return null;
    }

    /**
     * Get all communities for this binary at a specific level.
     */
    public List<ghidrassist.graphrag.community.Community> getCommunitiesForBinary(int level) {
        List<ghidrassist.graphrag.community.Community> communities = new ArrayList<>();
        String sql = "SELECT * FROM graph_communities WHERE binary_id = ? AND level = ? ORDER BY member_count DESC";

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, binaryId);
            stmt.setInt(2, level);
            ResultSet rs = stmt.executeQuery();

            while (rs.next()) {
                communities.add(resultSetToCommunity(rs));
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to get communities: " + e.getMessage(), e);
        }
        return communities;
    }

    /**
     * Add a node to a community.
     */
    public void addCommunityMember(String communityId, String nodeId, double score) {
        String sql = "INSERT OR REPLACE INTO community_members (community_id, node_id, membership_score) VALUES (?, ?, ?)";

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, communityId);
            stmt.setString(2, nodeId);
            stmt.setDouble(3, score);
            stmt.executeUpdate();
        } catch (SQLException e) {
            Msg.error(this, "Failed to add community member: " + e.getMessage(), e);
        }
    }

    /**
     * Get all member nodes of a community.
     */
    public List<KnowledgeNode> getCommunityMembers(String communityId) {
        List<KnowledgeNode> members = new ArrayList<>();
        String sql = "SELECT n.* FROM graph_nodes n " +
                "JOIN community_members cm ON n.id = cm.node_id " +
                "WHERE cm.community_id = ? " +
                "ORDER BY n.name";

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, communityId);
            ResultSet rs = stmt.executeQuery();

            while (rs.next()) {
                members.add(resultSetToNode(rs));
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to get community members: " + e.getMessage(), e);
        }
        return members;
    }

    /**
     * Get the community a node belongs to.
     */
    public String getNodeCommunity(String nodeId) {
        String sql = "SELECT community_id FROM community_members WHERE node_id = ? LIMIT 1";

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, nodeId);
            ResultSet rs = stmt.executeQuery();

            if (rs.next()) {
                return rs.getString("community_id");
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to get node community: " + e.getMessage(), e);
        }
        return null;
    }

    /**
     * Delete a community and its memberships.
     */
    public void deleteCommunity(String communityId) {
        String sql = "DELETE FROM graph_communities WHERE id = ?";

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, communityId);
            stmt.executeUpdate();
            // community_members cascade delete handles memberships
        } catch (SQLException e) {
            Msg.error(this, "Failed to delete community: " + e.getMessage(), e);
        }
    }

    /**
     * Clear all communities for this binary.
     */
    public void clearCommunitiesForBinary() {
        String sql = "DELETE FROM graph_communities WHERE binary_id = ?";

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, binaryId);
            stmt.executeUpdate();
            Msg.debug(this, "Cleared communities for binary: " + binaryId);
        } catch (SQLException e) {
            Msg.error(this, "Failed to clear communities: " + e.getMessage(), e);
        }
    }

    /**
     * Mark a community as stale (needs re-summarization).
     */
    public void markCommunityStale(String communityId) {
        String sql = "UPDATE graph_communities SET is_stale = 1, updated_at = ? WHERE id = ?";

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setLong(1, System.currentTimeMillis());
            stmt.setString(2, communityId);
            stmt.executeUpdate();
        } catch (SQLException e) {
            Msg.error(this, "Failed to mark community stale: " + e.getMessage(), e);
        }
    }

    /**
     * Get community count for this binary.
     */
    public int getCommunityCount() {
        String sql = "SELECT COUNT(*) FROM graph_communities WHERE binary_id = ?";

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, binaryId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to get community count: " + e.getMessage(), e);
        }
        return 0;
    }

    /**
     * Convert a ResultSet row to a Community object.
     */
    private ghidrassist.graphrag.community.Community resultSetToCommunity(ResultSet rs) throws SQLException {
        return new ghidrassist.graphrag.community.Community(
                rs.getString("id"),
                rs.getInt("level"),
                rs.getString("binary_id"),
                rs.getString("parent_community_id"),
                rs.getString("name"),
                rs.getString("summary"),
                rs.getInt("member_count"),
                rs.getInt("is_stale") == 1,
                rs.getLong("created_at"),
                rs.getLong("updated_at")
        );
    }

    // ========================================
    // Internal Methods
    // ========================================

    /**
     * Reload the in-memory graph from the database.
     * Call this after bulk operations to ensure memoryGraph is synchronized with DB.
     */
    public void reloadFromDatabase() {
        loadGraphIntoMemory();
    }

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

        // Load user_edited with fallback for older databases
        try {
            node.setUserEdited(rs.getInt("user_edited") == 1);
        } catch (SQLException e) {
            // Column doesn't exist in older databases
            node.setUserEdited(false);
        }

        // Load security detail columns with fallback for older databases
        try {
            node.setNetworkAPIs(KnowledgeNode.deserializeStringList(rs.getString("network_apis")));
        } catch (SQLException e) {
            // Column doesn't exist
        }
        try {
            node.setFileIOAPIs(KnowledgeNode.deserializeStringList(rs.getString("file_io_apis")));
        } catch (SQLException e) {
            // Column doesn't exist
        }
        try {
            node.setIPAddresses(KnowledgeNode.deserializeStringList(rs.getString("ip_addresses")));
        } catch (SQLException e) {
            // Column doesn't exist
        }
        try {
            node.setURLs(KnowledgeNode.deserializeStringList(rs.getString("urls")));
        } catch (SQLException e) {
            // Column doesn't exist
        }
        try {
            node.setFilePaths(KnowledgeNode.deserializeStringList(rs.getString("file_paths")));
        } catch (SQLException e) {
            // Column doesn't exist
        }
        try {
            node.setDomains(KnowledgeNode.deserializeStringList(rs.getString("domains")));
        } catch (SQLException e) {
            // Column doesn't exist
        }
        try {
            node.setRegistryKeys(KnowledgeNode.deserializeStringList(rs.getString("registry_keys")));
        } catch (SQLException e) {
            // Column doesn't exist
        }
        try {
            node.setRiskLevel(rs.getString("risk_level"));
        } catch (SQLException e) {
            // Column doesn't exist
        }
        try {
            node.setActivityProfile(rs.getString("activity_profile"));
        } catch (SQLException e) {
            // Column doesn't exist
        }

        return node;
    }

    private String escapeFtsQuery(String query) {
        // FTS5 has many special characters and operators that can cause errors:
        // - Column filter: column:term
        // - Phrase: "phrase"
        // - Prefix: term*
        // - Boolean: AND, OR, NOT
        // - Grouping: ( )
        // - Required/excluded: +term, -term
        // - NEAR operator
        //
        // The safest approach is to quote each term individually to make them literal.

        if (query == null || query.trim().isEmpty()) {
            return "\"\""; // Empty query
        }

        // Split into words and quote each one
        String[] words = query.trim().split("\\s+");
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < words.length; i++) {
            String word = words[i];
            if (word.isEmpty()) continue;

            // Escape internal quotes by doubling them
            word = word.replace("\"", "\"\"");

            // Remove characters that are problematic even inside quotes
            word = word.replace("*", "");

            if (sb.length() > 0) {
                sb.append(" ");
            }

            // Quote the word to treat it as a literal
            sb.append("\"").append(word).append("\"");
        }

        return sb.length() > 0 ? sb.toString() : "\"\"";
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
