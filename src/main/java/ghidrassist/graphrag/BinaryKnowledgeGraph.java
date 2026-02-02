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
import java.util.concurrent.ConcurrentHashMap;

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

    // Batch insert support for performance
    private static final int BATCH_SIZE = 200;
    private final List<KnowledgeNode> pendingNodes = Collections.synchronizedList(new ArrayList<>());
    private final List<PendingEdge> pendingEdges = Collections.synchronizedList(new ArrayList<>());
    private final Object batchLock = new Object();

    // Node caches for performance - populated on demand
    private final Map<String, KnowledgeNode> nodeCache = new ConcurrentHashMap<>();
    private final Map<NodeType, List<KnowledgeNode>> nodesByTypeCache = new ConcurrentHashMap<>();

    // Pending edge holder
    private static class PendingEdge {
        final String sourceId;
        final String targetId;
        final EdgeType type;
        final double weight;
        final String metadata;

        PendingEdge(String sourceId, String targetId, EdgeType type, double weight, String metadata) {
            this.sourceId = sourceId;
            this.targetId = targetId;
            this.type = type;
            this.weight = weight;
            this.metadata = metadata;
        }
    }

    // Pending community member holder
    private final List<PendingCommunityMember> pendingCommunityMembers = Collections.synchronizedList(new ArrayList<>());

    private static class PendingCommunityMember {
        final String communityId;
        final String nodeId;
        final double score;

        PendingCommunityMember(String communityId, String nodeId, double score) {
            this.communityId = communityId;
            this.nodeId = nodeId;
            this.score = score;
        }
    }

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
     * Uses cache for performance - nodes are cached on first access.
     */
    public KnowledgeNode getNode(String id) {
        if (id == null) {
            return null;
        }
        return nodeCache.computeIfAbsent(id, this::fetchNodeFromDB);
    }

    /**
     * Fetch a node from the database (internal method for cache miss).
     */
    private KnowledgeNode fetchNodeFromDB(String id) {
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
     * Get a pending node by address (not yet committed to database).
     * Thread-safe - checks the pending batch.
     * This is critical for parallel extraction to avoid creating duplicate nodes.
     */
    public KnowledgeNode getPendingNodeByAddress(long address) {
        synchronized (pendingNodes) {
            for (KnowledgeNode node : pendingNodes) {
                if (node.getAddress() != null && node.getAddress() == address) {
                    return node;
                }
            }
        }
        return null;
    }

    /**
     * Get a node by its Ghidra address within this binary.
     * Checks pending nodes first (for parallel extraction), then database.
     */
    public KnowledgeNode getNodeByAddress(long address) {
        // FIRST check pending nodes (not yet committed to database)
        // This prevents duplicate node creation during parallel extraction
        KnowledgeNode pending = getPendingNodeByAddress(address);
        if (pending != null) {
            return pending;
        }

        // Then check database
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
     * Get a pending node by name (not yet committed to database).
     * Thread-safe - checks the pending batch.
     */
    public KnowledgeNode getPendingNodeByName(String name) {
        synchronized (pendingNodes) {
            for (KnowledgeNode node : pendingNodes) {
                if (name != null && name.equals(node.getName())) {
                    return node;
                }
            }
        }
        return null;
    }

    /**
     * Get a function node by name.
     * Checks pending nodes first (for parallel extraction), then database.
     */
    public KnowledgeNode getNodeByName(String name) {
        // FIRST check pending nodes (not yet committed to database)
        // This prevents duplicate external function node creation during parallel extraction
        KnowledgeNode pending = getPendingNodeByName(name);
        if (pending != null) {
            return pending;
        }

        // Then check database
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
     * Uses cache for performance - results are cached after first query.
     */
    public List<KnowledgeNode> getNodesByType(NodeType type) {
        List<KnowledgeNode> cached = nodesByTypeCache.get(type);
        if (cached != null) {
            return new ArrayList<>(cached); // Return copy to prevent external modification
        }

        List<KnowledgeNode> nodes = new ArrayList<>();
        String sql = "SELECT * FROM graph_nodes WHERE binary_id = ? AND type = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, binaryId);
            stmt.setString(2, type.name());
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                KnowledgeNode node = resultSetToNode(rs);
                nodes.add(node);
                // Also populate the individual node cache
                nodeCache.put(node.getId(), node);
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to get nodes by type: " + e.getMessage(), e);
        }

        // Cache the result
        nodesByTypeCache.put(type, nodes);
        return new ArrayList<>(nodes); // Return copy
    }

    /**
     * Bulk fetch nodes by IDs - single query instead of N separate queries.
     * This is a performance optimization for operations that need many nodes.
     * Uses cache for performance - checks cache first, only fetches uncached nodes from DB.
     *
     * @param nodeIds Collection of node IDs to fetch
     * @return Map of node ID to KnowledgeNode (missing nodes are simply not in the map)
     */
    public Map<String, KnowledgeNode> getNodes(Collection<String> nodeIds) {
        Map<String, KnowledgeNode> result = new HashMap<>();
        if (nodeIds == null || nodeIds.isEmpty()) {
            return result;
        }

        // Check cache first
        List<String> uncachedIds = new ArrayList<>();
        for (String id : nodeIds) {
            KnowledgeNode cached = nodeCache.get(id);
            if (cached != null) {
                result.put(id, cached);
            } else {
                uncachedIds.add(id);
            }
        }

        // If all nodes were cached, we're done
        if (uncachedIds.isEmpty()) {
            return result;
        }

        // SQLite has a limit on the number of parameters, so we batch in chunks
        int batchSize = 500; // SQLite default SQLITE_MAX_VARIABLE_NUMBER is 999

        for (int i = 0; i < uncachedIds.size(); i += batchSize) {
            List<String> batch = uncachedIds.subList(i, Math.min(i + batchSize, uncachedIds.size()));
            String placeholders = String.join(",", Collections.nCopies(batch.size(), "?"));
            String sql = "SELECT * FROM graph_nodes WHERE id IN (" + placeholders + ")";

            try (PreparedStatement stmt = connection.prepareStatement(sql)) {
                int idx = 1;
                for (String id : batch) {
                    stmt.setString(idx++, id);
                }
                ResultSet rs = stmt.executeQuery();
                while (rs.next()) {
                    KnowledgeNode node = resultSetToNode(rs);
                    result.put(node.getId(), node);
                    // Populate cache
                    nodeCache.put(node.getId(), node);
                }
            } catch (SQLException e) {
                Msg.error(this, "Failed to batch get nodes: " + e.getMessage(), e);
            }
        }
        return result;
    }

    /**
     * Clear all node caches.
     * Call this after bulk operations like reindexing to ensure fresh data.
     */
    public void invalidateNodeCache() {
        nodeCache.clear();
        nodesByTypeCache.clear();
    }

    /**
     * Bulk fetch all outgoing edges for a set of source nodes - single query.
     * This is a performance optimization to avoid N+1 queries when exporting graphs.
     *
     * @param sourceNodeIds Collection of source node IDs
     * @return List of all edges originating from the given nodes
     */
    public List<GraphEdge> getEdgesForNodes(Collection<String> sourceNodeIds) {
        List<GraphEdge> edges = new ArrayList<>();
        if (sourceNodeIds == null || sourceNodeIds.isEmpty()) {
            return edges;
        }

        // Batch in chunks for large node sets
        List<String> idList = new ArrayList<>(sourceNodeIds);
        int batchSize = 500;

        for (int i = 0; i < idList.size(); i += batchSize) {
            List<String> batch = idList.subList(i, Math.min(i + batchSize, idList.size()));
            String placeholders = String.join(",", Collections.nCopies(batch.size(), "?"));
            String sql = "SELECT * FROM graph_edges WHERE source_id IN (" + placeholders + ")";

            try (PreparedStatement stmt = connection.prepareStatement(sql)) {
                int idx = 1;
                for (String id : batch) {
                    stmt.setString(idx++, id);
                }
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
                Msg.error(this, "Failed to batch get edges: " + e.getMessage(), e);
            }
        }
        return edges;
    }

    /**
     * Insert or update a node.
     * If a node with the same address already exists, updates it instead of creating a duplicate.
     * Synchronized for thread-safe parallel processing.
     */
    public synchronized void upsertNode(KnowledgeNode node) {
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
     * Uses INSERT OR IGNORE for new nodes, then UPDATE for existing nodes.
     */
    private void upsertNodeInternal(KnowledgeNode node, boolean isRetry) {
        // Step 1: Try INSERT OR IGNORE for new nodes (preserves edge references)
        String insertSql = "INSERT OR IGNORE INTO graph_nodes "
                + "(id, type, address, binary_id, name, raw_content, llm_summary, confidence, "
                + "embedding, security_flags, network_apis, file_io_apis, ip_addresses, urls, "
                + "file_paths, domains, registry_keys, risk_level, activity_profile, analysis_depth, "
                + "created_at, updated_at, is_stale, user_edited) "
                + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        // Step 2: UPDATE existing nodes (for when INSERT was ignored)
        String updateSql = "UPDATE graph_nodes SET "
                + "name = COALESCE(?, name), "
                + "raw_content = COALESCE(?, raw_content), "
                + "llm_summary = COALESCE(?, llm_summary), "
                + "confidence = ?, "
                + "embedding = COALESCE(?, embedding), "
                + "security_flags = COALESCE(?, security_flags), "
                + "network_apis = COALESCE(?, network_apis), "
                + "file_io_apis = COALESCE(?, file_io_apis), "
                + "ip_addresses = COALESCE(?, ip_addresses), "
                + "urls = COALESCE(?, urls), "
                + "file_paths = COALESCE(?, file_paths), "
                + "domains = COALESCE(?, domains), "
                + "registry_keys = COALESCE(?, registry_keys), "
                + "risk_level = COALESCE(?, risk_level), "
                + "activity_profile = COALESCE(?, activity_profile), "
                + "analysis_depth = ?, "
                + "updated_at = ?, "
                + "is_stale = ?, "
                + "user_edited = ? "
                + "WHERE id = ?";

        try {
            // Step 1: Try INSERT OR IGNORE for new nodes
            try (PreparedStatement insertStmt = connection.prepareStatement(insertSql)) {
                insertStmt.setString(1, node.getId());
                insertStmt.setString(2, node.getType().name());
                if (node.getAddress() != null) {
                    insertStmt.setLong(3, node.getAddress());
                } else {
                    insertStmt.setNull(3, Types.INTEGER);
                }
                insertStmt.setString(4, node.getBinaryId());
                insertStmt.setString(5, node.getName());
                insertStmt.setString(6, node.getRawContent());
                insertStmt.setString(7, node.getLlmSummary());
                insertStmt.setFloat(8, node.getConfidence());
                insertStmt.setBytes(9, node.serializeEmbedding());
                insertStmt.setString(10, node.serializeSecurityFlags());
                insertStmt.setString(11, node.serializeNetworkAPIs());
                insertStmt.setString(12, node.serializeFileIOAPIs());
                insertStmt.setString(13, node.serializeIPAddresses());
                insertStmt.setString(14, node.serializeURLs());
                insertStmt.setString(15, node.serializeFilePaths());
                insertStmt.setString(16, node.serializeDomains());
                insertStmt.setString(17, node.serializeRegistryKeys());
                insertStmt.setString(18, node.getRiskLevel());
                insertStmt.setString(19, node.getActivityProfile());
                insertStmt.setInt(20, node.getAnalysisDepth());
                insertStmt.setLong(21, node.getCreatedAt().toEpochMilli());
                insertStmt.setLong(22, node.getUpdatedAt().toEpochMilli());
                insertStmt.setInt(23, node.isStale() ? 1 : 0);
                insertStmt.setInt(24, node.isUserEdited() ? 1 : 0);

                insertStmt.executeUpdate();
            }

            // Step 2: UPDATE existing node data (handles case where INSERT was ignored)
            // This ensures summaries and other updated fields get saved
            try (PreparedStatement updateStmt = connection.prepareStatement(updateSql)) {
                updateStmt.setString(1, node.getName());
                updateStmt.setString(2, node.getRawContent());
                updateStmt.setString(3, node.getLlmSummary());
                updateStmt.setFloat(4, node.getConfidence());
                updateStmt.setBytes(5, node.serializeEmbedding());
                updateStmt.setString(6, node.serializeSecurityFlags());
                updateStmt.setString(7, node.serializeNetworkAPIs());
                updateStmt.setString(8, node.serializeFileIOAPIs());
                updateStmt.setString(9, node.serializeIPAddresses());
                updateStmt.setString(10, node.serializeURLs());
                updateStmt.setString(11, node.serializeFilePaths());
                updateStmt.setString(12, node.serializeDomains());
                updateStmt.setString(13, node.serializeRegistryKeys());
                updateStmt.setString(14, node.getRiskLevel());
                updateStmt.setString(15, node.getActivityProfile());
                updateStmt.setInt(16, node.getAnalysisDepth());
                updateStmt.setLong(17, node.getUpdatedAt().toEpochMilli());
                updateStmt.setInt(18, node.isStale() ? 1 : 0);
                updateStmt.setInt(19, node.isUserEdited() ? 1 : 0);
                updateStmt.setString(20, node.getId());

                updateStmt.executeUpdate();
            }

            // Add to in-memory graph if not present
            if (!memoryGraph.containsVertex(node.getId())) {
                memoryGraph.addVertex(node.getId());
                nodeCount++;
            }

            // Update node cache
            nodeCache.put(node.getId(), node);
            // Invalidate type cache since we may have added/modified a node
            nodesByTypeCache.remove(node.getType());
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
        // Get node type before deletion for cache invalidation
        KnowledgeNode existingNode = nodeCache.get(id);
        NodeType nodeType = existingNode != null ? existingNode.getType() : null;

        // Edges will be deleted via CASCADE
        String sql = "DELETE FROM graph_nodes WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, id);
            int affected = stmt.executeUpdate();
            if (affected > 0) {
                memoryGraph.removeVertex(id);
                nodeCount--;

                // Remove from caches
                nodeCache.remove(id);
                if (nodeType != null) {
                    nodesByTypeCache.remove(nodeType);
                }
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

    // ========================================
    // Batch Insert Operations (for performance)
    // ========================================

    /**
     * Queue a node for batch insertion, returning the canonical node for this address/name.
     * This method is thread-safe and ensures no duplicate nodes are queued.
     * If a node with the same address (or name for external functions) already exists
     * in pending, returns the existing node instead of adding a duplicate.
     *
     * @param node The node to queue
     * @return The canonical node (either the input node if added, or existing node if duplicate)
     */
    public KnowledgeNode queueNodeForBatch(KnowledgeNode node) {
        synchronized (pendingNodes) {
            // Check if a node with same address already exists in pending
            if (node.getAddress() != null && node.getAddress() != 0) {
                for (KnowledgeNode existing : pendingNodes) {
                    if (existing.getAddress() != null &&
                        existing.getAddress().equals(node.getAddress())) {
                        // If existing node has no rawContent but new node does, merge the content
                        if ((existing.getRawContent() == null || existing.getRawContent().isEmpty()) &&
                            node.getRawContent() != null && !node.getRawContent().isEmpty()) {
                            existing.setRawContent(node.getRawContent());
                            Msg.debug(this, "Merged rawContent into existing node: " + existing.getName());
                        }
                        return existing; // Return existing node
                    }
                }
            } else if (node.getName() != null) {
                // External function - check by name
                for (KnowledgeNode existing : pendingNodes) {
                    if (node.getName().equals(existing.getName()) &&
                        (existing.getAddress() == null || existing.getAddress() == 0)) {
                        // Merge rawContent if needed
                        if ((existing.getRawContent() == null || existing.getRawContent().isEmpty()) &&
                            node.getRawContent() != null && !node.getRawContent().isEmpty()) {
                            existing.setRawContent(node.getRawContent());
                        }
                        return existing; // Return existing node
                    }
                }
            }

            // No duplicate found, add the node
            pendingNodes.add(node);
        }

        if (pendingNodes.size() >= BATCH_SIZE) {
            flushNodeBatch();
        }
        return node;
    }

    /**
     * Queue an edge for batch insertion.
     * Automatically flushes when batch size is reached.
     */
    public void queueEdgeForBatch(String sourceId, String targetId, EdgeType type) {
        queueEdgeForBatch(sourceId, targetId, type, 1.0, null);
    }

    /**
     * Queue an edge with weight and metadata for batch insertion.
     */
    public void queueEdgeForBatch(String sourceId, String targetId, EdgeType type, double weight, String metadata) {
        pendingEdges.add(new PendingEdge(sourceId, targetId, type, weight, metadata));
        if (pendingEdges.size() >= BATCH_SIZE) {
            flushEdgeBatch();
        }
    }

    /**
     * Flush all pending nodes to the database.
     */
    public void flushNodeBatch() {
        List<KnowledgeNode> toInsert;
        synchronized (batchLock) {
            if (pendingNodes.isEmpty()) {
                return;
            }
            toInsert = new ArrayList<>(pendingNodes);
            pendingNodes.clear();
        }

        // Deduplicate within the batch to avoid constraint violations
        // - By address for regular functions (preserves original node ID)
        // - By name for external functions (address=0 or null)
        Map<Long, KnowledgeNode> addressToNode = new LinkedHashMap<>();
        Map<String, KnowledgeNode> nameToNode = new LinkedHashMap<>();
        List<KnowledgeNode> deduped = new ArrayList<>();
        for (KnowledgeNode node : toInsert) {
            if (node.getAddress() != null && node.getAddress() != 0) {
                // Regular function with address - dedupe by address
                if (!addressToNode.containsKey(node.getAddress())) {
                    addressToNode.put(node.getAddress(), node);
                    deduped.add(node);
                }
            } else if (node.getName() != null) {
                // External function (no address) - dedupe by name
                if (!nameToNode.containsKey(node.getName())) {
                    nameToNode.put(node.getName(), node);
                    deduped.add(node);
                }
            } else {
                // No address and no name - just add it
                deduped.add(node);
            }
        }

        // Use INSERT OR IGNORE to keep existing nodes intact.
        // This preserves node IDs that edges may reference.
        // Duplicates are already filtered by getPendingNodeByAddress() check.
        String sql = "INSERT OR IGNORE INTO graph_nodes "
                + "(id, type, address, binary_id, name, raw_content, llm_summary, confidence, "
                + "embedding, security_flags, network_apis, file_io_apis, ip_addresses, urls, "
                + "file_paths, domains, registry_keys, risk_level, activity_profile, analysis_depth, "
                + "created_at, updated_at, is_stale, user_edited) "
                + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        synchronized (batchLock) {
            try {
                boolean originalAutoCommit = connection.getAutoCommit();
                connection.setAutoCommit(false);

                try (PreparedStatement stmt = connection.prepareStatement(sql)) {
                    for (KnowledgeNode node : deduped) {
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
                        stmt.addBatch();

                        // Add to in-memory graph
                        if (!memoryGraph.containsVertex(node.getId())) {
                            memoryGraph.addVertex(node.getId());
                            nodeCount++;
                        }
                    }

                    stmt.executeBatch();
                    connection.commit();
                } catch (SQLException e) {
                    connection.rollback();
                    Msg.error(this, "Failed to batch insert nodes: " + e.getMessage(), e);
                } finally {
                    connection.setAutoCommit(originalAutoCommit);
                }
            } catch (SQLException e) {
                Msg.error(this, "Failed to manage transaction for batch insert: " + e.getMessage(), e);
            }
        }
    }

    /**
     * Flush all pending edges to the database.
     */
    public void flushEdgeBatch() {
        List<PendingEdge> toInsert;
        synchronized (batchLock) {
            if (pendingEdges.isEmpty()) {
                return;
            }
            toInsert = new ArrayList<>(pendingEdges);
            pendingEdges.clear();
        }

        // First, filter out edges that already exist
        Set<String> existingEdgeKeys = new HashSet<>();
        String checkSql = "SELECT source_id, target_id, type FROM graph_edges WHERE source_id IN (" +
                String.join(",", Collections.nCopies(toInsert.size(), "?")) + ")";

        try (PreparedStatement checkStmt = connection.prepareStatement(checkSql)) {
            Set<String> sourceIds = new HashSet<>();
            for (PendingEdge edge : toInsert) {
                sourceIds.add(edge.sourceId);
            }
            int idx = 1;
            for (String sourceId : sourceIds) {
                checkStmt.setString(idx++, sourceId);
            }
            // Pad remaining parameters if sourceIds < toInsert.size()
            for (int i = idx; i <= toInsert.size(); i++) {
                checkStmt.setString(i, "");
            }

            ResultSet rs = checkStmt.executeQuery();
            while (rs.next()) {
                String key = rs.getString("source_id") + "|" + rs.getString("target_id") + "|" + rs.getString("type");
                existingEdgeKeys.add(key);
            }
        } catch (SQLException e) {
            Msg.debug(this, "Failed to check existing edges: " + e.getMessage());
        }

        // Filter out existing edges
        List<PendingEdge> newEdges = new ArrayList<>();
        for (PendingEdge edge : toInsert) {
            String key = edge.sourceId + "|" + edge.targetId + "|" + edge.type.name();
            if (!existingEdgeKeys.contains(key)) {
                newEdges.add(edge);
            }
        }

        if (newEdges.isEmpty()) {
            return;
        }

        String sql = "INSERT INTO graph_edges (id, source_id, target_id, type, weight, metadata, created_at) "
                + "VALUES (?, ?, ?, ?, ?, ?, ?)";

        synchronized (batchLock) {
            try {
                boolean originalAutoCommit = connection.getAutoCommit();
                connection.setAutoCommit(false);

                try (PreparedStatement stmt = connection.prepareStatement(sql)) {
                    long now = Instant.now().toEpochMilli();

                    for (PendingEdge edge : newEdges) {
                        stmt.setString(1, UUID.randomUUID().toString());
                        stmt.setString(2, edge.sourceId);
                        stmt.setString(3, edge.targetId);
                        stmt.setString(4, edge.type.name());
                        stmt.setDouble(5, edge.weight);
                        stmt.setString(6, edge.metadata);
                        stmt.setLong(7, now);
                        stmt.addBatch();

                        // Add to in-memory graph
                        if (!memoryGraph.containsVertex(edge.sourceId)) {
                            memoryGraph.addVertex(edge.sourceId);
                        }
                        if (!memoryGraph.containsVertex(edge.targetId)) {
                            memoryGraph.addVertex(edge.targetId);
                        }
                        LabeledEdge memEdge = new LabeledEdge(edge.type);
                        memoryGraph.addEdge(edge.sourceId, edge.targetId, memEdge);
                        edgeCount++;
                    }

                    stmt.executeBatch();
                    connection.commit();
                } catch (SQLException e) {
                    connection.rollback();
                    Msg.error(this, "Failed to batch insert edges: " + e.getMessage(), e);
                } finally {
                    connection.setAutoCommit(originalAutoCommit);
                }
            } catch (SQLException e) {
                Msg.error(this, "Failed to manage transaction for edge batch insert: " + e.getMessage(), e);
            }
        }
    }

    /**
     * Queue a community member for batch insertion.
     */
    public void queueCommunityMemberForBatch(String communityId, String nodeId, double score) {
        pendingCommunityMembers.add(new PendingCommunityMember(communityId, nodeId, score));
        if (pendingCommunityMembers.size() >= BATCH_SIZE) {
            flushCommunityMemberBatch();
        }
    }

    /**
     * Flush all pending community members to the database.
     */
    public void flushCommunityMemberBatch() {
        List<PendingCommunityMember> toInsert;
        synchronized (batchLock) {
            if (pendingCommunityMembers.isEmpty()) {
                return;
            }
            toInsert = new ArrayList<>(pendingCommunityMembers);
            pendingCommunityMembers.clear();
        }

        String sql = "INSERT OR REPLACE INTO community_members (community_id, node_id, membership_score) VALUES (?, ?, ?)";

        synchronized (batchLock) {
            try {
                boolean originalAutoCommit = connection.getAutoCommit();
                connection.setAutoCommit(false);

                try (PreparedStatement stmt = connection.prepareStatement(sql)) {
                    for (PendingCommunityMember member : toInsert) {
                        stmt.setString(1, member.communityId);
                        stmt.setString(2, member.nodeId);
                        stmt.setDouble(3, member.score);
                        stmt.addBatch();
                    }
                    stmt.executeBatch();
                    connection.commit();
                } catch (SQLException e) {
                    connection.rollback();
                    Msg.error(this, "Failed to batch insert community members: " + e.getMessage(), e);
                } finally {
                    connection.setAutoCommit(originalAutoCommit);
                }
            } catch (SQLException e) {
                Msg.error(this, "Failed to manage transaction for community member batch insert: " + e.getMessage(), e);
            }
        }
    }

    /**
     * Resolve pending edge node IDs to their actual database IDs.
     * This fixes UUID mismatches that occur when upsertNode() changes a node's ID
     * to match an existing node with the same address.
     *
     * Called automatically before flushEdgeBatch() to ensure edges reference valid node IDs.
     */
    private void resolvePendingEdgeIds() {
        if (pendingEdges.isEmpty()) {
            return;
        }

        // Build lookup of address -> actual node ID from database
        Map<Long, String> addressToId = new HashMap<>();
        String sql = "SELECT id, address FROM graph_nodes WHERE binary_id = ? AND address IS NOT NULL AND address != 0";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, binaryId);
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                long addr = rs.getLong("address");
                addressToId.put(addr, rs.getString("id"));
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to build address lookup for edge resolution: " + e.getMessage(), e);
            return;
        }

        // Build UUID -> address lookup from pending nodes
        // This allows us to find the address for a pending node's UUID
        Map<String, Long> pendingUuidToAddress = new HashMap<>();
        synchronized (pendingNodes) {
            for (KnowledgeNode node : pendingNodes) {
                if (node.getAddress() != null && node.getAddress() != 0) {
                    pendingUuidToAddress.put(node.getId(), node.getAddress());
                    // Also update addressToId with pending nodes (they may not be in DB yet)
                    addressToId.put(node.getAddress(), node.getId());
                }
            }
        }

        // Resolve each pending edge's source and target IDs
        List<PendingEdge> resolvedEdges = new ArrayList<>();
        int resolvedCount = 0;

        synchronized (pendingEdges) {
            for (PendingEdge edge : pendingEdges) {
                String resolvedSource = edge.sourceId;
                String resolvedTarget = edge.targetId;
                boolean changed = false;

                // Try to resolve source ID via address lookup
                Long sourceAddr = pendingUuidToAddress.get(edge.sourceId);
                if (sourceAddr != null && addressToId.containsKey(sourceAddr)) {
                    String actualId = addressToId.get(sourceAddr);
                    if (!actualId.equals(edge.sourceId)) {
                        resolvedSource = actualId;
                        changed = true;
                    }
                }

                // Try to resolve target ID via address lookup
                Long targetAddr = pendingUuidToAddress.get(edge.targetId);
                if (targetAddr != null && addressToId.containsKey(targetAddr)) {
                    String actualId = addressToId.get(targetAddr);
                    if (!actualId.equals(edge.targetId)) {
                        resolvedTarget = actualId;
                        changed = true;
                    }
                }

                if (changed) {
                    resolvedCount++;
                }
                resolvedEdges.add(new PendingEdge(resolvedSource, resolvedTarget, edge.type, edge.weight, edge.metadata));
            }

            pendingEdges.clear();
            pendingEdges.addAll(resolvedEdges);
        }

        if (resolvedCount > 0) {
            Msg.info(this, String.format("Resolved %d edge IDs to match actual node IDs", resolvedCount));
        }
    }

    /**
     * Flush all pending batches (nodes, edges, and community members).
     * Call this at the end of batch operations to ensure all data is written.
     */
    public void flushAllBatches() {
        // CRITICAL: Flush nodes FIRST so they exist in DB
        flushNodeBatch();

        // CRITICAL: Resolve edge IDs BEFORE flushing edges
        // This fixes UUID mismatches from parallel extraction
        resolvePendingEdgeIds();

        // Now flush edges with correct IDs
        flushEdgeBatch();
        flushCommunityMemberBatch();
    }

    /**
     * Get count of pending items in batches.
     */
    public int getPendingBatchCount() {
        return pendingNodes.size() + pendingEdges.size() + pendingCommunityMembers.size();
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
     * @deprecated Use {@link #getNeighborsBatch(String, int)} for better performance
     */
    @Deprecated
    public List<KnowledgeNode> getNeighbors(String nodeId, int maxDepth) {
        // Delegate to batch version for better performance
        return getNeighborsBatch(nodeId, maxDepth);
    }

    /**
     * Get neighboring nodes within N hops using batch loading.
     * This method first collects all neighbor IDs from the in-memory graph,
     * then fetches all nodes in a single database query.
     *
     * @param nodeId   The starting node ID
     * @param maxDepth Maximum number of hops from the starting node
     * @return List of neighboring nodes within the specified depth
     */
    public List<KnowledgeNode> getNeighborsBatch(String nodeId, int maxDepth) {
        if (!memoryGraph.containsVertex(nodeId)) {
            return new ArrayList<>();
        }

        // Phase 1: Collect all neighbor IDs using in-memory graph (fast)
        Set<String> neighborIds = new HashSet<>();
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

            neighborIds.add(vertexId);
        }

        // Phase 2: Batch fetch all nodes in a single query
        Map<String, KnowledgeNode> nodeMap = getNodes(neighborIds);
        return new ArrayList<>(nodeMap.values());
    }

    /**
     * Get all callers of a function (nodes that have CALLS edge to this function).
     * Uses in-memory graph for topology (no DB hit) + batch fetch for node data.
     */
    public List<KnowledgeNode> getCallers(String functionId) {
        if (!memoryGraph.containsVertex(functionId)) {
            return new ArrayList<>();
        }

        // Use in-memory graph for topology (no DB hit)
        Set<LabeledEdge> inEdges = memoryGraph.incomingEdgesOf(functionId);

        List<String> callerIds = new ArrayList<>();
        for (LabeledEdge edge : inEdges) {
            if (edge.getType() == EdgeType.CALLS) {
                callerIds.add(memoryGraph.getEdgeSource(edge));
            }
        }

        if (callerIds.isEmpty()) {
            return new ArrayList<>();
        }

        // Batch fetch all caller nodes at once (uses cache)
        Map<String, KnowledgeNode> nodeMap = getNodes(callerIds);
        return new ArrayList<>(nodeMap.values());
    }

    /**
     * Get all callees of a function (nodes this function CALLS).
     * Uses in-memory graph for topology (no DB hit) + batch fetch for node data.
     */
    public List<KnowledgeNode> getCallees(String functionId) {
        if (!memoryGraph.containsVertex(functionId)) {
            return new ArrayList<>();
        }

        // Use in-memory graph for topology (no DB hit)
        Set<LabeledEdge> outEdges = memoryGraph.outgoingEdgesOf(functionId);

        List<String> calleeIds = new ArrayList<>();
        for (LabeledEdge edge : outEdges) {
            if (edge.getType() == EdgeType.CALLS) {
                calleeIds.add(memoryGraph.getEdgeTarget(edge));
            }
        }

        if (calleeIds.isEmpty()) {
            return new ArrayList<>();
        }

        // Batch fetch all callee nodes at once (uses cache)
        Map<String, KnowledgeNode> nodeMap = getNodes(calleeIds);
        return new ArrayList<>(nodeMap.values());
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
        // Join with graph_nodes to filter by binary_id BEFORE applying LIMIT
        String sql = "SELECT node_fts.id FROM node_fts, graph_nodes "
                   + "WHERE node_fts MATCH ? "
                   + "AND graph_nodes.rowid = node_fts.rowid "
                   + "AND graph_nodes.binary_id = ? "
                   + "LIMIT ?";

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            String ftsQuery = escapeFtsQuery(query);
            stmt.setString(1, ftsQuery);
            stmt.setString(2, binaryId);
            stmt.setInt(3, limit);

            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                KnowledgeNode node = getNode(rs.getString("id"));
                if (node != null) {
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
     * Results are ordered by address for predictable processing order.
     */
    public List<KnowledgeNode> getStaleNodes(int limit) {
        List<KnowledgeNode> nodes = new ArrayList<>();
        // Include nodes that are stale OR have no summary (null, empty, or whitespace-only)
        // Order by address for predictable sequential processing
        String sql = "SELECT * FROM graph_nodes WHERE binary_id = ? " +
                     "AND (is_stale = 1 OR llm_summary IS NULL OR TRIM(llm_summary) = '') " +
                     "ORDER BY address NULLS LAST LIMIT ?";

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
     * Used at the start of incremental reindex to identify unchanged nodes.
     *
     * @return Number of nodes marked stale
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
     * Get count of nodes with LLM summaries (non-stale with summary).
     * Useful for tracking how many summaries were preserved during incremental reindex.
     *
     * @return Count of nodes with preserved summaries
     */
    public int getPreservedSummaryCount() {
        String sql = "SELECT COUNT(*) FROM graph_nodes WHERE binary_id = ? " +
                     "AND is_stale = 0 AND llm_summary IS NOT NULL AND TRIM(llm_summary) != ''";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, binaryId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to get preserved summary count: " + e.getMessage(), e);
        }
        return 0;
    }

    /**
     * Get count of nodes that are stale (need re-summarization).
     *
     * @return Count of stale nodes
     */
    public int getStaleNodeCount() {
        String sql = "SELECT COUNT(*) FROM graph_nodes WHERE binary_id = ? AND is_stale = 1";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, binaryId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to get stale node count: " + e.getMessage(), e);
        }
        return 0;
    }

    /**
     * Delete all graph data for this binary.
     * Clears: edges, nodes, and communities.
     * FTS is synced separately via rebuildFts() after batch operations.
     */
    public void clearGraph() {
        String deleteEdges = "DELETE FROM graph_edges WHERE " +
                "source_id IN (SELECT id FROM graph_nodes WHERE binary_id = ?) OR " +
                "target_id IN (SELECT id FROM graph_nodes WHERE binary_id = ?)";
        String deleteNodes = "DELETE FROM graph_nodes WHERE binary_id = ?";
        String deleteCommunities = "DELETE FROM graph_communities WHERE binary_id = ?";

        try (PreparedStatement stmtEdges = connection.prepareStatement(deleteEdges);
             PreparedStatement stmtNodes = connection.prepareStatement(deleteNodes);
             PreparedStatement stmtCommunities = connection.prepareStatement(deleteCommunities)) {

            stmtEdges.setString(1, binaryId);
            stmtEdges.setString(2, binaryId);
            int edgesDeleted = stmtEdges.executeUpdate();

            stmtNodes.setString(1, binaryId);
            int nodesDeleted = stmtNodes.executeUpdate();

            stmtCommunities.setString(1, binaryId);
            int communitiesDeleted = stmtCommunities.executeUpdate();

            memoryGraph = new DefaultDirectedGraph<>(LabeledEdge.class);
            nodeCount = 0;
            edgeCount = 0;

            Msg.info(this, String.format("Cleared graph for binary %s: %d edges, %d nodes, %d communities",
                    binaryId, edgesDeleted, nodesDeleted, communitiesDeleted));
        } catch (SQLException e) {
            Msg.error(this, "Failed to clear graph: " + e.getMessage(), e);
        }
    }

    /**
     * Rebuild the FTS index from current graph_nodes data.
     * Call after batch operations to sync FTS with the base table.
     */
    public void rebuildFts() {
        if (analysisDB != null) {
            analysisDB.rebuildFts();
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

        // Load all edges for nodes in this binary (source OR target belongs to binary)
        // Use UNION to capture edges where either endpoint belongs to this binary
        String edgesSql = "SELECT DISTINCT e.source_id, e.target_id, e.type FROM graph_edges e "
                + "INNER JOIN graph_nodes n ON e.source_id = n.id "
                + "WHERE n.binary_id = ? "
                + "UNION "
                + "SELECT DISTINCT e.source_id, e.target_id, e.type FROM graph_edges e "
                + "INNER JOIN graph_nodes n ON e.target_id = n.id "
                + "WHERE n.binary_id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(edgesSql)) {
            stmt.setString(1, binaryId);
            stmt.setString(2, binaryId);
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                String sourceId = rs.getString("source_id");
                String targetId = rs.getString("target_id");
                EdgeType type = EdgeType.fromString(rs.getString("type"));

                // Dynamically add missing vertices instead of dropping edges
                // This ensures edges to/from external functions are included
                if (!memoryGraph.containsVertex(sourceId)) {
                    memoryGraph.addVertex(sourceId);
                }
                if (!memoryGraph.containsVertex(targetId)) {
                    memoryGraph.addVertex(targetId);
                }

                LabeledEdge edge = new LabeledEdge(type);
                try {
                    memoryGraph.addEdge(sourceId, targetId, edge);
                    edgeCount++;
                } catch (IllegalArgumentException e) {
                    // Edge already exists (can happen with UNION if both source and target
                    // belong to this binary) - silently skip
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
        if (query == null || query.trim().isEmpty()) {
            return "\"\"";
        }

        String[] words = query.trim().split("\\s+");
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < words.length; i++) {
            String word = words[i];
            if (word.isEmpty()) continue;

            // Skip FTS5 operator keywords so they don't become literal terms
            if (word.equalsIgnoreCase("OR") || word.equalsIgnoreCase("AND") || word.equalsIgnoreCase("NOT")) {
                continue;
            }

            word = word.replace("\"", "\"\"");
            word = word.replace("*", "");

            if (sb.length() > 0) {
                sb.append(" OR ");
            }

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
        private static final long serialVersionUID = 1L;
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
