package ghidrassist.services.symgraph;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Data models for SymGraph API integration.
 */
public class SymGraphModels {

    /**
     * Action type for conflict resolution during pull.
     */
    public enum ConflictAction {
        NEW("new"),           // Remote only, doesn't exist locally
        CONFLICT("conflict"), // Different values locally and remotely
        SAME("same");         // Identical values locally and remotely

        private final String value;

        ConflictAction(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }
    }

    /**
     * Scope for push operations.
     */
    public enum PushScope {
        FULL_BINARY("full"),
        CURRENT_FUNCTION("function");

        private final String value;

        PushScope(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }
    }

    /**
     * Statistics for a binary in SymGraph.
     */
    public static class BinaryStats {
        private int symbolCount;
        private int functionCount;
        private int graphNodeCount;
        private int queryCount;
        private String lastQueriedAt;

        public BinaryStats() {}

        public BinaryStats(int symbolCount, int functionCount, int graphNodeCount,
                          int queryCount, String lastQueriedAt) {
            this.symbolCount = symbolCount;
            this.functionCount = functionCount;
            this.graphNodeCount = graphNodeCount;
            this.queryCount = queryCount;
            this.lastQueriedAt = lastQueriedAt;
        }

        public int getSymbolCount() { return symbolCount; }
        public void setSymbolCount(int symbolCount) { this.symbolCount = symbolCount; }
        public int getFunctionCount() { return functionCount; }
        public void setFunctionCount(int functionCount) { this.functionCount = functionCount; }
        public int getGraphNodeCount() { return graphNodeCount; }
        public void setGraphNodeCount(int graphNodeCount) { this.graphNodeCount = graphNodeCount; }
        public int getQueryCount() { return queryCount; }
        public void setQueryCount(int queryCount) { this.queryCount = queryCount; }
        public String getLastQueriedAt() { return lastQueriedAt; }
        public void setLastQueriedAt(String lastQueriedAt) { this.lastQueriedAt = lastQueriedAt; }
    }

    /**
     * A symbol from SymGraph.
     */
    public static class Symbol {
        private long address;
        private String symbolType;
        private String name;
        private String dataType;
        private double confidence;
        private String provenance;
        private String source;
        private Map<String, Object> metadata;

        public Symbol() {}

        public Symbol(long address, String symbolType, String name,
                     double confidence, String provenance) {
            this.address = address;
            this.symbolType = symbolType;
            this.name = name;
            this.confidence = confidence;
            this.provenance = provenance;
        }

        public long getAddress() { return address; }
        public void setAddress(long address) { this.address = address; }
        public String getSymbolType() { return symbolType; }
        public void setSymbolType(String symbolType) { this.symbolType = symbolType; }
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getDataType() { return dataType; }
        public void setDataType(String dataType) { this.dataType = dataType; }
        public double getConfidence() { return confidence; }
        public void setConfidence(double confidence) { this.confidence = confidence; }
        public String getProvenance() { return provenance; }
        public void setProvenance(String provenance) { this.provenance = provenance; }
        public String getSource() { return source; }
        public void setSource(String source) { this.source = source; }
        public Map<String, Object> getMetadata() { return metadata; }
        public void setMetadata(Map<String, Object> metadata) { this.metadata = metadata; }
    }

    /**
     * A graph node from SymGraph.
     */
    public static class GraphNode {
        private String id;
        private long address;
        private String nodeType;
        private String name;
        private String summary;
        private Map<String, Object> properties;

        public GraphNode() {}

        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        public long getAddress() { return address; }
        public void setAddress(long address) { this.address = address; }
        public String getNodeType() { return nodeType; }
        public void setNodeType(String nodeType) { this.nodeType = nodeType; }
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getSummary() { return summary; }
        public void setSummary(String summary) { this.summary = summary; }
        public Map<String, Object> getProperties() { return properties; }
        public void setProperties(Map<String, Object> properties) { this.properties = properties; }
    }

    /**
     * A graph edge from SymGraph.
     */
    public static class GraphEdge {
        private long sourceAddress;
        private long targetAddress;
        private String edgeType;
        private Map<String, Object> properties;

        public GraphEdge() {}

        public GraphEdge(long sourceAddress, long targetAddress, String edgeType) {
            this.sourceAddress = sourceAddress;
            this.targetAddress = targetAddress;
            this.edgeType = edgeType;
        }

        public long getSourceAddress() { return sourceAddress; }
        public void setSourceAddress(long sourceAddress) { this.sourceAddress = sourceAddress; }
        public long getTargetAddress() { return targetAddress; }
        public void setTargetAddress(long targetAddress) { this.targetAddress = targetAddress; }
        public String getEdgeType() { return edgeType; }
        public void setEdgeType(String edgeType) { this.edgeType = edgeType; }
        public Map<String, Object> getProperties() { return properties; }
        public void setProperties(Map<String, Object> properties) { this.properties = properties; }
    }

    /**
     * Exported graph data from SymGraph.
     */
    public static class GraphExport {
        private String binarySha256;
        private List<GraphNode> nodes;
        private List<GraphEdge> edges;
        private String exportVersion;
        private Map<String, Object> metadata;

        public String getBinarySha256() { return binarySha256; }
        public void setBinarySha256(String binarySha256) { this.binarySha256 = binarySha256; }
        public List<GraphNode> getNodes() { return nodes != null ? nodes : new ArrayList<>(); }
        public void setNodes(List<GraphNode> nodes) { this.nodes = nodes; }
        public List<GraphEdge> getEdges() { return edges != null ? edges : new ArrayList<>(); }
        public void setEdges(List<GraphEdge> edges) { this.edges = edges; }
        public String getExportVersion() { return exportVersion; }
        public void setExportVersion(String exportVersion) { this.exportVersion = exportVersion; }
        public Map<String, Object> getMetadata() { return metadata; }
        public void setMetadata(Map<String, Object> metadata) { this.metadata = metadata; }
    }

    /**
     * An entry in the conflict resolution table.
     */
    public static class ConflictEntry {
        private long address;
        private String localName;
        private String remoteName;
        private ConflictAction action;
        private boolean selected;
        private Symbol remoteSymbol;

        public ConflictEntry() {}

        public ConflictEntry(long address, String localName, String remoteName,
                            ConflictAction action, boolean selected, Symbol remoteSymbol) {
            this.address = address;
            this.localName = localName;
            this.remoteName = remoteName;
            this.action = action;
            this.selected = selected;
            this.remoteSymbol = remoteSymbol;
        }

        public static ConflictEntry createNew(long address, Symbol remoteSymbol) {
            return new ConflictEntry(address, null, remoteSymbol.getName(),
                    ConflictAction.NEW, true, remoteSymbol);
        }

        public static ConflictEntry createConflict(long address, String localName, Symbol remoteSymbol) {
            return new ConflictEntry(address, localName, remoteSymbol.getName(),
                    ConflictAction.CONFLICT, false, remoteSymbol);
        }

        public static ConflictEntry createSame(long address, String name, Symbol remoteSymbol) {
            return new ConflictEntry(address, name, name,
                    ConflictAction.SAME, true, remoteSymbol);
        }

        public long getAddress() { return address; }
        public void setAddress(long address) { this.address = address; }
        public String getLocalName() { return localName; }
        public void setLocalName(String localName) { this.localName = localName; }
        public String getRemoteName() { return remoteName; }
        public void setRemoteName(String remoteName) { this.remoteName = remoteName; }
        public ConflictAction getAction() { return action; }
        public void setAction(ConflictAction action) { this.action = action; }
        public boolean isSelected() { return selected; }
        public void setSelected(boolean selected) { this.selected = selected; }
        public Symbol getRemoteSymbol() { return remoteSymbol; }
        public void setRemoteSymbol(Symbol remoteSymbol) { this.remoteSymbol = remoteSymbol; }

        public String getAddressHex() {
            return String.format("0x%x", address);
        }

        public String getLocalNameDisplay() {
            return localName != null ? localName : "<none>";
        }

        public String getRemoteNameDisplay() {
            return remoteName != null ? remoteName : "<none>";
        }
    }

    /**
     * Result of a SymGraph query operation.
     */
    public static class QueryResult {
        private boolean exists;
        private BinaryStats stats;
        private String error;

        public QueryResult() {}

        public static QueryResult found(BinaryStats stats) {
            QueryResult result = new QueryResult();
            result.exists = true;
            result.stats = stats;
            return result;
        }

        public static QueryResult notFound() {
            QueryResult result = new QueryResult();
            result.exists = false;
            return result;
        }

        public static QueryResult error(String errorMsg) {
            QueryResult result = new QueryResult();
            result.exists = false;
            result.error = errorMsg;
            return result;
        }

        public boolean isExists() { return exists; }
        public void setExists(boolean exists) { this.exists = exists; }
        public BinaryStats getStats() { return stats; }
        public void setStats(BinaryStats stats) { this.stats = stats; }
        public String getError() { return error; }
        public void setError(String error) { this.error = error; }
    }

    /**
     * Result of a SymGraph push operation.
     */
    public static class PushResult {
        private boolean success;
        private int symbolsPushed;
        private int nodesPushed;
        private int edgesPushed;
        private String error;

        public PushResult() {}

        public static PushResult success(int symbols, int nodes, int edges) {
            PushResult result = new PushResult();
            result.success = true;
            result.symbolsPushed = symbols;
            result.nodesPushed = nodes;
            result.edgesPushed = edges;
            return result;
        }

        public static PushResult failure(String errorMsg) {
            PushResult result = new PushResult();
            result.success = false;
            result.error = errorMsg;
            return result;
        }

        public boolean isSuccess() { return success; }
        public void setSuccess(boolean success) { this.success = success; }
        public int getSymbolsPushed() { return symbolsPushed; }
        public void setSymbolsPushed(int symbolsPushed) { this.symbolsPushed = symbolsPushed; }
        public int getNodesPushed() { return nodesPushed; }
        public void setNodesPushed(int nodesPushed) { this.nodesPushed = nodesPushed; }
        public int getEdgesPushed() { return edgesPushed; }
        public void setEdgesPushed(int edgesPushed) { this.edgesPushed = edgesPushed; }
        public String getError() { return error; }
        public void setError(String error) { this.error = error; }
    }

    /**
     * Result of a pull preview operation.
     */
    public static class PullPreviewResult {
        private boolean success;
        private List<ConflictEntry> conflicts;
        private String error;

        public PullPreviewResult() {
            this.conflicts = new ArrayList<>();
        }

        public static PullPreviewResult success(List<ConflictEntry> conflicts) {
            PullPreviewResult result = new PullPreviewResult();
            result.success = true;
            result.conflicts = conflicts;
            return result;
        }

        public static PullPreviewResult failure(String errorMsg) {
            PullPreviewResult result = new PullPreviewResult();
            result.success = false;
            result.error = errorMsg;
            return result;
        }

        public boolean isSuccess() { return success; }
        public void setSuccess(boolean success) { this.success = success; }
        public List<ConflictEntry> getConflicts() { return conflicts; }
        public void setConflicts(List<ConflictEntry> conflicts) { this.conflicts = conflicts; }
        public String getError() { return error; }
        public void setError(String error) { this.error = error; }
    }
}
