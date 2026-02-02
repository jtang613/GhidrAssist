package ghidrassist.workers;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.lang.Register;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidrassist.AnalysisDB;
import ghidrassist.graphrag.BinaryKnowledgeGraph;
import ghidrassist.graphrag.nodes.EdgeType;
import ghidrassist.graphrag.nodes.KnowledgeNode;
import ghidrassist.graphrag.nodes.NodeType;
import ghidrassist.services.symgraph.SymGraphModels.*;

import com.google.gson.Gson;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Background worker for applying SymGraph symbols and graph data.
 * Uses SwingWorker to run in the background without blocking the UI.
 */
public class SymGraphApplyWorker extends AnalysisWorker<SymGraphApplyWorker.Result> {

    /**
     * Result of the apply operation.
     */
    public static class Result {
        public final int symbolsApplied;
        public final int nodesApplied;
        public final int edgesApplied;
        public final long elapsedMs;
        public final boolean cancelled;
        public final String error;

        public Result(int symbolsApplied, int nodesApplied, int edgesApplied, long elapsedMs, boolean cancelled) {
            this.symbolsApplied = symbolsApplied;
            this.nodesApplied = nodesApplied;
            this.edgesApplied = edgesApplied;
            this.elapsedMs = elapsedMs;
            this.cancelled = cancelled;
            this.error = null;
        }

        public Result(String error) {
            this.symbolsApplied = 0;
            this.nodesApplied = 0;
            this.edgesApplied = 0;
            this.elapsedMs = 0;
            this.cancelled = false;
            this.error = error;
        }
    }

    private final Program program;
    private final AnalysisDB analysisDB;
    private final List<ConflictEntry> conflicts;
    private final GraphExport graphExport;
    private final String programHash;
    private final String mergePolicy;

    private static final String MERGE_POLICY_UPSERT = "upsert";
    private static final String MERGE_POLICY_PREFER_LOCAL = "prefer_local";
    private static final String MERGE_POLICY_REPLACE = "replace";

    /**
     * Create a new SymGraphApplyWorker.
     *
     * @param program      The Ghidra program to modify
     * @param analysisDB   The analysis database for graph operations
     * @param conflicts    List of symbols to apply
     * @param graphExport  Optional graph data to merge
     * @param programHash  SHA256 hash of the program
     * @param mergePolicy  Graph merge policy (upsert, prefer_local, replace)
     */
    public SymGraphApplyWorker(Program program, AnalysisDB analysisDB,
                                List<ConflictEntry> conflicts, GraphExport graphExport,
                                String programHash, String mergePolicy) {
        this.program = program;
        this.analysisDB = analysisDB;
        this.conflicts = conflicts != null ? conflicts : new ArrayList<>();
        this.graphExport = graphExport;
        this.programHash = programHash;
        this.mergePolicy = mergePolicy != null ? mergePolicy : MERGE_POLICY_UPSERT;
    }

    @Override
    protected Result doInBackground() throws Exception {
        long startTime = System.currentTimeMillis();
        int symbolsApplied = 0;
        int nodesApplied = 0;
        int edgesApplied = 0;

        int transactionId = program.startTransaction("Apply SymGraph Symbols");
        try {
            // Phase 1: Merge graph data (0-30%)
            if (graphExport != null && analysisDB != null) {
                publishProgress(0, 100, "Merging graph data...");

                int[] graphResults = mergeGraphData();
                nodesApplied = graphResults[0];
                edgesApplied = graphResults[1];

                if (isCancelRequested()) {
                    program.endTransaction(transactionId, false);
                    long elapsed = System.currentTimeMillis() - startTime;
                    return new Result(0, nodesApplied, edgesApplied, elapsed, true);
                }
            }

            // Phase 2: Apply symbols (30-95%)
            int total = conflicts.size();
            for (int i = 0; i < total; i++) {
                if (isCancelRequested()) {
                    break;
                }

                int progress = total > 0 ? 30 + (int)((i * 65L) / total) : 30;
                publishProgress(progress, 100,
                    String.format("Applying symbol %d/%d...", i + 1, total));

                ConflictEntry conflict = conflicts.get(i);
                if (applySymbol(conflict)) {
                    symbolsApplied++;
                }
            }

            // Phase 3: Finalize (95-100%)
            publishProgress(95, 100, "Finalizing...");

            if (isCancelRequested()) {
                program.endTransaction(transactionId, false);
                long elapsed = System.currentTimeMillis() - startTime;
                return new Result(symbolsApplied, nodesApplied, edgesApplied, elapsed, true);
            }

            program.endTransaction(transactionId, true);

            publishProgress(100, 100, "Complete");
            long elapsed = System.currentTimeMillis() - startTime;
            return new Result(symbolsApplied, nodesApplied, edgesApplied, elapsed, false);

        } catch (Exception e) {
            program.endTransaction(transactionId, false);
            throw e;
        }
    }

    /**
     * Apply a single symbol to the program.
     *
     * @param conflict The conflict entry containing the symbol to apply
     * @return true if the symbol was successfully applied
     */
    private boolean applySymbol(ConflictEntry conflict) {
        if (conflict.getRemoteSymbol() == null) {
            return false;
        }

        Symbol remoteSymbol = conflict.getRemoteSymbol();
        String symbolType = remoteSymbol.getSymbolType();

        Msg.debug(this, "Applying symbol type=" + symbolType + " at 0x" +
                Long.toHexString(conflict.getAddress()) + ", name=" +
                (remoteSymbol.getName() != null ? remoteSymbol.getName() : "<null>") +
                ", content=" + (remoteSymbol.getContent() != null ?
                        remoteSymbol.getContent().substring(0, Math.min(50, remoteSymbol.getContent().length())) + "..." : "<null>"));

        // Comments don't require a name, but need content
        if ("comment".equals(symbolType)) {
            return applyComment(conflict.getAddress(), remoteSymbol);
        }

        // Struct/enum types are applied to DataTypeManager, not at an address
        if ("struct".equals(symbolType) || "enum".equals(symbolType)) {
            return applyStructOrEnum(remoteSymbol);
        }

        // All other symbol types require a name
        if (remoteSymbol.getName() == null) {
            return false;
        }

        try {
            long addr = conflict.getAddress();
            Address address = program.getAddressFactory()
                .getDefaultAddressSpace().getAddress(addr);

            if ("variable".equals(symbolType)) {
                // Variable - use storage-aware application
                Function func = program.getFunctionManager().getFunctionContaining(address);
                if (func != null && func.getEntryPoint().getOffset() == addr) {
                    return applyVariableSymbol(func, remoteSymbol);
                }
            } else {
                // Function or other symbol
                Function func = program.getFunctionManager().getFunctionAt(address);
                if (func != null) {
                    func.setName(remoteSymbol.getName(), SourceType.USER_DEFINED);
                    return true;
                }
            }
        } catch (Exception e) {
            Msg.error(this, "Error applying symbol at 0x" +
                Long.toHexString(conflict.getAddress()) + ": " + e.getMessage());
        }

        return false;
    }

    /**
     * Apply a variable symbol using storage-aware matching.
     */
    private boolean applyVariableSymbol(Function func, Symbol remoteSymbol) {
        if (remoteSymbol == null || remoteSymbol.getName() == null) {
            return false;
        }

        Map<String, Object> metadata = remoteSymbol.getMetadata();
        if (metadata == null) {
            return false;
        }

        String storageClass = (String) metadata.get("storage_class");
        String targetName = remoteSymbol.getName();

        try {
            if ("parameter".equals(storageClass)) {
                Object paramIdxObj = metadata.get("parameter_index");
                if (paramIdxObj != null) {
                    int paramIdx = ((Number) paramIdxObj).intValue();
                    Parameter[] params = func.getParameters();
                    if (paramIdx < params.length) {
                        params[paramIdx].setName(targetName, SourceType.USER_DEFINED);
                        return true;
                    }
                }
            } else if ("stack".equals(storageClass)) {
                Object stackOffsetObj = metadata.get("stack_offset");
                if (stackOffsetObj != null) {
                    int stackOffset = ((Number) stackOffsetObj).intValue();
                    for (Variable var : func.getLocalVariables()) {
                        if (var.isStackVariable()) {
                            try {
                                if (var.getStackOffset() == stackOffset) {
                                    var.setName(targetName, SourceType.USER_DEFINED);
                                    return true;
                                }
                            } catch (UnsupportedOperationException e) {
                                // Not a simple stack var
                            }
                        }
                    }
                }
            } else if ("register".equals(storageClass)) {
                String regName = (String) metadata.get("register");
                if (regName != null) {
                    for (Variable var : func.getLocalVariables()) {
                        if (var.isRegisterVariable()) {
                            Register reg = var.getRegister();
                            if (reg != null && regName.equals(reg.getName())) {
                                var.setName(targetName, SourceType.USER_DEFINED);
                                return true;
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            Msg.error(this, "Error applying variable: " + e.getMessage());
        }

        return false;
    }

    /**
     * Apply a comment symbol at the given address.
     *
     * @param addr The address for the comment
     * @param remoteSymbol The symbol containing the comment content and metadata
     * @return true if the comment was successfully applied
     */
    private boolean applyComment(long addr, Symbol remoteSymbol) {
        String content = remoteSymbol.getContent();
        if (content == null || content.isEmpty()) {
            Msg.debug(this, "Skipping comment at 0x" + Long.toHexString(addr) + ": empty content");
            return false;
        }

        Map<String, Object> metadata = remoteSymbol.getMetadata();
        String commentType = "eol";
        if (metadata != null && metadata.get("type") != null) {
            commentType = (String) metadata.get("type");
        }
        Msg.debug(this, "Applying comment at 0x" + Long.toHexString(addr) +
                ", type=" + commentType + ", content length=" + content.length());

        try {
            Address address = program.getAddressFactory()
                .getDefaultAddressSpace().getAddress(addr);

            Listing listing = program.getListing();

            if ("function".equals(commentType)) {
                // Apply as function comment (plate comment on function)
                Function func = program.getFunctionManager().getFunctionAt(address);
                if (func != null) {
                    func.setComment(content);
                    return true;
                }
                // Fall back to plate comment if no function at address
                CodeUnit codeUnit = listing.getCodeUnitAt(address);
                if (codeUnit != null) {
                    codeUnit.setComment(CodeUnit.PLATE_COMMENT, content);
                    return true;
                }
                return false;
            }

            CodeUnit codeUnit = listing.getCodeUnitAt(address);
            if (codeUnit == null) {
                // Try to get code unit containing the address
                codeUnit = listing.getCodeUnitContaining(address);
            }

            if (codeUnit != null) {
                int ghidraCommentType;
                switch (commentType) {
                    case "pre":
                        ghidraCommentType = CodeUnit.PRE_COMMENT;
                        break;
                    case "post":
                        ghidraCommentType = CodeUnit.POST_COMMENT;
                        break;
                    case "plate":
                        ghidraCommentType = CodeUnit.PLATE_COMMENT;
                        break;
                    case "repeatable":
                        ghidraCommentType = CodeUnit.REPEATABLE_COMMENT;
                        break;
                    case "eol":
                    default:
                        ghidraCommentType = CodeUnit.EOL_COMMENT;
                        break;
                }
                codeUnit.setComment(ghidraCommentType, content);
                return true;
            }
        } catch (Exception e) {
            Msg.error(this, "Error applying comment at 0x" + Long.toHexString(addr) + ": " + e.getMessage());
        }

        return false;
    }

    /**
     * Apply a struct or enum type from symbol metadata.
     *
     * @param remoteSymbol The symbol containing the type definition in metadata
     * @return true if the type was successfully created
     */
    @SuppressWarnings("unchecked")
    private boolean applyStructOrEnum(Symbol remoteSymbol) {
        Map<String, Object> metadata = remoteSymbol.getMetadata();
        if (metadata == null) {
            return false;
        }

        String name = remoteSymbol.getName();
        if (name == null || name.isEmpty()) {
            return false;
        }

        String symbolType = remoteSymbol.getSymbolType();
        DataTypeManager dtm = program.getDataTypeManager();

        try {
            if ("enum".equals(symbolType)) {
                // Create enum from metadata
                Object membersObj = metadata.get("members");
                if (membersObj instanceof Map) {
                    Map<String, Object> members = (Map<String, Object>) membersObj;
                    int size = 4;  // Default to 4-byte enum
                    if (metadata.get("size") instanceof Number) {
                        size = ((Number) metadata.get("size")).intValue();
                    }

                    EnumDataType enumType = new EnumDataType(name, size);
                    for (Map.Entry<String, Object> entry : members.entrySet()) {
                        long value = 0;
                        if (entry.getValue() instanceof Number) {
                            value = ((Number) entry.getValue()).longValue();
                        }
                        enumType.add(entry.getKey(), value);
                    }
                    dtm.addDataType(enumType, DataTypeConflictHandler.REPLACE_HANDLER);
                    Msg.info(this, "Created enum type: " + name + " with " + members.size() + " members");
                    return true;
                }
            } else if ("struct".equals(symbolType)) {
                // Create struct from metadata
                Object fieldsObj = metadata.get("fields");
                if (fieldsObj instanceof java.util.List) {
                    java.util.List<Map<String, Object>> fields = (java.util.List<Map<String, Object>>) fieldsObj;

                    int structSize = 0;
                    if (metadata.get("size") instanceof Number) {
                        structSize = ((Number) metadata.get("size")).intValue();
                    }

                    StructureDataType struct = new StructureDataType(name, structSize);

                    for (Map<String, Object> field : fields) {
                        String fieldName = (String) field.get("name");
                        String fieldTypeName = (String) field.get("type");
                        int offset = 0;
                        int fieldSize = 0;

                        if (field.get("offset") instanceof Number) {
                            offset = ((Number) field.get("offset")).intValue();
                        }
                        if (field.get("size") instanceof Number) {
                            fieldSize = ((Number) field.get("size")).intValue();
                        }

                        DataType fieldType = resolveDataType(dtm, fieldTypeName);
                        if (fieldType == null) {
                            fieldType = DataType.DEFAULT;
                        }

                        // Use insertAtOffset for explicit placement
                        int actualSize = fieldSize > 0 ? fieldSize : fieldType.getLength();
                        if (actualSize <= 0) {
                            actualSize = 1;  // Minimum size
                        }
                        struct.insertAtOffset(offset, fieldType, actualSize, fieldName, null);
                    }

                    dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);
                    Msg.info(this, "Created struct type: " + name + " with " + fields.size() + " fields");
                    return true;
                }
            }
        } catch (Exception e) {
            Msg.error(this, "Error creating type " + name + ": " + e.getMessage());
        }

        return false;
    }

    /**
     * Resolve a data type by name from the DataTypeManager.
     *
     * @param dtm The data type manager
     * @param typeName The name of the type to resolve
     * @return The resolved DataType, or null if not found
     */
    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
        if (typeName == null || typeName.isEmpty()) {
            return null;
        }

        // Try to find in root category
        DataType dt = dtm.getDataType("/" + typeName);
        if (dt != null) {
            return dt;
        }

        // Try without leading slash
        dt = dtm.getDataType(typeName);
        if (dt != null) {
            return dt;
        }

        // Try to find built-in types by common names
        String lowerName = typeName.toLowerCase();
        switch (lowerName) {
            case "int":
            case "int32":
            case "int32_t":
                return ghidra.program.model.data.IntegerDataType.dataType;
            case "uint":
            case "uint32":
            case "uint32_t":
            case "unsigned int":
                return ghidra.program.model.data.UnsignedIntegerDataType.dataType;
            case "long":
            case "int64":
            case "int64_t":
                return ghidra.program.model.data.LongDataType.dataType;
            case "ulong":
            case "uint64":
            case "uint64_t":
            case "unsigned long":
                return ghidra.program.model.data.UnsignedLongDataType.dataType;
            case "short":
            case "int16":
            case "int16_t":
                return ghidra.program.model.data.ShortDataType.dataType;
            case "ushort":
            case "uint16":
            case "uint16_t":
            case "unsigned short":
                return ghidra.program.model.data.UnsignedShortDataType.dataType;
            case "char":
            case "int8":
            case "int8_t":
                return ghidra.program.model.data.CharDataType.dataType;
            case "uchar":
            case "uint8":
            case "uint8_t":
            case "unsigned char":
            case "byte":
                return ghidra.program.model.data.ByteDataType.dataType;
            case "float":
                return ghidra.program.model.data.FloatDataType.dataType;
            case "double":
                return ghidra.program.model.data.DoubleDataType.dataType;
            case "void":
                return ghidra.program.model.data.VoidDataType.dataType;
            case "pointer":
            case "ptr":
            case "void*":
                return ghidra.program.model.data.PointerDataType.dataType;
            default:
                return null;
        }
    }

    /**
     * Merge graph data from the export into the local knowledge graph.
     *
     * @return Array of [nodesApplied, edgesApplied]
     */
    private int[] mergeGraphData() {
        int nodesApplied = 0;
        int edgesApplied = 0;

        if (graphExport == null || programHash == null) {
            return new int[] { 0, 0 };
        }

        BinaryKnowledgeGraph graph = analysisDB.getKnowledgeGraph(programHash);
        if (MERGE_POLICY_REPLACE.equals(mergePolicy)) {
            graph.clearGraph();
        }

        Map<Long, String> addressToId = new HashMap<>();
        List<GraphNode> nodes = graphExport.getNodes();
        int totalNodes = nodes.size();

        // Process nodes
        for (int i = 0; i < totalNodes; i++) {
            if (isCancelRequested()) {
                break;
            }

            // Progress within the graph merge phase (0-25%)
            int progress = totalNodes > 0 ? (int)((i * 25L) / totalNodes) : 0;
            publishProgress(progress, 100,
                String.format("Merging node %d/%d...", i + 1, totalNodes));

            GraphNode node = nodes.get(i);
            NodeType nodeType = NodeType.fromString(node.getNodeType());
            if (nodeType == null) {
                nodeType = NodeType.FUNCTION;
            }

            KnowledgeNode existing = graph.getNodeByAddress(node.getAddress());
            if (MERGE_POLICY_PREFER_LOCAL.equals(mergePolicy) && existing != null) {
                addressToId.put(node.getAddress(), existing.getId());
                continue;
            }

            KnowledgeNode localNode = node.getId() != null
                    ? new KnowledgeNode(node.getId(), nodeType, programHash)
                    : new KnowledgeNode(nodeType, programHash);
            if (existing != null) {
                localNode.setId(existing.getId());
            }

            localNode.setAddress(node.getAddress());
            localNode.setName(node.getName());

            Map<String, Object> props = node.getProperties();
            String rawContent = props != null ? (String) props.get("raw_content") : null;
            if (rawContent == null && props != null) {
                rawContent = (String) props.get("raw_code");
            }
            String summary = node.getSummary();
            if (summary == null && props != null) {
                summary = (String) props.get("llm_summary");
            }

            localNode.setRawContent(rawContent);
            localNode.setLlmSummary(summary);
            localNode.setConfidence((float) getDoubleProperty(props, "confidence", 0.0));
            localNode.setSecurityFlags(getListProperty(props, "security_flags"));
            localNode.setNetworkAPIs(getListProperty(props, "network_apis"));
            localNode.setFileIOAPIs(getListProperty(props, "file_io_apis"));
            localNode.setIPAddresses(getListProperty(props, "ip_addresses"));
            localNode.setURLs(getListProperty(props, "urls"));
            localNode.setFilePaths(getListProperty(props, "file_paths"));
            localNode.setDomains(getListProperty(props, "domains"));
            localNode.setRegistryKeys(getListProperty(props, "registry_keys"));
            if (props != null) {
                localNode.setRiskLevel((String) props.get("risk_level"));
                localNode.setActivityProfile((String) props.get("activity_profile"));
                Object depth = props.get("analysis_depth");
                if (depth instanceof Number) {
                    localNode.setAnalysisDepth(((Number) depth).intValue());
                }
                Object isStale = props.get("is_stale");
                if (isStale instanceof Boolean) {
                    localNode.setStale((Boolean) isStale);
                }
                Object userEdited = props.get("user_edited");
                if (userEdited instanceof Boolean) {
                    localNode.setUserEdited((Boolean) userEdited);
                }
            }

            // Debug logging for graph node properties
            Msg.debug(this, "Node at 0x" + Long.toHexString(node.getAddress()) +
                    " - security_flags: " + localNode.getSecurityFlags() +
                    ", risk_level: " + localNode.getRiskLevel() +
                    ", network_apis: " + localNode.getNetworkAPIs() +
                    ", file_io_apis: " + localNode.getFileIOAPIs() +
                    ", has_summary: " + (localNode.getLlmSummary() != null));

            graph.upsertNode(localNode);
            addressToId.put(node.getAddress(), localNode.getId());
            nodesApplied++;
        }

        // Process edges
        List<GraphEdge> edges = graphExport.getEdges();
        int totalEdges = edges.size();
        Gson gson = new Gson();

        for (int i = 0; i < totalEdges; i++) {
            if (isCancelRequested()) {
                break;
            }

            // Progress within the edge merge phase (25-30%)
            int progress = totalEdges > 0 ? 25 + (int)((i * 5L) / totalEdges) : 25;
            publishProgress(progress, 100,
                String.format("Merging edge %d/%d...", i + 1, totalEdges));

            GraphEdge edge = edges.get(i);
            String sourceId = addressToId.get(edge.getSourceAddress());
            String targetId = addressToId.get(edge.getTargetAddress());
            if (sourceId == null || targetId == null) {
                continue;
            }
            EdgeType edgeType = EdgeType.fromString(edge.getEdgeType());
            if (edgeType == null) {
                edgeType = EdgeType.CALLS;
            }
            Map<String, Object> props = edge.getProperties();
            double weight = getDoubleProperty(props, "weight", 1.0);
            String metadata = props != null ? gson.toJson(props) : null;
            graph.addEdge(sourceId, targetId, edgeType, weight, metadata);
            edgesApplied++;
        }

        return new int[] { nodesApplied, edgesApplied };
    }

    private List<String> getListProperty(Map<String, Object> props, String key) {
        if (props == null) {
            return new ArrayList<>();
        }
        Object value = props.get(key);
        if (value instanceof List) {
            List<String> list = new ArrayList<>();
            for (Object item : (List<?>) value) {
                if (item != null) {
                    list.add(item.toString());
                }
            }
            return list;
        }
        return new ArrayList<>();
    }

    private double getDoubleProperty(Map<String, Object> props, String key, double defaultValue) {
        if (props == null) {
            return defaultValue;
        }
        Object value = props.get(key);
        if (value instanceof Number) {
            return ((Number) value).doubleValue();
        }
        return defaultValue;
    }
}
