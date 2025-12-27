package ghidrassist.graphrag.extraction;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import ghidrassist.graphrag.BinaryKnowledgeGraph;
import ghidrassist.graphrag.nodes.EdgeType;
import ghidrassist.graphrag.nodes.KnowledgeNode;
import ghidrassist.graphrag.nodes.NodeType;

import java.util.*;

/**
 * Extracts structural information from Ghidra binaries and populates the knowledge graph.
 *
 * This extractor handles:
 * - Function enumeration and decompilation caching
 * - Call graph extraction (CALLS edges)
 * - Basic block extraction (optional, for BLOCK nodes)
 * - Cross-reference extraction (REFERENCES edges)
 *
 * This is a "fast" extractor that doesn't use LLM - just Ghidra analysis data.
 * LLM summarization is handled separately by SemanticExtractor.
 */
public class StructureExtractor {

    private final Program program;
    private final BinaryKnowledgeGraph graph;
    private final String binaryId;
    private final TaskMonitor monitor;

    // Statistics
    private int functionsExtracted = 0;
    private int callEdgesCreated = 0;
    private int refEdgesCreated = 0;
    private int dataDepEdgesCreated = 0;
    private int vulnEdgesCreated = 0;

    // Decompiler instance (reused for efficiency)
    private DecompInterface decompiler;

    /**
     * Create a StructureExtractor for a program.
     *
     * @param program The Ghidra program to extract from
     * @param graph   The knowledge graph to populate
     * @param monitor Task monitor for progress/cancellation
     */
    public StructureExtractor(Program program, BinaryKnowledgeGraph graph, TaskMonitor monitor) {
        this.program = program;
        this.graph = graph;
        this.binaryId = graph.getBinaryId();
        this.monitor = monitor;
    }

    /**
     * Extract all functions and their relationships.
     * This is the main entry point for graph population.
     *
     * @param includeBlocks Whether to also extract basic blocks (increases graph size)
     * @return ExtractionResult with statistics
     */
    public ExtractionResult extractAll(boolean includeBlocks) {
        long startTime = System.currentTimeMillis();

        try {
            // Initialize decompiler
            decompiler = new DecompInterface();
            decompiler.openProgram(program);

            // Phase 1: Extract all functions as nodes
            monitor.setMessage("Extracting functions...");
            extractFunctions();

            // Phase 2: Extract call relationships
            monitor.setMessage("Extracting call graph...");
            extractCallGraph();

            // Phase 3: Optionally extract basic blocks
            if (includeBlocks) {
                monitor.setMessage("Extracting basic blocks...");
                extractBasicBlocks();
            }

            // Phase 4: Extract cross-references (REFERENCES edges)
            monitor.setMessage("Extracting cross-references...");
            extractReferences();

            // Phase 5: Extract data dependencies (DATA_DEPENDS edges)
            monitor.setMessage("Extracting data dependencies...");
            extractDataDependencies();

            // Phase 6: Extract vulnerable call edges (CALLS_VULNERABLE edges)
            monitor.setMessage("Extracting vulnerable call edges...");
            extractVulnerableCalls();

            // Phase 7: Create binary-level node
            monitor.setMessage("Creating binary summary node...");
            createBinaryNode();

        } finally {
            if (decompiler != null) {
                decompiler.dispose();
                decompiler = null;
            }
        }

        long elapsed = System.currentTimeMillis() - startTime;
        Msg.info(this, String.format("Structure extraction completed in %dms: %d functions, %d call edges, %d ref edges, %d data-dep edges, %d vuln edges",
                elapsed, functionsExtracted, callEdgesCreated, refEdgesCreated, dataDepEdgesCreated, vulnEdgesCreated));

        return new ExtractionResult(functionsExtracted, callEdgesCreated, refEdgesCreated, dataDepEdgesCreated, vulnEdgesCreated, elapsed);
    }

    /**
     * Extract a single function and its immediate relationships.
     * Used for incremental updates when a new function is discovered.
     *
     * @param function The function to extract
     * @return The created KnowledgeNode, or null on failure
     */
    public KnowledgeNode extractFunction(Function function) {
        if (function == null || function.isThunk()) {
            return null;
        }

        try {
            if (decompiler == null) {
                decompiler = new DecompInterface();
                decompiler.openProgram(program);
            }

            // Check if already cached
            KnowledgeNode existing = graph.getNodeByAddress(function.getEntryPoint().getOffset());
            if (existing != null && existing.getRawContent() != null) {
                // Node exists - but still update edges in case new edge types were added
                updateFunctionEdges(function, existing);
                return existing;
            }

            // Create or update node
            KnowledgeNode node = createFunctionNode(function);
            if (node != null) {
                graph.upsertNode(node);

                // Extract calls from this function
                extractFunctionCalls(function, node.getId());

                // Extract references from this function (REFERENCES edges)
                extractFunctionReferences(function, node);

                // Extract data dependencies for this function (DATA_DEPENDS edges)
                extractFunctionDataDependencies(function, node);

                // Extract vulnerable call edges for this function (CALLS_VULNERABLE edges)
                extractFunctionVulnerableCalls(function, node);

                functionsExtracted++;
            }

            return node;
        } catch (Exception e) {
            Msg.error(this, "Failed to extract function " + function.getName() + ": " + e.getMessage());
            return null;
        }
    }

    /**
     * Update edges for an existing function node.
     * Used to add new edge types to already-indexed functions.
     *
     * @param function The function
     * @param node The existing knowledge node
     */
    public void updateFunctionEdges(Function function, KnowledgeNode node) {
        if (function == null || node == null) {
            return;
        }

        try {
            // Check if edges need updating by looking for presence of new edge types
            // We use a simple heuristic: if there are no REFERENCES edges from this node, update
            boolean hasReferencesEdges = graph.hasEdgesOfType(node.getId(), EdgeType.REFERENCES);
            boolean hasDataDependsEdges = graph.hasEdgesOfType(node.getId(), EdgeType.DATA_DEPENDS);
            boolean hasVulnerableEdges = graph.hasEdgesOfType(node.getId(), EdgeType.CALLS_VULNERABLE);

            if (!hasReferencesEdges) {
                Msg.debug(this, "Updating REFERENCES edges for: " + function.getName());
                extractFunctionReferences(function, node);
            }

            if (!hasDataDependsEdges) {
                Msg.debug(this, "Updating DATA_DEPENDS edges for: " + function.getName());
                extractFunctionDataDependencies(function, node);
            }

            if (!hasVulnerableEdges) {
                Msg.debug(this, "Updating CALLS_VULNERABLE edges for: " + function.getName());
                extractFunctionVulnerableCalls(function, node);
            }
        } catch (Exception e) {
            Msg.debug(this, "Failed to update edges for " + function.getName() + ": " + e.getMessage());
        }
    }

    /**
     * Get decompiled code for a function, using cache if available.
     * This is the primary caching mechanism to avoid redundant decompilation.
     *
     * @param function The function to decompile
     * @return Decompiled code string, or null on failure
     */
    public String getDecompiledCode(Function function) {
        if (function == null) {
            return null;
        }

        // Check cache first
        String cached = graph.getCachedDecompiledCode(function.getEntryPoint().getOffset());
        if (cached != null) {
            Msg.debug(this, "Cache hit for function: " + function.getName());
            return cached;
        }

        // Decompile and cache
        try {
            if (decompiler == null) {
                decompiler = new DecompInterface();
                decompiler.openProgram(program);
            }

            DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
            if (results != null && results.decompileCompleted()) {
                String code = results.getDecompiledFunction().getC();

                // Cache in graph
                KnowledgeNode node = graph.getNodeByAddress(function.getEntryPoint().getOffset());
                if (node == null) {
                    node = KnowledgeNode.createFunction(
                            binaryId,
                            function.getEntryPoint().getOffset(),
                            function.getName()
                    );
                }
                node.setRawContent(code);
                graph.upsertNode(node);

                Msg.debug(this, "Cached decompiled code for: " + function.getName());
                return code;
            }
        } catch (Exception e) {
            Msg.error(this, "Decompilation failed for " + function.getName() + ": " + e.getMessage());
        }

        return null;
    }

    // ========================================
    // Private extraction methods
    // ========================================

    private void extractFunctions() {
        FunctionManager funcManager = program.getFunctionManager();
        FunctionIterator functions = funcManager.getFunctions(true);

        int total = funcManager.getFunctionCount();
        int processed = 0;

        while (functions.hasNext() && !monitor.isCancelled()) {
            Function func = functions.next();
            processed++;

            if (processed % 100 == 0) {
                monitor.setProgress(processed);
                monitor.setMessage(String.format("Extracting functions... %d/%d", processed, total));
            }

            // Skip thunks and external functions
            if (func.isThunk() || func.isExternal()) {
                continue;
            }

            KnowledgeNode node = createFunctionNode(func);
            if (node != null) {
                graph.upsertNode(node);
                functionsExtracted++;
            }
        }
    }

    private KnowledgeNode createFunctionNode(Function function) {
        try {
            long address = function.getEntryPoint().getOffset();
            String name = function.getName();

            // Check if node already exists
            KnowledgeNode node = graph.getNodeByAddress(address);
            if (node == null) {
                node = KnowledgeNode.createFunction(binaryId, address, name);
            } else {
                node.setName(name); // Update name in case of rename
            }

            // Decompile and store raw content
            DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
            if (results != null && results.decompileCompleted()) {
                String code = results.getDecompiledFunction().getC();
                node.setRawContent(code);
            } else {
                // Fall back to disassembly
                node.setRawContent(getDisassembly(function));
            }

            // Extract security features (network APIs, file I/O, strings)
            extractSecurityFeatures(function, node);

            // Mark as needing LLM summary
            node.markStale();

            return node;
        } catch (Exception e) {
            Msg.warn(this, "Failed to create node for " + function.getName() + ": " + e.getMessage());
            return null;
        }
    }

    /**
     * Extract security-relevant features from a function and apply to node.
     * Also generates and sets security flags for vulnerability tracking.
     */
    private void extractSecurityFeatures(Function function, KnowledgeNode node) {
        try {
            SecurityFeatureExtractor secExtractor = new SecurityFeatureExtractor(program, monitor);
            SecurityFeatures features = secExtractor.extractFeatures(function);

            if (!features.isEmpty()) {
                // Apply the raw security features to the node
                node.applySecurityFeatures(features);

                // Generate and set security flags for the graph_nodes.security_flags field
                java.util.List<String> securityFlags = features.generateSecurityFlags();
                if (!securityFlags.isEmpty()) {
                    node.setSecurityFlags(securityFlags);
                    Msg.debug(this, String.format("Security flags for %s: %s",
                            function.getName(), securityFlags));
                }

                Msg.debug(this, String.format("Extracted security features for %s: %s",
                        function.getName(), features.toString()));
            }
        } catch (Exception e) {
            Msg.debug(this, "Failed to extract security features for " + function.getName() + ": " + e.getMessage());
        }
    }

    private void extractCallGraph() {
        FunctionManager funcManager = program.getFunctionManager();
        FunctionIterator functions = funcManager.getFunctions(true);

        while (functions.hasNext() && !monitor.isCancelled()) {
            Function caller = functions.next();
            if (caller.isThunk() || caller.isExternal()) {
                continue;
            }

            KnowledgeNode callerNode = graph.getNodeByAddress(caller.getEntryPoint().getOffset());
            if (callerNode == null) {
                continue;
            }

            extractFunctionCalls(caller, callerNode.getId());
        }
    }

    private void extractFunctionCalls(Function caller, String callerNodeId) {
        Set<Function> calledFunctions = caller.getCalledFunctions(monitor);

        for (Function callee : calledFunctions) {
            if (monitor.isCancelled()) {
                break;
            }

            // Skip thunks - follow to real function
            Function realCallee = callee;
            while (realCallee.isThunk()) {
                Function thunked = realCallee.getThunkedFunction(true);
                if (thunked == null) break;
                realCallee = thunked;
            }

            if (realCallee.isExternal()) {
                // Create a node for external function if not exists
                KnowledgeNode extNode = graph.getNodeByName(realCallee.getName());
                if (extNode == null) {
                    extNode = KnowledgeNode.createFunction(binaryId, 0, realCallee.getName());
                    extNode.setRawContent("// External function: " + realCallee.getName());
                    graph.upsertNode(extNode);
                }
                graph.addEdge(callerNodeId, extNode.getId(), EdgeType.CALLS);
            } else {
                KnowledgeNode calleeNode = graph.getNodeByAddress(realCallee.getEntryPoint().getOffset());
                if (calleeNode != null) {
                    graph.addEdge(callerNodeId, calleeNode.getId(), EdgeType.CALLS);
                    callEdgesCreated++;
                }
            }
        }
    }

    private void extractBasicBlocks() {
        try {
            BasicBlockModel blockModel = new BasicBlockModel(program);
            FunctionManager funcManager = program.getFunctionManager();
            FunctionIterator functions = funcManager.getFunctions(true);

            while (functions.hasNext() && !monitor.isCancelled()) {
                Function func = functions.next();
                if (func.isThunk() || func.isExternal()) {
                    continue;
                }

                KnowledgeNode funcNode = graph.getNodeByAddress(func.getEntryPoint().getOffset());
                if (funcNode == null) {
                    continue;
                }

                // Get blocks within function
                CodeBlockIterator blocks = blockModel.getCodeBlocksContaining(func.getBody(), monitor);
                Map<Address, KnowledgeNode> blockNodes = new HashMap<>();

                while (blocks.hasNext()) {
                    CodeBlock block = blocks.next();
                    Address blockAddr = block.getFirstStartAddress();

                    // Create block node
                    KnowledgeNode blockNode = KnowledgeNode.createBlock(binaryId, blockAddr.getOffset());
                    blockNode.setRawContent(getBlockDisassembly(block));
                    blockNode.markStale();
                    graph.upsertNode(blockNode);
                    blockNodes.put(blockAddr, blockNode);

                    // Function CONTAINS block
                    graph.addEdge(funcNode.getId(), blockNode.getId(), EdgeType.CONTAINS);
                }

                // Extract control flow edges between blocks
                for (Map.Entry<Address, KnowledgeNode> entry : blockNodes.entrySet()) {
                    CodeBlock block = blockModel.getCodeBlockAt(entry.getKey(), monitor);
                    if (block == null) continue;

                    CodeBlockReferenceIterator dests = block.getDestinations(monitor);
                    while (dests.hasNext()) {
                        CodeBlockReference ref = dests.next();
                        Address destAddr = ref.getDestinationAddress();
                        KnowledgeNode destNode = blockNodes.get(destAddr);
                        if (destNode != null) {
                            graph.addEdge(entry.getValue().getId(), destNode.getId(), EdgeType.FLOWS_TO);
                        }
                    }
                }
            }
        } catch (Exception e) {
            Msg.error(this, "Failed to extract basic blocks: " + e.getMessage(), e);
        }
    }

    /**
     * Extract cross-references from functions to data and other code.
     * Creates REFERENCES edges for non-call references.
     */
    private void extractReferences() {
        try {
            ReferenceManager refMgr = program.getReferenceManager();
            FunctionManager funcMgr = program.getFunctionManager();
            FunctionIterator functions = funcMgr.getFunctions(true);

            int total = funcMgr.getFunctionCount();
            int processed = 0;

            while (functions.hasNext() && !monitor.isCancelled()) {
                Function func = functions.next();
                processed++;

                if (processed % 100 == 0) {
                    monitor.setProgress(processed);
                    monitor.setMessage(String.format("Extracting references... %d/%d", processed, total));
                }

                if (func.isThunk() || func.isExternal()) {
                    continue;
                }

                KnowledgeNode funcNode = graph.getNodeByAddress(func.getEntryPoint().getOffset());
                if (funcNode == null) {
                    continue;
                }

                // Get all references FROM this function's body
                AddressSetView body = func.getBody();
                Set<Long> referencedAddresses = new HashSet<>();

                for (Address addr : body.getAddresses(true)) {
                    if (monitor.isCancelled()) break;

                    Reference[] refs = refMgr.getReferencesFrom(addr);
                    for (Reference ref : refs) {
                        // Skip call references - already handled by CALLS edges
                        if (ref.getReferenceType().isCall()) {
                            continue;
                        }

                        Address toAddr = ref.getToAddress();
                        long toOffset = toAddr.getOffset();

                        // Avoid duplicate edges to same target
                        if (referencedAddresses.contains(toOffset)) {
                            continue;
                        }

                        if (ref.getReferenceType().isData()) {
                            // Code references data - check if it's in a data section
                            MemoryBlock block = program.getMemory().getBlock(toAddr);
                            if (block != null && !block.isExecute()) {
                                // This is a data reference - for now we just track it
                                // We could create DATA nodes if needed in the future
                                referencedAddresses.add(toOffset);
                                refEdgesCreated++; // Count it even without creating edge
                            }
                        } else {
                            // Other code references (jumps to other functions, etc.)
                            Function targetFunc = funcMgr.getFunctionContaining(toAddr);
                            if (targetFunc != null && !targetFunc.equals(func)) {
                                KnowledgeNode targetNode = graph.getNodeByAddress(
                                        targetFunc.getEntryPoint().getOffset());
                                if (targetNode != null) {
                                    graph.addEdge(funcNode.getId(), targetNode.getId(), EdgeType.REFERENCES);
                                    referencedAddresses.add(toOffset);
                                    refEdgesCreated++;
                                }
                            }
                        }
                    }
                }
            }

            Msg.info(this, String.format("Extracted %d reference edges", refEdgesCreated));
        } catch (Exception e) {
            Msg.error(this, "Failed to extract references: " + e.getMessage(), e);
        }
    }

    /**
     * Extract data dependency edges between functions that share global data.
     * Creates DATA_DEPENDS edges where reader depends on writer.
     */
    private void extractDataDependencies() {
        try {
            ReferenceManager refMgr = program.getReferenceManager();
            FunctionManager funcMgr = program.getFunctionManager();

            // Map: global address -> list of functions that READ from it
            Map<Long, List<KnowledgeNode>> dataReaders = new HashMap<>();
            // Map: global address -> list of functions that WRITE to it
            Map<Long, List<KnowledgeNode>> dataWriters = new HashMap<>();

            // First pass: collect all data reads and writes
            FunctionIterator functions = funcMgr.getFunctions(true);
            int total = funcMgr.getFunctionCount();
            int processed = 0;

            while (functions.hasNext() && !monitor.isCancelled()) {
                Function func = functions.next();
                processed++;

                if (processed % 100 == 0) {
                    monitor.setProgress(processed);
                    monitor.setMessage(String.format("Analyzing data dependencies... %d/%d (pass 1)", processed, total));
                }

                if (func.isThunk() || func.isExternal()) {
                    continue;
                }

                KnowledgeNode funcNode = graph.getNodeByAddress(func.getEntryPoint().getOffset());
                if (funcNode == null) {
                    continue;
                }

                AddressSetView body = func.getBody();
                for (Address addr : body.getAddresses(true)) {
                    if (monitor.isCancelled()) break;

                    Reference[] refs = refMgr.getReferencesFrom(addr);
                    for (Reference ref : refs) {
                        if (!ref.getReferenceType().isData()) {
                            continue;
                        }

                        Address toAddr = ref.getToAddress();
                        MemoryBlock block = program.getMemory().getBlock(toAddr);

                        // Only consider references to data sections (not code)
                        if (block == null || block.isExecute()) {
                            continue;
                        }

                        long dataAddr = toAddr.getOffset();

                        // Determine if this is a read or write based on reference type
                        if (ref.getReferenceType().isWrite()) {
                            dataWriters.computeIfAbsent(dataAddr, k -> new ArrayList<>()).add(funcNode);
                        } else if (ref.getReferenceType().isRead()) {
                            dataReaders.computeIfAbsent(dataAddr, k -> new ArrayList<>()).add(funcNode);
                        } else {
                            // Unknown access type - assume read
                            dataReaders.computeIfAbsent(dataAddr, k -> new ArrayList<>()).add(funcNode);
                        }
                    }
                }
            }

            // Second pass: create DATA_DEPENDS edges (reader depends on writer)
            monitor.setMessage("Creating data dependency edges...");
            Set<String> createdEdges = new HashSet<>(); // Avoid duplicates

            for (Map.Entry<Long, List<KnowledgeNode>> entry : dataReaders.entrySet()) {
                if (monitor.isCancelled()) break;

                Long dataAddr = entry.getKey();
                List<KnowledgeNode> readers = entry.getValue();
                List<KnowledgeNode> writers = dataWriters.getOrDefault(dataAddr, List.of());

                for (KnowledgeNode reader : readers) {
                    for (KnowledgeNode writer : writers) {
                        if (!reader.getId().equals(writer.getId())) {
                            String edgeKey = reader.getId() + "->" + writer.getId();
                            if (!createdEdges.contains(edgeKey)) {
                                graph.addEdge(reader.getId(), writer.getId(), EdgeType.DATA_DEPENDS);
                                createdEdges.add(edgeKey);
                                dataDepEdgesCreated++;
                            }
                        }
                    }
                }
            }

            Msg.info(this, String.format("Extracted %d data dependency edges", dataDepEdgesCreated));
        } catch (Exception e) {
            Msg.error(this, "Failed to extract data dependencies: " + e.getMessage(), e);
        }
    }

    /**
     * Extract CALLS_VULNERABLE edges from callers to functions with vulnerability risks.
     * Also propagates the CALLS_VULNERABLE_FUNCTION flag to callers.
     */
    private void extractVulnerableCalls() {
        try {
            List<KnowledgeNode> functionNodes = graph.getNodesByType(NodeType.FUNCTION);
            Set<String> processedCallers = new HashSet<>();

            monitor.setMessage("Extracting vulnerable call edges...");
            int total = functionNodes.size();
            int processed = 0;

            for (KnowledgeNode node : functionNodes) {
                if (monitor.isCancelled()) break;

                processed++;
                if (processed % 100 == 0) {
                    monitor.setProgress(processed);
                    monitor.setMessage(String.format("Extracting vulnerable calls... %d/%d", processed, total));
                }

                List<String> flags = node.getSecurityFlags();
                if (flags == null || flags.isEmpty()) {
                    continue;
                }

                // Check if this function has any vulnerability risk flags
                boolean hasVulnRisk = flags.stream().anyMatch(f -> f.endsWith("_RISK"));
                if (!hasVulnRisk) {
                    continue;
                }

                // This function has vulnerability risks - mark all callers
                List<KnowledgeNode> callers = graph.getCallers(node.getId());
                for (KnowledgeNode caller : callers) {
                    // Add CALLS_VULNERABLE edge
                    graph.addEdge(caller.getId(), node.getId(), EdgeType.CALLS_VULNERABLE);
                    vulnEdgesCreated++;

                    // Add flag to caller if not already processed
                    if (!processedCallers.contains(caller.getId())) {
                        List<String> callerFlags = caller.getSecurityFlags();
                        if (callerFlags == null) {
                            callerFlags = new ArrayList<>();
                        }
                        if (!callerFlags.contains("CALLS_VULNERABLE_FUNCTION")) {
                            callerFlags = new ArrayList<>(callerFlags); // Make mutable copy
                            callerFlags.add("CALLS_VULNERABLE_FUNCTION");
                            caller.setSecurityFlags(callerFlags);
                            graph.upsertNode(caller);
                        }
                        processedCallers.add(caller.getId());
                    }
                }
            }

            Msg.info(this, String.format("Extracted %d vulnerable call edges", vulnEdgesCreated));
        } catch (Exception e) {
            Msg.error(this, "Failed to extract vulnerable calls: " + e.getMessage(), e);
        }
    }

    // ========================================
    // Single-function edge extraction methods
    // (for on-demand/incremental indexing)
    // ========================================

    /**
     * Extract REFERENCES edges for a single function.
     * Called during on-demand function indexing.
     *
     * @param function The function to extract references from
     * @param funcNode The function's knowledge node
     */
    private void extractFunctionReferences(Function function, KnowledgeNode funcNode) {
        try {
            ReferenceManager refMgr = program.getReferenceManager();
            FunctionManager funcMgr = program.getFunctionManager();
            AddressSetView body = function.getBody();
            Set<Long> referencedAddresses = new HashSet<>();

            for (Address addr : body.getAddresses(true)) {
                if (monitor.isCancelled()) break;

                Reference[] refs = refMgr.getReferencesFrom(addr);
                for (Reference ref : refs) {
                    // Skip call references - already handled by CALLS edges
                    if (ref.getReferenceType().isCall()) {
                        continue;
                    }

                    Address toAddr = ref.getToAddress();
                    long toOffset = toAddr.getOffset();

                    // Avoid duplicate edges to same target
                    if (referencedAddresses.contains(toOffset)) {
                        continue;
                    }

                    if (!ref.getReferenceType().isData()) {
                        // Code references (jumps to other functions, etc.)
                        Function targetFunc = funcMgr.getFunctionContaining(toAddr);
                        if (targetFunc != null && !targetFunc.equals(function)) {
                            KnowledgeNode targetNode = graph.getNodeByAddress(
                                    targetFunc.getEntryPoint().getOffset());
                            if (targetNode != null) {
                                graph.addEdge(funcNode.getId(), targetNode.getId(), EdgeType.REFERENCES);
                                referencedAddresses.add(toOffset);
                                refEdgesCreated++;
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            Msg.debug(this, "Failed to extract references for " + function.getName() + ": " + e.getMessage());
        }
    }

    /**
     * Extract DATA_DEPENDS edges for a single function.
     * Creates edges from this function to functions that write data this function reads.
     *
     * @param function The function to extract data dependencies for
     * @param funcNode The function's knowledge node
     */
    private void extractFunctionDataDependencies(Function function, KnowledgeNode funcNode) {
        try {
            ReferenceManager refMgr = program.getReferenceManager();
            FunctionManager funcMgr = program.getFunctionManager();
            AddressSetView body = function.getBody();
            Set<String> createdEdges = new HashSet<>();

            // Find data addresses this function reads from
            Set<Long> readAddresses = new HashSet<>();
            for (Address addr : body.getAddresses(true)) {
                if (monitor.isCancelled()) break;

                Reference[] refs = refMgr.getReferencesFrom(addr);
                for (Reference ref : refs) {
                    if (!ref.getReferenceType().isData()) {
                        continue;
                    }

                    Address toAddr = ref.getToAddress();
                    MemoryBlock block = program.getMemory().getBlock(toAddr);

                    // Only consider references to data sections (not code)
                    if (block == null || block.isExecute()) {
                        continue;
                    }

                    // If this is a read, track the address
                    if (ref.getReferenceType().isRead() || !ref.getReferenceType().isWrite()) {
                        readAddresses.add(toAddr.getOffset());
                    }
                }
            }

            // For each read address, find functions that write to it
            for (Long dataAddr : readAddresses) {
                if (monitor.isCancelled()) break;

                Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(dataAddr);
                ReferenceIterator refsTo = refMgr.getReferencesTo(addr);

                while (refsTo.hasNext()) {
                    Reference ref = refsTo.next();
                    if (!ref.getReferenceType().isWrite()) {
                        continue;
                    }

                    // Find the function containing this write
                    Function writerFunc = funcMgr.getFunctionContaining(ref.getFromAddress());
                    if (writerFunc != null && !writerFunc.equals(function)) {
                        KnowledgeNode writerNode = graph.getNodeByAddress(
                                writerFunc.getEntryPoint().getOffset());
                        if (writerNode != null) {
                            String edgeKey = funcNode.getId() + "->" + writerNode.getId();
                            if (!createdEdges.contains(edgeKey)) {
                                graph.addEdge(funcNode.getId(), writerNode.getId(), EdgeType.DATA_DEPENDS);
                                createdEdges.add(edgeKey);
                                dataDepEdgesCreated++;
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            Msg.debug(this, "Failed to extract data dependencies for " + function.getName() + ": " + e.getMessage());
        }
    }

    /**
     * Extract CALLS_VULNERABLE edges for a single function.
     * If this function has vulnerability risks, marks its callers.
     * Also checks if this function calls vulnerable functions.
     *
     * @param function The function to analyze
     * @param funcNode The function's knowledge node
     */
    private void extractFunctionVulnerableCalls(Function function, KnowledgeNode funcNode) {
        try {
            List<String> flags = funcNode.getSecurityFlags();

            // Check if THIS function has vulnerability risks
            boolean hasVulnRisk = flags != null && flags.stream().anyMatch(f -> f.endsWith("_RISK"));

            if (hasVulnRisk) {
                // Mark all callers with CALLS_VULNERABLE edge
                List<KnowledgeNode> callers = graph.getCallers(funcNode.getId());
                for (KnowledgeNode caller : callers) {
                    graph.addEdge(caller.getId(), funcNode.getId(), EdgeType.CALLS_VULNERABLE);
                    vulnEdgesCreated++;

                    // Add flag to caller
                    List<String> callerFlags = caller.getSecurityFlags();
                    if (callerFlags == null) {
                        callerFlags = new ArrayList<>();
                    }
                    if (!callerFlags.contains("CALLS_VULNERABLE_FUNCTION")) {
                        callerFlags = new ArrayList<>(callerFlags);
                        callerFlags.add("CALLS_VULNERABLE_FUNCTION");
                        caller.setSecurityFlags(callerFlags);
                        graph.upsertNode(caller);
                    }
                }
            }

            // Also check if this function CALLS any vulnerable functions
            List<KnowledgeNode> callees = graph.getCallees(funcNode.getId());
            for (KnowledgeNode callee : callees) {
                List<String> calleeFlags = callee.getSecurityFlags();
                boolean calleeVuln = calleeFlags != null && calleeFlags.stream().anyMatch(f -> f.endsWith("_RISK"));

                if (calleeVuln) {
                    // This function calls a vulnerable function
                    graph.addEdge(funcNode.getId(), callee.getId(), EdgeType.CALLS_VULNERABLE);
                    vulnEdgesCreated++;

                    // Add flag to this function
                    if (flags == null) {
                        flags = new ArrayList<>();
                    }
                    if (!flags.contains("CALLS_VULNERABLE_FUNCTION")) {
                        flags = new ArrayList<>(flags);
                        flags.add("CALLS_VULNERABLE_FUNCTION");
                        funcNode.setSecurityFlags(flags);
                        graph.upsertNode(funcNode);
                    }
                }
            }
        } catch (Exception e) {
            Msg.debug(this, "Failed to extract vulnerable calls for " + function.getName() + ": " + e.getMessage());
        }
    }

    private void createBinaryNode() {
        String programName = program.getName();

        KnowledgeNode binaryNode = KnowledgeNode.createBinary(binaryId, programName);

        // Build binary description
        StringBuilder desc = new StringBuilder();
        desc.append("Binary: ").append(programName).append("\n");
        desc.append("Format: ").append(program.getExecutableFormat()).append("\n");
        desc.append("Language: ").append(program.getLanguage().getLanguageID()).append("\n");
        desc.append("Compiler: ").append(program.getCompiler()).append("\n");
        desc.append("Functions: ").append(program.getFunctionManager().getFunctionCount()).append("\n");

        // Add entry points
        desc.append("\nEntry Points:\n");
        for (Address entry : program.getSymbolTable().getExternalEntryPointIterator()) {
            Function func = program.getFunctionManager().getFunctionAt(entry);
            if (func != null) {
                desc.append("  - ").append(func.getName()).append(" @ ").append(entry).append("\n");
            }
        }

        binaryNode.setRawContent(desc.toString());
        binaryNode.markStale(); // Needs LLM summary
        graph.upsertNode(binaryNode);

        // Create CONTAINS edges from binary to all functions
        for (KnowledgeNode funcNode : graph.getNodesByType(NodeType.FUNCTION)) {
            graph.addEdge(binaryNode.getId(), funcNode.getId(), EdgeType.CONTAINS);
        }
    }

    // ========================================
    // Helper methods
    // ========================================

    private String getDisassembly(Function function) {
        StringBuilder sb = new StringBuilder();
        InstructionIterator instructions = program.getListing().getInstructions(function.getBody(), true);

        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            sb.append(String.format("%s  %s\n",
                    instr.getAddressString(true, true),
                    instr.toString()));
        }

        return sb.toString();
    }

    private String getBlockDisassembly(CodeBlock block) {
        StringBuilder sb = new StringBuilder();
        InstructionIterator instructions = program.getListing().getInstructions(block, true);

        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            sb.append(String.format("%s  %s\n",
                    instr.getAddressString(true, true),
                    instr.toString()));
        }

        return sb.toString();
    }

    /**
     * Cleanup resources.
     */
    public void dispose() {
        if (decompiler != null) {
            decompiler.dispose();
            decompiler = null;
        }
    }

    // ========================================
    // Result class
    // ========================================

    /**
     * Results from structure extraction.
     */
    public static class ExtractionResult {
        public final int functionsExtracted;
        public final int callEdgesCreated;
        public final int refEdgesCreated;
        public final int dataDepEdgesCreated;
        public final int vulnEdgesCreated;
        public final long elapsedMs;

        public ExtractionResult(int functions, int calls, int refs, int dataDeps, int vulns, long elapsed) {
            this.functionsExtracted = functions;
            this.callEdgesCreated = calls;
            this.refEdgesCreated = refs;
            this.dataDepEdgesCreated = dataDeps;
            this.vulnEdgesCreated = vulns;
            this.elapsedMs = elapsed;
        }

        @Override
        public String toString() {
            return String.format("Extracted %d functions, %d call edges, %d ref edges, %d data-dep edges, %d vuln edges in %dms",
                    functionsExtracted, callEdgesCreated, refEdgesCreated, dataDepEdgesCreated, vulnEdgesCreated, elapsedMs);
        }
    }
}
