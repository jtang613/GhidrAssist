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

            // Phase 4: Create binary-level node
            monitor.setMessage("Creating binary summary node...");
            createBinaryNode();

        } finally {
            if (decompiler != null) {
                decompiler.dispose();
                decompiler = null;
            }
        }

        long elapsed = System.currentTimeMillis() - startTime;
        Msg.info(this, String.format("Structure extraction completed in %dms: %d functions, %d call edges, %d ref edges",
                elapsed, functionsExtracted, callEdgesCreated, refEdgesCreated));

        return new ExtractionResult(functionsExtracted, callEdgesCreated, refEdgesCreated, elapsed);
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
                return existing; // Already extracted
            }

            // Create or update node
            KnowledgeNode node = createFunctionNode(function);
            if (node != null) {
                graph.upsertNode(node);

                // Extract calls from this function
                extractFunctionCalls(function, node.getId());

                functionsExtracted++;
            }

            return node;
        } catch (Exception e) {
            Msg.error(this, "Failed to extract function " + function.getName() + ": " + e.getMessage());
            return null;
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
        public final long elapsedMs;

        public ExtractionResult(int functions, int calls, int refs, long elapsed) {
            this.functionsExtracted = functions;
            this.callEdgesCreated = calls;
            this.refEdgesCreated = refs;
            this.elapsedMs = elapsed;
        }

        @Override
        public String toString() {
            return String.format("Extracted %d functions, %d call edges, %d ref edges in %dms",
                    functionsExtracted, callEdgesCreated, refEdgesCreated, elapsedMs);
        }
    }
}
