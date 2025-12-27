package ghidrassist.graphrag.extraction;

import ghidra.util.Msg;

import ghidrassist.apiprovider.APIProvider;
import ghidrassist.apiprovider.ChatMessage;
import ghidrassist.apiprovider.exceptions.APIProviderException;
import ghidrassist.graphrag.BinaryKnowledgeGraph;
import ghidrassist.graphrag.nodes.KnowledgeNode;
import ghidrassist.graphrag.nodes.NodeType;

import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

/**
 * LLM-powered semantic extraction for the knowledge graph.
 *
 * Handles:
 * - Function summarization with security focus
 * - Batch processing with rate limiting
 * - Embedding generation (when available)
 * - Module/community summarization
 *
 * Uses a tiered approach:
 * 1. If embeddings are available, generate them
 * 2. Generate LLM summaries in batches
 * 3. Track progress and allow cancellation
 */
public class SemanticExtractor {

    private final APIProvider provider;
    private final BinaryKnowledgeGraph graph;
    private final String binaryId;

    // Rate limiting
    private static final int DEFAULT_BATCH_SIZE = 5;
    private static final long DEFAULT_DELAY_MS = 500;
    private int batchSize;
    private long delayBetweenBatches;

    // Statistics
    private int summarized = 0;
    private int embeddingsGenerated = 0;
    private int errors = 0;

    // Cancellation
    private volatile boolean cancelled = false;

    /**
     * Create a SemanticExtractor.
     *
     * @param provider LLM provider for summarization
     * @param graph    Knowledge graph to update
     */
    public SemanticExtractor(APIProvider provider, BinaryKnowledgeGraph graph) {
        this.provider = provider;
        this.graph = graph;
        this.binaryId = graph.getBinaryId();
        this.batchSize = DEFAULT_BATCH_SIZE;
        this.delayBetweenBatches = DEFAULT_DELAY_MS;
    }

    /**
     * Configure batch processing parameters.
     */
    public void setBatchConfig(int batchSize, long delayMs) {
        this.batchSize = Math.max(1, batchSize);
        this.delayBetweenBatches = Math.max(0, delayMs);
    }

    /**
     * Process all stale nodes that need summarization.
     *
     * @param limit Maximum number of nodes to process (0 = unlimited)
     * @param progressCallback Optional callback for progress updates
     * @return ExtractionResult with statistics
     */
    public ExtractionResult summarizeStaleNodes(int limit, ProgressCallback progressCallback) {
        long startTime = System.currentTimeMillis();
        cancelled = false;
        summarized = 0;
        embeddingsGenerated = 0;
        errors = 0;

        // Get stale nodes
        List<KnowledgeNode> staleNodes = graph.getStaleNodes(limit > 0 ? limit : Integer.MAX_VALUE);
        int total = staleNodes.size();

        if (total == 0) {
            Msg.info(this, "No stale nodes to summarize");
            return new ExtractionResult(0, 0, 0, 0);
        }

        Msg.info(this, "Starting summarization of " + total + " stale nodes");

        // Process in batches
        for (int i = 0; i < staleNodes.size() && !cancelled; i += batchSize) {
            int end = Math.min(i + batchSize, staleNodes.size());
            List<KnowledgeNode> batch = staleNodes.subList(i, end);

            processBatch(batch);

            // Update progress
            if (progressCallback != null) {
                int processed = Math.min(i + batchSize, total);
                progressCallback.onProgress(processed, total, summarized, errors);
            }

            // Rate limiting delay
            if (end < staleNodes.size() && delayBetweenBatches > 0) {
                try {
                    Thread.sleep(delayBetweenBatches);
                } catch (InterruptedException e) {
                    cancelled = true;
                    Thread.currentThread().interrupt();
                }
            }
        }

        long elapsed = System.currentTimeMillis() - startTime;
        Msg.info(this, String.format("Semantic extraction completed in %dms: %d summarized, %d embeddings, %d errors",
                elapsed, summarized, embeddingsGenerated, errors));

        return new ExtractionResult(summarized, embeddingsGenerated, errors, elapsed);
    }

    /**
     * Summarize a single node on-demand.
     */
    public boolean summarizeNode(KnowledgeNode node) {
        if (node == null || node.getRawContent() == null || node.getRawContent().isEmpty()) {
            return false;
        }

        try {
            // Generate summary
            String summary = generateSummary(node);
            if (summary != null && !summary.isEmpty()) {
                node.setLlmSummary(summary);
                node.setConfidence(0.8f); // Default confidence
                node.markUpdated();

                // Try to generate embedding
                tryGenerateEmbedding(node);

                graph.upsertNode(node);
                return true;
            }
        } catch (Exception e) {
            Msg.error(this, "Failed to summarize node " + node.getId() + ": " + e.getMessage());
        }
        return false;
    }

    /**
     * Cancel ongoing extraction.
     */
    public void cancel() {
        cancelled = true;
    }

    // ========================================
    // Batch Processing
    // ========================================

    private void processBatch(List<KnowledgeNode> batch) {
        // Separate by type for appropriate prompts
        List<KnowledgeNode> functions = batch.stream()
                .filter(n -> n.getType() == NodeType.FUNCTION)
                .collect(Collectors.toList());

        List<KnowledgeNode> others = batch.stream()
                .filter(n -> n.getType() != NodeType.FUNCTION)
                .collect(Collectors.toList());

        // Process functions (most common case)
        if (!functions.isEmpty()) {
            processFunctionBatch(functions);
        }

        // Process other node types individually
        for (KnowledgeNode node : others) {
            if (cancelled) break;
            processOtherNode(node);
        }
    }

    private void processFunctionBatch(List<KnowledgeNode> functions) {
        // Try batch processing first (more efficient)
        if (functions.size() > 1) {
            try {
                String batchPrompt = ExtractionPrompts.batchFunctionSummaryPrompt(functions);
                String response = callLLM(batchPrompt);

                if (response != null) {
                    parseBatchResponse(response, functions);
                    return;
                }
            } catch (Exception e) {
                Msg.warn(this, "Batch processing failed, falling back to individual: " + e.getMessage());
            }
        }

        // Fall back to individual processing
        for (KnowledgeNode func : functions) {
            if (cancelled) break;
            processSingleFunction(func);
        }
    }

    private void processSingleFunction(KnowledgeNode node) {
        try {
            // Get context (callers/callees)
            List<String> callers = graph.getCallers(node.getId()).stream()
                    .map(n -> n.getName() != null ? n.getName() : "unknown")
                    .limit(5)
                    .collect(Collectors.toList());

            List<String> callees = graph.getCallees(node.getId()).stream()
                    .map(n -> n.getName() != null ? n.getName() : "unknown")
                    .limit(5)
                    .collect(Collectors.toList());

            // Generate prompt
            String prompt = ExtractionPrompts.functionSummaryPrompt(
                    node.getName() != null ? node.getName() : "unknown",
                    node.getRawContent(),
                    callers,
                    callees
            );

            String response = callLLM(prompt);
            if (response != null) {
                node.setLlmSummary(response);
                node.setConfidence(0.85f);

                // Extract security flags if present
                String securityNotes = ExtractionPrompts.extractSecurityNotes(response);
                if (securityNotes != null && !securityNotes.toLowerCase().contains("none")) {
                    node.addSecurityFlag("LLM_FLAGGED");
                }

                node.markUpdated();
                tryGenerateEmbedding(node);
                graph.upsertNode(node);
                summarized++;
            }
        } catch (Exception e) {
            Msg.warn(this, "Failed to summarize function " + node.getName() + ": " + e.getMessage());
            errors++;
        }
    }

    private void processOtherNode(KnowledgeNode node) {
        try {
            String summary = generateSummary(node);
            if (summary != null) {
                node.setLlmSummary(summary);
                node.setConfidence(0.7f);
                node.markUpdated();
                tryGenerateEmbedding(node);
                graph.upsertNode(node);
                summarized++;
            }
        } catch (Exception e) {
            Msg.warn(this, "Failed to summarize node " + node.getId() + ": " + e.getMessage());
            errors++;
        }
    }

    private void parseBatchResponse(String response, List<KnowledgeNode> functions) {
        // Parse numbered list response
        String[] lines = response.split("\n");
        int index = 0;

        for (String line : lines) {
            line = line.trim();
            if (line.isEmpty()) continue;

            // Match numbered lines like "1. Summary text" or "1) Summary text"
            if (line.matches("^\\d+[.)].*")) {
                // Extract summary after number
                int pos = line.indexOf(' ');
                if (pos > 0 && index < functions.size()) {
                    String summary = line.substring(pos).trim();
                    if (!summary.isEmpty()) {
                        KnowledgeNode node = functions.get(index);
                        node.setLlmSummary(summary);
                        node.setConfidence(0.75f);
                        node.markUpdated();
                        graph.upsertNode(node);
                        summarized++;
                    }
                    index++;
                }
            }
        }

        // Log if we didn't match all functions
        if (index < functions.size()) {
            Msg.warn(this, "Batch response only matched " + index + " of " + functions.size() + " functions");
        }
    }

    // ========================================
    // LLM and Embedding Helpers
    // ========================================

    private String generateSummary(KnowledgeNode node) {
        if (node.getRawContent() == null || node.getRawContent().isEmpty()) {
            return null;
        }

        String prompt;
        switch (node.getType()) {
            case FUNCTION:
                prompt = ExtractionPrompts.functionBriefSummaryPrompt(
                        node.getName() != null ? node.getName() : "unknown",
                        node.getRawContent()
                );
                break;
            case BINARY:
                prompt = "Summarize this binary in 2-3 sentences:\n\n" + node.getRawContent();
                break;
            case MODULE:
                prompt = "Summarize this module/component in 1-2 sentences:\n\n" + node.getRawContent();
                break;
            default:
                prompt = "Briefly describe this code:\n\n" + truncate(node.getRawContent(), 1000);
        }

        return callLLM(prompt);
    }

    private String callLLM(String prompt) {
        if (provider == null) {
            Msg.warn(this, "No LLM provider available for summarization");
            return null;
        }

        try {
            List<ChatMessage> messages = new ArrayList<>();
            messages.add(new ChatMessage("system",
                    "You are a binary analysis assistant. Provide concise, technical summaries focused on functionality and security."));
            messages.add(new ChatMessage("user", prompt));

            return provider.createChatCompletion(messages);
        } catch (APIProviderException e) {
            Msg.warn(this, "LLM call failed: " + e.getMessage());
            return null;
        }
    }

    private void tryGenerateEmbedding(KnowledgeNode node) {
        if (provider == null || node.getLlmSummary() == null) {
            return;
        }

        try {
            double[] embedding = provider.getEmbeddings(node.getLlmSummary());
            if (embedding != null && embedding.length > 0) {
                // Convert double[] to float[]
                float[] floatEmbedding = new float[embedding.length];
                for (int i = 0; i < embedding.length; i++) {
                    floatEmbedding[i] = (float) embedding[i];
                }
                node.setEmbedding(floatEmbedding);
                embeddingsGenerated++;
            }
        } catch (Exception e) {
            // Embeddings are optional - don't log as error
            Msg.debug(this, "Embedding generation not available: " + e.getMessage());
        }
    }

    private String truncate(String text, int maxLength) {
        if (text == null || text.length() <= maxLength) {
            return text;
        }
        return text.substring(0, maxLength) + "...";
    }

    // ========================================
    // Result and Callback Types
    // ========================================

    /**
     * Results from semantic extraction.
     */
    public static class ExtractionResult {
        public final int summarized;
        public final int embeddingsGenerated;
        public final int errors;
        public final long elapsedMs;

        public ExtractionResult(int summarized, int embeddings, int errors, long elapsed) {
            this.summarized = summarized;
            this.embeddingsGenerated = embeddings;
            this.errors = errors;
            this.elapsedMs = elapsed;
        }

        @Override
        public String toString() {
            return String.format("Summarized %d nodes, %d embeddings, %d errors in %dms",
                    summarized, embeddingsGenerated, errors, elapsedMs);
        }
    }

    /**
     * Callback for progress updates.
     */
    public interface ProgressCallback {
        void onProgress(int processed, int total, int summarized, int errors);
    }
}
