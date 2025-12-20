package ghidrassist.agent.react;

import ghidrassist.AnalysisDB;
import ghidrassist.apiprovider.ChatMessage;
import ghidra.util.Msg;

import java.util.ArrayList;
import java.util.List;

/**
 * Manages unified conversation history for ReAct agent with chunked iteration storage.
 *
 * Maintains single conversation list throughout all ReAct phases (planning, investigation,
 * reflection, synthesis) with per-iteration chunk boundaries for efficient storage and
 * retrieval.
 *
 * Design:
 * - All messages stored in single list with metadata (phase, iteration)
 * - Iteration boundaries marked with summaries for context compression
 * - Database integration for persistence across sessions
 * - Supports BinAssist parity: unified history instead of separate planning/investigation lists
 */
public class ConversationHistoryManager {

    private final List<ChatMessage> conversationHistory;
    private final List<IterationChunk> iterationChunks;
    private final AnalysisDB database;
    private final String programHash;
    private final int sessionId;

    /**
     * Represents a chunk of conversation for one iteration.
     */
    public static class IterationChunk {
        private final int iterationNumber;
        private final int messageStartIndex;
        private int messageEndIndex;  // Mutable until chunk is finalized
        private String iterationSummary;

        public IterationChunk(int iterationNumber, int messageStartIndex) {
            this.iterationNumber = iterationNumber;
            this.messageStartIndex = messageStartIndex;
            this.messageEndIndex = messageStartIndex;
        }

        public void finalizeChunk(int endIndex, String summary) {
            this.messageEndIndex = endIndex;
            this.iterationSummary = summary;
        }

        public int getIterationNumber() { return iterationNumber; }
        public int getMessageStartIndex() { return messageStartIndex; }
        public int getMessageEndIndex() { return messageEndIndex; }
        public String getIterationSummary() { return iterationSummary; }
    }

    /**
     * Create history manager for current ReAct session.
     *
     * @param database Database for persistence
     * @param programHash Current program hash
     * @param sessionId Current session ID
     */
    public ConversationHistoryManager(AnalysisDB database, String programHash, int sessionId) {
        this.conversationHistory = new ArrayList<>();
        this.iterationChunks = new ArrayList<>();
        this.database = database;
        this.programHash = programHash;
        this.sessionId = sessionId;
    }

    /**
     * Add message to conversation history with metadata.
     *
     * @param message Chat message to add
     * @param phase Current phase ("planning", "investigation", "reflection", "synthesis")
     * @param iterationNumber Current iteration (0 for planning)
     */
    public void addMessage(ChatMessage message, String phase, int iterationNumber) {
        conversationHistory.add(message);

        // Log for debugging
        Msg.debug(this, String.format(
            "Added message to history: phase=%s, iteration=%d, role=%s, size=%d",
            phase, iterationNumber, message.getRole(), conversationHistory.size()
        ));
    }

    /**
     * Start a new iteration chunk (marks beginning of iteration).
     *
     * @param iterationNumber Iteration number
     */
    public void startIterationChunk(int iterationNumber) {
        int startIndex = conversationHistory.size();
        IterationChunk chunk = new IterationChunk(iterationNumber, startIndex);
        iterationChunks.add(chunk);

        Msg.debug(this, String.format(
            "Started iteration chunk %d at message index %d",
            iterationNumber, startIndex
        ));
    }

    /**
     * Store iteration summary and finalize current chunk (marks end of iteration).
     *
     * @param iterationNumber Iteration number
     * @param summary LLM's summary of what was discovered in this iteration
     */
    public void storeIterationSummary(int iterationNumber, String summary) {
        // Find the chunk for this iteration
        for (IterationChunk chunk : iterationChunks) {
            if (chunk.getIterationNumber() == iterationNumber) {
                int endIndex = conversationHistory.size() - 1;
                chunk.finalizeChunk(endIndex, summary);

                Msg.debug(this, String.format(
                    "Finalized iteration chunk %d: messages [%d-%d], summary length=%d",
                    iterationNumber, chunk.getMessageStartIndex(), endIndex,
                    summary != null ? summary.length() : 0
                ));

                // Persist to database if available
                if (database != null) {
                    persistIterationChunk(chunk);
                }

                return;
            }
        }

        Msg.warn(this, "No chunk found for iteration " + iterationNumber);
    }

    /**
     * Get current conversation history (full unified list).
     *
     * @return List of all messages in conversation
     */
    public List<ChatMessage> getConversation() {
        return new ArrayList<>(conversationHistory);
    }

    /**
     * Get messages for a specific iteration.
     *
     * @param iterationNumber Iteration to retrieve
     * @return Messages from that iteration, or empty list if not found
     */
    public List<ChatMessage> getIterationMessages(int iterationNumber) {
        for (IterationChunk chunk : iterationChunks) {
            if (chunk.getIterationNumber() == iterationNumber) {
                int start = chunk.getMessageStartIndex();
                int end = Math.min(chunk.getMessageEndIndex() + 1, conversationHistory.size());
                return new ArrayList<>(conversationHistory.subList(start, end));
            }
        }
        return new ArrayList<>();
    }

    /**
     * Get all iteration summaries.
     *
     * @return List of summaries in iteration order
     */
    public List<String> getIterationSummaries() {
        List<String> summaries = new ArrayList<>();
        for (IterationChunk chunk : iterationChunks) {
            if (chunk.getIterationSummary() != null) {
                summaries.add(chunk.getIterationSummary());
            }
        }
        return summaries;
    }

    /**
     * Get formatted iteration summaries for prompt.
     *
     * @return Formatted string with iteration summaries
     */
    public String formatIterationSummaries() {
        if (iterationChunks.isEmpty()) {
            return "No iteration summaries available.";
        }

        StringBuilder sb = new StringBuilder();
        for (IterationChunk chunk : iterationChunks) {
            if (chunk.getIterationSummary() != null) {
                sb.append("### Iteration ").append(chunk.getIterationNumber()).append("\n");
                sb.append(chunk.getIterationSummary()).append("\n\n");
            }
        }
        return sb.toString();
    }

    /**
     * Restore conversation history from database.
     *
     * @param programHash Program hash to restore
     * @param sessionId Session ID to restore
     * @return Restored conversation history
     */
    public static List<ChatMessage> restoreConversation(
        AnalysisDB database,
        String programHash,
        int sessionId
    ) {
        if (database == null) {
            return new ArrayList<>();
        }

        // TODO: Implement database retrieval
        // This will query GHReActMessages table ordered by message_order
        // and reconstruct ChatMessage objects

        Msg.warn(ConversationHistoryManager.class,
            "Conversation restoration not yet implemented - database schema pending");

        return new ArrayList<>();
    }

    /**
     * Persist iteration chunk to database.
     */
    private void persistIterationChunk(IterationChunk chunk) {
        if (database == null) {
            return;
        }

        try {
            // Save iteration chunk metadata
            database.saveReActIterationChunk(
                programHash,
                sessionId,
                chunk.getIterationNumber(),
                chunk.getIterationSummary(),
                chunk.getMessageStartIndex(),
                chunk.getMessageEndIndex()
            );

            // Save all messages in this chunk
            for (int i = chunk.getMessageStartIndex(); i <= chunk.getMessageEndIndex() && i < conversationHistory.size(); i++) {
                ChatMessage message = conversationHistory.get(i);
                database.saveReActMessage(
                    programHash,
                    sessionId,
                    i,
                    "investigation",  // phase - determined by iteration context
                    chunk.getIterationNumber(),
                    message
                );
            }

            Msg.debug(this, String.format(
                "Persisted iteration chunk %d with %d messages to database",
                chunk.getIterationNumber(),
                chunk.getMessageEndIndex() - chunk.getMessageStartIndex() + 1
            ));

        } catch (Exception e) {
            Msg.error(this, "Failed to persist iteration chunk: " + e.getMessage(), e);
        }
    }

    /**
     * Clear all conversation history (for reset).
     */
    public void clear() {
        conversationHistory.clear();
        iterationChunks.clear();
        Msg.debug(this, "Cleared conversation history");
    }

    /**
     * Get conversation size (total message count).
     */
    public int size() {
        return conversationHistory.size();
    }

    /**
     * Get iteration chunk count.
     */
    public int getIterationCount() {
        return iterationChunks.size();
    }

    /**
     * Get summary statistics for logging/debugging.
     */
    public String getStats() {
        return String.format(
            "ConversationHistory: %d messages, %d iterations",
            conversationHistory.size(), iterationChunks.size()
        );
    }
}
