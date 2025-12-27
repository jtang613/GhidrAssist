package ghidrassist.graphrag.query;

/**
 * Result type for get_similar_functions() tool.
 * Represents a function similar to the query function based on graph structure.
 */
public class SimilarFunction {
    private final String name;
    private final long address;
    private final String summary;
    private final float similarityScore;
    private final SimilarityType similarityType;

    public enum SimilarityType {
        SAME_COMMUNITY,      // Functions in the same module/community
        SHARED_CALLERS,      // Functions called by the same callers
        SHARED_CALLEES,      // Functions that call the same callees
        FTS_MATCH,           // Full-text search match on summaries
        EMBEDDING_SIMILARITY // Vector similarity (if embeddings available)
    }

    public SimilarFunction(String name, long address, String summary,
                           float similarityScore, SimilarityType similarityType) {
        this.name = name;
        this.address = address;
        this.summary = summary;
        this.similarityScore = similarityScore;
        this.similarityType = similarityType;
    }

    // Getters
    public String getName() { return name; }
    public long getAddress() { return address; }
    public String getSummary() { return summary; }
    public float getSimilarityScore() { return similarityScore; }
    public SimilarityType getSimilarityType() { return similarityType; }

    /**
     * Convert to JSON-like string for tool output.
     */
    public String toToolOutput() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"name\": \"").append(name).append("\",\n");
        sb.append("  \"address\": \"0x").append(Long.toHexString(address)).append("\",\n");
        sb.append("  \"summary\": \"").append(escapeJson(summary)).append("\",\n");
        sb.append("  \"similarity_score\": ").append(similarityScore).append(",\n");
        sb.append("  \"similarity_type\": \"").append(similarityType.name().toLowerCase()).append("\"\n");
        sb.append("}");
        return sb.toString();
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
