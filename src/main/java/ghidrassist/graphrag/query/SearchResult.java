package ghidrassist.graphrag.query;

import java.util.List;

/**
 * Result type for search_semantic() tool.
 * Represents a search result from FTS5 on pre-computed summaries.
 */
public class SearchResult {
    private final String name;
    private final long address;
    private final String summary;
    private final float relevanceScore;
    private final String matchType;  // "fts_match", "embedding_match", etc.
    private final String matchedText;  // The portion of summary that matched

    public SearchResult(String name, long address, String summary,
                        float relevanceScore, String matchType, String matchedText) {
        this.name = name;
        this.address = address;
        this.summary = summary;
        this.relevanceScore = relevanceScore;
        this.matchType = matchType;
        this.matchedText = matchedText;
    }

    // Getters
    public String getName() { return name; }
    public long getAddress() { return address; }
    public String getSummary() { return summary; }
    public float getRelevanceScore() { return relevanceScore; }
    public String getMatchType() { return matchType; }
    public String getMatchedText() { return matchedText; }

    /**
     * Convert to JSON-like string for tool output.
     */
    public String toToolOutput() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"name\": \"").append(name).append("\",\n");
        sb.append("  \"address\": \"0x").append(Long.toHexString(address)).append("\",\n");
        sb.append("  \"summary\": \"").append(escapeJson(summary)).append("\",\n");
        sb.append("  \"relevance_score\": ").append(relevanceScore).append(",\n");
        sb.append("  \"match_type\": \"").append(matchType).append("\"");
        if (matchedText != null && !matchedText.isEmpty()) {
            sb.append(",\n  \"matched_text\": \"").append(escapeJson(matchedText)).append("\"");
        }
        sb.append("\n}");
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

    /**
     * Convert list of results to tool output.
     */
    public static String listToToolOutput(List<SearchResult> results) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"count\": ").append(results.size()).append(",\n");
        sb.append("  \"results\": [\n");
        for (int i = 0; i < results.size(); i++) {
            if (i > 0) sb.append(",\n");
            // Indent the result output
            String resultOutput = results.get(i).toToolOutput();
            String indented = resultOutput.replace("\n", "\n    ");
            sb.append("    ").append(indented);
        }
        sb.append("\n  ]\n");
        sb.append("}");
        return sb.toString();
    }
}
