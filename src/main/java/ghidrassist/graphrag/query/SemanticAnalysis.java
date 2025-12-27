package ghidrassist.graphrag.query;

import java.util.List;

/**
 * Result type for get_semantic_analysis() tool.
 * Contains pre-computed LLM analysis retrieved from the graph (NO LLM call at query time).
 */
public class SemanticAnalysis {
    private final String name;
    private final long address;
    private final String summary;           // Pre-computed by LLM during indexing
    private final List<String> securityFlags;
    private final String category;          // "crypto", "network", "auth", etc.
    private final float confidence;
    private final List<String> callers;
    private final List<String> callees;
    private final String community;         // Module/subsystem this belongs to
    private final String rawCode;           // Cached decompiled code
    private final boolean indexed;          // Whether this function has been indexed

    public SemanticAnalysis(String name, long address, String summary, List<String> securityFlags,
                            String category, float confidence, List<String> callers,
                            List<String> callees, String community, String rawCode, boolean indexed) {
        this.name = name;
        this.address = address;
        this.summary = summary;
        this.securityFlags = securityFlags;
        this.category = category;
        this.confidence = confidence;
        this.callers = callers;
        this.callees = callees;
        this.community = community;
        this.rawCode = rawCode;
        this.indexed = indexed;
    }

    /**
     * Create an "not indexed" result when function hasn't been analyzed yet.
     */
    public static SemanticAnalysis notIndexed(String name, long address) {
        return new SemanticAnalysis(name, address, null, List.of(), null, 0.0f,
                List.of(), List.of(), null, null, false);
    }

    // Getters
    public String getName() { return name; }
    public long getAddress() { return address; }
    public String getSummary() { return summary; }
    public List<String> getSecurityFlags() { return securityFlags; }
    public String getCategory() { return category; }
    public float getConfidence() { return confidence; }
    public List<String> getCallers() { return callers; }
    public List<String> getCallees() { return callees; }
    public String getCommunity() { return community; }
    public String getRawCode() { return rawCode; }
    public boolean isIndexed() { return indexed; }

    /**
     * Check if this function has security concerns flagged.
     */
    public boolean hasSecurityConcerns() {
        return securityFlags != null && !securityFlags.isEmpty();
    }

    /**
     * Check if we have any useful data (structure or semantic).
     */
    public boolean hasData() {
        return rawCode != null || (callers != null && !callers.isEmpty()) ||
               (callees != null && !callees.isEmpty());
    }

    /**
     * Check if we have LLM-generated semantic analysis.
     */
    public boolean hasSemanticAnalysis() {
        return summary != null && !summary.isEmpty();
    }

    /**
     * Convert to JSON-like string for tool output.
     * Shows all available data, even if LLM summary is not yet generated.
     */
    public String toToolOutput() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"name\": \"").append(name).append("\",\n");
        sb.append("  \"address\": \"0x").append(Long.toHexString(address)).append("\",\n");
        sb.append("  \"has_semantic_analysis\": ").append(hasSemanticAnalysis()).append(",\n");
        sb.append("  \"has_structure_data\": ").append(hasData()).append(",\n");

        // Always show available data
        if (hasData() || hasSemanticAnalysis()) {
            // Show LLM summary if available
            if (summary != null && !summary.isEmpty()) {
                sb.append("  \"summary\": \"").append(escapeJson(summary)).append("\",\n");
            } else {
                sb.append("  \"summary\": \"(LLM analysis pending - structure data available below)\",\n");
            }

            // Security flags
            sb.append("  \"security_flags\": ").append(listToJson(securityFlags)).append(",\n");

            // Category if available
            if (category != null) {
                sb.append("  \"category\": \"").append(category).append("\",\n");
            }

            // Confidence
            sb.append("  \"confidence\": ").append(confidence).append(",\n");

            // Callers and callees - always show
            sb.append("  \"callers\": ").append(listToJson(callers)).append(",\n");
            sb.append("  \"callees\": ").append(listToJson(callees)).append(",\n");

            // Community if available
            if (community != null) {
                sb.append("  \"community\": \"").append(community).append("\",\n");
            }

            // Raw code - always show if available
            if (rawCode != null) {
                // Truncate raw code for tool output
                String truncated = rawCode.length() > 2000
                    ? rawCode.substring(0, 2000) + "\n// ... (truncated)"
                    : rawCode;
                sb.append("  \"raw_code\": \"").append(escapeJson(truncated)).append("\"\n");
            } else {
                sb.append("  \"raw_code\": null\n");
            }
        } else {
            sb.append("  \"message\": \"Function not found in graph. Lazy indexing may have failed.\"\n");
        }

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

    private String listToJson(List<String> list) {
        if (list == null || list.isEmpty()) return "[]";
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < list.size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append("\"").append(escapeJson(list.get(i))).append("\"");
        }
        sb.append("]");
        return sb.toString();
    }
}
