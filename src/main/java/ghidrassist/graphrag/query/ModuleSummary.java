package ghidrassist.graphrag.query;

import java.util.List;

/**
 * Result type for get_module_summary() tool.
 * Contains community/module summary for a group of related functions.
 */
public class ModuleSummary {
    private final String moduleId;
    private final String moduleName;
    private final String moduleSummary;         // Pre-computed community summary
    private final List<String> memberFunctions; // All functions in this module
    private final List<String> keyFunctions;    // Most important functions
    private final String securityRelevance;     // Security notes for this module
    private final int level;                    // Hierarchy level (0 = leaf, higher = more abstract)
    private final int memberCount;

    public ModuleSummary(String moduleId, String moduleName, String moduleSummary,
                         List<String> memberFunctions, List<String> keyFunctions,
                         String securityRelevance, int level) {
        this.moduleId = moduleId;
        this.moduleName = moduleName;
        this.moduleSummary = moduleSummary;
        this.memberFunctions = memberFunctions;
        this.keyFunctions = keyFunctions;
        this.securityRelevance = securityRelevance;
        this.level = level;
        this.memberCount = memberFunctions != null ? memberFunctions.size() : 0;
    }

    /**
     * Create a "not found" result when function isn't part of any community.
     */
    public static ModuleSummary notFound(String functionName) {
        return new ModuleSummary(
            null,
            null,
            "Function '" + functionName + "' is not part of any detected community. " +
            "Run community detection to cluster functions into modules.",
            List.of(),
            List.of(),
            null,
            -1
        );
    }

    // Getters
    public String getModuleId() { return moduleId; }
    public String getModuleName() { return moduleName; }
    public String getModuleSummary() { return moduleSummary; }
    public List<String> getMemberFunctions() { return memberFunctions; }
    public List<String> getKeyFunctions() { return keyFunctions; }
    public String getSecurityRelevance() { return securityRelevance; }
    public int getLevel() { return level; }
    public int getMemberCount() { return memberCount; }

    /**
     * Convert to JSON-like string for tool output.
     */
    public String toToolOutput() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");

        if (moduleId == null) {
            // Not found case
            sb.append("  \"found\": false,\n");
            sb.append("  \"message\": \"").append(escapeJson(moduleSummary)).append("\"\n");
        } else {
            sb.append("  \"found\": true,\n");
            sb.append("  \"module_id\": \"").append(moduleId).append("\",\n");
            if (moduleName != null) {
                sb.append("  \"module_name\": \"").append(escapeJson(moduleName)).append("\",\n");
            }
            sb.append("  \"level\": ").append(level).append(",\n");
            sb.append("  \"member_count\": ").append(memberCount).append(",\n");

            if (moduleSummary != null) {
                sb.append("  \"module_summary\": \"").append(escapeJson(moduleSummary)).append("\",\n");
            }

            // Key functions (limited to top 10)
            sb.append("  \"key_functions\": [");
            if (keyFunctions != null) {
                int limit = Math.min(keyFunctions.size(), 10);
                for (int i = 0; i < limit; i++) {
                    if (i > 0) sb.append(", ");
                    sb.append("\"").append(escapeJson(keyFunctions.get(i))).append("\"");
                }
            }
            sb.append("],\n");

            // Member functions (limited to top 20)
            sb.append("  \"member_functions\": [");
            if (memberFunctions != null) {
                int limit = Math.min(memberFunctions.size(), 20);
                for (int i = 0; i < limit; i++) {
                    if (i > 0) sb.append(", ");
                    sb.append("\"").append(escapeJson(memberFunctions.get(i))).append("\"");
                }
                if (memberFunctions.size() > 20) {
                    sb.append(", \"... and ").append(memberFunctions.size() - 20).append(" more\"");
                }
            }
            sb.append("]");

            if (securityRelevance != null && !securityRelevance.isEmpty()) {
                sb.append(",\n  \"security_relevance\": \"").append(escapeJson(securityRelevance)).append("\"");
            }
            sb.append("\n");
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
}
