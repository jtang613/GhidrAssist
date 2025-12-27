package ghidrassist.graphrag.query;

import java.util.List;

/**
 * Result type for get_security_analysis() tool.
 * Contains security flags, taint paths, and attack surface information.
 */
public class SecurityAnalysis {
    private final String scopeType;  // "function" or "binary"
    private final String scopeName;  // Function name or binary name
    private final List<String> securityFlags;
    private final List<TaintPath> taintPaths;
    private final List<String> attackSurface;      // Entry points, external interfaces
    private final List<String> vulnerableCallers;  // Functions that call vulnerable code

    public SecurityAnalysis(String scopeType, String scopeName, List<String> securityFlags,
                            List<TaintPath> taintPaths, List<String> attackSurface,
                            List<String> vulnerableCallers) {
        this.scopeType = scopeType;
        this.scopeName = scopeName;
        this.securityFlags = securityFlags;
        this.taintPaths = taintPaths;
        this.attackSurface = attackSurface;
        this.vulnerableCallers = vulnerableCallers;
    }

    // Getters
    public String getScopeType() { return scopeType; }
    public String getScopeName() { return scopeName; }
    public List<String> getSecurityFlags() { return securityFlags; }
    public List<TaintPath> getTaintPaths() { return taintPaths; }
    public List<String> getAttackSurface() { return attackSurface; }
    public List<String> getVulnerableCallers() { return vulnerableCallers; }

    /**
     * Check if any security issues were found.
     */
    public boolean hasSecurityIssues() {
        return (securityFlags != null && !securityFlags.isEmpty()) ||
               (taintPaths != null && !taintPaths.isEmpty());
    }

    /**
     * Represents a taint propagation path from source to sink.
     */
    public static class TaintPath {
        private final String source;      // Source function (user input, network read, etc.)
        private final String sink;        // Sink function (strcpy, system, etc.)
        private final List<String> path;  // Path of functions between source and sink

        public TaintPath(String source, String sink, List<String> path) {
            this.source = source;
            this.sink = sink;
            this.path = path;
        }

        public String getSource() { return source; }
        public String getSink() { return sink; }
        public List<String> getPath() { return path; }

        public String toToolOutput() {
            StringBuilder sb = new StringBuilder();
            sb.append("{\n");
            sb.append("      \"source\": \"").append(source).append("\",\n");
            sb.append("      \"sink\": \"").append(sink).append("\",\n");
            sb.append("      \"path\": [");
            for (int i = 0; i < path.size(); i++) {
                if (i > 0) sb.append(", ");
                sb.append("\"").append(path.get(i)).append("\"");
            }
            sb.append("]\n");
            sb.append("    }");
            return sb.toString();
        }
    }

    /**
     * Convert to JSON-like string for tool output.
     */
    public String toToolOutput() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"scope_type\": \"").append(scopeType).append("\",\n");
        sb.append("  \"scope_name\": \"").append(scopeName).append("\",\n");

        // Security flags
        sb.append("  \"security_flags\": [");
        if (securityFlags != null) {
            for (int i = 0; i < securityFlags.size(); i++) {
                if (i > 0) sb.append(", ");
                sb.append("\"").append(securityFlags.get(i)).append("\"");
            }
        }
        sb.append("],\n");

        // Taint paths
        sb.append("  \"taint_paths\": [\n");
        if (taintPaths != null) {
            for (int i = 0; i < taintPaths.size(); i++) {
                if (i > 0) sb.append(",\n");
                sb.append("    ").append(taintPaths.get(i).toToolOutput());
            }
        }
        sb.append("\n  ],\n");

        // Attack surface
        sb.append("  \"attack_surface\": [");
        if (attackSurface != null) {
            for (int i = 0; i < attackSurface.size(); i++) {
                if (i > 0) sb.append(", ");
                sb.append("\"").append(attackSurface.get(i)).append("\"");
            }
        }
        sb.append("],\n");

        // Vulnerable callers
        sb.append("  \"vulnerable_callers\": [");
        if (vulnerableCallers != null) {
            for (int i = 0; i < vulnerableCallers.size(); i++) {
                if (i > 0) sb.append(", ");
                sb.append("\"").append(vulnerableCallers.get(i)).append("\"");
            }
        }
        sb.append("]\n");

        sb.append("}");
        return sb.toString();
    }
}
