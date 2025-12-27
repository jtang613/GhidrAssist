package ghidrassist.graphrag.query;

import java.util.List;

/**
 * Result type for get_call_context() tool.
 * Contains caller/callee relationships with their semantic summaries.
 */
public class CallContext {
    private final FunctionSummary center;
    private final List<ContextEntry> callers;
    private final List<ContextEntry> callees;

    public CallContext(FunctionSummary center, List<ContextEntry> callers, List<ContextEntry> callees) {
        this.center = center;
        this.callers = callers;
        this.callees = callees;
    }

    // Getters
    public FunctionSummary getCenter() { return center; }
    public List<ContextEntry> getCallers() { return callers; }
    public List<ContextEntry> getCallees() { return callees; }

    /**
     * Represents a brief function summary for context entries.
     */
    public static class FunctionSummary {
        private final String name;
        private final long address;
        private final String summary;
        private final List<String> securityFlags;

        public FunctionSummary(String name, long address, String summary, List<String> securityFlags) {
            this.name = name;
            this.address = address;
            this.summary = summary;
            this.securityFlags = securityFlags;
        }

        public String getName() { return name; }
        public long getAddress() { return address; }
        public String getSummary() { return summary; }
        public List<String> getSecurityFlags() { return securityFlags; }

        public String toToolOutput() {
            StringBuilder sb = new StringBuilder();
            sb.append("{\n");
            sb.append("    \"name\": \"").append(name).append("\",\n");
            sb.append("    \"address\": \"0x").append(Long.toHexString(address)).append("\",\n");
            sb.append("    \"summary\": \"").append(escapeJson(summary)).append("\"");
            if (securityFlags != null && !securityFlags.isEmpty()) {
                sb.append(",\n    \"security_flags\": [");
                for (int i = 0; i < securityFlags.size(); i++) {
                    if (i > 0) sb.append(", ");
                    sb.append("\"").append(securityFlags.get(i)).append("\"");
                }
                sb.append("]");
            }
            sb.append("\n  }");
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

    /**
     * Represents a caller/callee entry with depth information.
     */
    public static class ContextEntry {
        private final int depth;
        private final FunctionSummary function;

        public ContextEntry(int depth, FunctionSummary function) {
            this.depth = depth;
            this.function = function;
        }

        public int getDepth() { return depth; }
        public FunctionSummary getFunction() { return function; }

        public String toToolOutput() {
            return "{ \"depth\": " + depth + ", \"function\": " + function.toToolOutput() + " }";
        }
    }

    /**
     * Direction for call context queries.
     */
    public enum Direction {
        CALLERS,
        CALLEES,
        BOTH
    }

    /**
     * Convert to JSON-like string for tool output.
     */
    public String toToolOutput() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"center\": ").append(center.toToolOutput()).append(",\n");

        sb.append("  \"callers\": [\n");
        for (int i = 0; i < callers.size(); i++) {
            if (i > 0) sb.append(",\n");
            sb.append("    ").append(callers.get(i).toToolOutput());
        }
        sb.append("\n  ],\n");

        sb.append("  \"callees\": [\n");
        for (int i = 0; i < callees.size(); i++) {
            if (i > 0) sb.append(",\n");
            sb.append("    ").append(callees.get(i).toToolOutput());
        }
        sb.append("\n  ]\n");

        sb.append("}");
        return sb.toString();
    }
}
