package ghidrassist.agent.react;

import ghidra.util.Msg;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Accumulates findings/evidence during analysis.
 * Tracks what tools discovered and maintains relevance scoring.
 */
public class FindingsCache {

    public static class Finding {
        private final String fact;
        private final String evidence;
        private final String toolUsed;
        private final long timestamp;
        private int relevance;  // Mutable - can be updated

        public Finding(String fact, String evidence, String toolUsed, int relevance) {
            this.fact = fact;
            this.evidence = evidence;
            this.toolUsed = toolUsed;
            this.relevance = relevance;
            this.timestamp = System.currentTimeMillis();
        }

        public String getFact() { return fact; }
        public String getEvidence() { return evidence; }
        public String getToolUsed() { return toolUsed; }
        public int getRelevance() { return relevance; }
        public long getTimestamp() { return timestamp; }

        public void setRelevance(int relevance) { this.relevance = relevance; }
    }

    private final List<Finding> findings;
    private final List<String> iterationSummaries;
    private final int maxFindings;

    public FindingsCache() {
        this(100);  // Keep up to 100 findings
    }

    public FindingsCache(int maxFindings) {
        this.findings = new ArrayList<>();
        this.iterationSummaries = new ArrayList<>();
        this.maxFindings = maxFindings;
    }

    /**
     * Add a finding from tool observation.
     */
    public void addFinding(String fact, String evidence, String toolUsed, int relevance) {
        findings.add(new Finding(fact, evidence, toolUsed, relevance));

        // Prune old low-relevance findings if we exceed max
        if (findings.size() > maxFindings) {
            pruneFindings();
        }
    }

    /**
     * Add a simple finding with default relevance.
     */
    public void addFinding(String fact, String toolUsed) {
        addFinding(fact, null, toolUsed, 5);  // Default medium relevance
    }

    /**
     * Extract key findings from tool output.
     * This is a simple heuristic-based approach.
     */
    public void extractFromToolOutput(String toolName, String output) {
        if (output == null || output.isEmpty()) {
            return;
        }

        // Simple heuristics for extracting important information
        String[] lines = output.split("\n");
        for (String line : lines) {
            line = line.trim();

            // Look for patterns that indicate important findings
            if (line.contains("vulnerability") || line.contains("buffer overflow") ||
                line.contains("unsafe")) {
                addFinding(line, output, toolName, 10);  // High relevance
            } else if (line.contains("function") || line.contains("calls") ||
                      line.contains("address") || line.contains("0x")) {
                addFinding(line, output, toolName, 7);  // Medium-high relevance
            } else if (line.length() > 20 && line.length() < 200) {
                // Reasonable length lines might be useful
                addFinding(line, output, toolName, 3);  // Low relevance
            }
        }
    }

    /**
     * Remove low-relevance findings to stay within max limit.
     */
    private void pruneFindings() {
        if (findings.size() <= maxFindings) {
            return;
        }

        // Sort by relevance (descending) and keep top findings
        findings.sort(Comparator.comparingInt(Finding::getRelevance).reversed());

        // Remove lowest relevance findings
        while (findings.size() > maxFindings) {
            findings.remove(findings.size() - 1);
        }
    }

    /**
     * Format findings for LLM prompt - show most relevant.
     */
    public String formatForPrompt() {
        return formatForPrompt(10);  // Top 10 by default
    }

    /**
     * Format top N findings for prompt.
     */
    public String formatForPrompt(int maxShow) {
        if (findings.isEmpty()) {
            return "No significant findings yet.";
        }

        return findings.stream()
            .sorted(Comparator.comparingInt(Finding::getRelevance).reversed())
            .limit(maxShow)
            .map(f -> "• " + f.getFact())
            .collect(Collectors.joining("\n"));
    }

    /**
     * Get detailed findings with evidence.
     */
    public String formatDetailed() {
        if (findings.isEmpty()) {
            return "No findings.";
        }

        StringBuilder sb = new StringBuilder();
        findings.stream()
            .sorted(Comparator.comparingInt(Finding::getRelevance).reversed())
            .limit(20)
            .forEach(f -> {
                sb.append("**").append(f.getFact()).append("**");
                if (f.getToolUsed() != null) {
                    sb.append(" (from ").append(f.getToolUsed()).append(")");
                }
                sb.append("\n");
                if (f.getEvidence() != null && !f.getEvidence().isEmpty()) {
                    String truncated = f.getEvidence().length() > 200
                        ? f.getEvidence().substring(0, 200) + "..."
                        : f.getEvidence();
                    sb.append("Evidence: ").append(truncated).append("\n");
                }
                sb.append("\n");
            });

        return sb.toString();
    }

    /**
     * Summarize findings into compact form.
     * Used when context needs to be compressed.
     */
    public String summarize() {
        if (findings.isEmpty()) {
            return "No findings to summarize.";
        }

        // Get top findings by relevance
        List<Finding> topFindings = findings.stream()
            .sorted(Comparator.comparingInt(Finding::getRelevance).reversed())
            .limit(15)
            .collect(Collectors.toList());

        StringBuilder sb = new StringBuilder();
        sb.append("Key Findings Summary:\n");
        for (Finding f : topFindings) {
            sb.append("- ").append(f.getFact()).append("\n");
        }

        return sb.toString();
    }

    /**
     * Get count of findings.
     */
    public int getCount() {
        return findings.size();
    }

    /**
     * Get all findings.
     */
    public List<Finding> getAllFindings() {
        return new ArrayList<>(findings);
    }

    /**
     * Clear all findings (for context reset).
     */
    public void clear() {
        findings.clear();
        iterationSummaries.clear();
    }

    /**
     * Get compact representation for progress tracking.
     */
    public String toCompactString() {
        return String.format("%d findings accumulated", findings.size());
    }

    /**
     * Add a summary from an iteration.
     * This captures the LLM's analytical summary after each iteration.
     */
    public void addIterationSummary(String summary) {
        if (summary != null && !summary.trim().isEmpty()) {
            String trimmed = summary.trim();
            iterationSummaries.add(trimmed);

            // Debug logging: Show what we're capturing
            String preview = trimmed.length() > 100 ? trimmed.substring(0, 100) + "..." : trimmed;
            Msg.info(this, String.format("📝 Captured iteration summary #%d: %s",
                iterationSummaries.size(), preview));
        } else {
            Msg.warn(this, "⚠️ Attempted to add empty/null iteration summary - skipping");
        }
    }

    /**
     * Format iteration summaries for synthesis prompt.
     * Shows last 10 iterations by default.
     */
    public String formatIterationSummaries() {
        return formatIterationSummaries(10);
    }

    /**
     * Format iteration summaries with custom limit.
     */
    public String formatIterationSummaries(int maxIterations) {
        if (iterationSummaries.isEmpty()) {
            Msg.warn(this, "⚠️ formatIterationSummaries called but NO summaries were collected!");
            return "No iteration summaries available.";
        }

        // Get last N iterations (most recent)
        int startIdx = Math.max(0, iterationSummaries.size() - maxIterations);
        List<String> recent = iterationSummaries.subList(startIdx, iterationSummaries.size());

        // Debug logging: Show what we're sending to synthesis
        Msg.info(this, String.format("📤 Formatting %d iteration summaries for synthesis (out of %d total):",
            recent.size(), iterationSummaries.size()));

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < recent.size(); i++) {
            String summary = recent.get(i);
            String preview = summary.length() > 100 ? summary.substring(0, 100) + "..." : summary;
            Msg.info(this, String.format("  Iteration %d preview: %s", startIdx + i + 1, preview));

            sb.append("### Iteration ").append(startIdx + i + 1).append("\n");
            sb.append(summary).append("\n\n");
        }

        Msg.info(this, String.format("📤 Total synthesis context length: %d characters", sb.length()));
        return sb.toString();
    }
}
