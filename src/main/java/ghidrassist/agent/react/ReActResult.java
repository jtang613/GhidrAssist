package ghidrassist.agent.react;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Result of a ReAct agent analysis.
 * Much simpler than LATS AnalysisResult - no hypothesis trees or reflection data.
 */
public class ReActResult {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    /**
     * Analysis completion status.
     */
    public enum Status {
        SUCCESS,           // Agent provided an answer
        MAX_ITERATIONS,    // Reached max think-act-observe cycles
        MAX_TOOLS,         // Exhausted tool call budget
        ERROR,             // Unexpected error occurred
        CANCELLED          // User cancelled the analysis
    }

    // Core result data
    private final Status status;
    private final String answer;
    private final List<String> findings;

    // Metrics
    private final int iterationCount;
    private final int toolCallCount;
    private final Duration duration;

    // Error information (if applicable)
    private final String errorMessage;
    private final Throwable error;

    private ReActResult(Builder builder) {
        this.status = builder.status;
        this.answer = builder.answer;
        this.findings = new ArrayList<>(builder.findings);
        this.iterationCount = builder.iterationCount;
        this.toolCallCount = builder.toolCallCount;
        this.duration = builder.duration;
        this.errorMessage = builder.errorMessage;
        this.error = builder.error;
    }

    /**
     * Format result as markdown for display.
     */
    public String toMarkdown() {
        StringBuilder sb = new StringBuilder();

        // Status header
        sb.append("# ReAct Analysis Result\n\n");
        sb.append("**Status**: ").append(formatStatus()).append("\n");
        sb.append("**Iterations**: ").append(iterationCount).append("\n");
        sb.append("**Tool Calls**: ").append(toolCallCount).append("\n");
        sb.append("**Duration**: ").append(formatDuration()).append("\n\n");

        // Error message if applicable
        if (status == Status.ERROR && errorMessage != null) {
            sb.append("## Error\n\n");
            sb.append("```\n").append(errorMessage).append("\n```\n\n");
        }

        // Answer
        if (answer != null && !answer.isEmpty()) {
            sb.append("## Answer\n\n");
            sb.append(answer).append("\n\n");
        }

        // Key findings
        if (!findings.isEmpty()) {
            sb.append("## Key Findings\n\n");
            for (String finding : findings) {
                sb.append("- ").append(finding).append("\n");
            }
            sb.append("\n");
        }

        return sb.toString();
    }

    /**
     * Format result as compact summary for logging.
     */
    public String toSummary() {
        return String.format(
            "ReActResult[status=%s, iterations=%d, tools=%d, duration=%s]",
            status, iterationCount, toolCallCount, formatDuration()
        );
    }

    private String formatStatus() {
        switch (status) {
            case SUCCESS: return "✓ Success";
            case MAX_ITERATIONS: return "⚠ Max Iterations Reached";
            case MAX_TOOLS: return "⚠ Max Tool Calls Reached";
            case ERROR: return "✗ Error";
            case CANCELLED: return "⚠ Cancelled";
            default: return status.toString();
        }
    }

    private String formatDuration() {
        if (duration == null) {
            return "N/A";
        }
        long seconds = duration.getSeconds();
        if (seconds < 60) {
            return String.format("%ds", seconds);
        } else {
            long minutes = seconds / 60;
            long remainingSeconds = seconds % 60;
            return String.format("%dm %ds", minutes, remainingSeconds);
        }
    }

    // Getters
    public Status getStatus() { return status; }
    public String getAnswer() { return answer; }
    public List<String> getFindings() { return new ArrayList<>(findings); }
    public int getIterationCount() { return iterationCount; }
    public int getToolCallCount() { return toolCallCount; }
    public Duration getDuration() { return duration; }
    public String getErrorMessage() { return errorMessage; }
    public Throwable getError() { return error; }

    public boolean isSuccess() {
        return status == Status.SUCCESS;
    }

    /**
     * Serialize to JSON.
     */
    public String toJson() {
        return GSON.toJson(this);
    }

    /**
     * Builder for creating ReActResult instances.
     */
    public static class Builder {
        private Status status;
        private String answer = "";
        private List<String> findings = new ArrayList<>();
        private int iterationCount = 0;
        private int toolCallCount = 0;
        private Duration duration = Duration.ZERO;
        private String errorMessage = null;
        private Throwable error = null;

        public Builder status(Status status) {
            this.status = status;
            return this;
        }

        public Builder answer(String answer) {
            this.answer = answer;
            return this;
        }

        public Builder findings(List<String> findings) {
            this.findings = new ArrayList<>(findings);
            return this;
        }

        public Builder iterationCount(int count) {
            this.iterationCount = count;
            return this;
        }

        public Builder toolCallCount(int count) {
            this.toolCallCount = count;
            return this;
        }

        public Builder duration(Duration duration) {
            this.duration = duration;
            return this;
        }

        public Builder errorMessage(String message) {
            this.errorMessage = message;
            return this;
        }

        public Builder error(Throwable error) {
            this.error = error;
            if (error != null && this.errorMessage == null) {
                this.errorMessage = error.getMessage();
            }
            return this;
        }

        public ReActResult build() {
            if (status == null) {
                throw new IllegalStateException("Status must be set");
            }
            return new ReActResult(this);
        }
    }

    /**
     * Create an error result.
     */
    public static ReActResult error(Throwable error, FindingsCache findings, Duration duration) {
        return new Builder()
            .status(Status.ERROR)
            .error(error)
            .findings(findings != null ? findings.getAllFindings().stream().map(f -> f.getFact()).toList() : new ArrayList<>())
            .duration(duration)
            .build();
    }

    /**
     * Create a cancelled result.
     */
    public static ReActResult cancelled(FindingsCache findings, Duration duration) {
        return new Builder()
            .status(Status.CANCELLED)
            .findings(findings != null ? findings.getAllFindings().stream().map(f -> f.getFact()).toList() : new ArrayList<>())
            .duration(duration)
            .build();
    }
}
