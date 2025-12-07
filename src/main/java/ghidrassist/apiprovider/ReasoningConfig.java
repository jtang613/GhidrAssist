package ghidrassist.apiprovider;

/**
 * Configuration for LLM reasoning/thinking effort.
 * Different providers use different parameter formats:
 * - Anthropic: thinking.budget_tokens object
 * - OpenAI/Azure: reasoning_effort string
 * - Ollama/OpenWebUI: think boolean/string
 * - LMStudio: reasoning.effort object
 */
public class ReasoningConfig {

    public enum EffortLevel {
        NONE,    // Don't send any reasoning parameters
        LOW,     // Minimal reasoning
        MEDIUM,  // Balanced reasoning
        HIGH     // Maximum reasoning depth
    }

    private EffortLevel effort;

    public ReasoningConfig() {
        this.effort = EffortLevel.NONE;
    }

    public ReasoningConfig(EffortLevel effort) {
        this.effort = effort != null ? effort : EffortLevel.NONE;
    }

    public EffortLevel getEffort() {
        return effort;
    }

    public void setEffort(EffortLevel effort) {
        this.effort = effort != null ? effort : EffortLevel.NONE;
    }

    /**
     * Check if reasoning is enabled (not NONE).
     */
    public boolean isEnabled() {
        return effort != EffortLevel.NONE;
    }

    /**
     * Get the effort level as a lowercase string for API parameters.
     * Returns null if effort is NONE.
     */
    public String getEffortString() {
        if (effort == EffortLevel.NONE) {
            return null;
        }
        return effort.name().toLowerCase();
    }

    /**
     * Get the Anthropic thinking budget tokens based on effort level.
     * Returns 0 if effort is NONE.
     */
    public int getAnthropicBudget() {
        switch (effort) {
            case LOW:
                return 2000;
            case MEDIUM:
                return 10000;
            case HIGH:
                return 25000;
            default:
                return 0;
        }
    }

    /**
     * Get the Ollama/OpenWebUI think parameter value.
     * For gpt-oss models, returns effort string.
     * For other models, returns boolean equivalent.
     * Returns null if effort is NONE.
     */
    public Object getOllamaThinkValue() {
        if (effort == EffortLevel.NONE) {
            return null;
        }
        // Return the effort level string - works for gpt-oss and
        // Ollama will convert to boolean for other models
        return effort.name().toLowerCase();
    }

    /**
     * Parse an effort level from a string (case-insensitive).
     */
    public static EffortLevel parseEffort(String value) {
        if (value == null || value.trim().isEmpty() || value.equalsIgnoreCase("none")) {
            return EffortLevel.NONE;
        }
        try {
            return EffortLevel.valueOf(value.toUpperCase());
        } catch (IllegalArgumentException e) {
            return EffortLevel.NONE;
        }
    }

    /**
     * Create a ReasoningConfig from a string effort level.
     */
    public static ReasoningConfig fromString(String value) {
        return new ReasoningConfig(parseEffort(value));
    }

    @Override
    public String toString() {
        return "ReasoningConfig{effort=" + effort + "}";
    }
}
