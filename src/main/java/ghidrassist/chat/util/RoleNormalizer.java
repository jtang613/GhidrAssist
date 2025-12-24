package ghidrassist.chat.util;

/**
 * Utility class for normalizing chat message roles.
 * Provides consistent role strings across all chat-related components.
 */
public final class RoleNormalizer {

    // Standard role constants
    public static final String ROLE_USER = "user";
    public static final String ROLE_ASSISTANT = "assistant";
    public static final String ROLE_TOOL_CALL = "tool_call";
    public static final String ROLE_TOOL_RESPONSE = "tool_response";
    public static final String ROLE_ERROR = "error";
    public static final String ROLE_EDITED = "edited";
    public static final String ROLE_UNKNOWN = "unknown";

    private RoleNormalizer() {
        // Utility class - no instantiation
    }

    /**
     * Normalize role string from various formats to standard lowercase form.
     * Handles variations like "User", "ASSISTANT", "Tool Call", "tool_call", etc.
     *
     * @param role The role string to normalize (case-insensitive)
     * @return Normalized lowercase role string
     */
    public static String normalize(String role) {
        if (role == null || role.isEmpty()) {
            return ROLE_UNKNOWN;
        }

        switch (role.toLowerCase().trim()) {
            case "user":
                return ROLE_USER;

            case "assistant":
            case "ghidrassist":  // Legacy format
                return ROLE_ASSISTANT;

            case "tool call":
            case "tool_call":
            case "tool":
                return ROLE_TOOL_CALL;

            case "tool response":
            case "tool_response":
                return ROLE_TOOL_RESPONSE;

            case "error":
                return ROLE_ERROR;

            case "edited":
                return ROLE_EDITED;

            default:
                return role.toLowerCase().trim();
        }
    }

    /**
     * Format role for display in headers (capitalized form).
     * Used for generating markdown headers like "## User (timestamp)".
     *
     * @param role The role string (can be normalized or not)
     * @return Formatted role for display
     */
    public static String toDisplayFormat(String role) {
        if (role == null || role.isEmpty()) {
            return "Unknown";
        }

        String normalized = normalize(role);
        switch (normalized) {
            case ROLE_USER:
                return "User";
            case ROLE_ASSISTANT:
                return "Assistant";
            case ROLE_TOOL_CALL:
                return "Tool Call";
            case ROLE_TOOL_RESPONSE:
                return "Tool Response";
            case ROLE_ERROR:
                return "Error";
            case ROLE_EDITED:
                return "Edited";
            default:
                // Capitalize first letter
                if (normalized.isEmpty()) {
                    return "Unknown";
                }
                return normalized.substring(0, 1).toUpperCase() + normalized.substring(1);
        }
    }

    /**
     * Check if the role represents a user message.
     *
     * @param role The role to check
     * @return true if this is a user role
     */
    public static boolean isUser(String role) {
        return ROLE_USER.equals(normalize(role));
    }

    /**
     * Check if the role represents an assistant message.
     *
     * @param role The role to check
     * @return true if this is an assistant role
     */
    public static boolean isAssistant(String role) {
        return ROLE_ASSISTANT.equals(normalize(role));
    }

    /**
     * Check if the role represents a tool-related message.
     *
     * @param role The role to check
     * @return true if this is a tool call or tool response
     */
    public static boolean isTool(String role) {
        String normalized = normalize(role);
        return ROLE_TOOL_CALL.equals(normalized) || ROLE_TOOL_RESPONSE.equals(normalized);
    }
}
