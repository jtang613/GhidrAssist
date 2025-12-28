package ghidrassist.chat;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;

import ghidrassist.apiprovider.ChatMessage;
import ghidrassist.chat.message.ThreadSafeMessageStore;
import ghidrassist.chat.util.RoleNormalizer;

/**
 * Represents a single message in a chat conversation with persistence support.
 * Used for per-message storage and chunk-based editing.
 */
public class PersistedChatMessage {
    private Integer dbId;           // Database row ID (null for new messages)
    private String role;            // user/assistant/tool_call/tool_response/error/edited
    private String content;         // Message content
    private Timestamp timestamp;    // Message timestamp
    private int order;              // Message order in conversation
    private String chunkId;         // Generated for tracking edits
    private String providerType;    // anthropic/openai/ollama/edited
    private String nativeMessageData; // JSON with essential tool info (name, args, result)
    private String messageType;     // standard/tool_call/tool_response/edited

    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    /**
     * Create a new PersistedChatMessage.
     *
     * @param dbId Database row ID (null for new messages)
     * @param role Message role (user/assistant/tool_call/tool_response/error/edited)
     * @param content Message content
     * @param timestamp Message timestamp
     * @param order Message order in conversation (0-indexed)
     */
    public PersistedChatMessage(Integer dbId, String role, String content,
                                Timestamp timestamp, int order) {
        this.dbId = dbId;
        this.role = role;
        this.content = content;
        this.timestamp = timestamp;
        this.order = order;
        this.chunkId = generateChunkId();
        this.providerType = "unknown";
        this.nativeMessageData = "{}";
        this.messageType = "standard";
    }

    /**
     * Generate a stable chunk ID for tracking edits.
     * Format: msg_{dbId}_{role}_{order}_{contentHash}
     */
    private String generateChunkId() {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            String contentToHash = content != null ? content : "";
            byte[] digest = md.digest(contentToHash.getBytes("UTF-8"));
            String hash = bytesToHex(digest).substring(0, 8);
            return String.format("msg_%s_%s_%d_%s",
                dbId != null ? dbId.toString() : "new",
                role != null ? role : "unknown",
                order,
                hash);
        } catch (NoSuchAlgorithmException | java.io.UnsupportedEncodingException e) {
            // Fallback without hash
            return String.format("msg_%s_%s_%d",
                dbId != null ? dbId.toString() : "new",
                role != null ? role : "unknown",
                order);
        }
    }

    /**
     * Regenerate the chunk ID. Call after content changes.
     */
    public void regenerateChunkId() {
        this.chunkId = generateChunkId();
    }

    /**
     * Get the markdown header for this role.
     *
     * @return Formatted header like "## User (2025-01-15 10:30:00)"
     */
    public String getRoleHeader() {
        String timestampStr = timestamp != null ? DATE_FORMAT.format(timestamp) : "";

        if (role == null) {
            return "## Unknown (" + timestampStr + ")";
        }

        switch (role.toLowerCase()) {
            case "user":
                return "## User (" + timestampStr + ")";
            case "assistant":
                return "## Assistant (" + timestampStr + ")";
            case "tool_call":
                return "### Tool Call (" + timestampStr + ")";
            case "tool_response":
                return "### Tool Response (" + timestampStr + ")";
            case "error":
                return "## Error (" + timestampStr + ")";
            case "edited":
                return "## Edited (" + timestampStr + ")";
            default:
                return "## " + capitalize(role) + " (" + timestampStr + ")";
        }
    }

    /**
     * Convert this message to a markdown chunk with embedded tracking marker.
     *
     * @return Markdown string with chunk marker
     */
    public String toMarkdownChunk() {
        String marker = "<!-- CHUNK:" + chunkId + " -->";
        String header = getRoleHeader();
        String contentText = content != null ? content : "";
        return marker + "\n" + header + "\n" + contentText + "\n\n";
    }

    // Getters

    public Integer getDbId() {
        return dbId;
    }

    public String getRole() {
        return role;
    }

    public String getContent() {
        return content;
    }

    public Timestamp getTimestamp() {
        return timestamp;
    }

    public int getOrder() {
        return order;
    }

    public String getChunkId() {
        return chunkId;
    }

    public String getProviderType() {
        return providerType;
    }

    public String getNativeMessageData() {
        return nativeMessageData;
    }

    public String getMessageType() {
        return messageType;
    }

    // Setters

    public void setDbId(Integer dbId) {
        this.dbId = dbId;
        regenerateChunkId();
    }

    public void setRole(String role) {
        this.role = role;
        regenerateChunkId();
    }

    public void setContent(String content) {
        this.content = content;
        regenerateChunkId();
    }

    public void setTimestamp(Timestamp timestamp) {
        this.timestamp = timestamp;
    }

    public void setOrder(int order) {
        this.order = order;
        regenerateChunkId();
    }

    public void setProviderType(String providerType) {
        this.providerType = providerType;
    }

    public void setNativeMessageData(String nativeMessageData) {
        this.nativeMessageData = nativeMessageData;
    }

    public void setMessageType(String messageType) {
        this.messageType = messageType;
    }

    // ==================== API Conversion Methods ====================

    /**
     * Convert this persisted message to a ChatMessage for API calls.
     * Restores thinking content, tool calls, and other metadata from nativeMessageData.
     *
     * @return A ChatMessage with all metadata restored
     */
    public ChatMessage toChatMessage() {
        String apiRole = normalizeRoleForApi(this.role);
        return ThreadSafeMessageStore.deserializeNativeData(
                this.nativeMessageData,
                apiRole,
                this.content
        );
    }

    /**
     * Normalize display/internal role to API role format.
     * Maps tool_call, tool_response, error etc. to standard API roles.
     *
     * @param displayRole The role as stored/displayed
     * @return The role in API format (user, assistant, tool, system)
     */
    private String normalizeRoleForApi(String displayRole) {
        if (displayRole == null) {
            return ChatMessage.ChatMessageRole.USER;
        }

        String normalized = RoleNormalizer.normalize(displayRole);
        switch (normalized) {
            case RoleNormalizer.ROLE_USER:
                return ChatMessage.ChatMessageRole.USER;
            case RoleNormalizer.ROLE_ASSISTANT:
                return ChatMessage.ChatMessageRole.ASSISTANT;
            case RoleNormalizer.ROLE_TOOL_CALL:
            case RoleNormalizer.ROLE_TOOL_RESPONSE:
                return ChatMessage.ChatMessageRole.TOOL;
            case RoleNormalizer.ROLE_ERROR:
                // Errors are typically assistant messages
                return ChatMessage.ChatMessageRole.ASSISTANT;
            case RoleNormalizer.ROLE_EDITED:
                // Edited messages retain original role, default to user
                return ChatMessage.ChatMessageRole.USER;
            default:
                return ChatMessage.ChatMessageRole.USER;
        }
    }

    // Utility methods

    private static String capitalize(String s) {
        if (s == null || s.isEmpty()) {
            return s;
        }
        return s.substring(0, 1).toUpperCase() + s.substring(1);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    @Override
    public String toString() {
        return String.format("PersistedChatMessage{dbId=%d, role='%s', order=%d, chunkId='%s'}",
            dbId, role, order, chunkId);
    }
}
