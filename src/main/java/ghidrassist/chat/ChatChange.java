package ghidrassist.chat;

/**
 * Represents a detected change in chat content during editing.
 * Used to track modifications, deletions, and additions when
 * parsing edited content.
 */
public class ChatChange {
    private ChangeType changeType;
    private String chunkId;
    private String oldContent;
    private String newContent;
    private Integer dbId;
    private Integer newOrder;
    private String role;
    private String timestamp;

    /**
     * Private constructor - use factory methods instead.
     */
    private ChatChange(ChangeType changeType, String chunkId, String oldContent,
                       String newContent, Integer dbId, Integer newOrder,
                       String role, String timestamp) {
        this.changeType = changeType;
        this.chunkId = chunkId;
        this.oldContent = oldContent;
        this.newContent = newContent;
        this.dbId = dbId;
        this.newOrder = newOrder;
        this.role = role;
        this.timestamp = timestamp;
    }

    // Factory methods for common change types

    /**
     * Create a change representing a modified message.
     */
    public static ChatChange modified(String chunkId, Integer dbId,
                                      String oldContent, String newContent,
                                      String role, String timestamp) {
        return new ChatChange(ChangeType.MODIFIED, chunkId, oldContent,
                              newContent, dbId, null, role, timestamp);
    }

    /**
     * Create a change representing a deleted message.
     */
    public static ChatChange deleted(String chunkId, Integer dbId, String oldContent) {
        return new ChatChange(ChangeType.DELETED, chunkId, oldContent,
                              null, dbId, null, null, null);
    }

    /**
     * Create a change representing a new message.
     */
    public static ChatChange added(String newContent, String role,
                                   String timestamp, Integer order) {
        return new ChatChange(ChangeType.ADDED, null, null,
                              newContent, null, order, role, timestamp);
    }

    /**
     * Create a change representing a title modification.
     */
    public static ChatChange titleModified(String oldTitle, String newTitle) {
        return new ChatChange(ChangeType.MODIFIED, "title", oldTitle,
                              newTitle, null, null, "title", null);
    }

    // Getters

    public ChangeType getChangeType() {
        return changeType;
    }

    public String getChunkId() {
        return chunkId;
    }

    public String getOldContent() {
        return oldContent;
    }

    public String getNewContent() {
        return newContent;
    }

    public Integer getDbId() {
        return dbId;
    }

    public Integer getNewOrder() {
        return newOrder;
    }

    public String getRole() {
        return role;
    }

    public String getTimestamp() {
        return timestamp;
    }

    /**
     * Check if this is a title change.
     */
    public boolean isTitleChange() {
        return "title".equals(role) && "title".equals(chunkId);
    }

    @Override
    public String toString() {
        return String.format("ChatChange{type=%s, chunkId='%s', role='%s'}",
            changeType, chunkId, role);
    }
}
