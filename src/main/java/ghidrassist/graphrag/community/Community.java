package ghidrassist.graphrag.community;

import java.util.UUID;

/**
 * Represents a community (cluster) of related functions in the knowledge graph.
 * Communities are detected using graph clustering algorithms and stored as MODULE nodes.
 */
public class Community {
    private String id;
    private int level;              // 0=functions, 1=modules, 2=subsystems, etc.
    private String binaryId;
    private String parentCommunityId;  // For hierarchical communities
    private String name;
    private String summary;         // LLM-generated community summary
    private int memberCount;
    private boolean isStale;        // Needs re-summarization
    private long createdAt;
    private long updatedAt;

    /**
     * Create a new community with generated ID.
     */
    public Community(String binaryId, int level) {
        this.id = UUID.randomUUID().toString();
        this.binaryId = binaryId;
        this.level = level;
        this.isStale = true;
        this.memberCount = 0;
        this.createdAt = System.currentTimeMillis();
        this.updatedAt = this.createdAt;
    }

    /**
     * Create a community from database row.
     */
    public Community(String id, int level, String binaryId, String parentCommunityId,
                     String name, String summary, int memberCount, boolean isStale,
                     long createdAt, long updatedAt) {
        this.id = id;
        this.level = level;
        this.binaryId = binaryId;
        this.parentCommunityId = parentCommunityId;
        this.name = name;
        this.summary = summary;
        this.memberCount = memberCount;
        this.isStale = isStale;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }

    // ========================================
    // Getters
    // ========================================

    public String getId() {
        return id;
    }

    public int getLevel() {
        return level;
    }

    public String getBinaryId() {
        return binaryId;
    }

    public String getParentCommunityId() {
        return parentCommunityId;
    }

    public String getName() {
        return name;
    }

    public String getSummary() {
        return summary;
    }

    public int getMemberCount() {
        return memberCount;
    }

    public boolean isStale() {
        return isStale;
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public long getUpdatedAt() {
        return updatedAt;
    }

    // ========================================
    // Setters
    // ========================================

    public void setParentCommunityId(String parentCommunityId) {
        this.parentCommunityId = parentCommunityId;
        this.updatedAt = System.currentTimeMillis();
    }

    public void setName(String name) {
        this.name = name;
        this.updatedAt = System.currentTimeMillis();
    }

    public void setSummary(String summary) {
        this.summary = summary;
        this.isStale = false;
        this.updatedAt = System.currentTimeMillis();
    }

    public void setMemberCount(int memberCount) {
        this.memberCount = memberCount;
        this.updatedAt = System.currentTimeMillis();
    }

    public void markStale() {
        this.isStale = true;
        this.updatedAt = System.currentTimeMillis();
    }

    public void markFresh() {
        this.isStale = false;
        this.updatedAt = System.currentTimeMillis();
    }

    // ========================================
    // Utility Methods
    // ========================================

    /**
     * Generate a default name based on community ID and member count.
     */
    public String generateDefaultName() {
        return String.format("Community_%s (%d functions)",
                id.substring(0, 8), memberCount);
    }

    /**
     * Check if this community has a summary.
     */
    public boolean hasSummary() {
        return summary != null && !summary.isEmpty();
    }

    @Override
    public String toString() {
        return String.format("Community[id=%s, name=%s, members=%d, level=%d, stale=%b]",
                id.substring(0, 8), name, memberCount, level, isStale);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        Community other = (Community) obj;
        return id.equals(other.id);
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }
}
