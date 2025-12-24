package ghidrassist.chat.session;

import java.sql.Timestamp;
import java.util.Objects;

/**
 * Represents a chat session with its metadata.
 * Immutable value object with builder pattern for construction.
 */
public final class ChatSession {

    private final int id;
    private final String programHash;
    private final String description;
    private final Timestamp lastUpdate;
    private final boolean isReActSession;

    private ChatSession(Builder builder) {
        this.id = builder.id;
        this.programHash = builder.programHash;
        this.description = builder.description;
        this.lastUpdate = builder.lastUpdate;
        this.isReActSession = builder.isReActSession;
    }

    /**
     * Create a ChatSession from legacy AnalysisDB.ChatSession for backward compatibility.
     */
    public static ChatSession fromLegacy(int id, String description, Timestamp lastUpdate) {
        return new Builder()
                .id(id)
                .description(description)
                .lastUpdate(lastUpdate)
                .build();
    }

    // ==================== Getters ====================

    public int getId() {
        return id;
    }

    public String getProgramHash() {
        return programHash;
    }

    public String getDescription() {
        return description;
    }

    public Timestamp getLastUpdate() {
        return lastUpdate;
    }

    public boolean isReActSession() {
        return isReActSession;
    }

    // ==================== Builder ====================

    public static class Builder {
        private int id = -1;
        private String programHash;
        private String description = "";
        private Timestamp lastUpdate;
        private boolean isReActSession = false;

        public Builder() {
            this.lastUpdate = new Timestamp(System.currentTimeMillis());
        }

        public Builder id(int id) {
            this.id = id;
            return this;
        }

        public Builder programHash(String programHash) {
            this.programHash = programHash;
            return this;
        }

        public Builder description(String description) {
            this.description = description != null ? description : "";
            return this;
        }

        public Builder lastUpdate(Timestamp lastUpdate) {
            this.lastUpdate = lastUpdate != null ? lastUpdate : new Timestamp(System.currentTimeMillis());
            return this;
        }

        public Builder isReActSession(boolean isReActSession) {
            this.isReActSession = isReActSession;
            return this;
        }

        public ChatSession build() {
            return new ChatSession(this);
        }
    }

    // ==================== Object Methods ====================

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ChatSession that = (ChatSession) o;
        return id == that.id;
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return String.format("ChatSession{id=%d, description='%s', lastUpdate=%s, isReAct=%s}",
                id, description, lastUpdate, isReActSession);
    }
}
