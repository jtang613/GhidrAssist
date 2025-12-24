package ghidrassist.chat.session;

import java.util.List;
import java.util.Optional;

/**
 * Repository interface for chat session persistence operations.
 */
public interface ChatSessionRepository {

    /**
     * Create a new chat session.
     *
     * @param programHash The program hash
     * @param description The session description
     * @return The new session ID, or -1 on failure
     */
    int createSession(String programHash, String description);

    /**
     * Get all sessions for a program, ordered by last_update DESC.
     *
     * @param programHash The program hash
     * @return List of sessions (newest first)
     */
    List<ChatSession> getSessionsForProgram(String programHash);

    /**
     * Get a session by ID.
     *
     * @param sessionId The session ID
     * @return Optional containing the session if found
     */
    Optional<ChatSession> getSession(int sessionId);

    /**
     * Update session description.
     *
     * @param sessionId The session ID
     * @param description The new description
     * @return true if successful
     */
    boolean updateDescription(int sessionId, String description);

    /**
     * Update session last_update timestamp to current time.
     *
     * @param sessionId The session ID
     * @return true if successful
     */
    boolean touchSession(int sessionId);

    /**
     * Delete a session (messages will cascade delete via FK).
     *
     * @param sessionId The session ID
     * @return true if deleted
     */
    boolean deleteSession(int sessionId);

    /**
     * Check if session exists.
     *
     * @param sessionId The session ID
     * @return true if exists
     */
    boolean sessionExists(int sessionId);

    /**
     * Check if session is a ReAct session.
     *
     * @param sessionId The session ID
     * @return true if ReAct session
     */
    boolean isReActSession(int sessionId);

    /**
     * Get the next available session number for a program.
     * Used for generating default session descriptions like "Chat 1", "Chat 2".
     *
     * @param programHash The program hash
     * @return Next session number
     */
    int getNextSessionNumber(String programHash);

    /**
     * Get the legacy conversation blob for a session.
     * Used for backward compatibility during migration.
     *
     * @param sessionId The session ID
     * @return The conversation blob, or null if not found
     */
    String getLegacyConversation(int sessionId);
}
