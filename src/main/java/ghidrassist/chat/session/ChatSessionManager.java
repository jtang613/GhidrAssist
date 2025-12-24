package ghidrassist.chat.session;

import ghidrassist.chat.message.MessageRepository;
import ghidrassist.chat.message.MessageStore;
import ghidrassist.chat.PersistedChatMessage;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Thread-safe manager for chat session lifecycle.
 * Uses AtomicInteger for session ID to prevent race conditions.
 */
public class ChatSessionManager {

    /** Sentinel value indicating no active session */
    public static final int NO_SESSION = -1;

    private final AtomicInteger currentSessionId = new AtomicInteger(NO_SESSION);
    private final Object sessionLock = new Object();

    private final ChatSessionRepository sessionRepository;
    private final MessageRepository messageRepository;
    private final MessageStore messageStore;

    /**
     * Create a ChatSessionManager with the required dependencies.
     */
    public ChatSessionManager(ChatSessionRepository sessionRepository,
                              MessageRepository messageRepository,
                              MessageStore messageStore) {
        this.sessionRepository = sessionRepository;
        this.messageRepository = messageRepository;
        this.messageStore = messageStore;
    }

    // ==================== Session ID Accessors ====================

    /**
     * Get the current session ID.
     * Thread-safe read.
     *
     * @return Current session ID, or NO_SESSION (-1) if none
     */
    public int getCurrentSessionId() {
        return currentSessionId.get();
    }

    /**
     * Check if there is an active session.
     *
     * @return true if session is active
     */
    public boolean hasActiveSession() {
        return currentSessionId.get() != NO_SESSION;
    }

    // ==================== Session Lifecycle ====================

    /**
     * Create a new chat session and make it current.
     * Thread-safe via synchronized block.
     *
     * @param programHash The program hash
     * @return The new session ID, or NO_SESSION on failure
     */
    public int createNewSession(String programHash) {
        synchronized (sessionLock) {
            // Generate description based on session count
            int nextNumber = sessionRepository.getNextSessionNumber(programHash);
            String description = "Chat " + nextNumber;

            int sessionId = sessionRepository.createSession(programHash, description);
            if (sessionId != NO_SESSION) {
                currentSessionId.set(sessionId);
                messageStore.clear();
            }
            return sessionId;
        }
    }

    /**
     * Switch to a specific session.
     * Loads messages from database and updates the message store.
     * Thread-safe via synchronized block.
     *
     * @param programHash The program hash
     * @param sessionId The session ID to switch to
     * @return true if switch successful
     */
    public boolean switchToSession(String programHash, int sessionId) {
        synchronized (sessionLock) {
            if (!sessionRepository.sessionExists(sessionId)) {
                return false;
            }

            // Load messages from database
            List<PersistedChatMessage> messages = messageRepository.loadMessages(programHash, sessionId);

            // If no per-message storage, try legacy migration
            if (messages.isEmpty() && !messageRepository.hasMessages(programHash, sessionId)) {
                String legacyConversation = sessionRepository.getLegacyConversation(sessionId);
                if (legacyConversation != null && !legacyConversation.isEmpty()) {
                    // Migration will be handled by LegacyMigrator
                    // For now, just note that legacy data exists
                }
            }

            // Update state
            messageStore.setMessages(messages);
            currentSessionId.set(sessionId);
            return true;
        }
    }

    /**
     * Delete the current session.
     * Clears the message store and resets session ID.
     *
     * @return true if deleted successfully
     */
    public boolean deleteCurrentSession() {
        synchronized (sessionLock) {
            int sessionId = currentSessionId.get();
            if (sessionId == NO_SESSION) {
                return false;
            }

            boolean deleted = sessionRepository.deleteSession(sessionId);
            if (deleted) {
                messageStore.clear();
                currentSessionId.set(NO_SESSION);
            }
            return deleted;
        }
    }

    /**
     * Clear the current session without deleting from database.
     * Used when starting fresh conversation.
     */
    public void clearCurrentSession() {
        synchronized (sessionLock) {
            messageStore.clear();
            currentSessionId.set(NO_SESSION);
        }
    }

    // ==================== Session Queries ====================

    /**
     * Get all sessions for a program.
     *
     * @param programHash The program hash
     * @return List of sessions (newest first)
     */
    public List<ChatSession> getSessions(String programHash) {
        return sessionRepository.getSessionsForProgram(programHash);
    }

    /**
     * Get current session details.
     *
     * @return Optional containing current session, or empty if none
     */
    public Optional<ChatSession> getCurrentSession() {
        int sessionId = currentSessionId.get();
        if (sessionId == NO_SESSION) {
            return Optional.empty();
        }
        return sessionRepository.getSession(sessionId);
    }

    /**
     * Check if current session is a ReAct session.
     *
     * @return true if current session is ReAct
     */
    public boolean isCurrentSessionReAct() {
        int sessionId = currentSessionId.get();
        if (sessionId == NO_SESSION) {
            return false;
        }
        return sessionRepository.isReActSession(sessionId);
    }

    // ==================== Session Updates ====================

    /**
     * Update current session description.
     *
     * @param description The new description
     * @return true if successful
     */
    public boolean updateCurrentDescription(String description) {
        int sessionId = currentSessionId.get();
        if (sessionId == NO_SESSION) {
            return false;
        }
        return sessionRepository.updateDescription(sessionId, description);
    }

    /**
     * Update a specific session's description.
     *
     * @param sessionId The session ID
     * @param description The new description
     * @return true if successful
     */
    public boolean updateSessionDescription(int sessionId, String description) {
        return sessionRepository.updateDescription(sessionId, description);
    }

    /**
     * Touch current session to update last_update timestamp.
     */
    public void touchCurrentSession() {
        int sessionId = currentSessionId.get();
        if (sessionId != NO_SESSION) {
            sessionRepository.touchSession(sessionId);
        }
    }

    // ==================== Ensure Session ====================

    /**
     * Ensure a session exists for the current conversation.
     * Creates a new session if none exists and message store has content.
     *
     * @param programHash The program hash
     * @return The session ID (existing or newly created)
     */
    public int ensureSession(String programHash) {
        synchronized (sessionLock) {
            if (currentSessionId.get() == NO_SESSION && !messageStore.isEmpty()) {
                return createNewSession(programHash);
            }
            return currentSessionId.get();
        }
    }
}
