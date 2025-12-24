package ghidrassist.chat.message;

import ghidrassist.chat.PersistedChatMessage;

import java.util.List;

/**
 * Repository interface for message persistence operations.
 * Implementations handle database operations atomically.
 */
public interface MessageRepository {

    /**
     * Save a single message. Upserts if message with same order exists.
     *
     * @param programHash The program hash
     * @param sessionId The session ID
     * @param message The message to save
     * @return The database ID of the saved message, or -1 on failure
     */
    int saveMessage(String programHash, int sessionId, PersistedChatMessage message);

    /**
     * Save multiple messages in a single transaction.
     * Replaces all existing messages for the session.
     *
     * @param programHash The program hash
     * @param sessionId The session ID
     * @param messages The messages to save
     * @return true if successful
     */
    boolean replaceAllMessages(String programHash, int sessionId, List<PersistedChatMessage> messages);

    /**
     * Load all messages for a session, ordered by message_order.
     *
     * @param programHash The program hash
     * @param sessionId The session ID
     * @return List of messages in order
     */
    List<PersistedChatMessage> loadMessages(String programHash, int sessionId);

    /**
     * Delete all messages for a session.
     *
     * @param programHash The program hash
     * @param sessionId The session ID
     * @return Number of deleted messages
     */
    int deleteAllMessages(String programHash, int sessionId);

    /**
     * Check if session has any persisted messages.
     *
     * @param programHash The program hash
     * @param sessionId The session ID
     * @return true if messages exist
     */
    boolean hasMessages(String programHash, int sessionId);

    /**
     * Get message count for a session.
     *
     * @param programHash The program hash
     * @param sessionId The session ID
     * @return Number of messages
     */
    int getMessageCount(String programHash, int sessionId);

    /**
     * Update a specific message's content (for editing).
     *
     * @param messageId The database ID of the message
     * @param newContent The new content
     * @param newMessageType The new message type (e.g., "edited")
     * @return true if successful
     */
    boolean updateMessageContent(int messageId, String newContent, String newMessageType);

    /**
     * Delete a specific message by ID.
     *
     * @param messageId The database ID of the message
     * @return true if deleted
     */
    boolean deleteMessage(int messageId);
}
