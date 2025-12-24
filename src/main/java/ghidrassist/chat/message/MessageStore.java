package ghidrassist.chat.message;

import ghidrassist.apiprovider.ChatMessage;
import ghidrassist.chat.PersistedChatMessage;

import java.util.List;

/**
 * Single source of truth for in-memory chat messages.
 * Replaces the dual conversationHistory/messageList pattern.
 *
 * Implementations must be thread-safe for concurrent access.
 */
public interface MessageStore {

    /**
     * Add a user message to the store.
     *
     * @param content The message content
     * @param providerType The provider type (anthropic/openai/ollama)
     * @param apiMessage Optional API message with tool call info
     */
    void addUserMessage(String content, String providerType, ChatMessage apiMessage);

    /**
     * Add an assistant message to the store.
     *
     * @param content The message content
     * @param providerType The provider type
     * @param apiMessage Optional API message with tool call info
     */
    void addAssistantMessage(String content, String providerType, ChatMessage apiMessage);

    /**
     * Add a tool call message to the store.
     *
     * @param toolName The name of the tool
     * @param args The tool arguments (JSON)
     * @param result The tool result
     */
    void addToolCallMessage(String toolName, String args, String result);

    /**
     * Add an error message to the store.
     *
     * @param errorMessage The error message content
     */
    void addErrorMessage(String errorMessage);

    /**
     * Add a generic message to the store.
     *
     * @param message The message to add
     */
    void addMessage(PersistedChatMessage message);

    /**
     * Get all messages as an immutable list.
     * Returns a defensive copy to prevent external modification.
     *
     * @return List of all messages in order
     */
    List<PersistedChatMessage> getMessages();

    /**
     * Replace all messages (for loading from DB or after edit).
     * This clears the current messages and sets new ones.
     *
     * @param messages The new messages to set
     */
    void setMessages(List<PersistedChatMessage> messages);

    /**
     * Get formatted conversation string for LLM context.
     * Format: **User**:\n{content}\n\n**Assistant**:\n{content}\n\n
     *
     * @return Formatted conversation as a string
     */
    String getFormattedConversation();

    /**
     * Clear all messages.
     */
    void clear();

    /**
     * Get message count.
     *
     * @return Number of messages in the store
     */
    int size();

    /**
     * Check if the store is empty.
     *
     * @return true if no messages in store
     */
    boolean isEmpty();

    /**
     * Get the provider type for the current conversation.
     *
     * @return The current provider type
     */
    String getCurrentProviderType();

    /**
     * Set the current provider type.
     *
     * @param providerType The provider type to set
     */
    void setCurrentProviderType(String providerType);
}
