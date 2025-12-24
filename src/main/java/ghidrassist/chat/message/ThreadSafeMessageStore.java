package ghidrassist.chat.message;

import ghidrassist.apiprovider.ChatMessage;
import ghidrassist.chat.PersistedChatMessage;
import ghidrassist.chat.util.RoleNormalizer;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Thread-safe implementation of MessageStore.
 * Uses ReadWriteLock for concurrent access - allows concurrent reads during LLM streaming,
 * with exclusive lock only for writes.
 *
 * Replaces the dual conversationHistory/messageList pattern with a single source of truth.
 */
public class ThreadSafeMessageStore implements MessageStore {

    private final ReadWriteLock lock = new ReentrantReadWriteLock();
    private final List<PersistedChatMessage> messages = new ArrayList<>();
    private volatile String cachedConversation = null;
    private volatile String currentProviderType = "unknown";

    @Override
    public void addUserMessage(String content, String providerType, ChatMessage apiMessage) {
        PersistedChatMessage msg = createMessage(
                RoleNormalizer.ROLE_USER,
                content,
                providerType,
                apiMessage,
                "standard"
        );
        addMessage(msg);
    }

    @Override
    public void addAssistantMessage(String content, String providerType, ChatMessage apiMessage) {
        String messageType = (apiMessage != null && apiMessage.getToolCalls() != null)
                ? "tool_call" : "standard";

        PersistedChatMessage msg = createMessage(
                RoleNormalizer.ROLE_ASSISTANT,
                content,
                providerType,
                apiMessage,
                messageType
        );
        addMessage(msg);
    }

    @Override
    public void addToolCallMessage(String toolName, String args, String result) {
        String content = String.format("Tool: %s\nArguments: %s\nResult: %s", toolName, args, result);
        String nativeData = String.format("{\"tool\":\"%s\",\"args\":%s,\"result\":\"%s\"}",
                escapeJson(toolName), args, escapeJson(result));

        lock.writeLock().lock();
        try {
            PersistedChatMessage msg = new PersistedChatMessage(
                    null,
                    RoleNormalizer.ROLE_TOOL_CALL,
                    content,
                    new Timestamp(System.currentTimeMillis()),
                    messages.size()
            );
            msg.setProviderType(currentProviderType);
            msg.setNativeMessageData(nativeData);
            msg.setMessageType("tool_call");

            messages.add(msg);
            cachedConversation = null; // Invalidate cache
        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    public void addErrorMessage(String errorMessage) {
        lock.writeLock().lock();
        try {
            PersistedChatMessage msg = new PersistedChatMessage(
                    null,
                    RoleNormalizer.ROLE_ERROR,
                    errorMessage,
                    new Timestamp(System.currentTimeMillis()),
                    messages.size()
            );
            msg.setProviderType(currentProviderType);
            msg.setNativeMessageData("{}");
            msg.setMessageType("standard");

            messages.add(msg);
            cachedConversation = null; // Invalidate cache
        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    public void addMessage(PersistedChatMessage message) {
        lock.writeLock().lock();
        try {
            messages.add(message);
            cachedConversation = null; // Invalidate cache
        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    public List<PersistedChatMessage> getMessages() {
        lock.readLock().lock();
        try {
            // Return defensive copy
            return new ArrayList<>(messages);
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public void setMessages(List<PersistedChatMessage> newMessages) {
        lock.writeLock().lock();
        try {
            messages.clear();
            if (newMessages != null) {
                messages.addAll(newMessages);
            }
            cachedConversation = null; // Invalidate cache
        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    public String getFormattedConversation() {
        lock.readLock().lock();
        try {
            if (cachedConversation == null) {
                cachedConversation = formatMessages();
            }
            return cachedConversation;
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public void clear() {
        lock.writeLock().lock();
        try {
            messages.clear();
            cachedConversation = null;
        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    public int size() {
        lock.readLock().lock();
        try {
            return messages.size();
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public boolean isEmpty() {
        lock.readLock().lock();
        try {
            return messages.isEmpty();
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public String getCurrentProviderType() {
        return currentProviderType;
    }

    @Override
    public void setCurrentProviderType(String providerType) {
        this.currentProviderType = providerType != null ? providerType : "unknown";
    }

    // ==================== Private Helper Methods ====================

    /**
     * Create a PersistedChatMessage with proper initialization.
     */
    private PersistedChatMessage createMessage(String role, String content, String providerType,
                                                ChatMessage apiMessage, String messageType) {
        lock.writeLock().lock();
        try {
            PersistedChatMessage msg = new PersistedChatMessage(
                    null,
                    role,
                    content,
                    new Timestamp(System.currentTimeMillis()),
                    messages.size()
            );
            msg.setProviderType(providerType != null ? providerType : currentProviderType);
            msg.setNativeMessageData(serializeToolInfo(apiMessage));
            msg.setMessageType(messageType);
            return msg;
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Format all messages into a conversation string.
     * Format: **User**:\n{content}\n\n**Assistant**:\n{content}\n\n
     */
    private String formatMessages() {
        StringBuilder sb = new StringBuilder();
        for (PersistedChatMessage msg : messages) {
            String displayRole = RoleNormalizer.toDisplayFormat(msg.getRole());
            sb.append("**").append(displayRole).append("**:\n");
            sb.append(msg.getContent()).append("\n\n");
        }
        return sb.toString();
    }

    /**
     * Serialize essential tool info from ChatMessage to JSON.
     */
    private static String serializeToolInfo(ChatMessage apiMessage) {
        if (apiMessage == null) {
            return "{}";
        }

        if (apiMessage.getToolCalls() != null) {
            try {
                StringBuilder json = new StringBuilder("{\"tool_calls\":[");
                String toolCallsStr = apiMessage.getToolCalls().toString();
                json.append(toolCallsStr);
                json.append("]}");
                return json.toString();
            } catch (Exception e) {
                return "{}";
            }
        }

        return "{}";
    }

    /**
     * Escape string for JSON.
     */
    private static String escapeJson(String input) {
        if (input == null) {
            return "";
        }
        return input.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
