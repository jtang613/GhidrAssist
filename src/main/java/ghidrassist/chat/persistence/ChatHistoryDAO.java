package ghidrassist.chat.persistence;

import ghidra.util.Msg;
import ghidrassist.chat.PersistedChatMessage;
import ghidrassist.chat.message.MessageRepository;
import ghidrassist.chat.session.ChatSession;
import ghidrassist.chat.session.ChatSessionRepository;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Unified DAO for all chat history database operations.
 * Implements both MessageRepository and ChatSessionRepository interfaces.
 * Uses TransactionManager for atomic multi-statement operations.
 */
public class ChatHistoryDAO implements MessageRepository, ChatSessionRepository {

    private final TransactionManager transactionManager;

    public ChatHistoryDAO(TransactionManager transactionManager) {
        this.transactionManager = transactionManager;
    }

    // ==================== ChatSessionRepository Implementation ====================

    @Override
    public int createSession(String programHash, String description) {
        String sql = "INSERT INTO GHChatHistory (program_hash, description, conversation) VALUES (?, ?, '')";

        try (PreparedStatement pstmt = transactionManager.getConnection()
                .prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            pstmt.setString(1, programHash);
            pstmt.setString(2, description);
            pstmt.executeUpdate();

            ResultSet rs = pstmt.getGeneratedKeys();
            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to create chat session: " + e.getMessage());
        }
        return -1;
    }

    @Override
    public List<ChatSession> getSessionsForProgram(String programHash) {
        List<ChatSession> sessions = new ArrayList<>();
        String sql = "SELECT id, description, last_update FROM GHChatHistory " +
                     "WHERE program_hash = ? ORDER BY last_update DESC";

        try (PreparedStatement pstmt = transactionManager.getConnection().prepareStatement(sql)) {
            pstmt.setString(1, programHash);
            ResultSet rs = pstmt.executeQuery();

            while (rs.next()) {
                sessions.add(new ChatSession.Builder()
                        .id(rs.getInt("id"))
                        .programHash(programHash)
                        .description(rs.getString("description"))
                        .lastUpdate(rs.getTimestamp("last_update"))
                        .build());
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to get chat sessions: " + e.getMessage());
        }
        return sessions;
    }

    @Override
    public Optional<ChatSession> getSession(int sessionId) {
        String sql = "SELECT id, program_hash, description, last_update FROM GHChatHistory WHERE id = ?";

        try (PreparedStatement pstmt = transactionManager.getConnection().prepareStatement(sql)) {
            pstmt.setInt(1, sessionId);
            ResultSet rs = pstmt.executeQuery();

            if (rs.next()) {
                return Optional.of(new ChatSession.Builder()
                        .id(rs.getInt("id"))
                        .programHash(rs.getString("program_hash"))
                        .description(rs.getString("description"))
                        .lastUpdate(rs.getTimestamp("last_update"))
                        .isReActSession(isReActSession(sessionId))
                        .build());
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to get session: " + e.getMessage());
        }
        return Optional.empty();
    }

    @Override
    public boolean updateDescription(int sessionId, String description) {
        String sql = "UPDATE GHChatHistory SET description = ? WHERE id = ?";

        try (PreparedStatement pstmt = transactionManager.getConnection().prepareStatement(sql)) {
            pstmt.setString(1, description);
            pstmt.setInt(2, sessionId);
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            Msg.error(this, "Failed to update description: " + e.getMessage());
            return false;
        }
    }

    @Override
    public boolean touchSession(int sessionId) {
        String sql = "UPDATE GHChatHistory SET last_update = CURRENT_TIMESTAMP WHERE id = ?";

        try (PreparedStatement pstmt = transactionManager.getConnection().prepareStatement(sql)) {
            pstmt.setInt(1, sessionId);
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            Msg.error(this, "Failed to touch session: " + e.getMessage());
            return false;
        }
    }

    @Override
    public boolean deleteSession(int sessionId) {
        // Messages will cascade delete via FK
        String sql = "DELETE FROM GHChatHistory WHERE id = ?";

        try (PreparedStatement pstmt = transactionManager.getConnection().prepareStatement(sql)) {
            pstmt.setInt(1, sessionId);
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            Msg.error(this, "Failed to delete session: " + e.getMessage());
            return false;
        }
    }

    @Override
    public boolean sessionExists(int sessionId) {
        String sql = "SELECT 1 FROM GHChatHistory WHERE id = ?";

        try (PreparedStatement pstmt = transactionManager.getConnection().prepareStatement(sql)) {
            pstmt.setInt(1, sessionId);
            return pstmt.executeQuery().next();
        } catch (SQLException e) {
            return false;
        }
    }

    @Override
    public boolean isReActSession(int sessionId) {
        String sql = "SELECT 1 FROM GHReActMessages WHERE session_id = ? LIMIT 1";

        try (PreparedStatement pstmt = transactionManager.getConnection().prepareStatement(sql)) {
            pstmt.setInt(1, sessionId);
            return pstmt.executeQuery().next();
        } catch (SQLException e) {
            return false;
        }
    }

    @Override
    public int getNextSessionNumber(String programHash) {
        String sql = "SELECT COUNT(*) FROM GHChatHistory WHERE program_hash = ?";

        try (PreparedStatement pstmt = transactionManager.getConnection().prepareStatement(sql)) {
            pstmt.setString(1, programHash);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return rs.getInt(1) + 1;
            }
        } catch (SQLException e) {
            Msg.warn(this, "Failed to get session count: " + e.getMessage());
        }
        return 1;
    }

    @Override
    public String getLegacyConversation(int sessionId) {
        String sql = "SELECT conversation FROM GHChatHistory WHERE id = ?";

        try (PreparedStatement pstmt = transactionManager.getConnection().prepareStatement(sql)) {
            pstmt.setInt(1, sessionId);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return rs.getString("conversation");
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to get legacy conversation: " + e.getMessage());
        }
        return null;
    }

    // ==================== MessageRepository Implementation ====================

    @Override
    public int saveMessage(String programHash, int sessionId, PersistedChatMessage message) {
        // Check if message already exists at this order
        Integer existingId = findExistingMessageId(programHash, sessionId, message.getOrder());

        if (existingId != null) {
            // Update existing message
            return updateExistingMessage(existingId, message) ? existingId : -1;
        } else {
            // Insert new message
            return insertMessage(programHash, sessionId, message);
        }
    }

    @Override
    public boolean replaceAllMessages(String programHash, int sessionId, List<PersistedChatMessage> messages) {
        return transactionManager.executeInTransaction(conn -> {
            try {
                // Delete all existing messages
                deleteAllMessages(programHash, sessionId);

                // Insert all new messages
                for (int i = 0; i < messages.size(); i++) {
                    PersistedChatMessage msg = messages.get(i);
                    // Ensure order is correct
                    if (msg.getOrder() != i) {
                        msg.setOrder(i);
                    }
                    insertMessage(programHash, sessionId, msg);
                }
                return true;
            } catch (Exception e) {
                Msg.error(this, "Failed to replace messages: " + e.getMessage());
                throw new RuntimeException(e);
            }
        });
    }

    @Override
    public List<PersistedChatMessage> loadMessages(String programHash, int sessionId) {
        List<PersistedChatMessage> messages = new ArrayList<>();
        String sql = "SELECT id, role, content_text, message_order, created_at, " +
                     "provider_type, native_message_data, message_type " +
                     "FROM GHChatMessages WHERE program_hash = ? AND chat_id = ? " +
                     "ORDER BY message_order ASC";

        try (PreparedStatement pstmt = transactionManager.getConnection().prepareStatement(sql)) {
            pstmt.setString(1, programHash);
            pstmt.setInt(2, sessionId);

            ResultSet rs = pstmt.executeQuery();
            while (rs.next()) {
                PersistedChatMessage msg = new PersistedChatMessage(
                        rs.getInt("id"),
                        rs.getString("role"),
                        rs.getString("content_text"),
                        rs.getTimestamp("created_at"),
                        rs.getInt("message_order")
                );
                msg.setProviderType(rs.getString("provider_type"));
                msg.setNativeMessageData(rs.getString("native_message_data"));
                msg.setMessageType(rs.getString("message_type"));
                messages.add(msg);
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to load messages: " + e.getMessage());
        }
        return messages;
    }

    @Override
    public int deleteAllMessages(String programHash, int sessionId) {
        String sql = "DELETE FROM GHChatMessages WHERE program_hash = ? AND chat_id = ?";

        try (PreparedStatement pstmt = transactionManager.getConnection().prepareStatement(sql)) {
            pstmt.setString(1, programHash);
            pstmt.setInt(2, sessionId);
            return pstmt.executeUpdate();
        } catch (SQLException e) {
            Msg.error(this, "Failed to delete messages: " + e.getMessage());
            return 0;
        }
    }

    @Override
    public boolean hasMessages(String programHash, int sessionId) {
        return getMessageCount(programHash, sessionId) > 0;
    }

    @Override
    public int getMessageCount(String programHash, int sessionId) {
        String sql = "SELECT COUNT(*) FROM GHChatMessages WHERE program_hash = ? AND chat_id = ?";

        try (PreparedStatement pstmt = transactionManager.getConnection().prepareStatement(sql)) {
            pstmt.setString(1, programHash);
            pstmt.setInt(2, sessionId);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            Msg.warn(this, "Failed to get message count: " + e.getMessage());
        }
        return 0;
    }

    @Override
    public boolean updateMessageContent(int messageId, String newContent, String newMessageType) {
        String sql = "UPDATE GHChatMessages SET content_text = ?, message_type = ?, " +
                     "updated_at = CURRENT_TIMESTAMP WHERE id = ?";

        try (PreparedStatement pstmt = transactionManager.getConnection().prepareStatement(sql)) {
            pstmt.setString(1, newContent);
            pstmt.setString(2, newMessageType != null ? newMessageType : "edited");
            pstmt.setInt(3, messageId);
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            Msg.error(this, "Failed to update message content: " + e.getMessage());
            return false;
        }
    }

    @Override
    public boolean deleteMessage(int messageId) {
        String sql = "DELETE FROM GHChatMessages WHERE id = ?";

        try (PreparedStatement pstmt = transactionManager.getConnection().prepareStatement(sql)) {
            pstmt.setInt(1, messageId);
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            Msg.error(this, "Failed to delete message: " + e.getMessage());
            return false;
        }
    }

    // ==================== Private Helper Methods ====================

    private Integer findExistingMessageId(String programHash, int sessionId, int order) {
        String sql = "SELECT id FROM GHChatMessages WHERE program_hash = ? AND chat_id = ? AND message_order = ?";

        try (PreparedStatement pstmt = transactionManager.getConnection().prepareStatement(sql)) {
            pstmt.setString(1, programHash);
            pstmt.setInt(2, sessionId);
            pstmt.setInt(3, order);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return rs.getInt("id");
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to find message: " + e.getMessage());
        }
        return null;
    }

    private boolean updateExistingMessage(int messageId, PersistedChatMessage message) {
        String sql = "UPDATE GHChatMessages SET provider_type = ?, native_message_data = ?, " +
                     "role = ?, content_text = ?, message_type = ?, updated_at = CURRENT_TIMESTAMP " +
                     "WHERE id = ?";

        try (PreparedStatement pstmt = transactionManager.getConnection().prepareStatement(sql)) {
            pstmt.setString(1, message.getProviderType());
            pstmt.setString(2, message.getNativeMessageData() != null ? message.getNativeMessageData() : "{}");
            pstmt.setString(3, message.getRole());
            pstmt.setString(4, message.getContent());
            pstmt.setString(5, message.getMessageType() != null ? message.getMessageType() : "standard");
            pstmt.setInt(6, messageId);
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            Msg.error(this, "Failed to update message: " + e.getMessage());
            return false;
        }
    }

    private int insertMessage(String programHash, int sessionId, PersistedChatMessage message) {
        // Simplified INSERT without legacy columns (session_id, sequence_number)
        String sql = "INSERT INTO GHChatMessages " +
                     "(program_hash, chat_id, message_order, provider_type, native_message_data, " +
                     "role, content_text, message_type, created_at, updated_at) " +
                     "VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)";

        try (PreparedStatement pstmt = transactionManager.getConnection()
                .prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            pstmt.setString(1, programHash);
            pstmt.setInt(2, sessionId);
            pstmt.setInt(3, message.getOrder());
            pstmt.setString(4, message.getProviderType() != null ? message.getProviderType() : "unknown");
            pstmt.setString(5, message.getNativeMessageData() != null ? message.getNativeMessageData() : "{}");
            pstmt.setString(6, message.getRole());
            pstmt.setString(7, message.getContent());
            pstmt.setString(8, message.getMessageType() != null ? message.getMessageType() : "standard");
            pstmt.executeUpdate();

            ResultSet rs = pstmt.getGeneratedKeys();
            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to insert message: " + e.getMessage());
        }
        return -1;
    }
}
