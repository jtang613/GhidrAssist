package ghidrassist;

import ghidra.framework.preferences.Preferences;
import ghidra.program.model.address.Address;
import ghidra.util.Msg;
import ghidrassist.chat.PersistedChatMessage;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class AnalysisDB {
    private static final String DB_PATH_PROPERTY = "GhidrAssist.AnalysisDBPath";
    private static final String DEFAULT_DB_PATH = "ghidrassist_analysis.db";
    private Connection connection;

    public AnalysisDB() {
        String dbPath = Preferences.getProperty(DB_PATH_PROPERTY, DEFAULT_DB_PATH);
        initializeDatabase(dbPath);
    }

    private void initializeDatabase(String dbPath) {
        try {
            connection = DriverManager.getConnection("jdbc:sqlite:" + dbPath);
            createAnalysisTables();
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error", "Failed to initialize Analysis database: " + e.getMessage());
        }
    }

    private void createAnalysisTables() throws SQLException {
        String createTableSQL = "CREATE TABLE IF NOT EXISTS GHAnalysis ("
                + "program_hash TEXT NOT NULL,"
                + "function_address TEXT NOT NULL,"
                + "query TEXT NOT NULL,"
                + "response TEXT NOT NULL,"
                + "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,"
                + "PRIMARY KEY (program_hash, function_address)"
                + ")";
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(createTableSQL);
        }

        String createContextTableSQL = "CREATE TABLE IF NOT EXISTS GHContext ("
                + "program_hash TEXT PRIMARY KEY,"
                + "system_context TEXT NOT NULL,"
                + "reasoning_effort TEXT DEFAULT 'none',"
                + "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP"
                + ")";
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(createContextTableSQL);
        }

        // Migration: Add reasoning_effort column if it doesn't exist
        try (Statement stmt = connection.createStatement()) {
            stmt.execute("ALTER TABLE GHContext ADD COLUMN reasoning_effort TEXT DEFAULT 'none'");
        } catch (SQLException e) {
            // Column already exists, ignore
        }
        
        String createChatHistoryTableSQL = "CREATE TABLE IF NOT EXISTS GHChatHistory ("
                + "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                + "program_hash TEXT NOT NULL,"
                + "description TEXT NOT NULL,"
                + "conversation TEXT NOT NULL,"
                + "last_update DATETIME DEFAULT CURRENT_TIMESTAMP"
                + ")";
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(createChatHistoryTableSQL);
        }

        // Per-message storage table for enhanced chat history
        // First check if table exists with wrong schema and drop it if needed
        migrateChatMessagesTable();

        String createChatMessagesTableSQL = "CREATE TABLE IF NOT EXISTS GHChatMessages ("
                + "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                + "program_hash TEXT NOT NULL,"
                + "chat_id INTEGER NOT NULL,"
                + "message_order INTEGER NOT NULL,"
                + "provider_type TEXT NOT NULL,"
                + "native_message_data TEXT NOT NULL,"
                + "role TEXT NOT NULL,"
                + "content_text TEXT,"
                + "message_type TEXT DEFAULT 'standard',"
                + "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
                + "updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
                + "UNIQUE(program_hash, chat_id, message_order),"
                + "FOREIGN KEY (chat_id) REFERENCES GHChatHistory(id) ON DELETE CASCADE"
                + ")";
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(createChatMessagesTableSQL);
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_chat_messages_lookup "
                    + "ON GHChatMessages(program_hash, chat_id, message_order)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_chat_messages_role "
                    + "ON GHChatMessages(role)");
        }

        // ReAct agent conversation storage with chunked iterations
        String createReActMessagesTableSQL = "CREATE TABLE IF NOT EXISTS GHReActMessages ("
                + "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                + "program_hash TEXT NOT NULL,"
                + "session_id INTEGER NOT NULL,"
                + "message_order INTEGER NOT NULL,"
                + "phase TEXT NOT NULL,"  // "planning", "investigation", "reflection", "synthesis"
                + "iteration_number INTEGER,"
                + "role TEXT NOT NULL,"  // "system", "user", "assistant", "tool"
                + "content_text TEXT,"
                + "native_message_data TEXT,"  // JSON: tool_calls, tool_call_id, etc.
                + "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
                + "UNIQUE(program_hash, session_id, message_order),"
                + "FOREIGN KEY (session_id) REFERENCES GHChatHistory(id) ON DELETE CASCADE"
                + ")";
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(createReActMessagesTableSQL);
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_react_messages_lookup "
                    + "ON GHReActMessages(program_hash, session_id, phase, iteration_number)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_react_messages_order "
                    + "ON GHReActMessages(session_id, message_order)");
        }

        // ReAct iteration chunks for context boundaries
        String createReActIterationChunksTableSQL = "CREATE TABLE IF NOT EXISTS GHReActIterationChunks ("
                + "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                + "program_hash TEXT NOT NULL,"
                + "session_id INTEGER NOT NULL,"
                + "iteration_number INTEGER NOT NULL,"
                + "iteration_summary TEXT,"  // LLM's analysis summary
                + "message_start_index INTEGER NOT NULL,"
                + "message_end_index INTEGER NOT NULL,"
                + "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
                + "UNIQUE(program_hash, session_id, iteration_number),"
                + "FOREIGN KEY (session_id) REFERENCES GHChatHistory(id) ON DELETE CASCADE"
                + ")";
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(createReActIterationChunksTableSQL);
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_react_chunks_lookup "
                    + "ON GHReActIterationChunks(program_hash, session_id, iteration_number)");
        }
    }

    /**
     * Migrate GHChatMessages table - add any missing columns.
     * Uses PRAGMA table_info to check what columns actually exist.
     */
    private void migrateChatMessagesTable() {
        // First check if table exists
        boolean tableExists = false;
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(
                 "SELECT name FROM sqlite_master WHERE type='table' AND name='GHChatMessages'")) {
            tableExists = rs.next();
        } catch (SQLException e) {
            Msg.error(this, "Failed to check if GHChatMessages table exists: " + e.getMessage());
            return;
        }

        if (!tableExists) {
            // Table doesn't exist - let CREATE TABLE IF NOT EXISTS handle it
            return;
        }

        // Table exists - get existing columns
        java.util.Set<String> existingColumns = new java.util.HashSet<>();
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery("PRAGMA table_info(GHChatMessages)")) {
            while (rs.next()) {
                existingColumns.add(rs.getString("name").toLowerCase());
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to get GHChatMessages columns: " + e.getMessage());
            return;
        }

        Msg.info(this, "GHChatMessages existing columns: " + existingColumns);

        // Define columns to add with their definitions
        // Note: SQLite ALTER TABLE cannot use non-constant defaults like CURRENT_TIMESTAMP
        // So we add these columns without defaults and handle timestamps in INSERT/UPDATE
        String[][] columnsToAdd = {
            {"program_hash", "TEXT"},
            {"chat_id", "INTEGER"},
            {"message_order", "INTEGER"},
            {"provider_type", "TEXT"},
            {"native_message_data", "TEXT"},
            {"role", "TEXT"},
            {"content_text", "TEXT"},
            {"message_type", "TEXT DEFAULT 'standard'"},
            {"created_at", "TIMESTAMP"},
            {"updated_at", "TIMESTAMP"}
        };

        // Add only missing columns
        for (String[] colDef : columnsToAdd) {
            String colName = colDef[0];
            String colType = colDef[1];
            if (!existingColumns.contains(colName.toLowerCase())) {
                String alterSql = "ALTER TABLE GHChatMessages ADD COLUMN " + colName + " " + colType;
                try (Statement stmt = connection.createStatement()) {
                    stmt.execute(alterSql);
                    Msg.info(this, "Added missing column to GHChatMessages: " + colName);
                } catch (SQLException e) {
                    Msg.error(this, "Failed to add column " + colName + " to GHChatMessages: " + e.getMessage());
                }
            }
        }
    }

    public void upsertAnalysis(String programHash, Address functionAddress, String query, String response) {
        String upsertSQL = "INSERT INTO GHAnalysis (program_hash, function_address, query, response) "
                + "VALUES (?, ?, ?, ?) "
                + "ON CONFLICT(program_hash, function_address) "
                + "DO UPDATE SET query = ?, response = ?, timestamp = CURRENT_TIMESTAMP";
        
        try (PreparedStatement pstmt = connection.prepareStatement(upsertSQL)) {
            pstmt.setString(1, programHash);
            pstmt.setString(2, functionAddress.toString());
            pstmt.setString(3, query);
            pstmt.setString(4, response);
            pstmt.setString(5, query);
            pstmt.setString(6, response);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error", "Failed to store analysis: " + e.getMessage());
        }
    }

    /**
     * Deletes the analysis entry for the specified program and function
     * 
     * @param programHash The hash of the program
     * @param functionAddress The address of the function
     * @return true if an entry was deleted, false otherwise
     */
    public boolean deleteAnalysis(String programHash, Address functionAddress) {
        String deleteSQL = "DELETE FROM GHAnalysis WHERE program_hash = ? AND function_address = ?";
        
        if (programHash == null || functionAddress == null) {
            Msg.error(this, "Cannot delete analysis: programHash or functionAddress is null");
            return false;
        }
        
        Msg.info(this, "Attempting to delete analysis for " + programHash + " at " + functionAddress.toString());
        
        try (PreparedStatement pstmt = connection.prepareStatement(deleteSQL)) {
            pstmt.setString(1, programHash);
            pstmt.setString(2, functionAddress.toString());
            
            int rowsAffected = pstmt.executeUpdate();
            Msg.info(this, "Delete operation affected " + rowsAffected + " rows");
            return rowsAffected > 0;
        } catch (SQLException e) {
            Msg.error(this, "Failed to delete analysis: " + e.getMessage());
            return false;
        }
    }

    public Analysis getAnalysis(String programHash, Address functionAddress) {
        String selectSQL = "SELECT query, response, timestamp FROM GHAnalysis "
                + "WHERE program_hash = ? AND function_address = ?";
        
        try (PreparedStatement pstmt = connection.prepareStatement(selectSQL)) {
            pstmt.setString(1, programHash);
            pstmt.setString(2, functionAddress.toString());
            
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return new Analysis(
                    rs.getString("query"),
                    rs.getString("response"),
                    rs.getTimestamp("timestamp")
                );
            }
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error", "Failed to retrieve analysis: " + e.getMessage());
        }
        return null;
    }

    public void upsertContext(String programHash, String context) {
        if (context == null) {
            // If context is null, delete the entry to revert to default
            deleteContext(programHash);
            return;
        }
        
        String upsertSQL = "INSERT INTO GHContext (program_hash, system_context) "
                + "VALUES (?, ?) "
                + "ON CONFLICT(program_hash) "
                + "DO UPDATE SET system_context = ?, timestamp = CURRENT_TIMESTAMP";
        
        try (PreparedStatement pstmt = connection.prepareStatement(upsertSQL)) {
            pstmt.setString(1, programHash);
            pstmt.setString(2, context);
            pstmt.setString(3, context);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error", "Failed to store context: " + e.getMessage());
        }
    }
    
    public void deleteContext(String programHash) {
        String deleteSQL = "DELETE FROM GHContext WHERE program_hash = ?";
        
        try (PreparedStatement pstmt = connection.prepareStatement(deleteSQL)) {
            pstmt.setString(1, programHash);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error", "Failed to delete context: " + e.getMessage());
        }
    }

    public String getContext(String programHash) {
        String selectSQL = "SELECT system_context FROM GHContext WHERE program_hash = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(selectSQL)) {
            pstmt.setString(1, programHash);

            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return rs.getString("system_context");
            }
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error", "Failed to retrieve context: " + e.getMessage());
        }
        return null;
    }

    public void upsertReasoningEffort(String programHash, String reasoningEffort) {
        if (reasoningEffort == null || reasoningEffort.equalsIgnoreCase("none")) {
            reasoningEffort = "none";
        }

        // Check if context entry exists
        String selectSQL = "SELECT program_hash FROM GHContext WHERE program_hash = ?";
        boolean exists = false;
        try (PreparedStatement pstmt = connection.prepareStatement(selectSQL)) {
            pstmt.setString(1, programHash);
            ResultSet rs = pstmt.executeQuery();
            exists = rs.next();
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error", "Failed to check context: " + e.getMessage());
            return;
        }

        if (!exists) {
            // Create entry with default context
            String insertSQL = "INSERT INTO GHContext (program_hash, system_context, reasoning_effort) VALUES (?, '', ?)";
            try (PreparedStatement pstmt = connection.prepareStatement(insertSQL)) {
                pstmt.setString(1, programHash);
                pstmt.setString(2, reasoningEffort);
                pstmt.executeUpdate();
            } catch (SQLException e) {
                Msg.showError(this, null, "Database Error", "Failed to insert reasoning effort: " + e.getMessage());
            }
        } else {
            // Update existing entry
            String updateSQL = "UPDATE GHContext SET reasoning_effort = ?, timestamp = CURRENT_TIMESTAMP WHERE program_hash = ?";
            try (PreparedStatement pstmt = connection.prepareStatement(updateSQL)) {
                pstmt.setString(1, reasoningEffort);
                pstmt.setString(2, programHash);
                pstmt.executeUpdate();
            } catch (SQLException e) {
                Msg.showError(this, null, "Database Error", "Failed to update reasoning effort: " + e.getMessage());
            }
        }
    }

    public String getReasoningEffort(String programHash) {
        String selectSQL = "SELECT reasoning_effort FROM GHContext WHERE program_hash = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(selectSQL)) {
            pstmt.setString(1, programHash);

            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                String effort = rs.getString("reasoning_effort");
                return effort != null ? effort : "none";
            }
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error", "Failed to retrieve reasoning effort: " + e.getMessage());
        }
        return "none"; // Default to none if not found
    }

    // Chat History Methods
    
    public int createChatSession(String programHash, String description, String conversation) {
        String insertSQL = "INSERT INTO GHChatHistory (program_hash, description, conversation) VALUES (?, ?, ?)";
        
        try (PreparedStatement pstmt = connection.prepareStatement(insertSQL, Statement.RETURN_GENERATED_KEYS)) {
            pstmt.setString(1, programHash);
            pstmt.setString(2, description);
            pstmt.setString(3, conversation);
            pstmt.executeUpdate();
            
            ResultSet rs = pstmt.getGeneratedKeys();
            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error", "Failed to create chat session: " + e.getMessage());
        }
        return -1;
    }
    
    public void updateChatSession(int sessionId, String conversation) {
        String updateSQL = "UPDATE GHChatHistory SET conversation = ?, last_update = CURRENT_TIMESTAMP WHERE id = ?";
        
        try (PreparedStatement pstmt = connection.prepareStatement(updateSQL)) {
            pstmt.setString(1, conversation);
            pstmt.setInt(2, sessionId);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error", "Failed to update chat session: " + e.getMessage());
        }
    }
    
    public void updateChatDescription(int sessionId, String description) {
        String updateSQL = "UPDATE GHChatHistory SET description = ? WHERE id = ?";
        
        try (PreparedStatement pstmt = connection.prepareStatement(updateSQL)) {
            pstmt.setString(1, description);
            pstmt.setInt(2, sessionId);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error", "Failed to update chat description: " + e.getMessage());
        }
    }
    
    public boolean deleteChatSession(int sessionId) {
        String deleteSQL = "DELETE FROM GHChatHistory WHERE id = ?";
        
        try (PreparedStatement pstmt = connection.prepareStatement(deleteSQL)) {
            pstmt.setInt(1, sessionId);
            int rowsAffected = pstmt.executeUpdate();
            return rowsAffected > 0;
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error", "Failed to delete chat session: " + e.getMessage());
            return false;
        }
    }
    
    public java.util.List<ChatSession> getChatSessions(String programHash) {
        java.util.List<ChatSession> sessions = new java.util.ArrayList<>();
        String selectSQL = "SELECT id, description, last_update FROM GHChatHistory WHERE program_hash = ? ORDER BY last_update DESC";
        
        try (PreparedStatement pstmt = connection.prepareStatement(selectSQL)) {
            pstmt.setString(1, programHash);
            
            ResultSet rs = pstmt.executeQuery();
            while (rs.next()) {
                sessions.add(new ChatSession(
                    rs.getInt("id"),
                    rs.getString("description"),
                    rs.getTimestamp("last_update")
                ));
            }
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error", "Failed to retrieve chat sessions: " + e.getMessage());
        }
        return sessions;
    }
    
    public String getChatConversation(int sessionId) {
        String selectSQL = "SELECT conversation FROM GHChatHistory WHERE id = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(selectSQL)) {
            pstmt.setInt(1, sessionId);

            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return rs.getString("conversation");
            }
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error", "Failed to retrieve chat conversation: " + e.getMessage());
        }
        return null;
    }

    // Per-Message Storage Methods

    /**
     * Save a single chat message to the per-message storage.
     *
     * @param programHash Program hash
     * @param chatId Chat session ID
     * @param order Message order in conversation
     * @param providerType Provider type (anthropic/openai/ollama/edited)
     * @param nativeData JSON with essential tool info
     * @param role Message role
     * @param content Message content
     * @param messageType Message type (standard/tool_call/tool_response/edited)
     * @return Generated message ID, or -1 on failure
     */
    public int saveMessage(String programHash, int chatId, int order,
                           String providerType, String nativeData,
                           String role, String content, String messageType) {
        // Check if row exists
        String checkSql = "SELECT id FROM GHChatMessages WHERE program_hash = ? AND chat_id = ? AND message_order = ?";
        int existingId = -1;

        try (PreparedStatement checkStmt = connection.prepareStatement(checkSql)) {
            checkStmt.setString(1, programHash);
            checkStmt.setInt(2, chatId);
            checkStmt.setInt(3, order);
            ResultSet rs = checkStmt.executeQuery();
            if (rs.next()) {
                existingId = rs.getInt("id");
            }
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error", "Failed to check existing message: " + e.getMessage());
            return -1;
        }

        if (existingId > 0) {
            // Update existing row
            String updateSql = "UPDATE GHChatMessages SET provider_type = ?, native_message_data = ?, "
                    + "role = ?, content_text = ?, message_type = ?, updated_at = CURRENT_TIMESTAMP "
                    + "WHERE id = ?";
            try (PreparedStatement pstmt = connection.prepareStatement(updateSql)) {
                pstmt.setString(1, providerType);
                pstmt.setString(2, nativeData != null ? nativeData : "{}");
                pstmt.setString(3, role);
                pstmt.setString(4, content);
                pstmt.setString(5, messageType != null ? messageType : "standard");
                pstmt.setInt(6, existingId);
                pstmt.executeUpdate();
                return existingId;
            } catch (SQLException e) {
                Msg.showError(this, null, "Database Error", "Failed to update message: " + e.getMessage());
                return -1;
            }
        } else {
            // Insert new row
            // Note: session_id and sequence_number included for compatibility with older table schemas
            String insertSql = "INSERT INTO GHChatMessages "
                    + "(program_hash, chat_id, session_id, message_order, sequence_number, provider_type, native_message_data, "
                    + "role, content_text, message_type, created_at, updated_at) "
                    + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)";
            try (PreparedStatement pstmt = connection.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS)) {
                pstmt.setString(1, programHash);
                pstmt.setInt(2, chatId);
                pstmt.setInt(3, chatId);  // session_id = chat_id for compatibility
                pstmt.setInt(4, order);
                pstmt.setInt(5, order);   // sequence_number = message_order for compatibility
                pstmt.setString(6, providerType);
                pstmt.setString(7, nativeData != null ? nativeData : "{}");
                pstmt.setString(8, role);
                pstmt.setString(9, content);
                pstmt.setString(10, messageType != null ? messageType : "standard");
                pstmt.executeUpdate();

                ResultSet rs = pstmt.getGeneratedKeys();
                if (rs.next()) {
                    return rs.getInt(1);
                }
            } catch (SQLException e) {
                Msg.showError(this, null, "Database Error", "Failed to insert message: " + e.getMessage());
            }
        }
        return -1;
    }

    /**
     * Get all messages for a chat session.
     *
     * @param programHash Program hash
     * @param chatId Chat session ID
     * @return List of PersistedChatMessage objects, ordered by message_order
     */
    public List<PersistedChatMessage> getMessages(String programHash, int chatId) {
        List<PersistedChatMessage> messages = new ArrayList<>();
        // Use COALESCE to fall back to timestamp column for older rows without created_at
        String sql = "SELECT id, role, content_text, message_order, "
                + "COALESCE(created_at, timestamp, CURRENT_TIMESTAMP) as created_at, "
                + "provider_type, native_message_data, message_type "
                + "FROM GHChatMessages WHERE program_hash = ? AND chat_id = ? "
                + "ORDER BY message_order ASC";

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, programHash);
            pstmt.setInt(2, chatId);

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
            Msg.showError(this, null, "Database Error",
                    "Failed to retrieve messages: " + e.getMessage());
        }
        return messages;
    }

    /**
     * Delete all messages for a chat session.
     *
     * @param programHash Program hash
     * @param chatId Chat session ID
     * @return Number of messages deleted
     */
    public int deleteMessages(String programHash, int chatId) {
        String sql = "DELETE FROM GHChatMessages WHERE program_hash = ? AND chat_id = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, programHash);
            pstmt.setInt(2, chatId);
            return pstmt.executeUpdate();
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error",
                    "Failed to delete messages: " + e.getMessage());
        }
        return 0;
    }

    /**
     * Check if a chat session has per-message storage (has been migrated).
     *
     * @param programHash Program hash
     * @param chatId Chat session ID
     * @return true if the session has per-message storage
     */
    public boolean hasPerMessageStorage(String programHash, int chatId) {
        String sql = "SELECT COUNT(*) FROM GHChatMessages WHERE program_hash = ? AND chat_id = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, programHash);
            pstmt.setInt(2, chatId);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return rs.getInt(1) > 0;
            }
        } catch (SQLException e) {
            // Table may not exist yet in older databases
            Msg.warn(this, "Error checking per-message storage: " + e.getMessage());
        }
        return false;
    }

    /**
     * Get the count of messages in a chat session.
     *
     * @param programHash Program hash
     * @param chatId Chat session ID
     * @return Number of messages
     */
    public int getMessageCount(String programHash, int chatId) {
        String sql = "SELECT COUNT(*) FROM GHChatMessages WHERE program_hash = ? AND chat_id = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, programHash);
            pstmt.setInt(2, chatId);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            Msg.warn(this, "Error getting message count: " + e.getMessage());
        }
        return 0;
    }

    public void close() {
        try {
            if (connection != null && !connection.isClosed()) {
                connection.close();
            }
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error", "Failed to close Analysis database connection: " + e.getMessage());
        }
    }

    public static class Analysis {
        private final String query;
        private final String response;
        private final Timestamp timestamp;

        public Analysis(String query, String response, Timestamp timestamp) {
            this.query = query;
            this.response = response;
            this.timestamp = timestamp;
        }

        public String getQuery() { return query; }
        public String getResponse() { return response; }
        public Timestamp getTimestamp() { return timestamp; }
    }
    
    public static class ChatSession {
        private final int id;
        private final String description;
        private final Timestamp lastUpdate;

        public ChatSession(int id, String description, Timestamp lastUpdate) {
            this.id = id;
            this.description = description;
            this.lastUpdate = lastUpdate;
        }

        public int getId() { return id; }
        public String getDescription() { return description; }
        public Timestamp getLastUpdate() { return lastUpdate; }
    }

    // ReAct Message Storage Methods

    /**
     * Save a ReAct message to GHReActMessages table.
     *
     * @param programHash Program hash
     * @param sessionId Chat session ID
     * @param messageOrder Message order in conversation
     * @param phase Current phase (planning/investigation/reflection/synthesis)
     * @param iterationNumber Iteration number (null for planning/synthesis)
     * @param message ChatMessage to save
     * @return Generated message ID, or -1 on failure
     */
    public int saveReActMessage(String programHash, int sessionId, int messageOrder,
                                String phase, Integer iterationNumber,
                                ghidrassist.apiprovider.ChatMessage message) {
        String sql = "INSERT OR REPLACE INTO GHReActMessages " +
                "(program_hash, session_id, message_order, phase, iteration_number, role, content_text, native_message_data) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

        try (PreparedStatement pstmt = connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            pstmt.setString(1, programHash);
            pstmt.setInt(2, sessionId);
            pstmt.setInt(3, messageOrder);
            pstmt.setString(4, phase);
            if (iterationNumber != null) {
                pstmt.setInt(5, iterationNumber);
            } else {
                pstmt.setNull(5, java.sql.Types.INTEGER);
            }
            pstmt.setString(6, message.getRole());
            pstmt.setString(7, message.getContent());

            // Store native message data as JSON (tool_calls, tool_call_id, etc.)
            String nativeData = serializeMessageMetadata(message);
            pstmt.setString(8, nativeData);

            pstmt.executeUpdate();

            ResultSet rs = pstmt.getGeneratedKeys();
            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to save ReAct message: " + e.getMessage(), e);
        }
        return -1;
    }

    /**
     * Save a ReAct iteration chunk to GHReActIterationChunks table.
     *
     * @param programHash Program hash
     * @param sessionId Chat session ID
     * @param iterationNumber Iteration number
     * @param summary Iteration summary from LLM
     * @param messageStartIndex Start index in message list
     * @param messageEndIndex End index in message list
     * @return Generated chunk ID, or -1 on failure
     */
    public int saveReActIterationChunk(String programHash, int sessionId, int iterationNumber,
                                       String summary, int messageStartIndex, int messageEndIndex) {
        String sql = "INSERT OR REPLACE INTO GHReActIterationChunks " +
                "(program_hash, session_id, iteration_number, iteration_summary, message_start_index, message_end_index) " +
                "VALUES (?, ?, ?, ?, ?, ?)";

        try (PreparedStatement pstmt = connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            pstmt.setString(1, programHash);
            pstmt.setInt(2, sessionId);
            pstmt.setInt(3, iterationNumber);
            pstmt.setString(4, summary);
            pstmt.setInt(5, messageStartIndex);
            pstmt.setInt(6, messageEndIndex);

            pstmt.executeUpdate();

            ResultSet rs = pstmt.getGeneratedKeys();
            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to save ReAct iteration chunk: " + e.getMessage(), e);
        }
        return -1;
    }

    /**
     * Serialize ChatMessage metadata to JSON for storage.
     */
    private String serializeMessageMetadata(ghidrassist.apiprovider.ChatMessage message) {
        com.google.gson.JsonObject json = new com.google.gson.JsonObject();

        if (message.getToolCalls() != null) {
            json.add("tool_calls", message.getToolCalls());
        }
        if (message.getToolCallId() != null) {
            json.addProperty("tool_call_id", message.getToolCallId());
        }
        if (message.getThinkingContent() != null) {
            json.addProperty("thinking_content", message.getThinkingContent());
        }
        if (message.getThinkingSignature() != null) {
            json.addProperty("thinking_signature", message.getThinkingSignature());
        }

        return json.toString();
    }

    /**
     * Get ReAct messages for a session.
     *
     * @param programHash Program hash
     * @param sessionId Session ID
     * @return List of messages ordered by message_order
     */
    public List<ghidrassist.apiprovider.ChatMessage> getReActMessages(String programHash, int sessionId) {
        List<ghidrassist.apiprovider.ChatMessage> messages = new ArrayList<>();
        String sql = "SELECT role, content_text, native_message_data FROM GHReActMessages " +
                "WHERE program_hash = ? AND session_id = ? ORDER BY message_order ASC";

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, programHash);
            pstmt.setInt(2, sessionId);

            ResultSet rs = pstmt.executeQuery();
            com.google.gson.Gson gson = new com.google.gson.Gson();

            while (rs.next()) {
                String role = rs.getString("role");
                String content = rs.getString("content_text");
                String nativeData = rs.getString("native_message_data");

                ghidrassist.apiprovider.ChatMessage message = new ghidrassist.apiprovider.ChatMessage(role, content);

                // Restore metadata from JSON
                if (nativeData != null && !nativeData.isEmpty()) {
                    try {
                        com.google.gson.JsonObject json = gson.fromJson(nativeData, com.google.gson.JsonObject.class);

                        if (json.has("tool_calls")) {
                            message.setToolCalls(json.get("tool_calls").getAsJsonArray());
                        }
                        if (json.has("tool_call_id")) {
                            message.setToolCallId(json.get("tool_call_id").getAsString());
                        }
                        if (json.has("thinking_content")) {
                            message.setThinkingContent(json.get("thinking_content").getAsString());
                        }
                        if (json.has("thinking_signature")) {
                            message.setThinkingSignature(json.get("thinking_signature").getAsString());
                        }
                    } catch (Exception e) {
                        Msg.warn(this, "Failed to parse message metadata: " + e.getMessage());
                    }
                }

                messages.add(message);
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to retrieve ReAct messages: " + e.getMessage(), e);
        }

        return messages;
    }

    /**
     * Get ReAct iteration chunks for a session.
     *
     * @param programHash Program hash
     * @param sessionId Session ID
     * @return List of iteration summaries ordered by iteration number
     */
    public List<String> getReActIterationSummaries(String programHash, int sessionId) {
        List<String> summaries = new ArrayList<>();
        String sql = "SELECT iteration_summary FROM GHReActIterationChunks " +
                "WHERE program_hash = ? AND session_id = ? ORDER BY iteration_number ASC";

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, programHash);
            pstmt.setInt(2, sessionId);

            ResultSet rs = pstmt.executeQuery();
            while (rs.next()) {
                String summary = rs.getString("iteration_summary");
                if (summary != null) {
                    summaries.add(summary);
                }
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to retrieve ReAct iteration summaries: " + e.getMessage(), e);
        }

        return summaries;
    }

    /**
     * Check if a session has ReAct messages.
     *
     * @param sessionId Session ID
     * @return true if session has ReAct messages
     */
    public boolean isReActSession(int sessionId) {
        String sql = "SELECT COUNT(*) FROM GHReActMessages WHERE session_id = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setInt(1, sessionId);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return rs.getInt(1) > 0;
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to check if ReAct session: " + e.getMessage(), e);
        }

        return false;
    }
}