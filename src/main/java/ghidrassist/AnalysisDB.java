package ghidrassist;

import ghidra.framework.preferences.Preferences;
import ghidra.program.model.address.Address;
import ghidra.util.Msg;
import java.sql.*;

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
                + "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP"
                + ")";
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(createContextTableSQL);
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
}