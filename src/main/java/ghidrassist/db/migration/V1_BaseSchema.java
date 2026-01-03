package ghidrassist.db.migration;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Migration V1: Base schema.
 * Creates the core tables: GHAnalysis, GHContext, GHChatHistory, GHChatMessages,
 * GHReActMessages, GHReActIterationChunks.
 */
public class V1_BaseSchema implements SchemaMigration {

    @Override
    public int getVersion() {
        return 1;
    }

    @Override
    public String getDescription() {
        return "Base schema with analysis, context, and chat tables";
    }

    @Override
    public void migrate(Connection connection) throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            // GHAnalysis table
            stmt.execute("CREATE TABLE IF NOT EXISTS GHAnalysis ("
                    + "program_hash TEXT NOT NULL,"
                    + "function_address TEXT NOT NULL,"
                    + "query TEXT NOT NULL,"
                    + "response TEXT NOT NULL,"
                    + "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,"
                    + "PRIMARY KEY (program_hash, function_address)"
                    + ")");

            // GHContext table
            stmt.execute("CREATE TABLE IF NOT EXISTS GHContext ("
                    + "program_hash TEXT PRIMARY KEY,"
                    + "system_context TEXT NOT NULL,"
                    + "reasoning_effort TEXT DEFAULT 'none',"
                    + "max_tool_calls INTEGER DEFAULT 10,"
                    + "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP"
                    + ")");

            // Migration: Add reasoning_effort column if it doesn't exist (for upgrades)
            addColumnIfNotExists(connection, "GHContext", "reasoning_effort", "TEXT DEFAULT 'none'");

            // Migration: Add max_tool_calls column if it doesn't exist (for upgrades)
            addColumnIfNotExists(connection, "GHContext", "max_tool_calls", "INTEGER DEFAULT 10");

            // GHChatHistory table
            stmt.execute("CREATE TABLE IF NOT EXISTS GHChatHistory ("
                    + "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                    + "program_hash TEXT NOT NULL,"
                    + "description TEXT NOT NULL,"
                    + "conversation TEXT NOT NULL,"
                    + "last_update DATETIME DEFAULT CURRENT_TIMESTAMP"
                    + ")");

            // GHChatMessages table
            stmt.execute("CREATE TABLE IF NOT EXISTS GHChatMessages ("
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
                    + ")");

            stmt.execute("CREATE INDEX IF NOT EXISTS idx_chat_messages_lookup "
                    + "ON GHChatMessages(program_hash, chat_id, message_order)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_chat_messages_role "
                    + "ON GHChatMessages(role)");

            // GHReActMessages table
            stmt.execute("CREATE TABLE IF NOT EXISTS GHReActMessages ("
                    + "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                    + "program_hash TEXT NOT NULL,"
                    + "session_id INTEGER NOT NULL,"
                    + "message_order INTEGER NOT NULL,"
                    + "phase TEXT NOT NULL,"
                    + "iteration_number INTEGER,"
                    + "role TEXT NOT NULL,"
                    + "content_text TEXT,"
                    + "native_message_data TEXT,"
                    + "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
                    + "UNIQUE(program_hash, session_id, message_order),"
                    + "FOREIGN KEY (session_id) REFERENCES GHChatHistory(id) ON DELETE CASCADE"
                    + ")");

            stmt.execute("CREATE INDEX IF NOT EXISTS idx_react_messages_lookup "
                    + "ON GHReActMessages(program_hash, session_id, phase, iteration_number)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_react_messages_order "
                    + "ON GHReActMessages(session_id, message_order)");

            // GHReActIterationChunks table
            stmt.execute("CREATE TABLE IF NOT EXISTS GHReActIterationChunks ("
                    + "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                    + "program_hash TEXT NOT NULL,"
                    + "session_id INTEGER NOT NULL,"
                    + "iteration_number INTEGER NOT NULL,"
                    + "iteration_summary TEXT,"
                    + "message_start_index INTEGER NOT NULL,"
                    + "message_end_index INTEGER NOT NULL,"
                    + "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
                    + "UNIQUE(program_hash, session_id, iteration_number),"
                    + "FOREIGN KEY (session_id) REFERENCES GHChatHistory(id) ON DELETE CASCADE"
                    + ")");

            stmt.execute("CREATE INDEX IF NOT EXISTS idx_react_chunks_lookup "
                    + "ON GHReActIterationChunks(program_hash, session_id, iteration_number)");
        }
    }

    /**
     * Add a column to a table if it doesn't exist.
     * Uses try-catch to handle "duplicate column" errors silently.
     */
    private void addColumnIfNotExists(Connection connection, String tableName,
                                       String columnName, String columnDef) throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute("ALTER TABLE " + tableName + " ADD COLUMN " + columnName + " " + columnDef);
        } catch (SQLException e) {
            // Column already exists, ignore
            if (!e.getMessage().contains("duplicate column")) {
                throw e;
            }
        }
    }
}
