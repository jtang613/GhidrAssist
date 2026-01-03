package ghidrassist.db.migration;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Migration V2: Graph-RAG core tables.
 * Creates: graph_nodes (base columns), graph_edges, graph_communities,
 * community_members, node_fts (FTS5), and FTS triggers.
 */
public class V2_GraphRAGCore implements SchemaMigration {

    @Override
    public int getVersion() {
        return 2;
    }

    @Override
    public String getDescription() {
        return "Graph-RAG knowledge graph core tables";
    }

    @Override
    public void migrate(Connection connection) throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            // graph_nodes table (base columns without security features)
            stmt.execute("CREATE TABLE IF NOT EXISTS graph_nodes ("
                    + "id TEXT PRIMARY KEY,"
                    + "type TEXT NOT NULL,"
                    + "address INTEGER,"
                    + "binary_id TEXT NOT NULL,"
                    + "name TEXT,"
                    + "raw_content TEXT,"
                    + "llm_summary TEXT,"
                    + "confidence REAL DEFAULT 0.0,"
                    + "embedding BLOB,"
                    + "security_flags TEXT,"
                    + "analysis_depth INTEGER DEFAULT 0,"
                    + "created_at INTEGER,"
                    + "updated_at INTEGER,"
                    + "is_stale INTEGER DEFAULT 0"
                    + ")");

            stmt.execute("CREATE INDEX IF NOT EXISTS idx_nodes_address ON graph_nodes(address)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_nodes_type ON graph_nodes(type)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_nodes_binary ON graph_nodes(binary_id)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_nodes_name ON graph_nodes(name)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_nodes_stale ON graph_nodes(binary_id, is_stale)");

            // graph_edges table
            stmt.execute("CREATE TABLE IF NOT EXISTS graph_edges ("
                    + "id TEXT PRIMARY KEY,"
                    + "source_id TEXT NOT NULL,"
                    + "target_id TEXT NOT NULL,"
                    + "type TEXT NOT NULL,"
                    + "weight REAL DEFAULT 1.0,"
                    + "metadata TEXT,"
                    + "created_at INTEGER,"
                    + "FOREIGN KEY (source_id) REFERENCES graph_nodes(id) ON DELETE CASCADE,"
                    + "FOREIGN KEY (target_id) REFERENCES graph_nodes(id) ON DELETE CASCADE"
                    + ")");

            stmt.execute("CREATE INDEX IF NOT EXISTS idx_edges_source ON graph_edges(source_id)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_edges_target ON graph_edges(target_id)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_edges_type ON graph_edges(type)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_edges_source_type ON graph_edges(source_id, type)");

            // graph_communities table
            stmt.execute("CREATE TABLE IF NOT EXISTS graph_communities ("
                    + "id TEXT PRIMARY KEY,"
                    + "level INTEGER NOT NULL,"
                    + "binary_id TEXT NOT NULL,"
                    + "parent_community_id TEXT,"
                    + "name TEXT,"
                    + "summary TEXT,"
                    + "member_count INTEGER DEFAULT 0,"
                    + "is_stale INTEGER DEFAULT 1,"
                    + "created_at INTEGER,"
                    + "updated_at INTEGER,"
                    + "FOREIGN KEY (parent_community_id) REFERENCES graph_communities(id) ON DELETE SET NULL"
                    + ")");

            stmt.execute("CREATE INDEX IF NOT EXISTS idx_communities_binary ON graph_communities(binary_id)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_communities_level ON graph_communities(level)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_communities_parent ON graph_communities(parent_community_id)");

            // community_members table
            stmt.execute("CREATE TABLE IF NOT EXISTS community_members ("
                    + "community_id TEXT NOT NULL,"
                    + "node_id TEXT NOT NULL,"
                    + "membership_score REAL DEFAULT 1.0,"
                    + "PRIMARY KEY (community_id, node_id),"
                    + "FOREIGN KEY (community_id) REFERENCES graph_communities(id) ON DELETE CASCADE,"
                    + "FOREIGN KEY (node_id) REFERENCES graph_nodes(id) ON DELETE CASCADE"
                    + ")");

            stmt.execute("CREATE INDEX IF NOT EXISTS idx_community_members_node ON community_members(node_id)");

            // FTS5 virtual table for semantic search
            // Check if it exists first (FTS5 doesn't support IF NOT EXISTS)
            ResultSet rs = stmt.executeQuery(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='node_fts'");
            if (!rs.next()) {
                stmt.execute("CREATE VIRTUAL TABLE node_fts USING fts5("
                        + "id, "
                        + "name, "
                        + "llm_summary, "
                        + "security_flags, "
                        + "content='graph_nodes', "
                        + "content_rowid='rowid'"
                        + ")");
            }
            rs.close();

            // FTS triggers for synchronization
            stmt.execute("CREATE TRIGGER IF NOT EXISTS graph_nodes_ai AFTER INSERT ON graph_nodes BEGIN "
                    + "INSERT INTO node_fts(rowid, id, name, llm_summary, security_flags) "
                    + "VALUES (NEW.rowid, NEW.id, NEW.name, NEW.llm_summary, NEW.security_flags); "
                    + "END");

            stmt.execute("CREATE TRIGGER IF NOT EXISTS graph_nodes_ad AFTER DELETE ON graph_nodes BEGIN "
                    + "INSERT INTO node_fts(node_fts, rowid, id, name, llm_summary, security_flags) "
                    + "VALUES ('delete', OLD.rowid, OLD.id, OLD.name, OLD.llm_summary, OLD.security_flags); "
                    + "END");

            stmt.execute("CREATE TRIGGER IF NOT EXISTS graph_nodes_au AFTER UPDATE ON graph_nodes BEGIN "
                    + "INSERT INTO node_fts(node_fts, rowid, id, name, llm_summary, security_flags) "
                    + "VALUES ('delete', OLD.rowid, OLD.id, OLD.name, OLD.llm_summary, OLD.security_flags); "
                    + "INSERT INTO node_fts(rowid, id, name, llm_summary, security_flags) "
                    + "VALUES (NEW.rowid, NEW.id, NEW.name, NEW.llm_summary, NEW.security_flags); "
                    + "END");
        }
    }
}
