package ghidrassist.db.migration;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashSet;
import java.util.Set;

/**
 * Detects the current schema version of the database.
 * Uses PRAGMA user_version first, then fingerprints by table/column existence.
 */
public class SchemaVersionDetector {

    /** Fresh database with no tables */
    public static final int VERSION_EMPTY = 0;

    /** Base schema: GHAnalysis, GHContext, GHChatHistory, GHChatMessages, etc. */
    public static final int VERSION_BASE = 1;

    /** Graph-RAG core tables without security columns */
    public static final int VERSION_GRAPHRAG_CORE = 2;

    /** Graph-RAG with security columns, without user_edited */
    public static final int VERSION_GRAPHRAG_SECURITY = 3;

    /** Current full schema with user_edited column */
    public static final int VERSION_CURRENT = 4;

    private final Connection connection;

    public SchemaVersionDetector(Connection connection) {
        this.connection = connection;
    }

    /**
     * Detect the current schema version.
     * First checks PRAGMA user_version, then uses fingerprinting for legacy databases.
     *
     * @return Detected version number
     * @throws SQLException on database error
     */
    public int detectVersion() throws SQLException {
        // First check explicit version stored in PRAGMA user_version
        int userVersion = getUserVersion();
        if (userVersion > 0) {
            return userVersion;
        }

        // Fingerprint detection for legacy databases (user_version = 0)
        return detectByFingerprint();
    }

    /**
     * Get the PRAGMA user_version value.
     *
     * @return user_version, or 0 if not set
     * @throws SQLException on database error
     */
    public int getUserVersion() throws SQLException {
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery("PRAGMA user_version")) {
            if (rs.next()) {
                return rs.getInt(1);
            }
        }
        return 0;
    }

    /**
     * Set the PRAGMA user_version value.
     *
     * @param version Version number to set
     * @throws SQLException on database error
     */
    public void setUserVersion(int version) throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute("PRAGMA user_version = " + version);
        }
    }

    /**
     * Detect version by examining which tables and columns exist.
     * Used for databases that don't have user_version set (legacy databases).
     *
     * @return Detected version based on schema fingerprint
     * @throws SQLException on database error
     */
    private int detectByFingerprint() throws SQLException {
        // Check if any base tables exist
        if (!tableExists("GHAnalysis")) {
            return VERSION_EMPTY;
        }

        // Check if Graph-RAG tables exist
        if (!tableExists("graph_nodes")) {
            return VERSION_BASE;
        }

        // Check for security columns in graph_nodes
        Set<String> graphNodeColumns = getTableColumns("graph_nodes");

        if (!graphNodeColumns.contains("network_apis")) {
            return VERSION_GRAPHRAG_CORE;
        }

        if (!graphNodeColumns.contains("user_edited")) {
            return VERSION_GRAPHRAG_SECURITY;
        }

        return VERSION_CURRENT;
    }

    /**
     * Check if a table exists in the database.
     *
     * @param tableName Name of the table
     * @return true if table exists
     * @throws SQLException on database error
     */
    public boolean tableExists(String tableName) throws SQLException {
        String sql = "SELECT name FROM sqlite_master WHERE type='table' AND name=?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, tableName);
            try (ResultSet rs = stmt.executeQuery()) {
                return rs.next();
            }
        }
    }

    /**
     * Get the set of column names for a table.
     *
     * @param tableName Name of the table
     * @return Set of column names (lowercase)
     * @throws SQLException on database error
     */
    public Set<String> getTableColumns(String tableName) throws SQLException {
        Set<String> columns = new HashSet<>();
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery("PRAGMA table_info(" + tableName + ")")) {
            while (rs.next()) {
                columns.add(rs.getString("name").toLowerCase());
            }
        }
        return columns;
    }

    /**
     * Check if a column exists in a table.
     *
     * @param tableName Name of the table
     * @param columnName Name of the column
     * @return true if column exists
     * @throws SQLException on database error
     */
    public boolean columnExists(String tableName, String columnName) throws SQLException {
        return getTableColumns(tableName).contains(columnName.toLowerCase());
    }
}
