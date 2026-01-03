package ghidrassist.db.migration;

import ghidra.util.Msg;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Orchestrates database schema migrations.
 * Detects current version, applies necessary migrations, and handles errors.
 */
public class SchemaMigrationRunner {

    private final Connection connection;
    private final SchemaVersionDetector versionDetector;
    private final List<SchemaMigration> migrations;

    public SchemaMigrationRunner(Connection connection) {
        this.connection = connection;
        this.versionDetector = new SchemaVersionDetector(connection);
        this.migrations = new ArrayList<>();
        registerMigrations();
    }

    /**
     * Register all available migrations in order.
     */
    private void registerMigrations() {
        migrations.add(new V1_BaseSchema());
        migrations.add(new V2_GraphRAGCore());
        migrations.add(new V3_SecurityColumns());
        migrations.add(new V4_UserEditedColumn());

        // Sort by version number to ensure correct order
        migrations.sort(Comparator.comparingInt(SchemaMigration::getVersion));
    }

    /**
     * Run all pending migrations.
     * Detects current version and applies migrations sequentially.
     *
     * @throws SQLException if a critical error occurs
     */
    public void runMigrations() throws SQLException {
        int currentVersion = versionDetector.detectVersion();
        int targetVersion = getTargetVersion();

        if (currentVersion >= targetVersion) {
            Msg.info(this, "Database schema is up to date (version " + currentVersion + ")");
            return;
        }

        Msg.info(this, "Starting database migration from version " + currentVersion + " to " + targetVersion);

        // Ensure schema_migrations table exists
        ensureMigrationTable();

        for (SchemaMigration migration : migrations) {
            if (migration.getVersion() > currentVersion) {
                applyMigration(migration);
            }
        }

        Msg.info(this, "Database migration completed successfully. Version: " + getTargetVersion());
    }

    /**
     * Apply a single migration.
     * On failure, backs up affected tables and recreates them.
     *
     * @param migration The migration to apply
     * @throws SQLException if migration cannot be completed
     */
    private void applyMigration(SchemaMigration migration) throws SQLException {
        Msg.info(this, "Applying migration V" + migration.getVersion() + ": " + migration.getDescription());

        boolean autoCommit = connection.getAutoCommit();
        try {
            connection.setAutoCommit(false);

            migration.migrate(connection);

            // Update version after successful migration
            versionDetector.setUserVersion(migration.getVersion());
            recordMigration(migration);

            connection.commit();
            Msg.info(this, "Migration V" + migration.getVersion() + " completed successfully");

        } catch (SQLException e) {
            connection.rollback();
            Msg.warn(this, "Migration V" + migration.getVersion() + " failed: " + e.getMessage());

            // Attempt recovery: backup and recreate
            if (attemptRecovery(migration, e)) {
                Msg.warn(this, "Migration V" + migration.getVersion() + " recovered via backup/recreate strategy");
            } else {
                throw new SQLException("Migration V" + migration.getVersion() + " failed and recovery unsuccessful", e);
            }
        } finally {
            connection.setAutoCommit(autoCommit);
        }
    }

    /**
     * Attempt to recover from a failed migration by backing up and recreating tables.
     *
     * @param migration The failed migration
     * @param originalError The original error
     * @return true if recovery was successful
     */
    private boolean attemptRecovery(SchemaMigration migration, SQLException originalError) {
        try {
            Msg.warn(this, "Attempting recovery for migration V" + migration.getVersion());

            // For Graph-RAG migrations, backup the affected tables
            if (migration.getVersion() >= SchemaVersionDetector.VERSION_GRAPHRAG_CORE) {
                backupAndDropGraphRagTables();
            }

            // Retry the migration
            connection.setAutoCommit(false);
            migration.migrate(connection);
            versionDetector.setUserVersion(migration.getVersion());
            recordMigration(migration);
            connection.commit();

            return true;

        } catch (SQLException e) {
            Msg.error(this, "Recovery failed for migration V" + migration.getVersion() + ": " + e.getMessage(), e);
            try {
                connection.rollback();
            } catch (SQLException rollbackError) {
                Msg.error(this, "Rollback failed: " + rollbackError.getMessage());
            }
            return false;
        }
    }

    /**
     * Backup Graph-RAG tables by renaming them with _bak suffix.
     */
    private void backupAndDropGraphRagTables() throws SQLException {
        String[] graphRagTables = {"node_fts", "community_members", "graph_communities", "graph_edges", "graph_nodes"};

        // First drop triggers to avoid issues
        dropGraphNodeTriggers();

        for (String tableName : graphRagTables) {
            if (versionDetector.tableExists(tableName)) {
                String backupName = getNextBackupName(tableName);
                Msg.warn(this, "Backing up table " + tableName + " to " + backupName);

                try (Statement stmt = connection.createStatement()) {
                    // For virtual tables (FTS), just drop - can't rename
                    if (tableName.equals("node_fts")) {
                        stmt.execute("DROP TABLE IF EXISTS " + tableName);
                    } else {
                        stmt.execute("ALTER TABLE " + tableName + " RENAME TO " + backupName);
                    }
                }
            }
        }
    }

    /**
     * Drop FTS triggers.
     */
    private void dropGraphNodeTriggers() throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute("DROP TRIGGER IF EXISTS graph_nodes_ai");
            stmt.execute("DROP TRIGGER IF EXISTS graph_nodes_ad");
            stmt.execute("DROP TRIGGER IF EXISTS graph_nodes_au");
        }
    }

    /**
     * Get next available backup name for a table.
     *
     * @param tableName Original table name
     * @return Backup table name (e.g., tablename_bak or tablename_bak_2)
     */
    private String getNextBackupName(String tableName) throws SQLException {
        String baseName = tableName + "_bak";
        if (!versionDetector.tableExists(baseName)) {
            return baseName;
        }

        int suffix = 2;
        while (versionDetector.tableExists(baseName + "_" + suffix)) {
            suffix++;
        }
        return baseName + "_" + suffix;
    }

    /**
     * Ensure the schema_migrations metadata table exists.
     */
    private void ensureMigrationTable() throws SQLException {
        String sql = "CREATE TABLE IF NOT EXISTS schema_migrations ("
                + "version INTEGER PRIMARY KEY,"
                + "description TEXT NOT NULL,"
                + "applied_at INTEGER NOT NULL"
                + ")";
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(sql);
        }
    }

    /**
     * Record a completed migration in the metadata table.
     *
     * @param migration The completed migration
     */
    private void recordMigration(SchemaMigration migration) throws SQLException {
        String sql = "INSERT OR REPLACE INTO schema_migrations (version, description, applied_at) VALUES (?, ?, ?)";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, migration.getVersion());
            stmt.setString(2, migration.getDescription());
            stmt.setLong(3, System.currentTimeMillis());
            stmt.executeUpdate();
        }
    }

    /**
     * Get the target (highest) version number.
     *
     * @return Target version
     */
    public int getTargetVersion() {
        return migrations.stream()
                .mapToInt(SchemaMigration::getVersion)
                .max()
                .orElse(0);
    }

    /**
     * Get the current database version.
     *
     * @return Current version
     * @throws SQLException on database error
     */
    public int getCurrentVersion() throws SQLException {
        return versionDetector.detectVersion();
    }

    /**
     * Check if any migrations are pending.
     *
     * @return true if migrations need to be applied
     * @throws SQLException on database error
     */
    public boolean hasPendingMigrations() throws SQLException {
        return getCurrentVersion() < getTargetVersion();
    }

    /**
     * Get list of applied migrations from the metadata table.
     *
     * @return List of applied version numbers
     */
    public List<Integer> getAppliedMigrations() {
        List<Integer> applied = new ArrayList<>();
        try {
            if (!versionDetector.tableExists("schema_migrations")) {
                return applied;
            }

            String sql = "SELECT version FROM schema_migrations ORDER BY version";
            try (Statement stmt = connection.createStatement();
                 ResultSet rs = stmt.executeQuery(sql)) {
                while (rs.next()) {
                    applied.add(rs.getInt("version"));
                }
            }
        } catch (SQLException e) {
            Msg.warn(this, "Error reading applied migrations: " + e.getMessage());
        }
        return applied;
    }
}
