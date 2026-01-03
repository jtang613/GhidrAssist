package ghidrassist.db.migration;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Migration V3: Security analysis columns.
 * Adds security-related columns to graph_nodes table for detailed
 * security profiling of code entities.
 */
public class V3_SecurityColumns implements SchemaMigration {

    @Override
    public int getVersion() {
        return 3;
    }

    @Override
    public String getDescription() {
        return "Add security analysis columns to graph_nodes";
    }

    @Override
    public void migrate(Connection connection) throws SQLException {
        // Security detail columns to add
        String[] securityColumns = {
            "network_apis TEXT",
            "file_io_apis TEXT",
            "ip_addresses TEXT",
            "urls TEXT",
            "file_paths TEXT",
            "domains TEXT",
            "registry_keys TEXT",
            "risk_level TEXT",
            "activity_profile TEXT"
        };

        for (String columnDef : securityColumns) {
            addColumnIfNotExists(connection, "graph_nodes", columnDef);
        }
    }

    /**
     * Add a column to a table if it doesn't exist.
     * Uses try-catch to handle "duplicate column" errors silently.
     */
    private void addColumnIfNotExists(Connection connection, String tableName,
                                       String columnDef) throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute("ALTER TABLE " + tableName + " ADD COLUMN " + columnDef);
        } catch (SQLException e) {
            // Column already exists, ignore
            if (!e.getMessage().contains("duplicate column")) {
                throw e;
            }
        }
    }
}
