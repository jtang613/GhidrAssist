package ghidrassist.db.migration;

import java.sql.Connection;
import java.sql.SQLException;

/**
 * Interface for database schema migrations.
 * Each migration represents a specific schema version transition.
 */
public interface SchemaMigration {

    /**
     * Get the schema version this migration produces.
     * @return Version number (must be unique and sequential)
     */
    int getVersion();

    /**
     * Get a human-readable description of this migration.
     * @return Description of what this migration does
     */
    String getDescription();

    /**
     * Apply the migration to the database.
     * Implementations should be idempotent where possible.
     *
     * @param connection The database connection
     * @throws SQLException if migration fails
     */
    void migrate(Connection connection) throws SQLException;
}
