package ghidrassist.db.migration;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Migration V4: User edited column.
 * Adds user_edited column to graph_nodes to protect LLM summaries
 * from being auto-overwritten when manually edited by user.
 */
public class V4_UserEditedColumn implements SchemaMigration {

    @Override
    public int getVersion() {
        return 4;
    }

    @Override
    public String getDescription() {
        return "Add user_edited column to graph_nodes";
    }

    @Override
    public void migrate(Connection connection) throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute("ALTER TABLE graph_nodes ADD COLUMN user_edited INTEGER DEFAULT 0");
        } catch (SQLException e) {
            // Column already exists, ignore
            if (!e.getMessage().contains("duplicate column")) {
                throw e;
            }
        }
    }
}
