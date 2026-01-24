package ghidrassist.db.migration;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Migration V6: Line Explanations table.
 * Creates table for caching line-level explanations from decompiler/disassembly views.
 */
public class V6_LineExplanations implements SchemaMigration {

    @Override
    public int getVersion() {
        return 6;
    }

    @Override
    public String getDescription() {
        return "Add line_explanations table for per-line analysis cache";
    }

    @Override
    public void migrate(Connection connection) throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(
                "CREATE TABLE IF NOT EXISTS line_explanations (" +
                "    id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "    binary_id TEXT NOT NULL," +
                "    function_address INTEGER NOT NULL," +
                "    line_address INTEGER NOT NULL," +
                "    view_type TEXT NOT NULL," +  // 'DECOMPILER' or 'DISASSEMBLY'
                "    line_content TEXT," +
                "    context_before TEXT," +
                "    context_after TEXT," +
                "    explanation TEXT NOT NULL," +
                "    created_at INTEGER NOT NULL," +
                "    updated_at INTEGER NOT NULL," +
                "    UNIQUE(binary_id, line_address, view_type)" +
                ")"
            );

            // Create index for efficient lookups
            stmt.execute(
                "CREATE INDEX IF NOT EXISTS idx_line_explanations_lookup " +
                "ON line_explanations(binary_id, line_address, view_type)"
            );

            // Create index for function-level operations (clear all lines for a function)
            stmt.execute(
                "CREATE INDEX IF NOT EXISTS idx_line_explanations_function " +
                "ON line_explanations(binary_id, function_address)"
            );
        }
    }
}
