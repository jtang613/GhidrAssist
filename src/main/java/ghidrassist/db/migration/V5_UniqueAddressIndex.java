package ghidrassist.db.migration;

import ghidra.util.Msg;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Migration V5: Unique address index.
 * Adds a unique index on (binary_id, address) to prevent duplicate nodes
 * with the same address during parallel extraction.
 * Also cleans up any existing duplicate nodes.
 */
public class V5_UniqueAddressIndex implements SchemaMigration {

    @Override
    public int getVersion() {
        return 5;
    }

    @Override
    public String getDescription() {
        return "Add unique index on (binary_id, address) to prevent duplicate nodes";
    }

    @Override
    public void migrate(Connection connection) throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            // First, clean up any existing duplicate nodes
            // Keep the node with the most edges (most likely to be the "correct" one)
            int duplicatesRemoved = cleanupDuplicateNodes(connection);
            if (duplicatesRemoved > 0) {
                Msg.info(this, "Cleaned up " + duplicatesRemoved + " duplicate nodes");
            }

            // Create unique partial index (only for non-null addresses)
            // SQLite supports partial indexes with WHERE clause
            stmt.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_graph_nodes_binary_address "
                    + "ON graph_nodes(binary_id, address) WHERE address IS NOT NULL");
        }
    }

    /**
     * Clean up duplicate nodes with the same (binary_id, address).
     * For each set of duplicates, keep the one with the most edge references.
     *
     * @param connection Database connection
     * @return Number of duplicate nodes removed
     */
    private int cleanupDuplicateNodes(Connection connection) throws SQLException {
        int totalRemoved = 0;

        try (Statement stmt = connection.createStatement()) {
            // Find all addresses with duplicates
            String findDuplicatesSql = "SELECT binary_id, address, COUNT(*) as cnt "
                    + "FROM graph_nodes "
                    + "WHERE address IS NOT NULL "
                    + "GROUP BY binary_id, address "
                    + "HAVING cnt > 1";

            ResultSet duplicates = stmt.executeQuery(findDuplicatesSql);

            while (duplicates.next()) {
                String binaryId = duplicates.getString("binary_id");
                long address = duplicates.getLong("address");

                // For each duplicate set, find the node with most edges
                String findBestNodeSql = "SELECT n.id, "
                        + "(SELECT COUNT(*) FROM graph_edges e WHERE e.source_id = n.id OR e.target_id = n.id) as edge_count "
                        + "FROM graph_nodes n "
                        + "WHERE n.binary_id = '" + binaryId.replace("'", "''") + "' "
                        + "AND n.address = " + address + " "
                        + "ORDER BY edge_count DESC "
                        + "LIMIT 1";

                try (Statement findStmt = connection.createStatement();
                     ResultSet best = findStmt.executeQuery(findBestNodeSql)) {

                    if (best.next()) {
                        String keepId = best.getString("id");

                        // Delete all other nodes with same binary_id and address
                        String deleteOthersSql = "DELETE FROM graph_nodes "
                                + "WHERE binary_id = '" + binaryId.replace("'", "''") + "' "
                                + "AND address = " + address + " "
                                + "AND id != '" + keepId.replace("'", "''") + "'";

                        try (Statement deleteStmt = connection.createStatement()) {
                            int deleted = deleteStmt.executeUpdate(deleteOthersSql);
                            totalRemoved += deleted;
                        }
                    }
                }
            }
        }

        return totalRemoved;
    }
}
