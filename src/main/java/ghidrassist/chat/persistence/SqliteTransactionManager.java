package ghidrassist.chat.persistence;

import ghidra.util.Msg;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * SQLite implementation of TransactionManager.
 * Provides transaction boundaries for atomic database operations.
 */
public class SqliteTransactionManager implements TransactionManager {

    private final Connection connection;

    /**
     * Create a new SqliteTransactionManager with the given connection.
     *
     * @param connection The SQLite database connection
     */
    public SqliteTransactionManager(Connection connection) {
        this.connection = connection;
    }

    @Override
    public <T> T executeInTransaction(Function<Connection, T> operation) {
        boolean wasAutoCommit = true;
        try {
            wasAutoCommit = connection.getAutoCommit();
            connection.setAutoCommit(false);

            T result = operation.apply(connection);

            connection.commit();
            return result;

        } catch (Exception e) {
            try {
                connection.rollback();
                Msg.warn(this, "Transaction rolled back due to error: " + e.getMessage());
            } catch (SQLException rollbackEx) {
                Msg.error(this, "Failed to rollback transaction: " + rollbackEx.getMessage());
            }
            throw new RuntimeException("Transaction failed: " + e.getMessage(), e);

        } finally {
            try {
                connection.setAutoCommit(wasAutoCommit);
            } catch (SQLException e) {
                Msg.error(this, "Failed to restore autocommit: " + e.getMessage());
            }
        }
    }

    @Override
    public void executeInTransaction(Consumer<Connection> operation) {
        executeInTransaction(conn -> {
            operation.accept(conn);
            return null;
        });
    }

    @Override
    public Connection getConnection() {
        return connection;
    }
}
