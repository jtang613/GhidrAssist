package ghidrassist.chat.persistence;

import java.sql.Connection;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * Manages database transactions for atomic operations.
 * Provides transaction boundaries for multi-statement database operations.
 */
public interface TransactionManager {

    /**
     * Execute operations within a transaction and return a result.
     * Commits on success, rolls back on exception.
     *
     * @param <T> The return type
     * @param operation The operation to execute with the connection
     * @return The result of the operation
     * @throws RuntimeException if the operation fails (wraps SQLException)
     */
    <T> T executeInTransaction(Function<Connection, T> operation);

    /**
     * Execute void operations within a transaction.
     * Commits on success, rolls back on exception.
     *
     * @param operation The operation to execute with the connection
     * @throws RuntimeException if the operation fails (wraps SQLException)
     */
    void executeInTransaction(Consumer<Connection> operation);

    /**
     * Get the underlying connection for read-only operations.
     * Note: For write operations, use executeInTransaction() instead.
     *
     * @return The database connection
     */
    Connection getConnection();
}
