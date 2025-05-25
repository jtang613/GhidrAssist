package ghidrassist.apiprovider;

import ghidrassist.apiprovider.exceptions.*;
import ghidra.util.Msg;

import java.util.concurrent.Callable;
import java.util.function.Supplier;

/**
 * Handles retry logic for API provider operations
 */
public class RetryHandler {
    private static final int DEFAULT_MAX_RETRIES = 3;
    private static final int BASE_BACKOFF_MS = 1000; // 1 second
    private static final int MAX_BACKOFF_MS = 90000; // 90 seconds
    
    private final int maxRetries;
    private final Object source; // For logging
    
    public RetryHandler() {
        this(DEFAULT_MAX_RETRIES, null);
    }
    
    public RetryHandler(int maxRetries, Object source) {
        this.maxRetries = maxRetries;
        this.source = source;
    }
    
    /**
     * Execute an operation with retry logic
     */
    public <T> T executeWithRetry(Supplier<T> operation, String operationName) throws APIProviderException {
        return executeWithRetryCallable(() -> operation.get(), operationName);
    }
    
    /**
     * Execute a callable operation with retry logic
     */
    public <T> T executeWithRetryCallable(Callable<T> operation, String operationName) throws APIProviderException {
        APIProviderException lastException = null;
        
        for (int attempt = 1; attempt <= maxRetries; attempt++) {
            try {
                return operation.call();
            } catch (APIProviderException e) {
                lastException = e;
                
                if (!shouldRetry(e, attempt)) {
                    throw e;
                }
                
                logRetryAttempt(operationName, attempt, e);
                
                if (attempt < maxRetries) {
                    waitForRetry(e, attempt);
                }
            } catch (Exception e) {
                // Convert non-API exceptions to APIProviderException
                throw new APIProviderException(
                    APIProviderException.ErrorCategory.SERVICE_ERROR,
                    "Unknown", 
                    operationName,
                    "Unexpected error: " + e.getMessage()
                );
            }
        }
        
        // If we get here, all retries failed
        throw lastException;
    }
    
    /**
     * Execute an operation with retry logic that doesn't return a value
     */
    public void executeWithRetryRunnable(Runnable operation, String operationName) throws APIProviderException {
        executeWithRetryCallable(() -> {
            operation.run();
            return null;
        }, operationName);
    }
    
    private boolean shouldRetry(APIProviderException e, int attempt) {
        // Don't retry if we've exceeded max attempts
        if (attempt >= maxRetries) {
            return false;
        }
        
        // Check if the error is retryable based on category
        switch (e.getCategory()) {
            case RATE_LIMIT:
            case NETWORK:
            case TIMEOUT:
            case SERVICE_ERROR:
                return true;
                
            case AUTHENTICATION:
            case MODEL_ERROR:
            case CONFIGURATION:
            case RESPONSE_ERROR:
            case CANCELLED:
                return false;
                
            default:
                // For unknown errors, check the isRetryable flag
                return e.isRetryable();
        }
    }
    
    private void waitForRetry(APIProviderException e, int attempt) {
        int waitTimeMs = calculateWaitTime(e, attempt);
        
        if (source != null) {
            Msg.info(source, String.format("Waiting %d seconds before retry...", waitTimeMs / 1000 ));
        }
        
        try {
            Thread.sleep(waitTimeMs);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Retry interrupted", ie);
        }
    }
    
    private int calculateWaitTime(APIProviderException e, int attempt) {
        // For rate limit errors, use the provided retry-after if available
        if (e.getCategory() == APIProviderException.ErrorCategory.RATE_LIMIT && 
            e.getRetryAfterSeconds() != null) {
            return e.getRetryAfterSeconds() * 1000;
        }
        
        // For other errors, use exponential backoff with jitter
        int backoffMs = BASE_BACKOFF_MS * (int) Math.pow(2, attempt - 1);
        
        // Add jitter (±25%)
        int jitter = (int) (backoffMs * 0.25 * (Math.random() - 0.5));
        backoffMs += jitter;
        
        // Cap at maximum backoff
        return Math.min(backoffMs, MAX_BACKOFF_MS);
    }
    
    private void logRetryAttempt(String operationName, int attempt, APIProviderException e) {
        if (source != null) {
            String message = String.format(
                "Retry attempt %d/%d for %s: %s (%s)",
                attempt, maxRetries, operationName, 
                e.getCategory().getDisplayName(), e.getProviderName()
            );
            Msg.warn(source, message);
        }
    }
    
    /**
     * Check if an exception indicates a transient error that might succeed on retry
     */
    public static boolean isTransientError(Throwable error) {
        if (error instanceof APIProviderException) {
            APIProviderException ape = (APIProviderException) error;
            return ape.isRetryable() || isTransientCategory(ape.getCategory());
        }
        
        // Check for common transient error indicators in message
        String message = error.getMessage();
        if (message != null) {
            message = message.toLowerCase();
            return message.contains("timeout") || 
                   message.contains("connection reset") ||
                   message.contains("temporary") ||
                   message.contains("service unavailable");
        }
        
        return false;
    }
    
    private static boolean isTransientCategory(APIProviderException.ErrorCategory category) {
        switch (category) {
            case RATE_LIMIT:
            case NETWORK:
            case TIMEOUT:
            case SERVICE_ERROR:
                return true;
            default:
                return false;
        }
    }
}