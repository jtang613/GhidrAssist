package ghidrassist.apiprovider;

import ghidrassist.apiprovider.exceptions.APIProviderException;
import ghidra.util.Msg;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Structured logging and analytics for API provider errors
 */
public class APIProviderLogger {
    private static final ConcurrentHashMap<String, ErrorStats> errorStats = new ConcurrentHashMap<>();
    
    /**
     * Log an API provider error with structured information
     */
    public static void logError(Object source, APIProviderException e) {
        // Log the structured error message
        String logMessage = formatErrorMessage(e);
        Msg.error(source, logMessage, e);
        
        // Update error statistics
        updateErrorStats(e);
        
        // Log additional context if available
        if (e.getCause() != null) {
            Msg.debug(source, "Underlying cause: " + e.getCause().getClass().getSimpleName() + 
                              " - " + e.getCause().getMessage());
        }
    }
    
    /**
     * Log a warning for retry attempts
     */
    public static void logRetry(Object source, APIProviderException e, int attempt, int maxAttempts) {
        String message = String.format(
            "[%s] Retry %d/%d for %s: %s",
            e.getProviderName(),
            attempt,
            maxAttempts,
            e.getOperation(),
            e.getCategory().getDisplayName()
        );
        Msg.warn(source, message);
        
        // Update retry statistics
        updateRetryStats(e);
    }
    
    /**
     * Log successful recovery after retries
     */
    public static void logRecovery(Object source, String providerName, String operation, int attempts) {
        String message = String.format(
            "[%s] Operation %s succeeded after %d attempts",
            providerName,
            operation,
            attempts
        );
        Msg.info(source, message);
    }
    
    /**
     * Log provider status changes
     */
    public static void logProviderStatus(Object source, String providerName, String status, String details) {
        String message = String.format("[%s] Status: %s - %s", providerName, status, details);
        Msg.info(source, message);
    }
    
    /**
     * Get error statistics for diagnostics
     */
    public static ErrorStats getErrorStats(String providerName) {
        return errorStats.get(providerName);
    }
    
    /**
     * Get all error statistics
     */
    public static ConcurrentHashMap<String, ErrorStats> getAllErrorStats() {
        return new ConcurrentHashMap<>(errorStats);
    }
    
    /**
     * Clear error statistics
     */
    public static void clearStats() {
        errorStats.clear();
    }
    
    /**
     * Generate a diagnostics report
     */
    public static String generateDiagnosticsReport() {
        StringBuilder report = new StringBuilder();
        report.append("=== API Provider Error Statistics ===\n\n");
        
        if (errorStats.isEmpty()) {
            report.append("No errors recorded.\n");
            return report.toString();
        }
        
        for (String providerName : errorStats.keySet()) {
            ErrorStats stats = errorStats.get(providerName);
            report.append(String.format("Provider: %s\n", providerName));
            report.append(String.format("  Total Errors: %d\n", stats.getTotalErrors()));
            report.append(String.format("  Total Retries: %d\n", stats.getTotalRetries()));
            report.append(String.format("  Last Error: %s\n", 
                stats.getLastErrorTime() > 0 ? new java.util.Date(stats.getLastErrorTime()).toString() : "None"));
            
            report.append("  Errors by Category:\n");
            for (APIProviderException.ErrorCategory category : APIProviderException.ErrorCategory.values()) {
                int count = stats.getCategoryCount(category);
                if (count > 0) {
                    report.append(String.format("    %s: %d\n", category.getDisplayName(), count));
                }
            }
            
            // Reliability calculation
            double reliability = stats.calculateReliability();
            report.append(String.format("  Estimated Reliability: %.1f%%\n", reliability * 100));
            
            report.append("\n");
        }
        
        return report.toString();
    }
    
    private static String formatErrorMessage(APIProviderException e) {
        StringBuilder message = new StringBuilder();
        
        message.append(String.format("[%s] %s failed", 
            e.getProviderName(), e.getOperation()));
        
        message.append(String.format(" - %s", e.getCategory().getDisplayName()));
        
        if (e.getHttpStatusCode() > 0) {
            message.append(String.format(" (HTTP %d)", e.getHttpStatusCode()));
        }
        
        if (e.getApiErrorCode() != null && !e.getApiErrorCode().isEmpty()) {
            message.append(String.format(" [%s]", e.getApiErrorCode()));
        }
        
        if (e.getMessage() != null) {
            message.append(": ").append(e.getMessage());
        }
        
        return message.toString();
    }
    
    private static void updateErrorStats(APIProviderException e) {
        errorStats.computeIfAbsent(e.getProviderName(), k -> new ErrorStats())
                  .recordError(e.getCategory());
    }
    
    private static void updateRetryStats(APIProviderException e) {
        errorStats.computeIfAbsent(e.getProviderName(), k -> new ErrorStats())
                  .recordRetry();
    }
    
    /**
     * Statistics tracking for API provider errors
     */
    public static class ErrorStats {
        private final AtomicInteger totalErrors = new AtomicInteger(0);
        private final AtomicInteger totalRetries = new AtomicInteger(0);
        private final AtomicLong lastErrorTime = new AtomicLong(0);
        private final ConcurrentHashMap<APIProviderException.ErrorCategory, AtomicInteger> categoryStats = 
            new ConcurrentHashMap<>();
        
        public void recordError(APIProviderException.ErrorCategory category) {
            totalErrors.incrementAndGet();
            lastErrorTime.set(System.currentTimeMillis());
            categoryStats.computeIfAbsent(category, k -> new AtomicInteger(0)).incrementAndGet();
        }
        
        public void recordRetry() {
            totalRetries.incrementAndGet();
        }
        
        public int getTotalErrors() {
            return totalErrors.get();
        }
        
        public int getTotalRetries() {
            return totalRetries.get();
        }
        
        public long getLastErrorTime() {
            return lastErrorTime.get();
        }
        
        public int getCategoryCount(APIProviderException.ErrorCategory category) {
            AtomicInteger count = categoryStats.get(category);
            return count != null ? count.get() : 0;
        }
        
        /**
         * Calculate estimated reliability based on error patterns
         * This is a simple heuristic that can be improved with more sophisticated metrics
         */
        public double calculateReliability() {
            int totalErrors = getTotalErrors();
            if (totalErrors == 0) {
                return 1.0; // 100% reliability if no errors
            }
            
            // Simple calculation: assume some baseline number of successful operations
            // This is a rough estimate and could be improved with actual success tracking
            int estimatedTotalOperations = Math.max(totalErrors * 10, 100); // Assume 10:1 success ratio minimum
            return Math.max(0.0, 1.0 - (double) totalErrors / estimatedTotalOperations);
        }
        
        /**
         * Check if provider is experiencing frequent errors (more than 10 in last hour)
         */
        public boolean isFrequentErrorsDetected() {
            long oneHourAgo = System.currentTimeMillis() - (60 * 60 * 1000);
            return lastErrorTime.get() > oneHourAgo && totalErrors.get() > 10;
        }
    }
}