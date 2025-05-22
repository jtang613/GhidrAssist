package ghidrassist.apiprovider.exceptions;

/**
 * Base exception for all API provider errors with structured error information
 */
public class APIProviderException extends Exception {
    private final ErrorCategory category;
    private final String providerName;
    private final String operation;
    private final int httpStatusCode;
    private final String apiErrorCode;
    private final boolean isRetryable;
    private final Integer retryAfterSeconds;
    
    public enum ErrorCategory {
        AUTHENTICATION("Authentication Error", "Check your API key and credentials"),
        NETWORK("Network Error", "Check your internet connection and API URL"),
        RATE_LIMIT("Rate Limit Exceeded", "Too many requests - please wait before retrying"),
        MODEL_ERROR("Model Error", "Issue with the specified model or unsupported feature"),
        CONFIGURATION("Configuration Error", "Invalid settings or configuration"),
        RESPONSE_ERROR("Response Error", "Invalid or unexpected response from API"),
        SERVICE_ERROR("Service Error", "API service is experiencing issues"),
        TIMEOUT("Timeout Error", "Request took too long to complete"),
        CANCELLED("Request Cancelled", "Operation was cancelled");
        
        private final String displayName;
        private final String description;
        
        ErrorCategory(String displayName, String description) {
            this.displayName = displayName;
            this.description = description;
        }
        
        public String getDisplayName() { return displayName; }
        public String getDescription() { return description; }
    }
    
    public APIProviderException(ErrorCategory category, String providerName, String operation, 
                              String message) {
        this(category, providerName, operation, -1, null, message, false, null, null);
    }
    
    public APIProviderException(ErrorCategory category, String providerName, String operation,
                              int httpStatusCode, String apiErrorCode, String message) {
        this(category, providerName, operation, httpStatusCode, apiErrorCode, message, false, null, null);
    }
    
    public APIProviderException(ErrorCategory category, String providerName, String operation,
                              int httpStatusCode, String apiErrorCode, String message, 
                              boolean isRetryable, Integer retryAfterSeconds, Throwable cause) {
        super(message, cause);
        this.category = category;
        this.providerName = providerName;
        this.operation = operation;
        this.httpStatusCode = httpStatusCode;
        this.apiErrorCode = apiErrorCode;
        this.isRetryable = isRetryable;
        this.retryAfterSeconds = retryAfterSeconds;
    }
    
    // Getters
    public ErrorCategory getCategory() { return category; }
    public String getProviderName() { return providerName; }
    public String getOperation() { return operation; }
    public int getHttpStatusCode() { return httpStatusCode; }
    public String getApiErrorCode() { return apiErrorCode; }
    public boolean isRetryable() { return isRetryable; }
    public Integer getRetryAfterSeconds() { return retryAfterSeconds; }
    
    /**
     * Get technical details for debugging
     */
    public String getTechnicalDetails() {
        StringBuilder details = new StringBuilder();
        details.append("Provider: ").append(providerName).append("\n");
        details.append("Operation: ").append(operation).append("\n");
        details.append("Category: ").append(category.getDisplayName()).append("\n");
        
        if (httpStatusCode > 0) {
            details.append("HTTP Status: ").append(httpStatusCode).append("\n");
        }
        
        if (apiErrorCode != null && !apiErrorCode.isEmpty()) {
            details.append("API Error Code: ").append(apiErrorCode).append("\n");
        }
        
        if (getMessage() != null) {
            details.append("Message: ").append(getMessage()).append("\n");
        }
        
        if (getCause() != null) {
            details.append("Cause: ").append(getCause().getClass().getSimpleName()).append("\n");
        }
        
        return details.toString();
    }
}