package ghidrassist.apiprovider.exceptions;

/**
 * Exception for rate limiting errors
 */
public class RateLimitException extends APIProviderException {
    
    public RateLimitException(String providerName, String operation, Integer retryAfterSeconds) {
        super(ErrorCategory.RATE_LIMIT, providerName, operation, 429, "rate_limit_exceeded",
              "Rate limit exceeded. Please wait before retrying.", true, retryAfterSeconds, null);
    }
    
    public RateLimitException(String providerName, String operation, String message, 
                            Integer retryAfterSeconds) {
        super(ErrorCategory.RATE_LIMIT, providerName, operation, 429, "rate_limit_exceeded",
              message, true, retryAfterSeconds, null);
    }
    
    public RateLimitException(String providerName, String operation, int httpStatusCode,
                            String apiErrorCode, String message, Integer retryAfterSeconds) {
        super(ErrorCategory.RATE_LIMIT, providerName, operation, httpStatusCode, apiErrorCode,
              message, true, retryAfterSeconds, null);
    }
}