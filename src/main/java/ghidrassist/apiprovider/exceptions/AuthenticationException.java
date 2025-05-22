package ghidrassist.apiprovider.exceptions;

/**
 * Exception for authentication and authorization failures
 */
public class AuthenticationException extends APIProviderException {
    
    public AuthenticationException(String providerName, String operation, String message) {
        super(ErrorCategory.AUTHENTICATION, providerName, operation, message);
    }
    
    public AuthenticationException(String providerName, String operation, int httpStatusCode, 
                                 String apiErrorCode, String message) {
        super(ErrorCategory.AUTHENTICATION, providerName, operation, httpStatusCode, apiErrorCode, 
              message, false, null, null);
    }
    
    public AuthenticationException(String providerName, String operation, String message, Throwable cause) {
        super(ErrorCategory.AUTHENTICATION, providerName, operation, -1, null, message, false, null, cause);
    }
}