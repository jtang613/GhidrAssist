package ghidrassist.apiprovider.exceptions;

/**
 * Exception for response parsing and format errors
 */
public class ResponseException extends APIProviderException {
    
    public enum ResponseErrorType {
        MALFORMED_JSON("Response contains invalid JSON"),
        MISSING_REQUIRED_FIELD("Required field missing from response"),
        UNEXPECTED_FORMAT("Response format is not as expected"),
        EMPTY_RESPONSE("Received empty response"),
        STREAM_INTERRUPTED("Response stream was interrupted");
        
        private final String description;
        
        ResponseErrorType(String description) {
            this.description = description;
        }
        
        public String getDescription() { return description; }
    }
    
    private final ResponseErrorType responseErrorType;
    
    public ResponseException(String providerName, String operation, ResponseErrorType errorType) {
        super(ErrorCategory.RESPONSE_ERROR, providerName, operation, errorType.getDescription());
        this.responseErrorType = errorType;
    }
    
    public ResponseException(String providerName, String operation, ResponseErrorType errorType,
                           Throwable cause) {
        super(ErrorCategory.RESPONSE_ERROR, providerName, operation, -1, null, 
              errorType.getDescription(), false, null, cause);
        this.responseErrorType = errorType;
    }
    
    public ResponseException(String providerName, String operation, String message) {
        super(ErrorCategory.RESPONSE_ERROR, providerName, operation, message);
        this.responseErrorType = null;
    }
    
    public ResponseErrorType getResponseErrorType() {
        return responseErrorType;
    }
}