package ghidrassist.apiprovider.exceptions;

/**
 * Exception for stream cancellation scenarios
 */
public class StreamCancelledException extends APIProviderException {
    
    public enum CancellationReason {
        USER_REQUESTED("User cancelled the request"),
        TIMEOUT("Request timed out"),
        CONNECTION_LOST("Network connection was lost"),
        PROVIDER_ERROR("API provider terminated the stream"),
        SHUTDOWN("Application is shutting down");
        
        private final String description;
        
        CancellationReason(String description) {
            this.description = description;
        }
        
        public String getDescription() { return description; }
    }
    
    private final CancellationReason cancellationReason;
    
    public StreamCancelledException(String providerName, String operation, CancellationReason reason) {
        super(ErrorCategory.CANCELLED, providerName, operation, reason.getDescription());
        this.cancellationReason = reason;
    }
    
    public StreamCancelledException(String providerName, String operation, CancellationReason reason,
                                  Throwable cause) {
        super(ErrorCategory.CANCELLED, providerName, operation, -1, null, reason.getDescription(),
              false, null, cause);
        this.cancellationReason = reason;
    }
    
    public CancellationReason getCancellationReason() {
        return cancellationReason;
    }
}