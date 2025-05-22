package ghidrassist.apiprovider.exceptions;

/**
 * Exception for network-related failures
 */
public class NetworkException extends APIProviderException {
    
    public enum NetworkErrorType {
        CONNECTION_FAILED("Cannot connect to server"),
        TIMEOUT("Request timed out"),
        SSL_ERROR("SSL/TLS connection failed"),
        DNS_ERROR("Cannot resolve hostname"),
        CONNECTION_LOST("Connection was lost during request");
        
        private final String description;
        
        NetworkErrorType(String description) {
            this.description = description;
        }
        
        public String getDescription() { return description; }
    }
    
    private final NetworkErrorType networkErrorType;
    
    public NetworkException(String providerName, String operation, NetworkErrorType errorType) {
        super(ErrorCategory.NETWORK, providerName, operation, errorType.getDescription());
        this.networkErrorType = errorType;
    }
    
    public NetworkException(String providerName, String operation, NetworkErrorType errorType, 
                          Throwable cause) {
        super(ErrorCategory.NETWORK, providerName, operation, -1, null, errorType.getDescription(), 
              true, null, cause);
        this.networkErrorType = errorType;
    }
    
    public NetworkException(String providerName, String operation, String message) {
        super(ErrorCategory.NETWORK, providerName, operation, message);
        this.networkErrorType = null;
    }
    
    public NetworkErrorType getNetworkErrorType() {
        return networkErrorType;
    }
}