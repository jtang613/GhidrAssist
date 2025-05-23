package ghidrassist.apiprovider.factory;

import ghidrassist.apiprovider.APIProvider;

/**
 * Exception thrown when a factory cannot create a requested provider type.
 */
public class UnsupportedProviderException extends Exception {
    
    private final APIProvider.ProviderType requestedType;
    private final String factoryName;
    
    public UnsupportedProviderException(APIProvider.ProviderType requestedType, String factoryName) {
        super(String.format("Factory '%s' does not support provider type '%s'", factoryName, requestedType));
        this.requestedType = requestedType;
        this.factoryName = factoryName;
    }
    
    public UnsupportedProviderException(APIProvider.ProviderType requestedType, String factoryName, String message) {
        super(message);
        this.requestedType = requestedType;
        this.factoryName = factoryName;
    }
    
    public UnsupportedProviderException(APIProvider.ProviderType requestedType, String factoryName, String message, Throwable cause) {
        super(message, cause);
        this.requestedType = requestedType;
        this.factoryName = factoryName;
    }
    
    public APIProvider.ProviderType getRequestedType() {
        return requestedType;
    }
    
    public String getFactoryName() {
        return factoryName;
    }
}