package ghidrassist.apiprovider.factory;

import ghidrassist.apiprovider.APIProvider;
import ghidrassist.apiprovider.APIProviderConfig;

/**
 * Factory interface for creating API providers.
 * Follows the Factory Method pattern to allow extensibility.
 */
public interface APIProviderFactory {
    
    /**
     * Create an API provider instance from configuration
     * @param config The provider configuration
     * @return A configured API provider instance
     * @throws UnsupportedProviderException if this factory cannot create the requested provider type
     */
    APIProvider createProvider(APIProviderConfig config) throws UnsupportedProviderException;
    
    /**
     * Check if this factory supports creating the given provider type
     * @param type The provider type to check
     * @return true if this factory can create providers of the given type
     */
    boolean supports(APIProvider.ProviderType type);
    
    /**
     * Get the provider type this factory creates
     * @return The provider type
     */
    APIProvider.ProviderType getProviderType();
    
    /**
     * Get a human-readable name for this factory
     * @return Factory name
     */
    String getFactoryName();
}