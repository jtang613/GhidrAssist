package ghidrassist.apiprovider.capabilities;

import ghidrassist.apiprovider.exceptions.APIProviderException;

import java.util.List;

/**
 * Interface for providers that can list available models.
 * Not all providers support this capability.
 */
public interface ModelListProvider {
    
    /**
     * Get list of available models from this provider
     * @return List of model identifiers
     * @throws APIProviderException if the request fails
     */
    List<String> getAvailableModels() throws APIProviderException;
    
    /**
     * Check if this provider supports model listing
     * @return true if model listing is supported
     */
    default boolean supportsModelListing() {
        return true;
    }
}