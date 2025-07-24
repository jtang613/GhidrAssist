package ghidrassist.apiprovider.factory;

import ghidrassist.apiprovider.APIProvider;
import ghidrassist.apiprovider.APIProviderConfig;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Registry for API provider factories.
 * Manages the creation of providers through registered factories.
 * Thread-safe and follows the Registry pattern.
 */
public class ProviderRegistry {
    
    private final Map<APIProvider.ProviderType, APIProviderFactory> factories = new ConcurrentHashMap<>();
    private static final ProviderRegistry INSTANCE = new ProviderRegistry();
    
    /**
     * Get the singleton instance of the provider registry
     */
    public static ProviderRegistry getInstance() {
        return INSTANCE;
    }
    
    /**
     * Private constructor for singleton
     */
    private ProviderRegistry() {
        // Register default factories
        registerDefaultFactories();
    }
    
    /**
     * Register a factory for a specific provider type
     * @param factory The factory to register
     */
    public void registerFactory(APIProviderFactory factory) {
        if (factory == null) {
            throw new IllegalArgumentException("Factory cannot be null");
        }
        
        APIProvider.ProviderType type = factory.getProviderType();
        if (type == null) {
            throw new IllegalArgumentException("Factory must specify a provider type");
        }
        
        factories.put(type, factory);
    }
    
    /**
     * Unregister a factory for a specific provider type
     * @param type The provider type to unregister
     * @return The previously registered factory, or null if none was registered
     */
    public APIProviderFactory unregisterFactory(APIProvider.ProviderType type) {
        return factories.remove(type);
    }
    
    /**
     * Create a provider using the appropriate factory
     * @param config The provider configuration
     * @return A configured provider instance
     * @throws UnsupportedProviderException if no factory is registered for the provider type
     */
    public APIProvider createProvider(APIProviderConfig config) throws UnsupportedProviderException {
        if (config == null) {
            throw new IllegalArgumentException("Provider config cannot be null");
        }
        
        APIProvider.ProviderType type = config.getType();
        APIProviderFactory factory = factories.get(type);
        
        if (factory == null) {
            throw new UnsupportedProviderException(type, "ProviderRegistry", 
                "No factory registered for provider type: " + type);
        }
        
        return factory.createProvider(config);
    }
    
    /**
     * Check if a provider type is supported
     * @param type The provider type to check
     * @return true if a factory is registered for this type
     */
    public boolean isSupported(APIProvider.ProviderType type) {
        return factories.containsKey(type);
    }
    
    /**
     * Get all supported provider types
     * @return Set of supported provider types
     */
    public Set<APIProvider.ProviderType> getSupportedTypes() {
        return new HashSet<>(factories.keySet());
    }
    
    /**
     * Get all registered factories
     * @return Map of provider types to their factories
     */
    public Map<APIProvider.ProviderType, APIProviderFactory> getRegisteredFactories() {
        return new HashMap<>(factories);
    }
    
    /**
     * Get the factory for a specific provider type
     * @param type The provider type
     * @return The factory, or null if none is registered
     */
    public APIProviderFactory getFactory(APIProvider.ProviderType type) {
        return factories.get(type);
    }
    
    /**
     * Clear all registered factories (mainly for testing)
     */
    public void clearFactories() {
        factories.clear();
    }
    
    /**
     * Register the default built-in factories
     */
    private void registerDefaultFactories() {
        registerFactory(new AnthropicProviderFactory());
        registerFactory(new OpenAIProviderFactory());
        registerFactory(new AzureOpenAIProviderFactory());
        registerFactory(new OllamaProviderFactory());
        registerFactory(new LMStudioProviderFactory());
        registerFactory(new OpenWebUiProviderFactory());
    }
    
    /**
     * Get information about all registered factories
     * @return Human-readable string describing registered factories
     */
    public String getRegistryInfo() {
        StringBuilder sb = new StringBuilder();
        sb.append("Registered Provider Factories:\n");
        
        for (Map.Entry<APIProvider.ProviderType, APIProviderFactory> entry : factories.entrySet()) {
            sb.append(String.format("  %s -> %s\n", 
                entry.getKey(), 
                entry.getValue().getFactoryName()));
        }
        
        return sb.toString();
    }
}