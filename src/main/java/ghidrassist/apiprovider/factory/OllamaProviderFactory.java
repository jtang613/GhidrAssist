package ghidrassist.apiprovider.factory;

import ghidrassist.apiprovider.APIProvider;
import ghidrassist.apiprovider.APIProviderConfig;
import ghidrassist.apiprovider.OllamaProvider;

/**
 * Factory for creating Ollama API providers.
 */
public class OllamaProviderFactory implements APIProviderFactory {
    
    @Override
    public APIProvider createProvider(APIProviderConfig config) throws UnsupportedProviderException {
        if (!supports(config.getType())) {
            throw new UnsupportedProviderException(config.getType(), getFactoryName());
        }
        
        return new OllamaProvider(
            config.getName(),
            config.getModel(),
            config.getMaxTokens(),
            config.getUrl(),
            config.getKey(),
            config.isDisableTlsVerification(),
            config.getTimeout()
        );
    }
    
    @Override
    public boolean supports(APIProvider.ProviderType type) {
        return type == APIProvider.ProviderType.OLLAMA;
    }
    
    @Override
    public APIProvider.ProviderType getProviderType() {
        return APIProvider.ProviderType.OLLAMA;
    }
    
    @Override
    public String getFactoryName() {
        return "OllamaProviderFactory";
    }
}