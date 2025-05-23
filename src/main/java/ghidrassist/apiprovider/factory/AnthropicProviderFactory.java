package ghidrassist.apiprovider.factory;

import ghidrassist.apiprovider.APIProvider;
import ghidrassist.apiprovider.APIProviderConfig;
import ghidrassist.apiprovider.AnthropicProvider;

/**
 * Factory for creating Anthropic API providers.
 */
public class AnthropicProviderFactory implements APIProviderFactory {
    
    @Override
    public APIProvider createProvider(APIProviderConfig config) throws UnsupportedProviderException {
        if (!supports(config.getType())) {
            throw new UnsupportedProviderException(config.getType(), getFactoryName());
        }
        
        return new AnthropicProvider(
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
        return type == APIProvider.ProviderType.ANTHROPIC;
    }
    
    @Override
    public APIProvider.ProviderType getProviderType() {
        return APIProvider.ProviderType.ANTHROPIC;
    }
    
    @Override
    public String getFactoryName() {
        return "AnthropicProviderFactory";
    }
}