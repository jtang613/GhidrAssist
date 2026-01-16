package ghidrassist.apiprovider.factory;

import ghidrassist.apiprovider.APIProvider;
import ghidrassist.apiprovider.APIProviderConfig;
import ghidrassist.apiprovider.AnthropicOAuthProvider;

/**
 * Factory for creating Claude OAuth API providers.
 * 
 * This provider uses OAuth authentication for Claude Pro/Max subscriptions.
 */
public class AnthropicOAuthProviderFactory implements APIProviderFactory {
    
    @Override
    public APIProvider createProvider(APIProviderConfig config) throws UnsupportedProviderException {
        if (!supports(config.getType())) {
            throw new UnsupportedProviderException(config.getType(), getFactoryName());
        }
        
        return new AnthropicOAuthProvider(
            config.getName(),
            config.getModel(),
            config.getMaxTokens(),
            config.getUrl(),
            config.getKey(),  // Contains OAuth credentials as JSON
            config.isDisableTlsVerification(),
            config.getTimeout()
        );
    }
    
    @Override
    public boolean supports(APIProvider.ProviderType type) {
        return type == APIProvider.ProviderType.ANTHROPIC_OAUTH;
    }
    
    @Override
    public APIProvider.ProviderType getProviderType() {
        return APIProvider.ProviderType.ANTHROPIC_OAUTH;
    }
    
    @Override
    public String getFactoryName() {
        return "AnthropicOAuthProviderFactory";
    }
}
