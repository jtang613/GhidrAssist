package ghidrassist.apiprovider.factory;

import ghidrassist.apiprovider.APIProvider;
import ghidrassist.apiprovider.APIProviderConfig;
import ghidrassist.apiprovider.OpenAIOAuthProvider;

/**
 * Factory for creating OpenAI OAuth API providers.
 * 
 * This provider uses OAuth authentication for ChatGPT Pro/Plus subscriptions,
 * routing requests through the Codex Responses API endpoint.
 */
public class OpenAIOAuthProviderFactory implements APIProviderFactory {
    
    @Override
    public APIProvider createProvider(APIProviderConfig config) throws UnsupportedProviderException {
        if (!supports(config.getType())) {
            throw new UnsupportedProviderException(config.getType(), getFactoryName());
        }
        
        return new OpenAIOAuthProvider(
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
        return type == APIProvider.ProviderType.OPENAI_OAUTH;
    }
    
    @Override
    public APIProvider.ProviderType getProviderType() {
        return APIProvider.ProviderType.OPENAI_OAUTH;
    }
    
    @Override
    public String getFactoryName() {
        return "OpenAIOAuthProviderFactory";
    }
}
