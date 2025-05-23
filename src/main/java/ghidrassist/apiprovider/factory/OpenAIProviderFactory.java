package ghidrassist.apiprovider.factory;

import ghidrassist.apiprovider.APIProvider;
import ghidrassist.apiprovider.APIProviderConfig;
import ghidrassist.apiprovider.OpenAIProvider;

/**
 * Factory for creating OpenAI API providers.
 */
public class OpenAIProviderFactory implements APIProviderFactory {
    
    @Override
    public APIProvider createProvider(APIProviderConfig config) throws UnsupportedProviderException {
        if (!supports(config.getType())) {
            throw new UnsupportedProviderException(config.getType(), getFactoryName());
        }
        
        return new OpenAIProvider(
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
        return type == APIProvider.ProviderType.OPENAI;
    }
    
    @Override
    public APIProvider.ProviderType getProviderType() {
        return APIProvider.ProviderType.OPENAI;
    }
    
    @Override
    public String getFactoryName() {
        return "OpenAIProviderFactory";
    }
}