package ghidrassist.apiprovider.factory;

import ghidrassist.apiprovider.APIProvider;
import ghidrassist.apiprovider.APIProviderConfig;
import ghidrassist.apiprovider.LMStudioProvider;

/**
 * Factory for creating LM Studio API providers.
 */
public class LMStudioProviderFactory implements APIProviderFactory {
    
    @Override
    public APIProvider createProvider(APIProviderConfig config) throws UnsupportedProviderException {
        if (!supports(config.getType())) {
            throw new UnsupportedProviderException(config.getType(), getFactoryName());
        }
        
        return new LMStudioProvider(
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
        return type == APIProvider.ProviderType.LMSTUDIO;
    }
    
    @Override
    public APIProvider.ProviderType getProviderType() {
        return APIProvider.ProviderType.LMSTUDIO;
    }
    
    @Override
    public String getFactoryName() {
        return "LMStudioProviderFactory";
    }
}