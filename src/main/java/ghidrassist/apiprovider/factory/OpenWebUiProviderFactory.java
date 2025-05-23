package ghidrassist.apiprovider.factory;

import ghidrassist.apiprovider.APIProvider;
import ghidrassist.apiprovider.APIProviderConfig;
import ghidrassist.apiprovider.OpenWebUiProvider;

/**
 * Factory for creating OpenWebUI API providers.
 */
public class OpenWebUiProviderFactory implements APIProviderFactory {
    
    @Override
    public APIProvider createProvider(APIProviderConfig config) throws UnsupportedProviderException {
        if (!supports(config.getType())) {
            throw new UnsupportedProviderException(config.getType(), getFactoryName());
        }
        
        return new OpenWebUiProvider(
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
        return type == APIProvider.ProviderType.OPENWEBUI;
    }
    
    @Override
    public APIProvider.ProviderType getProviderType() {
        return APIProvider.ProviderType.OPENWEBUI;
    }
    
    @Override
    public String getFactoryName() {
        return "OpenWebUiProviderFactory";
    }
}