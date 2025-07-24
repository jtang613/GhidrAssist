package ghidrassist.apiprovider.factory;

import ghidrassist.apiprovider.APIProvider;
import ghidrassist.apiprovider.APIProviderConfig;
import ghidrassist.apiprovider.AzureOpenAIProvider;

/**
 * Factory for creating Azure OpenAI API providers.
 */
public class AzureOpenAIProviderFactory implements APIProviderFactory {

    @Override
    public APIProvider createProvider(APIProviderConfig config) throws UnsupportedProviderException {
        if (!supports(config.getType())) {
            throw new UnsupportedProviderException(config.getType(), getFactoryName());
        }

        return new AzureOpenAIProvider(
                config.getName(),
                config.getModel(),
                config.getMaxTokens(),
                config.getUrl(),
                config.getKey(),
                config.isDisableTlsVerification(),
                config.getTimeout());
    }

    @Override
    public boolean supports(APIProvider.ProviderType type) {
        return type == APIProvider.ProviderType.AZURE_OPENAI;
    }

    @Override
    public APIProvider.ProviderType getProviderType() {
        return APIProvider.ProviderType.AZURE_OPENAI;
    }

    @Override
    public String getFactoryName() {
        return "AzureOpenAIProviderFactory";
    }
}
