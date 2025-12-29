package ghidrassist.apiprovider.factory;

import ghidrassist.apiprovider.APIProvider;
import ghidrassist.apiprovider.APIProviderConfig;
import ghidrassist.apiprovider.LiteLLMProvider;

/**
 * Factory for creating LiteLLM API providers.
 * LiteLLM is a proxy that provides an OpenAI-compatible API to various backends
 * including AWS Bedrock, Azure, Google, and more.
 */
public class LiteLLMProviderFactory implements APIProviderFactory {

    @Override
    public APIProvider createProvider(APIProviderConfig config) throws UnsupportedProviderException {
        if (!supports(config.getType())) {
            throw new UnsupportedProviderException(config.getType(), getFactoryName());
        }

        return new LiteLLMProvider(
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
        return type == APIProvider.ProviderType.LITELLM;
    }

    @Override
    public APIProvider.ProviderType getProviderType() {
        return APIProvider.ProviderType.LITELLM;
    }

    @Override
    public String getFactoryName() {
        return "LiteLLMProviderFactory";
    }
}
