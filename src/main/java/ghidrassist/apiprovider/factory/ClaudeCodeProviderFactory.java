package ghidrassist.apiprovider.factory;

import ghidrassist.apiprovider.APIProvider;
import ghidrassist.apiprovider.APIProviderConfig;
import ghidrassist.apiprovider.ClaudeCodeProvider;

/**
 * Factory for creating Claude Code CLI providers.
 *
 * The Claude Code provider proxies API requests through the claude CLI,
 * enabling use of Claude models without requiring an API key.
 */
public class ClaudeCodeProviderFactory implements APIProviderFactory {

    @Override
    public APIProvider createProvider(APIProviderConfig config) throws UnsupportedProviderException {
        if (!supports(config.getType())) {
            throw new UnsupportedProviderException(config.getType(), getFactoryName());
        }

        return new ClaudeCodeProvider(
            config.getName(),
            config.getModel(),
            config.getMaxTokens(),
            config.getUrl(),      // Not used but kept for API consistency
            config.getKey(),      // Not used but kept for API consistency
            config.isDisableTlsVerification(),
            config.getTimeout()
        );
    }

    @Override
    public boolean supports(APIProvider.ProviderType type) {
        return type == APIProvider.ProviderType.CLAUDE_CODE;
    }

    @Override
    public APIProvider.ProviderType getProviderType() {
        return APIProvider.ProviderType.CLAUDE_CODE;
    }

    @Override
    public String getFactoryName() {
        return "ClaudeCodeProviderFactory";
    }
}
