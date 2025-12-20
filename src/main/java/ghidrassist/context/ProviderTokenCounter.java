package ghidrassist.context;

import ghidrassist.apiprovider.APIProvider;
import ghidrassist.apiprovider.ChatMessage;
import ghidrassist.apiprovider.exceptions.APIProviderException;
import ghidra.util.Msg;

import java.util.List;
import java.util.Map;

/**
 * Token counter that delegates to provider-specific token counting when available,
 * falling back to character-based estimation when not supported.
 */
public class ProviderTokenCounter implements TokenCounter {

    private final APIProvider provider;
    private final CharacterBasedTokenCounter fallback;

    public ProviderTokenCounter(APIProvider provider) {
        this.provider = provider;
        this.fallback = new CharacterBasedTokenCounter();
    }

    @Override
    public int countTokens(List<ChatMessage> messages) {
        try {
            // Try provider-specific counting first
            int providerCount = provider.countTokens(messages);
            if (providerCount >= 0) {
                return providerCount;
            }
        } catch (APIProviderException e) {
            Msg.debug(this, "Provider token counting failed, using fallback: " + e.getMessage());
        }

        // Fall back to character-based estimation
        return fallback.countTokens(messages);
    }

    @Override
    public int countTokens(String text) {
        try {
            // Try provider-specific counting first
            int providerCount = provider.countTokens(text);
            if (providerCount >= 0) {
                return providerCount;
            }
        } catch (APIProviderException e) {
            Msg.debug(this, "Provider token counting failed, using fallback: " + e.getMessage());
        }

        // Fall back to character-based estimation
        return fallback.countTokens(text);
    }

    @Override
    public int estimateTokensForTools(List<Map<String, Object>> tools) {
        try {
            // Try provider-specific estimation first
            int providerEstimate = provider.estimateTokensForTools(tools);
            if (providerEstimate >= 0) {
                return providerEstimate;
            }
        } catch (APIProviderException e) {
            Msg.debug(this, "Provider tool token estimation failed, using fallback: " + e.getMessage());
        }

        // Fall back to character-based estimation
        return fallback.estimateTokensForTools(tools);
    }
}
