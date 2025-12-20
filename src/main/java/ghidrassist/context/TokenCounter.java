package ghidrassist.context;

import ghidrassist.apiprovider.ChatMessage;

import java.util.List;
import java.util.Map;

/**
 * Interface for counting tokens in messages and text.
 * Provides abstraction over different token counting methods (provider-specific or estimation).
 */
public interface TokenCounter {

    /**
     * Count tokens in a list of chat messages.
     *
     * @param messages List of chat messages
     * @return Estimated token count, or -1 if unable to count
     */
    int countTokens(List<ChatMessage> messages);

    /**
     * Count tokens in a text string.
     *
     * @param text Text to count tokens for
     * @return Estimated token count, or -1 if unable to count
     */
    int countTokens(String text);

    /**
     * Estimate tokens required for tool definitions.
     * Tools are passed to LLM as part of the request and consume tokens.
     *
     * @param tools List of tool definitions in OpenAI function format
     * @return Estimated token count for tools, or -1 if unable to estimate
     */
    int estimateTokensForTools(List<Map<String, Object>> tools);
}
