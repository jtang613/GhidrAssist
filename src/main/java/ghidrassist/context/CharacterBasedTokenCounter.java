package ghidrassist.context;

import ghidrassist.apiprovider.ChatMessage;
import com.google.gson.Gson;

import java.util.List;
import java.util.Map;

/**
 * Fallback token counter that uses character-based estimation.
 * Uses a 4-characters-per-token heuristic, which is reasonably accurate
 * for English text and matches OpenAI's general guidance.
 */
public class CharacterBasedTokenCounter implements TokenCounter {

    private static final int CHARS_PER_TOKEN = 4;
    private static final int TOOL_DEFINITION_AVG_TOKENS = 150; // Rough estimate per tool
    private final Gson gson = new Gson();

    @Override
    public int countTokens(List<ChatMessage> messages) {
        if (messages == null || messages.isEmpty()) {
            return 0;
        }

        int totalChars = 0;

        for (ChatMessage message : messages) {
            // Count role name (adds small overhead)
            if (message.getRole() != null) {
                totalChars += message.getRole().length();
            }

            // Count message content
            if (message.getContent() != null) {
                totalChars += message.getContent().length();
            }

            // Count tool call information if present
            if (message.getToolCalls() != null && !message.getToolCalls().isEmpty()) {
                String toolCallsJson = gson.toJson(message.getToolCalls());
                totalChars += toolCallsJson.length();
            }

            // Count tool call ID if present
            if (message.getToolCallId() != null) {
                totalChars += message.getToolCallId().length();
            }

            // Count thinking content if present
            if (message.getThinkingContent() != null) {
                totalChars += message.getThinkingContent().length();
            }
        }

        return totalChars / CHARS_PER_TOKEN;
    }

    @Override
    public int countTokens(String text) {
        if (text == null || text.isEmpty()) {
            return 0;
        }
        return text.length() / CHARS_PER_TOKEN;
    }

    @Override
    public int estimateTokensForTools(List<Map<String, Object>> tools) {
        if (tools == null || tools.isEmpty()) {
            return 0;
        }

        // Approach 1: If we want to be precise, serialize and count
        String toolsJson = gson.toJson(tools);
        int jsonTokens = toolsJson.length() / CHARS_PER_TOKEN;

        // Approach 2: Use average estimate
        int avgEstimate = tools.size() * TOOL_DEFINITION_AVG_TOKENS;

        // Return the larger of the two (conservative estimate)
        return Math.max(jsonTokens, avgEstimate);
    }
}
