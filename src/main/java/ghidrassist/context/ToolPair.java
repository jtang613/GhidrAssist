package ghidrassist.context;

import ghidrassist.apiprovider.ChatMessage;

import java.util.ArrayList;
import java.util.List;

/**
 * Represents a complete tool calling pair:
 * - Assistant message with tool_calls
 * - One or more tool result messages
 *
 * Tool pairs must be kept together during context compression to maintain
 * conversation coherence. Splitting a pair would leave orphaned tool calls
 * or orphaned tool results, confusing the LLM.
 */
public class ToolPair {

    private final ChatMessage assistantMessage;    // Assistant message with tool_calls
    private final List<ChatMessage> toolResults;   // Tool result messages

    public ToolPair(ChatMessage assistantMessage) {
        this.assistantMessage = assistantMessage;
        this.toolResults = new ArrayList<>();
    }

    /**
     * Add a tool result message to this pair.
     */
    public void addToolResult(ChatMessage toolResult) {
        toolResults.add(toolResult);
    }

    /**
     * Get all messages in this pair (assistant + tool results).
     */
    public List<ChatMessage> getAllMessages() {
        List<ChatMessage> all = new ArrayList<>();
        all.add(assistantMessage);
        all.addAll(toolResults);
        return all;
    }

    /**
     * Check if this pair is complete (has at least one tool result).
     */
    public boolean isComplete() {
        return !toolResults.isEmpty();
    }

    /**
     * Get the number of tool calls in the assistant message.
     */
    public int getToolCallCount() {
        if (assistantMessage == null || assistantMessage.getToolCalls() == null) {
            return 0;
        }
        return assistantMessage.getToolCalls().size();
    }

    /**
     * Get the number of tool results.
     */
    public int getToolResultCount() {
        return toolResults.size();
    }

    // Getters
    public ChatMessage getAssistantMessage() {
        return assistantMessage;
    }

    public List<ChatMessage> getToolResults() {
        return toolResults;
    }

    @Override
    public String toString() {
        return String.format(
            "ToolPair{assistant with %d tool_calls, %d tool results, complete=%s}",
            getToolCallCount(), getToolResultCount(), isComplete()
        );
    }
}
