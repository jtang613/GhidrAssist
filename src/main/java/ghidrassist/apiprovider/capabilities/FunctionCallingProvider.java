package ghidrassist.apiprovider.capabilities;

import ghidrassist.apiprovider.ChatMessage;
import ghidrassist.apiprovider.exceptions.APIProviderException;

import java.util.List;
import java.util.Map;

/**
 * Interface for providers that support function calling / tool calling.
 * Not all providers support this capability.
 */
public interface FunctionCallingProvider {
    
    /**
     * Create a chat completion with function calling support
     * @param messages The conversation messages
     * @param functions Available functions/tools that the model can call
     * @return The completion response, potentially containing function calls
     * @throws APIProviderException if the request fails
     */
    String createChatCompletionWithFunctions(List<ChatMessage> messages, List<Map<String, Object>> functions) throws APIProviderException;
    
    /**
     * Check if this provider supports function calling
     * @return true if function calling is supported
     */
    default boolean supportsFunctionCalling() {
        return true;
    }
}