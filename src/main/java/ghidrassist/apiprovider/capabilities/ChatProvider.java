package ghidrassist.apiprovider.capabilities;

import ghidrassist.LlmApi;
import ghidrassist.apiprovider.ChatMessage;
import ghidrassist.apiprovider.exceptions.APIProviderException;

import java.util.List;

/**
 * Interface for providers that support basic chat completion.
 * This is the core capability that all LLM providers should support.
 */
public interface ChatProvider {
    
    /**
     * Create a chat completion (blocking/synchronous)
     * @param messages The conversation messages
     * @return The completion response
     * @throws APIProviderException if the request fails
     */
    String createChatCompletion(List<ChatMessage> messages) throws APIProviderException;
    
    /**
     * Stream a chat completion (non-blocking/asynchronous)
     * @param messages The conversation messages
     * @param handler Handler for streaming response chunks
     * @throws APIProviderException if the request fails
     */
    void streamChatCompletion(List<ChatMessage> messages, LlmApi.LlmResponseHandler handler) throws APIProviderException;
}