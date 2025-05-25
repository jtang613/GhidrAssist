package ghidrassist;

import ghidrassist.apiprovider.APIProviderConfig;
import ghidrassist.core.ConversationalToolHandler;
import ghidrassist.core.LlmApiClient;
import ghidrassist.core.LlmErrorHandler;
import ghidrassist.core.LlmTaskExecutor;
import ghidrassist.core.ResponseProcessor;

import java.util.List;
import java.util.Map;

/**
 * - LlmApiClient: Provider management and API calls
 * - ResponseProcessor: Text filtering and processing
 * - LlmTaskExecutor: Background task execution
 * - LlmErrorHandler: Error handling and user feedback
 */
public class LlmApi {
    
    private final LlmApiClient apiClient;
    private final ResponseProcessor responseProcessor;
    private final LlmTaskExecutor taskExecutor;
    private final LlmErrorHandler errorHandler;
    private volatile ConversationalToolHandler activeConversationalHandler;
    
    public LlmApi(APIProviderConfig config, GhidrAssistPlugin plugin) {
        this.apiClient = new LlmApiClient(config, plugin);
        this.responseProcessor = new ResponseProcessor();
        this.taskExecutor = new LlmTaskExecutor();
        this.errorHandler = new LlmErrorHandler(plugin, this);
    }

    /**
     * Get the system prompt for regular queries
     */
    public String getSystemPrompt() {
        return apiClient.getSystemPrompt();
    }

    /**
     * Send a streaming request with enhanced error handling
     */
    public void sendRequestAsync(String prompt, LlmResponseHandler responseHandler) {
        if (!apiClient.isProviderAvailable()) {
            errorHandler.handleError(
                new IllegalStateException("LLM provider is not initialized."), 
                "send request", 
                null
            );
            return;
        }

        // Create enhanced response handler that includes error handling
        LlmTaskExecutor.LlmResponseHandler enhancedHandler = new LlmTaskExecutor.LlmResponseHandler() {
            @Override
            public void onStart() {
                responseHandler.onStart();
            }

            @Override
            public void onUpdate(String partialResponse) {
                responseHandler.onUpdate(partialResponse);
            }

            @Override
            public void onComplete(String fullResponse) {
                responseHandler.onComplete(fullResponse);
            }

            @Override
            public void onError(Throwable error) {
                // Handle error with enhanced error handling
                Runnable retryAction = () -> sendRequestAsync(prompt, responseHandler);
                errorHandler.handleError(error, "stream chat completion", retryAction);
                responseHandler.onError(error);
            }

            @Override
            public boolean shouldContinue() {
                return responseHandler.shouldContinue();
            }
        };

        taskExecutor.executeStreamingRequest(apiClient, prompt, responseProcessor, enhancedHandler);
    }

    /**
     * Send a conversational tool calling request that handles multiple turns
     * Monitors finish_reason to determine when to execute tools vs. complete
     */
    public void sendConversationalToolRequest(String prompt, List<Map<String, Object>> functions, LlmResponseHandler responseHandler) {
        if (!apiClient.isProviderAvailable()) {
            errorHandler.handleError(
                new IllegalStateException("LLM provider is not initialized."), 
                "send conversational tool request", 
                null
            );
            return;
        }

        // Create completion callback to clear reference
        Runnable onCompletion = () -> {
            activeConversationalHandler = null;
        };
        
        // Create enhanced response handler for conversational tool calling
        ConversationalToolHandler toolHandler = new ConversationalToolHandler(
            apiClient, functions, responseProcessor, responseHandler, errorHandler, onCompletion);
        
        // Store reference for cancellation
        activeConversationalHandler = toolHandler;
        
        // Start the conversation
        toolHandler.startConversation(prompt);
    }

    /**
     * Send a function calling request with enhanced error handling (legacy method)
     */
    public void sendRequestAsyncWithFunctions(String prompt, List<Map<String, Object>> functions, LlmResponseHandler responseHandler) {
        if (!apiClient.isProviderAvailable()) {
            errorHandler.handleError(
                new IllegalStateException("LLM provider is not initialized."), 
                "send function request", 
                null
            );
            return;
        }

        // Create enhanced response handler that includes error handling
        LlmTaskExecutor.LlmResponseHandler enhancedHandler = new LlmTaskExecutor.LlmResponseHandler() {
            @Override
            public void onStart() {
                responseHandler.onStart();
            }

            @Override
            public void onUpdate(String partialResponse) {
                responseHandler.onUpdate(partialResponse);
            }

            @Override
            public void onComplete(String fullResponse) {
                responseHandler.onComplete(fullResponse);
            }

            @Override
            public void onError(Throwable error) {
                // Handle error with enhanced error handling
                Runnable retryAction = () -> sendRequestAsyncWithFunctions(prompt, functions, responseHandler);
                errorHandler.handleError(error, "chat completion with functions", retryAction);
                responseHandler.onError(error);
            }

            @Override
            public boolean shouldContinue() {
                return responseHandler.shouldContinue();
            }
        };

        taskExecutor.executeFunctionRequest(apiClient, prompt, functions, responseProcessor, enhancedHandler);
    }

    /**
     * Cancel the current request
     */
    public void cancelCurrentRequest() {
        // Cancel conversational tool handler if active
        if (activeConversationalHandler != null) {
            activeConversationalHandler.cancel();
            activeConversationalHandler = null;
        }
        
        // Cancel regular task executor
        taskExecutor.cancelCurrentRequest();
    }

    /**
     * Check if currently processing a request
     */
    public boolean isStreaming() {
        return taskExecutor.isStreaming();
    }
    
    /**
     * Get provider information for debugging/logging
     */
    public String getProviderInfo() {
        return String.format("Provider: %s, Model: %s", 
            apiClient.getProviderName(), 
            apiClient.getProviderModel());
    }

    /**
     * Interface for handling LLM responses - maintains compatibility with existing code
     */
    public interface LlmResponseHandler {
        void onStart();
        void onUpdate(String partialResponse);
        void onComplete(String fullResponse);
        void onError(Throwable error);
        default boolean shouldContinue() {
            return true;
        }
    }
}