package ghidrassist.core;

import ghidrassist.LlmApi;
import ghidrassist.apiprovider.exceptions.APIProviderException;

import javax.swing.SwingWorker;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Handles background task execution for LLM operations.
 * Focused on managing SwingWorker tasks and request lifecycle.
 */
public class LlmTaskExecutor {
    
    private final Object streamLock = new Object();
    private volatile boolean isStreaming = false;
    private final AtomicBoolean shouldCancel = new AtomicBoolean(false);
    
    /**
     * Execute a streaming chat request in the background
     */
    public void executeStreamingRequest(
            LlmApiClient client, 
            String prompt, 
            ResponseProcessor responseProcessor,
            LlmResponseHandler responseHandler) {
        
        if (!client.isProviderAvailable()) {
            responseHandler.onError(new IllegalStateException("LLM provider is not initialized."));
            return;
        }

        // Cancel any existing stream
        cancelCurrentRequest();
        shouldCancel.set(false);

        try {
            synchronized (streamLock) {
                isStreaming = true;
                ResponseProcessor.StreamingResponseFilter filter = responseProcessor.createStreamingFilter();
                
                client.streamChatCompletion(client.createChatMessages(prompt), new LlmApi.LlmResponseHandler() {
                    private boolean isFirst = true;

                    @Override
                    public void onStart() {
                        if (isFirst && shouldCancel.get() == false) {
                            responseHandler.onStart();
                            isFirst = false;
                        }
                    }

                    @Override
                    public void onUpdate(String partialResponse) {
                        if (shouldCancel.get()) {
                            return;
                        }
                        String filteredContent = filter.processChunk(partialResponse);
                        if (filteredContent != null && !filteredContent.isEmpty()) {
                            responseHandler.onUpdate(filteredContent);
                        }
                    }

                    @Override
                    public void onComplete(String fullResponse) {
                        synchronized (streamLock) {
                            isStreaming = false;
                        }
                        if (!shouldCancel.get()) {
                            responseHandler.onComplete(filter.getFilteredContent());
                        }
                    }

                    @Override
                    public void onError(Throwable error) {
                        synchronized (streamLock) {
                            isStreaming = false;
                        }
                        if (!shouldCancel.get()) {
                            responseHandler.onError(error);
                        }
                    }

                    @Override
                    public boolean shouldContinue() {
                        return !shouldCancel.get() && responseHandler.shouldContinue();
                    }
                });
            }
        } catch (Exception e) {
            synchronized (streamLock) {
                isStreaming = false;
            }
            if (!shouldCancel.get()) {
                responseHandler.onError(e);
            }
        }
    }
    
    /**
     * Execute a function calling request in the background
     */
    public void executeFunctionRequest(
            LlmApiClient client,
            String prompt,
            List<Map<String, Object>> functions,
            ResponseProcessor responseProcessor,
            LlmResponseHandler responseHandler) {
        
        if (!client.isProviderAvailable()) {
            responseHandler.onError(new IllegalStateException("LLM provider is not initialized."));
            return;
        }

        shouldCancel.set(false);

        // Create a background task
        SwingWorker<Void, String> worker = new SwingWorker<>() {
            @Override
            protected Void doInBackground() {
                try {
                    synchronized (streamLock) {
                        isStreaming = true;
                    }
                    
                    if (!shouldCancel.get()) {
                        responseHandler.onStart();
                        String response = client.createChatCompletionWithFunctions(
                            client.createFunctionMessages(prompt), functions);
                        
                        if (!shouldCancel.get() && responseHandler.shouldContinue()) {
                            String filteredResponse = responseProcessor.filterThinkBlocks(response);
                            responseHandler.onComplete(filteredResponse);
                        }
                    }
                } catch (APIProviderException e) {
                    if (!shouldCancel.get() && responseHandler.shouldContinue()) {
                        responseHandler.onError(e);
                    }
                } finally {
                    synchronized (streamLock) {
                        isStreaming = false;
                    }
                }
                return null;
            }

            @Override
            protected void done() {
                try {
                    get(); // Check for exceptions
                } catch (Exception e) {
                    if (!shouldCancel.get() && responseHandler.shouldContinue()) {
                        responseHandler.onError(e);
                    }
                }
            }
        };

        worker.execute();
    }
    
    /**
     * Cancel the current request
     */
    public void cancelCurrentRequest() {
        shouldCancel.set(true);
        synchronized (streamLock) {
            isStreaming = false;
        }
    }
    
    /**
     * Check if currently streaming
     */
    public boolean isStreaming() {
        synchronized (streamLock) {
            return isStreaming;
        }
    }
    
    /**
     * Interface for handling LLM responses
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