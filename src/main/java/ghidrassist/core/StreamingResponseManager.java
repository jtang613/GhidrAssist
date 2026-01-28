package ghidrassist.core;

import ghidra.util.Msg;
import ghidrassist.LlmApi;
import ghidrassist.core.streaming.RenderUpdate;
import ghidrassist.core.streaming.StreamingMarkdownRenderer;
import ghidrassist.services.FeedbackService;
import ghidrassist.services.QueryService;
import ghidrassist.ui.tabs.ExplainTab;
import ghidrassist.ui.tabs.QueryTab;
import ghidrassist.ui.tabs.ActionsTab;

import javax.swing.*;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * Manages streaming response handlers and renderers for LLM interactions.
 * Provides factory methods for creating response handlers with standardized patterns.
 *
 * Extracted from TabController as part of decomposition refactoring.
 */
public class StreamingResponseManager {

    private final MarkdownHelper markdownHelper;

    // Streaming renderers - volatile for thread safety
    private volatile StreamingMarkdownRenderer currentStreamingRenderer;
    private volatile StreamingMarkdownRenderer currentExplainStreamingRenderer;
    private volatile StreamingMarkdownRenderer currentLineExplainStreamingRenderer;

    public StreamingResponseManager(MarkdownHelper markdownHelper) {
        this.markdownHelper = markdownHelper;
    }

    // ==== Renderer Access ====

    public StreamingMarkdownRenderer getCurrentStreamingRenderer() {
        return currentStreamingRenderer;
    }

    public void setCurrentStreamingRenderer(StreamingMarkdownRenderer renderer) {
        this.currentStreamingRenderer = renderer;
    }

    public StreamingMarkdownRenderer getCurrentExplainStreamingRenderer() {
        return currentExplainStreamingRenderer;
    }

    public void setCurrentExplainStreamingRenderer(StreamingMarkdownRenderer renderer) {
        this.currentExplainStreamingRenderer = renderer;
    }

    public StreamingMarkdownRenderer getCurrentLineExplainStreamingRenderer() {
        return currentLineExplainStreamingRenderer;
    }

    public void setCurrentLineExplainStreamingRenderer(StreamingMarkdownRenderer renderer) {
        this.currentLineExplainStreamingRenderer = renderer;
    }

    // ==== Cleanup ====

    /**
     * Cancel all active renderers.
     * Used during operation cancellation.
     */
    public void cancelAllRenderers() {
        currentStreamingRenderer = null;
        currentExplainStreamingRenderer = null;
        currentLineExplainStreamingRenderer = null;
    }

    /**
     * Clean up a specific renderer.
     */
    public void cleanupRenderer(StreamingMarkdownRenderer renderer) {
        if (renderer == currentStreamingRenderer) {
            currentStreamingRenderer = null;
        } else if (renderer == currentExplainStreamingRenderer) {
            currentExplainStreamingRenderer = null;
        } else if (renderer == currentLineExplainStreamingRenderer) {
            currentLineExplainStreamingRenderer = null;
        }
    }

    // ==== Handler Factory Methods ====

    /**
     * Create a conversation handler for the Query tab.
     * Handles streaming responses with conversation history prefix.
     */
    public LlmApi.LlmResponseHandler createConversationHandler(
            QueryTab queryTab,
            QueryService queryService,
            FeedbackService feedbackService,
            Supplier<Boolean> isRunning,
            Runnable onComplete,
            Consumer<LlmApi> clearLlmApi) {

        return new LlmApi.LlmResponseHandler() {
            private final StringBuilder responseBuffer = new StringBuilder();
            private final Object bufferLock = new Object();

            @Override
            public void onStart() {
                synchronized (bufferLock) {
                    responseBuffer.setLength(0);
                }

                // Render existing conversation history as prefix
                String existingHtml = markdownHelper.markdownToHtmlFragment(
                    queryService.getConversationHistory());

                // Create streaming renderer
                currentStreamingRenderer = new StreamingMarkdownRenderer(
                    update -> queryTab.applyRenderUpdate(update),
                    markdownHelper
                );
                currentStreamingRenderer.setConversationPrefix(existingHtml);

                // Initialize streaming display
                SwingUtilities.invokeLater(() -> queryTab.initializeForStreaming(existingHtml));
            }

            @Override
            public void onUpdate(String partialResponse) {
                if (partialResponse == null || partialResponse.isEmpty()) {
                    return;
                }

                String delta;
                synchronized (bufferLock) {
                    String currentBuffer = responseBuffer.toString();
                    if (partialResponse.startsWith(currentBuffer)) {
                        delta = partialResponse.substring(currentBuffer.length());
                        if (!delta.isEmpty()) {
                            responseBuffer.append(delta);
                        }
                    } else {
                        delta = partialResponse;
                        responseBuffer.append(delta);
                    }
                }

                // Send delta to streaming renderer
                if (!delta.isEmpty() && currentStreamingRenderer != null) {
                    currentStreamingRenderer.onChunkReceived(delta);
                }
            }

            @Override
            public void onComplete(String fullResponse) {
                synchronized (bufferLock) {
                    if (fullResponse != null && fullResponse.length() > responseBuffer.length()) {
                        responseBuffer.setLength(0);
                        responseBuffer.append(fullResponse);
                    }

                    final String finalResponse = responseBuffer.toString();

                    // Signal stream complete
                    if (currentStreamingRenderer != null) {
                        currentStreamingRenderer.onStreamComplete();
                        currentStreamingRenderer = null;
                    }

                    SwingUtilities.invokeLater(() -> {
                        feedbackService.cacheLastInteraction(feedbackService.getLastPrompt(), finalResponse);
                        queryService.addAssistantResponse(finalResponse);

                        // Final markdown rendering
                        String conversationHistory = queryService.getConversationHistory();
                        String html = markdownHelper.markdownToHtml(conversationHistory);
                        queryTab.setResponseText(html);
                        queryTab.setMarkdownSource(conversationHistory);

                        onComplete.run();
                        clearLlmApi.accept(null);
                    });
                }
            }

            @Override
            public void onError(Throwable error) {
                // Clean up streaming renderer
                if (currentStreamingRenderer != null) {
                    currentStreamingRenderer = null;
                }

                synchronized (bufferLock) {
                    if (responseBuffer.length() > 0) {
                        final String partialResponse = responseBuffer.toString();
                        SwingUtilities.invokeLater(() -> {
                            queryService.addAssistantMessage(partialResponse + "\n\n[Incomplete - Error occurred]",
                                queryService.getCurrentProviderType(), null);
                        });
                    }
                }

                SwingUtilities.invokeLater(() -> {
                    queryService.addError(error.getMessage());
                    String html = markdownHelper.markdownToHtml(queryService.getConversationHistory());
                    queryTab.setResponseText(html);
                    onComplete.run();
                    clearLlmApi.accept(null);
                });
            }

            @Override
            public boolean shouldContinue() {
                if (!isRunning.get()) {
                    savePartialResponseOnCancel();
                }
                return isRunning.get();
            }

            private void savePartialResponseOnCancel() {
                synchronized (bufferLock) {
                    if (responseBuffer.length() > 0) {
                        final String partialResponse = responseBuffer.toString();
                        responseBuffer.setLength(0);

                        if (currentStreamingRenderer != null) {
                            currentStreamingRenderer = null;
                        }

                        SwingUtilities.invokeLater(() -> {
                            queryService.addAssistantMessage(partialResponse + "\n\n[Cancelled by user]",
                                queryService.getCurrentProviderType(), null);

                            String html = markdownHelper.markdownToHtml(queryService.getConversationHistory());
                            queryTab.setResponseText(html);
                            onComplete.run();
                            clearLlmApi.accept(null);
                        });
                    }
                }
            }
        };
    }

    /**
     * Create a simple explain handler (non-streaming full replacement).
     */
    public LlmApi.LlmResponseHandler createExplainHandler(
            ExplainTab explainTab,
            FeedbackService feedbackService,
            Supplier<Boolean> isRunning,
            Runnable onComplete) {

        return new LlmApi.LlmResponseHandler() {
            @Override
            public void onStart() {
                SwingUtilities.invokeLater(() ->
                    explainTab.setExplanationText("Processing..."));
            }

            @Override
            public void onUpdate(String partialResponse) {
                SwingUtilities.invokeLater(() ->
                    explainTab.setExplanationText(
                        markdownHelper.markdownToHtml(partialResponse)));
            }

            @Override
            public void onComplete(String fullResponse) {
                SwingUtilities.invokeLater(() -> {
                    feedbackService.cacheLastInteraction(feedbackService.getLastPrompt(), fullResponse);
                    explainTab.setExplanationText(
                        markdownHelper.markdownToHtml(fullResponse));
                    explainTab.setMarkdownSource(fullResponse);
                    onComplete.run();
                });
            }

            @Override
            public void onError(Throwable error) {
                SwingUtilities.invokeLater(() -> {
                    explainTab.setExplanationText("An error occurred: " + error.getMessage());
                    onComplete.run();
                });
            }

            @Override
            public boolean shouldContinue() {
                return isRunning.get();
            }
        };
    }

    /**
     * Create a handler for line explanation with streaming support.
     */
    public LlmApi.LlmResponseHandler createLineExplainHandler(
            ExplainTab explainTab,
            ghidrassist.AnalysisDB analysisDB,
            String programHash,
            long functionAddress,
            long lineAddress,
            String viewType,
            String lineContent,
            String contextBefore,
            String contextAfter,
            Supplier<Boolean> isRunning,
            Runnable onComplete) {

        return new LlmApi.LlmResponseHandler() {
            private final StringBuilder responseBuffer = new StringBuilder();

            @Override
            public void onStart() {
                responseBuffer.setLength(0);

                // Initialize streaming
                currentLineExplainStreamingRenderer = new StreamingMarkdownRenderer(
                    update -> explainTab.applyLineRenderUpdate(update),
                    markdownHelper
                );

                SwingUtilities.invokeLater(() -> explainTab.initializeLineExplanationForStreaming());
            }

            @Override
            public void onUpdate(String partialResponse) {
                if (partialResponse == null || partialResponse.isEmpty()) {
                    return;
                }

                // Extract delta
                String currentBuffer = responseBuffer.toString();
                String delta;
                if (partialResponse.startsWith(currentBuffer)) {
                    delta = partialResponse.substring(currentBuffer.length());
                    responseBuffer.append(delta);
                } else {
                    delta = partialResponse;
                    responseBuffer.append(delta);
                }

                // Feed delta to renderer
                if (!delta.isEmpty() && currentLineExplainStreamingRenderer != null) {
                    currentLineExplainStreamingRenderer.onChunkReceived(delta);
                }
            }

            @Override
            public void onComplete(String fullResponse) {
                final String finalResponse = (fullResponse != null && !fullResponse.isEmpty())
                        ? fullResponse : responseBuffer.toString();

                // Complete streaming
                if (currentLineExplainStreamingRenderer != null) {
                    currentLineExplainStreamingRenderer.onStreamComplete();
                    currentLineExplainStreamingRenderer = null;
                }

                // Cache the result
                analysisDB.upsertLineExplanation(
                        programHash, functionAddress, lineAddress,
                        viewType, lineContent, contextBefore, contextAfter,
                        finalResponse
                );

                SwingUtilities.invokeLater(() -> {
                    onComplete.run();
                });
            }

            @Override
            public void onError(Throwable error) {
                if (currentLineExplainStreamingRenderer != null) {
                    currentLineExplainStreamingRenderer.onStreamComplete();
                    currentLineExplainStreamingRenderer = null;
                }

                SwingUtilities.invokeLater(() -> {
                    String partialContent = responseBuffer.toString();
                    if (!partialContent.isEmpty()) {
                        String html = markdownHelper.markdownToHtml(partialContent + "\n\n[Error: " + error.getMessage() + "]");
                        explainTab.setLineExplanationText(html);
                    } else {
                        explainTab.setLineExplanationText("<html><body>Error: " + error.getMessage() + "</body></html>");
                    }
                    onComplete.run();
                });
            }

            @Override
            public boolean shouldContinue() {
                return isRunning.get();
            }
        };
    }

    /**
     * Create a streaming handler that renders to a generic target.
     */
    public LlmApi.LlmResponseHandler createGenericStreamingHandler(
            Consumer<RenderUpdate> renderCallback,
            Runnable initializeCallback,
            Consumer<String> completeCallback,
            Consumer<String> errorCallback,
            Supplier<Boolean> isRunning) {

        return new LlmApi.LlmResponseHandler() {
            private final StringBuilder responseBuffer = new StringBuilder();
            private StreamingMarkdownRenderer renderer;

            @Override
            public void onStart() {
                responseBuffer.setLength(0);
                renderer = new StreamingMarkdownRenderer(renderCallback, markdownHelper);
                if (initializeCallback != null) {
                    SwingUtilities.invokeLater(initializeCallback);
                }
            }

            @Override
            public void onUpdate(String partialResponse) {
                if (partialResponse == null || partialResponse.isEmpty()) {
                    return;
                }

                String currentBuffer = responseBuffer.toString();
                String delta;
                if (partialResponse.startsWith(currentBuffer)) {
                    delta = partialResponse.substring(currentBuffer.length());
                    responseBuffer.append(delta);
                } else {
                    delta = partialResponse;
                    responseBuffer.append(delta);
                }

                if (!delta.isEmpty() && renderer != null) {
                    renderer.onChunkReceived(delta);
                }
            }

            @Override
            public void onComplete(String fullResponse) {
                final String finalResponse = (fullResponse != null && !fullResponse.isEmpty())
                        ? fullResponse : responseBuffer.toString();

                if (renderer != null) {
                    renderer.onStreamComplete();
                    renderer = null;
                }

                if (completeCallback != null) {
                    SwingUtilities.invokeLater(() -> completeCallback.accept(finalResponse));
                }
            }

            @Override
            public void onError(Throwable error) {
                if (renderer != null) {
                    renderer = null;
                }

                if (errorCallback != null) {
                    SwingUtilities.invokeLater(() -> errorCallback.accept(error.getMessage()));
                }
            }

            @Override
            public boolean shouldContinue() {
                return isRunning.get();
            }
        };
    }

    // ==== MarkdownHelper access ====

    public MarkdownHelper getMarkdownHelper() {
        return markdownHelper;
    }
}
