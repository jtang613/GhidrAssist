package ghidrassist.agent.react;

import ghidrassist.GhidrAssistPlugin;
import ghidrassist.LlmApi;
import ghidrassist.apiprovider.APIProviderConfig;
import ghidrassist.mcp2.tools.MCPToolManager;

import ghidra.util.Msg;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * ReAct orchestrator that adds Think-Act-Observe structure on top of
 * the existing ConversationalToolHandler.
 *
 * Key features:
 * - Todo list management for tracking investigation progress
 * - Findings accumulation for building evidence
 * - Context summarization to stay within token limits
 * - Structured prompts with todos and findings
 */
public class ReActOrchestrator {

    // Configuration
    private final int maxIterations;
    private final int contextSummaryThreshold;

    // Dependencies
    private final LlmApi llmApi;
    private final MCPToolManager toolManager;
    private final GhidrAssistPlugin plugin;

    // Cancellation support
    private final AtomicBoolean cancelled = new AtomicBoolean(false);

    public ReActOrchestrator(APIProviderConfig providerConfig, GhidrAssistPlugin plugin) {
        this(providerConfig, plugin, 15, 8000);
    }

    public ReActOrchestrator(
        APIProviderConfig providerConfig,
        GhidrAssistPlugin plugin,
        int maxIterations,
        int contextSummaryThreshold
    ) {
        this.plugin = plugin;
        this.maxIterations = maxIterations;
        this.contextSummaryThreshold = contextSummaryThreshold;
        this.llmApi = new LlmApi(providerConfig, plugin);
        this.toolManager = MCPToolManager.getInstance();
    }

    /**
     * Analyze a query using ReAct pattern with conversational tool calling.
     */
    public CompletableFuture<ReActResult> analyze(
        String query,
        String initialContext,
        String sessionId,
        ReActProgressHandler handler
    ) {
        CompletableFuture<ReActResult> resultFuture = new CompletableFuture<>();

        // Run asynchronously
        CompletableFuture.runAsync(() -> {
            Instant startTime = Instant.now();
            cancelled.set(false);

            try {
                // Initialize components
                TodoListManager todoManager = new TodoListManager(query);
                FindingsCache findings = new FindingsCache();
                ContextSummarizer summarizer = new ContextSummarizer(contextSummaryThreshold);

                handler.onStart(query);

                // First, ask LLM to propose investigation steps
                Msg.info(this, "Asking LLM to plan investigation steps...");
                String planningPrompt = ReActPrompts.getPlanningPrompt(query, initialContext);

                // Get todo plan from LLM (synchronous for simplicity)
                CompletableFuture<String> planningFuture = new CompletableFuture<>();
                llmApi.sendRequestAsync(planningPrompt, new LlmApi.LlmResponseHandler() {
                    private final StringBuilder planResponse = new StringBuilder();

                    @Override
                    public void onStart() {
                        planResponse.setLength(0);
                    }

                    @Override
                    public void onUpdate(String partialResponse) {
                        planResponse.append(partialResponse);
                    }

                    @Override
                    public void onComplete(String fullResponse) {
                        planningFuture.complete(fullResponse);
                    }

                    @Override
                    public void onError(Throwable error) {
                        planningFuture.completeExceptionally(error);
                    }

                    @Override
                    public boolean shouldContinue() {
                        return !cancelled.get() && handler.shouldContinue();
                    }
                });

                // Wait for planning to complete
                String todoList = planningFuture.get(30, java.util.concurrent.TimeUnit.SECONDS);
                todoManager.initializeFromLLMResponse(todoList);
                Msg.info(this, "Investigation plan created with " + todoManager.getAllTodos().size() + " steps");

                handler.onTodosUpdated(todoManager.formatForPrompt());

                // Get available tools
                List<Map<String, Object>> tools = toolManager.getToolsAsFunction();
                if (tools.isEmpty()) {
                    Msg.warn(this, "No MCP tools available - analysis may be limited");
                }

                // Track iteration count
                AtomicInteger iteration = new AtomicInteger(0);
                AtomicInteger toolCallCount = new AtomicInteger(0);

                // Main ReAct loop
                runReActIteration(
                    query,
                    initialContext,
                    todoManager,
                    findings,
                    summarizer,
                    tools,
                    iteration,
                    toolCallCount,
                    handler,
                    startTime,
                    resultFuture
                );

            } catch (Exception e) {
                Msg.error(this, "ReAct analysis error: " + e.getMessage(), e);
                Duration duration = Duration.between(startTime, Instant.now());
                FindingsCache emptyFindings = new FindingsCache();
                ReActResult result = ReActResult.error(e, emptyFindings, duration);
                handler.onError(e);
                handler.onComplete(result);
                resultFuture.complete(result);
            }
        });

        return resultFuture;
    }

    /**
     * Run one iteration of the ReAct loop.
     */
    private void runReActIteration(
        String objective,
        String initialContext,
        TodoListManager todoManager,
        FindingsCache findings,
        ContextSummarizer summarizer,
        List<Map<String, Object>> tools,
        AtomicInteger iteration,
        AtomicInteger toolCallCount,
        ReActProgressHandler handler,
        Instant startTime,
        CompletableFuture<ReActResult> resultFuture
    ) {
        // Check termination conditions
        if (cancelled.get() || !handler.shouldContinue()) {
            Duration duration = Duration.between(startTime, Instant.now());
            resultFuture.complete(ReActResult.cancelled(findings, duration));
            return;
        }

        int currentIteration = iteration.incrementAndGet();

        if (currentIteration > maxIterations) {
            // Max iterations reached - synthesize answer
            synthesizeFinalAnswer(objective, todoManager, findings, tools, handler, startTime, resultFuture, currentIteration, toolCallCount.get(), ReActResult.Status.MAX_ITERATIONS);
            return;
        }

        if (todoManager.allComplete()) {
            // All todos done - synthesize answer
            synthesizeFinalAnswer(objective, todoManager, findings, tools, handler, startTime, resultFuture, currentIteration, toolCallCount.get(), ReActResult.Status.SUCCESS);
            return;
        }

        Msg.info(this, String.format("ReAct iteration %d/%d", currentIteration, maxIterations));

        // Mark next pending todo as in progress
        TodoListManager.Todo nextTodo = todoManager.getNextPending();
        if (nextTodo != null) {
            todoManager.setInProgress(nextTodo.getTask());
            handler.onTodosUpdated(todoManager.formatForPrompt());
        }

        // Build investigation prompt
        String prompt = ReActPrompts.buildInvestigationPrompt(
            objective,
            currentIteration == 1 ? initialContext : null,  // Only include context on first iteration
            todoManager.formatForPrompt(),
            findings.formatForPrompt(),
            currentIteration
        );

        // Add warning if approaching limit
        if (maxIterations - currentIteration <= 3) {
            prompt += ReActPrompts.getIterationLimitWarning(maxIterations - currentIteration);
            handler.onIterationWarning(maxIterations - currentIteration);
        }

        // Create response handler for this iteration
        LlmApi.LlmResponseHandler iterationHandler = new LlmApi.LlmResponseHandler() {
            private final StringBuilder responseBuffer = new StringBuilder();
            private final StringBuilder displayBuffer = new StringBuilder();
            private boolean hasCalledTools = false;

            @Override
            public void onStart() {
                responseBuffer.setLength(0);
                displayBuffer.setLength(0);
            }

            @Override
            public void onUpdate(String partialResponse) {
                // Forward ALL conversational updates to the UI immediately
                if (partialResponse != null && !partialResponse.isEmpty()) {
                    responseBuffer.append(partialResponse);
                    displayBuffer.append(partialResponse);

                    // Pass through to progress handler for real-time display
                    // This shows tool execution, assistant thinking, etc.
                    handler.onThought(displayBuffer.toString(), currentIteration);
                }

                // Detect tool calls for tracking purposes
                if (partialResponse.contains("🔧") || partialResponse.contains("Executing tools")) {
                    hasCalledTools = true;
                    toolCallCount.incrementAndGet();
                }
            }

            @Override
            public void onComplete(String fullResponse) {
                // Extract findings from the response (keyword-based, for backwards compatibility)
                findings.extractFromToolOutput("llm_response", fullResponse);

                // Store the iteration summary (LLM's final analysis) for synthesis
                findings.addIterationSummary(fullResponse);

                // Update todos based on progress
                updateTodosFromResponse(todoManager, fullResponse);
                handler.onTodosUpdated(todoManager.formatForPrompt());

                // Check if we should continue or finish
                if (todoManager.allComplete() || !hasCalledTools) {
                    // Either done or no more tools to call - synthesize
                    synthesizeFinalAnswer(objective, todoManager, findings, tools, handler, startTime, resultFuture, currentIteration, toolCallCount.get(), ReActResult.Status.SUCCESS);
                } else {
                    // Perform self-reflection to determine if we should continue
                    performSelfReflection(
                        objective,
                        initialContext,
                        todoManager,
                        findings,
                        summarizer,
                        tools,
                        iteration,
                        toolCallCount,
                        handler,
                        startTime,
                        resultFuture,
                        currentIteration
                    );
                }
            }

            @Override
            public void onError(Throwable error) {
                Duration duration = Duration.between(startTime, Instant.now());
                ReActResult result = ReActResult.error(error, null, duration);
                handler.onError(error);
                handler.onComplete(result);
                resultFuture.complete(result);
            }

            @Override
            public boolean shouldContinue() {
                return handler.shouldContinue() && !cancelled.get();
            }
        };

        // Call the conversational tool handler
        llmApi.sendConversationalToolRequest(prompt, tools, iterationHandler);
    }

    /**
     * Synthesize final answer from accumulated findings.
     */
    private void synthesizeFinalAnswer(
        String objective,
        TodoListManager todoManager,
        FindingsCache findings,
        List<Map<String, Object>> tools,
        ReActProgressHandler handler,
        Instant startTime,
        CompletableFuture<ReActResult> resultFuture,
        int iterationCount,
        int toolCallCount,
        ReActResult.Status completionStatus
    ) {
        String synthesisPrompt = ReActPrompts.getSynthesisPrompt(
            objective,
            findings.formatDetailed(),
            todoManager.getCompletedSummary(),
            findings.formatIterationSummaries()
        );

        // Get final answer without tool calling
        llmApi.sendRequestAsync(synthesisPrompt, new LlmApi.LlmResponseHandler() {
            private final StringBuilder answer = new StringBuilder();

            @Override
            public void onStart() {
                answer.setLength(0);
            }

            @Override
            public void onUpdate(String partialResponse) {
                answer.append(partialResponse);
            }

            @Override
            public void onComplete(String fullResponse) {
                Duration duration = Duration.between(startTime, Instant.now());

                // Build result with the provided completion status
                ReActResult result = new ReActResult.Builder()
                    .status(completionStatus)
                    .answer(fullResponse)
                    .findings(findings.getAllFindings().stream()
                        .map(f -> f.getFact())
                        .toList())
                    .iterationCount(iterationCount)
                    .toolCallCount(toolCallCount)
                    .duration(duration)
                    .build();

                handler.onComplete(result);
                resultFuture.complete(result);
            }

            @Override
            public void onError(Throwable error) {
                Duration duration = Duration.between(startTime, Instant.now());
                ReActResult result = ReActResult.error(error, null, duration);
                handler.onError(error);
                handler.onComplete(result);
                resultFuture.complete(result);
            }

            @Override
            public boolean shouldContinue() {
                return true;
            }
        });
    }

    /**
     * Perform self-reflection to determine if investigation should continue.
     */
    private void performSelfReflection(
        String objective,
        String initialContext,
        TodoListManager todoManager,
        FindingsCache findings,
        ContextSummarizer summarizer,
        List<Map<String, Object>> tools,
        AtomicInteger iteration,
        AtomicInteger toolCallCount,
        ReActProgressHandler handler,
        Instant startTime,
        CompletableFuture<ReActResult> resultFuture,
        int currentIteration
    ) {
        String reflectionPrompt = ReActPrompts.getReflectionPrompt(
            objective,
            findings.formatForPrompt(),
            todoManager.formatForPrompt()
        );

        // Ask the LLM to reflect
        CompletableFuture<String> reflectionFuture = new CompletableFuture<>();
        llmApi.sendRequestAsync(reflectionPrompt, new LlmApi.LlmResponseHandler() {
            private final StringBuilder reflection = new StringBuilder();

            @Override
            public void onStart() {
                reflection.setLength(0);
            }

            @Override
            public void onUpdate(String partialResponse) {
                reflection.append(partialResponse);
            }

            @Override
            public void onComplete(String fullResponse) {
                reflectionFuture.complete(fullResponse);
            }

            @Override
            public void onError(Throwable error) {
                // On error, default to continuing
                Msg.warn(ReActOrchestrator.this, "Reflection failed, continuing investigation: " + error.getMessage());
                reflectionFuture.complete("CONTINUE: Reflection error, continuing investigation");
            }

            @Override
            public boolean shouldContinue() {
                return !cancelled.get() && handler.shouldContinue();
            }
        });

        // Wait for reflection and decide next action
        reflectionFuture.thenAccept(reflectionResponse -> {
            String trimmedResponse = reflectionResponse.trim();

            // Parse the reflection response - check if it indicates readiness
            String upperResponse = trimmedResponse.toUpperCase();
            boolean containsReady = upperResponse.contains("READY:");
            boolean startsWithReady = upperResponse.startsWith("READY");
            boolean containsNotReady = upperResponse.contains("NOT READY");

            boolean shouldSynthesize = containsReady || (startsWithReady && !containsNotReady);

            if (shouldSynthesize) {
                // Log reflection and decision as findings, not thoughts (to avoid replacing iteration output)
                handler.onFinding("Self-Reflection: " + trimmedResponse);
                handler.onFinding("Decision: Sufficient information gathered - synthesizing final answer");
                synthesizeFinalAnswer(objective, todoManager, findings, tools, handler, startTime, resultFuture, currentIteration, toolCallCount.get(), ReActResult.Status.SUCCESS);
            } else {
                // Log reflection and decision as findings, not thoughts (to avoid replacing iteration output)
                handler.onFinding("Self-Reflection: " + trimmedResponse);
                handler.onFinding("Decision: More investigation needed - continuing");
                // Continue to next iteration
                runReActIteration(
                    objective,
                    initialContext,
                    todoManager,
                    findings,
                    summarizer,
                    tools,
                    iteration,
                    toolCallCount,
                    handler,
                    startTime,
                    resultFuture
                );
            }
        }).exceptionally(error -> {
            Msg.error(this, "Reflection handling failed: " + error.getMessage(), error);
            handler.onThought("⚠️ **Error in reflection**: " + error.getMessage() + ". Continuing investigation...\n\n", currentIteration);
            // On error, continue investigation
            runReActIteration(
                objective,
                initialContext,
                todoManager,
                findings,
                summarizer,
                tools,
                iteration,
                toolCallCount,
                handler,
                startTime,
                resultFuture
            );
            return null;
        });
    }

    /**
     * Extract tool name from conversational handler update.
     */
    private String extractToolName(String message) {
        // ConversationalToolHandler formats as "🔧 Calling tool: <name>"
        if (message.contains("Calling tool:")) {
            int start = message.indexOf("Calling tool:") + 13;
            int end = message.indexOf("\n", start);
            if (end == -1) end = message.length();
            return message.substring(start, end).trim();
        }
        return null;
    }

    /**
     * Update todos based on iteration completion.
     * Marks the current in-progress todo as complete after an iteration.
     */
    private void updateTodosFromResponse(TodoListManager todoManager, String response) {
        // After each iteration with tool calls, mark the current in-progress todo as complete
        // The iteration has gathered information, so we consider the step done
        for (TodoListManager.Todo todo : todoManager.getAllTodos()) {
            if (todo.getStatus() == TodoListManager.TodoStatus.IN_PROGRESS) {
                // Mark complete - the investigation step has been executed
                todoManager.completeTodo(todo.getTask(), "Investigation step completed");
                Msg.info(this, "Completed todo: " + todo.getTask());
                break;  // Only one should be in progress at a time
            }
        }
    }

    /**
     * Cancel the current analysis.
     */
    public void cancel() {
        cancelled.set(true);
        llmApi.cancelCurrentRequest();
    }
}
