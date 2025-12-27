package ghidrassist.agent.react;

/**
 * Prompt templates for ReAct-style agent using function calling API.
 * Focus on structured thinking with todos and findings.
 */
public class ReActPrompts {

    /**
     * System prompt that sets up the ReAct mindset.
     * This goes in the initial system message.
     */
    public static String getSystemPrompt() {
        return """
            You are a reverse engineering assistant helping analyze binary code in Ghidra.

            You have access to powerful analysis tools. Work systematically:

            1. **Review the todo list** - what needs investigation
            2. **Check findings** - what you've already learned
            3. **Think** - what's the next most important thing to investigate
            4. **Use tools** - call the appropriate tool to get information
            5. **Reflect** - update your understanding based on observations
            6. **Track progress** - note what you've learned and what's still unknown

            ## Tool Selection Priority

            Tool names are prefixed with their provider:
            - Native GhidrAssist tools use `ga_` prefix (e.g., `ga_get_semantic_analysis`)
            - MCP server tools use `servername_` prefix (e.g., `ghidrassistmcp_decompile_function`)

            For understanding function behavior, PREFER these LLM-free semantic query tools:
            - `ga_get_semantic_analysis(address)` - Returns pre-computed summary, security flags, and relationships
            - `ga_get_similar_functions(address)` - Find structurally similar functions
            - `ga_get_call_context(address)` - Get callers/callees with their summaries
            - `ga_get_security_analysis(address)` - Get vulnerability flags and taint paths
            - `ga_search_semantic(query)` - Search functions by semantic keywords
            - `ga_get_module_summary(address)` - Get the module/subsystem a function belongs to
            - `ga_get_activity_analysis(address)` - Get network/file activity, APIs, and risk level

            These tools return pre-indexed semantic analysis and are MUCH faster than raw decompilation.
            Only use `decompile_function` when you need the actual source code (e.g., for specific
            line-by-line analysis) or when semantic analysis is not yet available.

            When you've gathered enough information to answer the user's question,
            provide a clear, comprehensive answer.

            Be systematic and thorough. Use the tools to gather facts, then synthesize
            your findings into actionable insights.
            """;
    }

    /**
     * Prompt for planning investigation steps.
     * Asks the LLM to propose a todo list.
     */
    public static String getPlanningPrompt(String objective, String initialContext) {
        StringBuilder sb = new StringBuilder();

        sb.append("## Investigation Planning\n\n");
        sb.append("**User's Question**: ").append(objective).append("\n\n");

        if (initialContext != null && !initialContext.isEmpty()) {
            sb.append("**Available Context**:\n```\n");
            String truncated = initialContext.length() > 1000
                ? initialContext.substring(0, 1000) + "\n... [truncated]"
                : initialContext;
            sb.append(truncated);
            sb.append("\n```\n\n");
        }

        sb.append("Before we start investigating, let's plan the investigation steps.\n\n");
        sb.append("**Task**: Based on the user's question");
        if (initialContext != null && !initialContext.isEmpty()) {
            sb.append(" and the available context");
        }
        sb.append(", propose a list of 3-5 investigation steps to answer this question.\n\n");
        sb.append("Format your response as a markdown checklist, for example:\n");
        sb.append("- [ ] First investigation step\n");
        sb.append("- [ ] Second investigation step\n");
        sb.append("- [ ] Third investigation step\n\n");
        sb.append("Focus on specific, actionable steps that use the available tools.\n");

        return sb.toString();
    }

    /**
     * Build the investigation prompt with current state.
     * Enhanced with BinAssist parity: iteration context, current task focus marker.
     */
    public static String buildInvestigationPrompt(
        String objective,
        String initialContext,
        String todos,
        String findings,
        int iteration
    ) {
        StringBuilder sb = new StringBuilder();

        sb.append("## Investigation Iteration ").append(iteration).append("\n\n");

        sb.append("**Your Goal**: ").append(objective).append("\n\n");

        if (initialContext != null && !initialContext.isEmpty() && iteration == 1) {
            // Only show initial context on first iteration
            sb.append("**Initial Context**:\n```\n");
            // Truncate if too long
            String truncated = initialContext.length() > 2000
                ? initialContext.substring(0, 2000) + "\n... [truncated]"
                : initialContext;
            sb.append(truncated);
            sb.append("\n```\n\n");
        }

        sb.append("**Investigation Progress**:\n");
        sb.append(todos).append("\n\n");

        if (findings != null && !findings.equals("No significant findings yet.")) {
            sb.append("**What You've Discovered**:\n");
            sb.append(findings).append("\n\n");
        }

        sb.append("**Current Task**: Focus on the task marked with [->] in the progress list above.\n\n");

        sb.append("**Instructions**:\n");
        sb.append("1. Think about what information you still need for the current task\n");
        sb.append("2. Call the appropriate tool(s) to gather that information:\n");
        sb.append("   - PREFER `ga_get_semantic_analysis`, `ga_get_call_context`, `ga_search_semantic` for understanding function behavior\n");
        sb.append("   - Use `decompile_function` (with appropriate server prefix) only when you need actual source code\n");
        sb.append("3. After receiving results, briefly summarize what you learned\n\n");

        sb.append("If you believe the current task is complete based on previous findings,\n");
        sb.append("you may proceed without additional tool calls.\n");

        return sb.toString();
    }

    /**
     * Build investigation prompt with iteration warning when approaching limit.
     */
    public static String buildInvestigationPromptWithWarning(
        String objective,
        String initialContext,
        String todos,
        String findings,
        int iteration,
        int remaining
    ) {
        String basePrompt = buildInvestigationPrompt(objective, initialContext, todos, findings, iteration);

        if (remaining <= 3) {
            return basePrompt + "\n" + getIterationLimitWarning(remaining);
        }

        return basePrompt;
    }

    /**
     * Prompt for when approaching iteration limit.
     */
    public static String getIterationLimitWarning(int remaining) {
        return String.format(
            "\n⚠️ **Note**: %d iteration%s remaining. If you have enough information, " +
            "consider synthesizing your answer soon.\n",
            remaining,
            remaining == 1 ? "" : "s"
        );
    }

    /**
     * Prompt to encourage final synthesis when todos are complete.
     */
    public static String getSynthesisPrompt(String objective, String findings, String todos, String iterationSummaries) {
        StringBuilder sb = new StringBuilder();
        sb.append("## Time to Synthesize\n\n");
        sb.append("**Goal**: ").append(objective).append("\n\n");

        sb.append("**Completed Investigation**:\n");
        sb.append(todos).append("\n\n");

        // Include iteration summaries for full context
        if (iterationSummaries != null && !iterationSummaries.trim().isEmpty() &&
            !iterationSummaries.equals("No iteration summaries available.")) {
            sb.append("**Investigation History** (what you discovered in each iteration):\n");
            sb.append(iterationSummaries).append("\n");
        }

        sb.append("**Key Findings**:\n");
        sb.append(findings).append("\n\n");

        sb.append("You've completed your investigation todos. Based on all the information\n");
        sb.append("you've gathered (shown in the investigation history above), provide a\n");
        sb.append("comprehensive answer to the user's question.\n\n");
        sb.append("Synthesize your findings into a clear, actionable response.\n");

        return sb.toString();
    }

    /**
     * Prompt for when max iterations reached without completion.
     */
    public static String getMaxIterationsPrompt(String objective, String findings, String todos) {
        return String.format("""
            ## Investigation Limit Reached

            **Goal**: %s

            **Progress**:
            %s

            **Findings**:
            %s

            You've reached the maximum number of investigation iterations.
            Based on what you've learned, provide the best answer you can.
            Note any limitations or areas that need further investigation.
            """,
            objective,
            todos,
            findings
        );
    }

    /**
     * Build a refresher prompt after context summarization.
     */
    public static String buildRefresherPrompt(String summary) {
        return String.format("""
            ## Investigation Context Refreshed

            Your previous investigation has been summarized to manage context:

            %s

            Continue from where you left off. Review the pending todos and use
            tools to gather any additional information needed.
            """,
            summary
        );
    }

    /**
     * Prompt for self-reflection after an iteration.
     * Asks the agent to assess progress, update plan, and decide readiness.
     * Uses strict formatting for reliable parsing (BinAssist parity).
     */
    public static String getReflectionPrompt(String objective, String findings, String todos) {
        return String.format("""
            ## Self-Reflection & Plan Adaptation

            **Original Question**: %s

            **Current Investigation Plan**:
            %s

            **Findings Accumulated**:
            %s

            **Reflection Tasks**:
            1. **Progress Assessment**: Review what you've learned and how it relates to the objective
            2. **Plan Adaptation**: Based on new findings, should the investigation plan change?
            3. **Readiness Check**: Can you now answer the user's question comprehensively?

            **Required Response Format** (use plain text, keep label and content on same line):

            **Assessment:** [Your assessment here on same line]

            **Plan Updates:**
            - ADD: [task] (or "None")
            - REMOVE: [task] (or "None")

            **Decision:** READY or CONTINUE

            **Reason:** [Your reason here on same line - do NOT put a newline after "Reason:"]

            **Guidelines**:
            - Keep each label and its content on the SAME LINE
            - **ADD** new tasks if findings reveal unexpected complexity or new investigation paths
            - **REMOVE** pending tasks that are no longer relevant based on what you've learned
            - Say **CONTINUE** if there are pending tasks that would provide valuable information
            - Say **READY** only if ALL planned tasks are complete OR remaining tasks would not
              meaningfully improve the answer
            - Completing investigation tasks thoroughly leads to better answers
            - Do NOT use code blocks, backticks, or extra newlines after labels
            """,
            objective,
            todos,
            findings
        );
    }
}
