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

        if (initialContext != null && !initialContext.isEmpty()) {
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

        sb.append("**Next Step**:\n");
        sb.append("Think about what information you still need. ");
        sb.append("Which tool should you use to gather it? ");
        sb.append("Call the appropriate tool to continue your investigation.\n");

        return sb.toString();
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
    public static String getSynthesisPrompt(String objective, String findings, String todos) {
        return String.format("""
            ## Time to Synthesize

            **Goal**: %s

            **Completed Investigation**:
            %s

            **Findings**:
            %s

            You've completed your investigation todos. Based on all the information
            you've gathered, provide a comprehensive answer to the user's question.

            Synthesize your findings into a clear, actionable response.
            """,
            objective,
            todos,
            findings
        );
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
}
