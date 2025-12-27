package ghidrassist.graphrag.extraction;

import ghidrassist.graphrag.nodes.KnowledgeNode;
import ghidrassist.graphrag.nodes.NodeType;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Prompt templates for LLM-based semantic extraction.
 *
 * These prompts are designed for:
 * - Function summarization (purpose, behavior, security)
 * - Module/community summarization (subsystem identification)
 * - Binary-level summarization (overall purpose, attack surface)
 * - Security analysis (vulnerability patterns)
 */
public class ExtractionPrompts {

    // ========================================
    // Function Summarization
    // ========================================

    /**
     * Generate a prompt to summarize a function.
     *
     * @param functionName Name of the function
     * @param decompiledCode Decompiled C code
     * @param callers List of caller function names (context)
     * @param callees List of callee function names (context)
     * @return Prompt string for LLM
     */
    public static String functionSummaryPrompt(String functionName, String decompiledCode,
                                                List<String> callers, List<String> callees) {
        StringBuilder prompt = new StringBuilder();

        prompt.append("Analyze this decompiled function and provide a concise summary.\n\n");

        prompt.append("## Function: ").append(functionName).append("\n\n");

        if (!callers.isEmpty()) {
            prompt.append("**Called by:** ").append(String.join(", ", callers)).append("\n");
        }
        if (!callees.isEmpty()) {
            prompt.append("**Calls:** ").append(String.join(", ", callees)).append("\n");
        }
        prompt.append("\n");

        prompt.append("```c\n").append(truncateCode(decompiledCode, 2000)).append("\n```\n\n");

        prompt.append("Provide a summary in the following format:\n\n");
        prompt.append("**Purpose:** [1-2 sentences describing what this function does]\n\n");
        prompt.append("**Behavior:** [Key operations, data transformations, control flow]\n\n");
        prompt.append("**Security Notes:** [Any potential security concerns: buffer handling, ");
        prompt.append("input validation, crypto usage, privilege operations. Write 'None identified' if none.]\n\n");
        prompt.append("**Category:** [One of: initialization, data_processing, io_operations, ");
        prompt.append("network, crypto, authentication, error_handling, utility, unknown]\n");

        return prompt.toString();
    }

    /**
     * Generate a brief one-line summary prompt (for batch processing).
     */
    public static String functionBriefSummaryPrompt(String functionName, String decompiledCode) {
        return String.format(
                "Summarize this function in ONE sentence (max 100 chars):\n\n" +
                "Function: %s\n```c\n%s\n```\n\n" +
                "Summary:",
                functionName,
                truncateCode(decompiledCode, 1500)
        );
    }

    // ========================================
    // Module/Community Summarization
    // ========================================

    /**
     * Generate a prompt to summarize a module (community of functions).
     *
     * @param moduleName Name/ID of the module
     * @param memberSummaries Brief summaries of member functions
     * @param internalCallCount Number of calls within the module
     * @param externalCallCount Number of calls to/from outside
     * @return Prompt string for LLM
     */
    public static String moduleSummaryPrompt(String moduleName, List<String> memberSummaries,
                                              int internalCallCount, int externalCallCount) {
        StringBuilder prompt = new StringBuilder();

        prompt.append("Analyze this module (cluster of related functions) and provide a summary.\n\n");

        prompt.append("## Module: ").append(moduleName).append("\n\n");
        prompt.append("**Internal calls:** ").append(internalCallCount).append("\n");
        prompt.append("**External interface calls:** ").append(externalCallCount).append("\n\n");

        prompt.append("### Member Functions:\n");
        for (int i = 0; i < Math.min(memberSummaries.size(), 20); i++) {
            prompt.append("- ").append(memberSummaries.get(i)).append("\n");
        }
        if (memberSummaries.size() > 20) {
            prompt.append("- ... and ").append(memberSummaries.size() - 20).append(" more functions\n");
        }
        prompt.append("\n");

        prompt.append("Provide a summary in the following format:\n\n");
        prompt.append("**Subsystem:** [Name this subsystem/module based on its functions]\n\n");
        prompt.append("**Purpose:** [2-3 sentences describing what this module does]\n\n");
        prompt.append("**Key Functions:** [List 3-5 most important functions and their roles]\n\n");
        prompt.append("**Security Relevance:** [Attack surface, sensitive operations, trust boundaries]\n");

        return prompt.toString();
    }

    // ========================================
    // Binary-Level Summarization
    // ========================================

    /**
     * Generate a prompt to summarize the entire binary.
     *
     * @param binaryName Name of the binary
     * @param format Executable format (PE, ELF, etc.)
     * @param moduleSummaries Summaries of detected modules
     * @param entryPoints Entry point function names
     * @param imports Notable imported functions
     * @return Prompt string for LLM
     */
    public static String binarySummaryPrompt(String binaryName, String format,
                                              List<String> moduleSummaries,
                                              List<String> entryPoints,
                                              List<String> imports) {
        StringBuilder prompt = new StringBuilder();

        prompt.append("Analyze this binary based on its structure and provide a security-focused summary.\n\n");

        prompt.append("## Binary: ").append(binaryName).append("\n");
        prompt.append("**Format:** ").append(format).append("\n\n");

        if (!entryPoints.isEmpty()) {
            prompt.append("### Entry Points:\n");
            for (String entry : entryPoints) {
                prompt.append("- ").append(entry).append("\n");
            }
            prompt.append("\n");
        }

        if (!imports.isEmpty()) {
            prompt.append("### Notable Imports:\n");
            for (String imp : imports.subList(0, Math.min(imports.size(), 30))) {
                prompt.append("- ").append(imp).append("\n");
            }
            prompt.append("\n");
        }

        if (!moduleSummaries.isEmpty()) {
            prompt.append("### Detected Modules:\n");
            for (String mod : moduleSummaries) {
                prompt.append("- ").append(mod).append("\n");
            }
            prompt.append("\n");
        }

        prompt.append("Provide a summary in the following format:\n\n");
        prompt.append("**Program Type:** [What kind of program is this? e.g., server, client, utility, malware]\n\n");
        prompt.append("**Primary Purpose:** [2-3 sentences describing what this program does]\n\n");
        prompt.append("**Key Capabilities:** [Bullet list of main capabilities]\n\n");
        prompt.append("**Attack Surface:** [Input sources, network interfaces, file operations]\n\n");
        prompt.append("**Security Concerns:** [Potential vulnerabilities, dangerous patterns, trust issues]\n");

        return prompt.toString();
    }

    // ========================================
    // Security Analysis Prompts
    // ========================================

    /**
     * Generate a prompt to analyze a potential vulnerability.
     */
    public static String vulnerabilityAnalysisPrompt(String functionName, String code,
                                                      String vulnerabilityType) {
        StringBuilder prompt = new StringBuilder();

        prompt.append("Analyze this function for potential ").append(vulnerabilityType).append(" vulnerability.\n\n");

        prompt.append("## Function: ").append(functionName).append("\n\n");
        prompt.append("```c\n").append(truncateCode(code, 2000)).append("\n```\n\n");

        prompt.append("Provide analysis in the following format:\n\n");
        prompt.append("**Vulnerability Present:** [Yes/No/Possible]\n\n");
        prompt.append("**Evidence:** [Specific code patterns that indicate the vulnerability]\n\n");
        prompt.append("**Exploitation:** [How could this be exploited?]\n\n");
        prompt.append("**Severity:** [Critical/High/Medium/Low/Informational]\n\n");
        prompt.append("**Remediation:** [How to fix this issue]\n");

        return prompt.toString();
    }

    /**
     * Generate a prompt to analyze taint flow between functions.
     */
    public static String taintAnalysisPrompt(String sourceFunctionCode, String sinkFunctionCode,
                                              List<String> pathFunctions) {
        StringBuilder prompt = new StringBuilder();

        prompt.append("Analyze the data flow between these functions for security issues.\n\n");

        prompt.append("## Source (user input):\n");
        prompt.append("```c\n").append(truncateCode(sourceFunctionCode, 1000)).append("\n```\n\n");

        if (!pathFunctions.isEmpty()) {
            prompt.append("## Path through:\n");
            for (String func : pathFunctions) {
                prompt.append("- ").append(func).append("\n");
            }
            prompt.append("\n");
        }

        prompt.append("## Sink (sensitive operation):\n");
        prompt.append("```c\n").append(truncateCode(sinkFunctionCode, 1000)).append("\n```\n\n");

        prompt.append("Analyze:\n");
        prompt.append("1. Is user-controlled data reaching the sink without validation?\n");
        prompt.append("2. What type of vulnerability could this represent?\n");
        prompt.append("3. What exploitation scenario is possible?\n");

        return prompt.toString();
    }

    // ========================================
    // Batch Processing
    // ========================================

    /**
     * Generate a batch prompt for summarizing multiple functions at once.
     * More efficient for LLM API calls.
     *
     * @param nodes List of KnowledgeNodes to summarize
     * @return Prompt string for batch processing
     */
    public static String batchFunctionSummaryPrompt(List<KnowledgeNode> nodes) {
        StringBuilder prompt = new StringBuilder();

        prompt.append("Summarize each of these functions in ONE sentence (max 80 chars each).\n");
        prompt.append("Format your response as a numbered list matching the input.\n\n");

        for (int i = 0; i < nodes.size(); i++) {
            KnowledgeNode node = nodes.get(i);
            prompt.append(String.format("%d. **%s**\n```c\n%s\n```\n\n",
                    i + 1,
                    node.getName() != null ? node.getName() : "unknown",
                    truncateCode(node.getRawContent(), 800)
            ));
        }

        prompt.append("Summaries:\n");
        return prompt.toString();
    }

    // ========================================
    // Response Parsing Helpers
    // ========================================

    /**
     * Extract the purpose line from a function summary response.
     */
    public static String extractPurpose(String response) {
        return extractSection(response, "Purpose:");
    }

    /**
     * Extract the security notes from a function summary response.
     */
    public static String extractSecurityNotes(String response) {
        return extractSection(response, "Security Notes:");
    }

    /**
     * Extract the category from a function summary response.
     */
    public static String extractCategory(String response) {
        return extractSection(response, "Category:");
    }

    private static String extractSection(String response, String header) {
        int start = response.indexOf(header);
        if (start == -1) return null;

        start += header.length();
        int end = response.indexOf("\n\n", start);
        if (end == -1) end = response.indexOf("\n**", start);
        if (end == -1) end = response.length();

        return response.substring(start, end).trim();
    }

    // ========================================
    // Utility
    // ========================================

    private static String truncateCode(String code, int maxLength) {
        if (code == null) return "";
        if (code.length() <= maxLength) return code;

        // Try to truncate at a line boundary
        int cutoff = code.lastIndexOf('\n', maxLength);
        if (cutoff < maxLength / 2) cutoff = maxLength;

        return code.substring(0, cutoff) + "\n// ... (truncated)";
    }
}
