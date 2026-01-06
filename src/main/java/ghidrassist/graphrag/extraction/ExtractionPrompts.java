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

        // Analyze complexity to determine appropriate summary length
        ComplexityMetrics complexity = analyzeComplexity(decompiledCode);

        prompt.append("Analyze this decompiled function and provide a structured summary.\n\n");

        prompt.append("## Function: ").append(functionName).append("\n\n");

        // Include complexity info for the LLM
        prompt.append("**Complexity:** ").append(complexity.toString()).append("\n");

        if (!callers.isEmpty()) {
            prompt.append("**Called by:** ").append(String.join(", ", callers)).append("\n");
        }
        if (!callees.isEmpty()) {
            prompt.append("**Calls:** ").append(String.join(", ", callees)).append("\n");
        }
        prompt.append("\n");

        // Use larger truncation limit for complex functions
        int truncateLimit = complexity.level.equals("very_complex") ? 4000 :
                           complexity.level.equals("complex") ? 3000 : 2000;
        prompt.append("```c\n").append(truncateCode(decompiledCode, truncateLimit)).append("\n```\n\n");

        // Output format instructions - explicit and mandatory
        prompt.append("## Output Format (REQUIRED - follow this structure exactly):\n\n");

        prompt.append("**Summary:** [1-3 sentences describing what this function does]\n\n");

        // Complexity-based section guidance
        if (complexity.level.equals("simple")) {
            prompt.append("For this simple function, provide ONLY the Summary and Category sections.\n\n");
        } else {
            prompt.append("[Include the following sections ONLY if applicable to this function:]\n\n");

            if (complexity.level.equals("very_complex") || complexity.level.equals("complex")) {
                prompt.append("**Details:** [Detailed explanation of the function's logic including:\n");
                prompt.append("- Main code paths and control flow\n");
                prompt.append("- Key data transformations and algorithms\n");
                prompt.append("- Important state changes and side effects\n");
                prompt.append("- Error handling patterns\n");
                prompt.append("Use multiple paragraphs as needed for complex functions.]\n\n");
            } else {
                prompt.append("**Details:** [Brief description of control flow and key operations. ");
                prompt.append("Skip this section for trivial utility functions.]\n\n");
            }

            prompt.append("**File IO:** [ONLY if this function performs file operations: ");
            prompt.append("list operations like fopen, fread, fwrite, fclose, CreateFile, ReadFile, etc. ");
            prompt.append("Otherwise OMIT this section entirely.]\n\n");

            prompt.append("**Network IO:** [ONLY if this function performs network operations: ");
            prompt.append("list operations like socket, connect, send, recv, WSAStartup, getaddrinfo, etc. ");
            prompt.append("Otherwise OMIT this section entirely.]\n\n");

            prompt.append("**Security:** [ONLY if security-relevant observations exist: ");
            prompt.append("buffer handling concerns, input validation issues, crypto usage, ");
            prompt.append("privilege operations, error handling gaps. Otherwise OMIT this section.]\n\n");
        }

        prompt.append("**Category:** [REQUIRED - One of: initialization, data_processing, io_operations, ");
        prompt.append("network, crypto, authentication, error_handling, utility, unknown]\n");

        return prompt.toString();
    }

    /**
     * Generate a complexity-scaled summary prompt for individual function processing.
     * Uses simplified format for batch/brief processing - Summary and Category only.
     */
    public static String functionBriefSummaryPrompt(String functionName, String decompiledCode) {
        ComplexityMetrics complexity = analyzeComplexity(decompiledCode);
        StringBuilder prompt = new StringBuilder();

        prompt.append("Summarize this decompiled function.\n\n");
        prompt.append("Function: ").append(functionName).append("\n");
        prompt.append("Complexity: ").append(complexity.toString()).append("\n\n");

        // Scale truncation limit with complexity
        int truncateLimit = complexity.level.equals("very_complex") ? 4000 :
                           complexity.level.equals("complex") ? 3000 :
                           complexity.level.equals("moderate") ? 2000 : 1500;
        prompt.append("```c\n").append(truncateCode(decompiledCode, truncateLimit)).append("\n```\n\n");

        prompt.append("## Output Format (REQUIRED):\n\n");
        prompt.append("**Summary:** [");
        if (complexity.level.equals("simple")) {
            prompt.append("1-2 sentences");
        } else if (complexity.level.equals("moderate")) {
            prompt.append("2-4 sentences");
        } else {
            prompt.append("1-2 paragraphs covering key functionality");
        }
        prompt.append(" describing what this function does]\n\n");

        prompt.append("**Category:** [One of: initialization, data_processing, io_operations, ");
        prompt.append("network, crypto, authentication, error_handling, utility, unknown]\n\n");

        prompt.append("Do NOT include other sections (Details, File IO, Network IO, Security) in this brief format.");

        return prompt.toString();
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
     * Summary length scales with each function's complexity.
     *
     * @param nodes List of KnowledgeNodes to summarize
     * @return Prompt string for batch processing
     */
    public static String batchFunctionSummaryPrompt(List<KnowledgeNode> nodes) {
        StringBuilder prompt = new StringBuilder();

        prompt.append("Summarize each of these functions. Scale your summary length based on complexity:\n");
        prompt.append("- Simple functions (few lines, no loops/branches): 1-2 sentences\n");
        prompt.append("- Moderate functions: 3-5 sentences\n");
        prompt.append("- Complex functions (many branches, loops, calls): 1-2 paragraphs\n");
        prompt.append("- Very complex functions: 2-3 paragraphs covering all major code paths\n\n");
        prompt.append("Format your response as a numbered list matching the input.\n\n");

        for (int i = 0; i < nodes.size(); i++) {
            KnowledgeNode node = nodes.get(i);
            String code = node.getRawContent();
            ComplexityMetrics complexity = analyzeComplexity(code);

            // Scale truncation based on complexity
            int truncateLimit = complexity.level.equals("very_complex") ? 2000 :
                               complexity.level.equals("complex") ? 1500 :
                               complexity.level.equals("moderate") ? 1000 : 800;

            prompt.append(String.format("%d. **%s** [%s]\n```c\n%s\n```\n\n",
                    i + 1,
                    node.getName() != null ? node.getName() : "unknown",
                    complexity.level,
                    truncateCode(code, truncateLimit)
            ));
        }

        prompt.append("Summaries:\n");
        return prompt.toString();
    }

    // ========================================
    // Response Parsing Helpers
    // ========================================

    /**
     * Extract the Summary section from a function summary response.
     */
    public static String extractSummary(String response) {
        return extractSection(response, "Summary:");
    }

    /**
     * Extract the Details section from a function summary response.
     * Returns null if section not present.
     */
    public static String extractDetails(String response) {
        return extractSection(response, "Details:");
    }

    /**
     * Extract the File IO section from a function summary response.
     * Returns null if section not present.
     */
    public static String extractFileIO(String response) {
        return extractSection(response, "File IO:");
    }

    /**
     * Extract the Network IO section from a function summary response.
     * Returns null if section not present.
     */
    public static String extractNetworkIO(String response) {
        return extractSection(response, "Network IO:");
    }

    /**
     * Extract the Security section from a function summary response.
     * Returns null if section not present.
     */
    public static String extractSecurity(String response) {
        return extractSection(response, "Security:");
    }

    /**
     * Extract the category from a function summary response.
     */
    public static String extractCategory(String response) {
        return extractSection(response, "Category:");
    }

    /**
     * Legacy: Extract the purpose line (maps to Summary for backwards compatibility).
     * @deprecated Use extractSummary() instead
     */
    @Deprecated
    public static String extractPurpose(String response) {
        // Try new format first, fall back to old format
        String summary = extractSection(response, "Summary:");
        if (summary != null) return summary;
        return extractSection(response, "Purpose:");
    }

    /**
     * Legacy: Extract the security notes (maps to Security for backwards compatibility).
     * @deprecated Use extractSecurity() instead
     */
    @Deprecated
    public static String extractSecurityNotes(String response) {
        // Try new format first, fall back to old format
        String security = extractSection(response, "Security:");
        if (security != null) return security;
        return extractSection(response, "Security Notes:");
    }

    private static String extractSection(String response, String header) {
        if (response == null) return null;

        // Try with ** markdown formatting first
        int start = response.indexOf("**" + header);
        if (start != -1) {
            start = response.indexOf("**", start + 2);  // Find closing **
            if (start != -1) start += 2;  // Move past **
        }

        // Fall back to plain header
        if (start == -1) {
            start = response.indexOf(header);
            if (start != -1) start += header.length();
        }

        if (start == -1) return null;

        // Find the end of this section (next section header or end of text)
        int end = response.length();

        // Look for next section (with ** prefix)
        int nextSection = response.indexOf("\n**", start);
        if (nextSection != -1 && nextSection < end) end = nextSection;

        // Also check for double newline as section separator
        int doubleNewline = response.indexOf("\n\n", start);
        // Only use double newline if there's content after it that looks like a header
        if (doubleNewline != -1 && doubleNewline < end) {
            String afterNewline = response.substring(doubleNewline + 2).trim();
            if (afterNewline.startsWith("**") || afterNewline.matches("^[A-Z][a-z]+:.*")) {
                end = doubleNewline;
            }
        }

        String result = response.substring(start, end).trim();
        // Remove leading colon if present (from ** format)
        if (result.startsWith(":")) result = result.substring(1).trim();

        return result.isEmpty() ? null : result;
    }

    // ========================================
    // Complexity Analysis
    // ========================================

    /**
     * Complexity metrics for a function.
     */
    public static class ComplexityMetrics {
        public final int lineCount;
        public final int branchCount;     // if, while, for, switch, case
        public final int callCount;       // function calls
        public final int loopCount;       // while, for, do
        public final String level;        // "simple", "moderate", "complex", "very_complex"
        public final String summaryGuidance;

        public ComplexityMetrics(int lines, int branches, int calls, int loops) {
            this.lineCount = lines;
            this.branchCount = branches;
            this.callCount = calls;
            this.loopCount = loops;

            // Calculate complexity level
            int score = 0;
            score += lines > 50 ? 2 : (lines > 20 ? 1 : 0);
            score += branches > 10 ? 2 : (branches > 5 ? 1 : 0);
            score += calls > 8 ? 2 : (calls > 4 ? 1 : 0);
            score += loops > 3 ? 2 : (loops > 1 ? 1 : 0);

            if (score >= 6) {
                this.level = "very_complex";
                this.summaryGuidance = "This is a very complex function. Provide a detailed multi-paragraph summary (3-5 paragraphs) covering all major code paths, data transformations, and behaviors.";
            } else if (score >= 4) {
                this.level = "complex";
                this.summaryGuidance = "This is a complex function. Provide a thorough summary (2-3 paragraphs) explaining the main logic, key operations, and any notable patterns.";
            } else if (score >= 2) {
                this.level = "moderate";
                this.summaryGuidance = "This is a moderately complex function. Provide a detailed summary (1-2 paragraphs) explaining its purpose and key operations.";
            } else {
                this.level = "simple";
                this.summaryGuidance = "This is a simple function. Provide a concise summary (2-4 sentences) capturing its purpose and behavior.";
            }
        }

        @Override
        public String toString() {
            return String.format("%d lines, %d branches, %d calls, %d loops (%s)",
                    lineCount, branchCount, callCount, loopCount, level);
        }
    }

    /**
     * Analyze code complexity metrics.
     *
     * @param code Decompiled C code
     * @return Complexity metrics
     */
    public static ComplexityMetrics analyzeComplexity(String code) {
        if (code == null || code.isEmpty()) {
            return new ComplexityMetrics(0, 0, 0, 0);
        }

        // Count lines
        int lines = code.split("\n").length;

        // Count branches (if, else if, switch, case, ? ternary)
        int branches = 0;
        branches += countOccurrences(code, "\\bif\\s*\\(");
        branches += countOccurrences(code, "\\bswitch\\s*\\(");
        branches += countOccurrences(code, "\\bcase\\s+");
        branches += countOccurrences(code, "\\?.*:");  // ternary

        // Count loops (while, for, do)
        int loops = 0;
        loops += countOccurrences(code, "\\bwhile\\s*\\(");
        loops += countOccurrences(code, "\\bfor\\s*\\(");
        loops += countOccurrences(code, "\\bdo\\s*\\{");

        // Count function calls (identifier followed by parenthesis)
        int calls = countOccurrences(code, "\\b[a-zA-Z_][a-zA-Z0-9_]*\\s*\\(");
        // Subtract control structures which also match the pattern
        calls -= branches + loops;
        calls = Math.max(0, calls);

        return new ComplexityMetrics(lines, branches, calls, loops);
    }

    private static int countOccurrences(String text, String regex) {
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(regex);
        java.util.regex.Matcher matcher = pattern.matcher(text);
        int count = 0;
        while (matcher.find()) {
            count++;
        }
        return count;
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
