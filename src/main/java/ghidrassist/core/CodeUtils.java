package ghidrassist.core;

import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class CodeUtils {

    /**
     * View type enumeration for line explanation context.
     */
    public enum ViewType {
        DECOMPILER,
        DISASSEMBLY
    }

    /**
     * Data class holding line context for explanation generation.
     */
    public static class LineContext {
        private final String currentLine;
        private final String linesBefore;
        private final String linesAfter;
        private final ViewType viewType;
        private final long lineAddress;
        private final String functionName;

        public LineContext(String currentLine, String linesBefore, String linesAfter,
                           ViewType viewType, long lineAddress, String functionName) {
            this.currentLine = currentLine;
            this.linesBefore = linesBefore;
            this.linesAfter = linesAfter;
            this.viewType = viewType;
            this.lineAddress = lineAddress;
            this.functionName = functionName;
        }

        public String getCurrentLine() { return currentLine; }
        public String getLinesBefore() { return linesBefore; }
        public String getLinesAfter() { return linesAfter; }
        public ViewType getViewType() { return viewType; }
        public long getLineAddress() { return lineAddress; }
        public String getFunctionName() { return functionName; }

        /**
         * Check if this context has valid content.
         */
        public boolean isValid() {
            return currentLine != null && !currentLine.trim().isEmpty();
        }
    }

    /**
     * Gets the decompiled code for a function.
     * @param function The function to decompile
     * @param monitor Task monitor for tracking progress
     * @return The decompiled code as a string
     */
    public static String getFunctionCode(Function function, TaskMonitor monitor) {
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(function.getProgram());

        try {
            DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
            if (results != null && results.decompileCompleted()) {
                return results.getDecompiledFunction().getC();
            } else {
                return "Failed to decompile function.";
            }
        } catch (Exception e) {
            return "Failed to decompile function: " + e.getMessage();
        } finally {
            decompiler.dispose();
        }
    }

    /**
     * Gets the disassembly for a function.
     * @param function The function to disassemble
     * @return The disassembled code as a string
     */
    public static String getFunctionDisassembly(Function function) {
        StringBuilder sb = new StringBuilder();
        Listing listing = function.getProgram().getListing();
        InstructionIterator instructions = listing.getInstructions(function.getBody(), true);

        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            sb.append(formatInstruction(instr)).append("\n");
        }

        return sb.toString();
    }

    /**
     * Gets the decompiled code for a specific line at an address.
     * @param address The address to get code for
     * @param monitor Task monitor for tracking progress
     * @param program The current program
     * @return The decompiled line as a string
     */
    public static String getLineCode(Address address, TaskMonitor monitor, Program program) {
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(program);

        try {
            Function function = program.getFunctionManager().getFunctionContaining(address);
            if (function == null) {
                return "No function containing the address.";
            }

            DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
            if (results != null && results.decompileCompleted()) {
                ClangTokenGroup tokens = results.getCCodeMarkup();
                if (tokens != null) {
                    // Find closest token to the address
                    ClangToken closestToken = findClosestTokenForAddress(tokens, address);
                    if (closestToken != null) {
                        // Get the line content from the token's line parent
                        ClangLine lineParent = closestToken.getLineParent();
                        if (lineParent != null) {
                            StringBuilder lineText = new StringBuilder();
                            // Use ClangLine's getAllTokens() method
                            for (ClangToken lineToken : lineParent.getAllTokens()) {
                                String text = lineToken.getText();
                                if (text != null) {
                                    lineText.append(text);
                                }
                            }
                            if (lineText.length() > 0) {
                                return lineText.toString().trim();
                            }
                        }
                        // Fallback to just the token text
                        return closestToken.getText();
                    }
                    return "No code line found at the address.";
                } else {
                    return "Failed to get code tokens.";
                }
            } else {
                return "Failed to decompile function.";
            }
        } catch (Exception e) {
            return "Failed to decompile line: " + e.getMessage();
        } finally {
            decompiler.dispose();
        }
    }

    /**
     * Gets the disassembly for a specific address.
     * @param address The address to get disassembly for
     * @param program The current program
     * @return The disassembled instruction as a string
     */
    public static String getLineDisassembly(Address address, Program program) {
        Instruction instruction = program.getListing().getInstructionAt(address);
        if (instruction != null) {
            return formatInstruction(instruction);
        }
        return null;
    }

    /**
     * Gets decompiled line with surrounding context.
     * @param address The target address
     * @param monitor Task monitor
     * @param program The current program
     * @param contextLines Number of context lines before/after (default 5)
     * @return LineContext with the target line and surrounding context
     */
    public static LineContext getDecompiledLineWithContext(Address address, TaskMonitor monitor,
                                                            Program program, int contextLines) {
        ghidra.util.Msg.info(CodeUtils.class, "getDecompiledLineWithContext: address=" + address);

        Function function = program.getFunctionManager().getFunctionContaining(address);
        if (function == null) {
            ghidra.util.Msg.warn(CodeUtils.class, "getDecompiledLineWithContext: No function at address " + address);
            return null;
        }
        ghidra.util.Msg.info(CodeUtils.class, "getDecompiledLineWithContext: function=" + function.getName());

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(program);

        try {
            ghidra.util.Msg.info(CodeUtils.class, "getDecompiledLineWithContext: Decompiling function...");
            DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
            if (results == null) {
                ghidra.util.Msg.warn(CodeUtils.class, "getDecompiledLineWithContext: Decompile results is null");
                return null;
            }
            if (!results.decompileCompleted()) {
                ghidra.util.Msg.warn(CodeUtils.class, "getDecompiledLineWithContext: Decompile did not complete");
                return null;
            }

            String fullCode = results.getDecompiledFunction().getC();
            if (fullCode == null || fullCode.isEmpty()) {
                ghidra.util.Msg.warn(CodeUtils.class, "getDecompiledLineWithContext: No decompiled code");
                return null;
            }
            ghidra.util.Msg.info(CodeUtils.class, "getDecompiledLineWithContext: Got decompiled code, length=" + fullCode.length());

            // Split code into lines
            String[] lines = fullCode.split("\n");
            ghidra.util.Msg.info(CodeUtils.class, "getDecompiledLineWithContext: Total lines=" + lines.length);

            // Get the specific line at this address using token analysis
            ClangTokenGroup tokens = results.getCCodeMarkup();
            int targetLineNum = -1;

            if (tokens != null) {
                ghidra.util.Msg.info(CodeUtils.class, "getDecompiledLineWithContext: Got tokens, finding closest token...");
                // Try to find a token at or near this address
                ClangToken closestToken = findClosestTokenForAddress(tokens, address);
                if (closestToken != null) {
                    ghidra.util.Msg.info(CodeUtils.class, "getDecompiledLineWithContext: Found closestToken: '" +
                        closestToken.getText() + "' at addr=" + closestToken.getMinAddress());
                    // Get line number by finding the token's line in the decompiled output
                    targetLineNum = getLineNumberFromToken(closestToken, lines);
                    ghidra.util.Msg.info(CodeUtils.class, "getDecompiledLineWithContext: targetLineNum from token=" + targetLineNum);
                } else {
                    ghidra.util.Msg.warn(CodeUtils.class, "getDecompiledLineWithContext: No closest token found");
                }
            } else {
                ghidra.util.Msg.warn(CodeUtils.class, "getDecompiledLineWithContext: No tokens from decompiler");
            }

            // Fallback: if token-based lookup failed, use a simple heuristic
            // Find a line that might correspond to this address based on function structure
            if (targetLineNum < 0) {
                ghidra.util.Msg.info(CodeUtils.class, "getDecompiledLineWithContext: Using fallback heuristic");
                // Default to first non-signature line (typically line 2 or 3 in decompiled output)
                targetLineNum = Math.min(2, lines.length - 1);
                // Try to find a line with actual code (not just braces or whitespace)
                for (int i = 2; i < lines.length - 1; i++) {
                    String trimmed = lines[i].trim();
                    if (!trimmed.isEmpty() && !trimmed.equals("{") && !trimmed.equals("}")) {
                        targetLineNum = i;
                        break;
                    }
                }
                ghidra.util.Msg.info(CodeUtils.class, "getDecompiledLineWithContext: Fallback targetLineNum=" + targetLineNum);
            }

            if (targetLineNum < 0 || targetLineNum >= lines.length) {
                ghidra.util.Msg.warn(CodeUtils.class, "getDecompiledLineWithContext: Invalid line number " +
                    targetLineNum + " (lines.length=" + lines.length + ")");
                return null;
            }

            String currentLine = lines[targetLineNum];
            ghidra.util.Msg.info(CodeUtils.class, "getDecompiledLineWithContext: Selected line " +
                targetLineNum + ": '" + currentLine + "'");

            // Gather context lines before
            StringBuilder beforeBuilder = new StringBuilder();
            int startIdx = Math.max(0, targetLineNum - contextLines);
            for (int i = startIdx; i < targetLineNum; i++) {
                beforeBuilder.append(lines[i]).append("\n");
            }

            // Gather context lines after
            StringBuilder afterBuilder = new StringBuilder();
            int endIdx = Math.min(lines.length, targetLineNum + 1 + contextLines);
            for (int i = targetLineNum + 1; i < endIdx; i++) {
                afterBuilder.append(lines[i]).append("\n");
            }

            ghidra.util.Msg.info(CodeUtils.class, "getDecompiledLineWithContext: SUCCESS - returning LineContext");
            return new LineContext(
                currentLine.trim(),
                beforeBuilder.toString(),
                afterBuilder.toString(),
                ViewType.DECOMPILER,
                address.getOffset(),
                function.getName()
            );

        } catch (Exception e) {
            ghidra.util.Msg.error(CodeUtils.class, "getDecompiledLineWithContext: Exception: " + e.getMessage(), e);
            return null;
        } finally {
            decompiler.dispose();
        }
    }

    /**
     * Find the closest token to a given address.
     */
    private static ClangToken findClosestTokenForAddress(ClangTokenGroup tokens, Address targetAddress) {
        ClangToken[] result = new ClangToken[1];
        long[] bestDistance = new long[]{Long.MAX_VALUE};

        findClosestTokenRecursive(tokens, targetAddress, result, bestDistance);
        return result[0];
    }

    /**
     * Recursive helper to find the closest token to an address.
     */
    private static void findClosestTokenRecursive(ClangNode node, Address targetAddress,
                                                   ClangToken[] result, long[] bestDistance) {
        if (node instanceof ClangToken) {
            ClangToken token = (ClangToken) node;
            Address minAddr = token.getMinAddress();
            Address maxAddr = token.getMaxAddress();

            if (minAddr != null) {
                // Check if address is within range
                if (maxAddr != null &&
                    minAddr.compareTo(targetAddress) <= 0 &&
                    maxAddr.compareTo(targetAddress) >= 0) {
                    // Exact match - this is the best possible
                    result[0] = token;
                    bestDistance[0] = 0;
                    return;
                }

                // Calculate distance to this token
                long distance = Math.abs(minAddr.getOffset() - targetAddress.getOffset());
                if (distance < bestDistance[0]) {
                    bestDistance[0] = distance;
                    result[0] = token;
                }
            }
        }

        if (node instanceof ClangTokenGroup) {
            ClangTokenGroup group = (ClangTokenGroup) node;
            for (int i = 0; i < group.numChildren(); i++) {
                findClosestTokenRecursive(group.Child(i), targetAddress, result, bestDistance);
                // Early exit if we found an exact match
                if (bestDistance[0] == 0) {
                    return;
                }
            }
        }
    }

    /**
     * Get the line number of a token using ClangLine.getLineNumber().
     * The line number from ClangLine is 1-indexed, so we subtract 1 to get 0-indexed.
     */
    private static int getLineNumberFromToken(ClangToken token, String[] lines) {
        if (token == null) {
            ghidra.util.Msg.warn(CodeUtils.class, "getLineNumberFromToken: token is null");
            return -1;
        }

        // Get the ClangLine parent which has the line number
        ClangLine lineParent = token.getLineParent();
        if (lineParent != null) {
            // ClangLine.getLineNumber() returns 1-indexed line number
            int lineNum = lineParent.getLineNumber();
            ghidra.util.Msg.info(CodeUtils.class, "getLineNumberFromToken: ClangLine.getLineNumber()=" + lineNum);

            // Convert to 0-indexed and validate
            int zeroIndexed = lineNum - 1;
            if (zeroIndexed >= 0 && zeroIndexed < lines.length) {
                return zeroIndexed;
            }
            ghidra.util.Msg.warn(CodeUtils.class, "getLineNumberFromToken: lineNum " + lineNum +
                " out of range (lines.length=" + lines.length + ")");
        } else {
            ghidra.util.Msg.warn(CodeUtils.class, "getLineNumberFromToken: lineParent is null");
        }

        // Fallback: try to match the token text in the lines
        String tokenText = token.getText();
        if (tokenText != null && !tokenText.trim().isEmpty()) {
            ghidra.util.Msg.info(CodeUtils.class, "getLineNumberFromToken: Fallback - searching for token text: '" + tokenText + "'");
            for (int i = 0; i < lines.length; i++) {
                if (lines[i].contains(tokenText.trim())) {
                    ghidra.util.Msg.info(CodeUtils.class, "getLineNumberFromToken: Found token text at line " + i);
                    return i;
                }
            }
        }

        return -1;
    }

    /**
     * Collect all text from a node and its children.
     */
    private static void collectTokenText(ClangNode node, StringBuilder sb) {
        if (node instanceof ClangToken) {
            String text = ((ClangToken) node).getText();
            if (text != null) {
                sb.append(text);
            }
        } else if (node instanceof ClangTokenGroup) {
            ClangTokenGroup group = (ClangTokenGroup) node;
            for (int i = 0; i < group.numChildren(); i++) {
                collectTokenText(group.Child(i), sb);
            }
        }
    }

    /**
     * Gets disassembly line with surrounding instruction context.
     * @param address The target address
     * @param program The current program
     * @param contextLines Number of instructions before/after (default 5)
     * @return LineContext with the target instruction and surrounding context
     */
    public static LineContext getDisassemblyLineWithContext(Address address, Program program, int contextLines) {
        Function function = program.getFunctionManager().getFunctionContaining(address);
        if (function == null) {
            return null;
        }

        Listing listing = program.getListing();
        Instruction currentInstr = listing.getInstructionAt(address);
        if (currentInstr == null) {
            // Try to find nearest instruction
            currentInstr = listing.getInstructionContaining(address);
            if (currentInstr == null) {
                return null;
            }
        }

        String currentLine = formatInstruction(currentInstr);

        // Gather instructions before
        StringBuilder beforeBuilder = new StringBuilder();
        Instruction prevInstr = currentInstr;
        java.util.List<String> beforeList = new java.util.ArrayList<>();
        for (int i = 0; i < contextLines; i++) {
            prevInstr = prevInstr.getPrevious();
            if (prevInstr == null || !function.getBody().contains(prevInstr.getAddress())) {
                break;
            }
            beforeList.add(0, formatInstruction(prevInstr));
        }
        for (String line : beforeList) {
            beforeBuilder.append(line).append("\n");
        }

        // Gather instructions after
        StringBuilder afterBuilder = new StringBuilder();
        Instruction nextInstr = currentInstr;
        for (int i = 0; i < contextLines; i++) {
            nextInstr = nextInstr.getNext();
            if (nextInstr == null || !function.getBody().contains(nextInstr.getAddress())) {
                break;
            }
            afterBuilder.append(formatInstruction(nextInstr)).append("\n");
        }

        return new LineContext(
            currentLine,
            beforeBuilder.toString(),
            afterBuilder.toString(),
            ViewType.DISASSEMBLY,
            address.getOffset(),
            function.getName()
        );
    }


    /**
     * Formats an instruction with its address and representation.
     * @param instruction The instruction to format
     * @return A formatted string representation of the instruction
     */
    private static String formatInstruction(Instruction instruction) {
        return String.format("%s  %s", 
            instruction.getAddressString(true, true), 
            instruction.toString());
    }
}
