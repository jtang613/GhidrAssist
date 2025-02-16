package ghidrassist.core;

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
                    StringBuilder codeLineBuilder = new StringBuilder();
                    boolean found = collectCodeLine(tokens, address, codeLineBuilder);
                    if (found && codeLineBuilder.length() > 0) {
                        return codeLineBuilder.toString();
                    } else {
                        return "No code line found at the address.";
                    }
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
     * Collects all code tokens for a specific line containing an address.
     * @param node The current ClangNode
     * @param address The target address
     * @param codeLineBuilder StringBuilder to collect the code
     * @return true if the address was found and code collected
     */
    private static boolean collectCodeLine(ClangNode node, Address address, StringBuilder codeLineBuilder) {
        if (node instanceof ClangToken) {
            ClangToken token = (ClangToken) node;
            if (token.getMinAddress() != null && token.getMaxAddress() != null) {
                if (token.getMinAddress().compareTo(address) <= 0 && 
                    token.getMaxAddress().compareTo(address) >= 0) {
                    // Found the token corresponding to the address
                    ClangNode parent = token.Parent();
                    if (parent != null) {
                        for (int i = 0; i < parent.numChildren(); i++) {
                            ClangNode sibling = parent.Child(i);
                            if (sibling instanceof ClangToken) {
                                codeLineBuilder.append(((ClangToken) sibling).getText());
                            }
                        }
                    } else {
                        codeLineBuilder.append(token.getText());
                    }
                    return true;
                }
            }
        } else if (node instanceof ClangTokenGroup) {
            ClangTokenGroup group = (ClangTokenGroup) node;
            for (int i = 0; i < group.numChildren(); i++) {
                ClangNode child = group.Child(i);
                boolean found = collectCodeLine(child, address, codeLineBuilder);
                if (found) {
                    return true;
                }
            }
        }
        return false;
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
