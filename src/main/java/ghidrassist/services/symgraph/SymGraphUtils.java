package ghidrassist.services.symgraph;

import java.util.regex.Pattern;

/**
 * Utility methods for SymGraph operations.
 * Includes cross-tool default name detection for symbol filtering.
 */
public class SymGraphUtils {

    /**
     * Unified default name patterns for cross-tool compatibility.
     * These patterns identify auto-generated names from various disassemblers:
     * - Binary Ninja: sub_*, data_*, byte_*, arg*, var_*
     * - Ghidra: FUN_*, DAT_*, param_*, local_*, uVar*, etc.
     * - radare2: fcn.*, func_*
     * - IDA: sub_*, a1-a9
     */
    private static final Pattern[] DEFAULT_NAME_PATTERNS = {
        // Functions
        Pattern.compile("^sub_[0-9a-fA-F]+$"),          // Binary Ninja, IDA
        Pattern.compile("^FUN_[0-9a-fA-F]+$"),          // Ghidra
        Pattern.compile("^fcn\\.[0-9a-fA-F]+$"),        // radare2
        Pattern.compile("^func_[0-9a-fA-F]+$"),         // Generic
        Pattern.compile("^j_.*$"),                       // Thunks
        // Data
        Pattern.compile("^(data|DAT|byte|BYTE|dword|DWORD|qword|QWORD)_[0-9a-fA-F]+$", Pattern.CASE_INSENSITIVE),
        // Variables (Ghidra decompiler patterns)
        Pattern.compile("^(var|local|uVar|iVar|lVar|pVar|cVar|bVar|sVar|auVar|puVar)_?\\d*$"),
        // Parameters
        Pattern.compile("^(arg|param)_?\\d+$"),
        Pattern.compile("^a[1-9]$"),                     // IDA-style numbered args
    };

    /**
     * Check if a symbol name matches auto-generated patterns from any disassembler.
     *
     * @param name The symbol name to check
     * @return true if the name is auto-generated (default), false if user-defined
     */
    public static boolean isDefaultName(String name) {
        if (name == null || name.isEmpty()) {
            return true;
        }
        for (Pattern pattern : DEFAULT_NAME_PATTERNS) {
            if (pattern.matcher(name).matches()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if a symbol name is user-defined (not auto-generated).
     *
     * @param name The symbol name to check
     * @return true if the name is user-defined, false if auto-generated
     */
    public static boolean isUserDefinedName(String name) {
        return !isDefaultName(name);
    }
}
