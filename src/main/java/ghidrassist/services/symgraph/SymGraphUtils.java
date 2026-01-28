package ghidrassist.services.symgraph;

import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;

import java.util.ArrayList;
import java.util.List;
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
     * Handles qualified names by extracting the simple name part before matching.
     * For example, "Class::FUN_12345" will extract "FUN_12345" and match it against patterns.
     *
     * @param name The symbol name to check (may include namespace qualifiers like "Namespace::Name")
     * @return true if the name is auto-generated (default), false if user-defined
     */
    public static boolean isDefaultName(String name) {
        if (name == null || name.isEmpty()) {
            return true;
        }

        // Extract simple name from qualified name (e.g., "Class::method" -> "method")
        String simpleName = name;
        int lastSeparator = name.lastIndexOf("::");
        if (lastSeparator >= 0 && lastSeparator < name.length() - 2) {
            simpleName = name.substring(lastSeparator + 2);
        }

        for (Pattern pattern : DEFAULT_NAME_PATTERNS) {
            if (pattern.matcher(simpleName).matches()) {
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

    /**
     * Get the fully qualified name of a function including its namespace.
     * Returns "Namespace::FunctionName" for namespaced functions, or just the name for global functions.
     * Skips Ghidra internal namespaces like &lt;EXTERNAL&gt;.
     *
     * @param func The function to get the qualified name for
     * @return The fully qualified function name
     */
    public static String getQualifiedFunctionName(Function func) {
        if (func == null) {
            return null;
        }

        Symbol symbol = func.getSymbol();
        if (symbol == null) {
            return func.getName();
        }

        Namespace parentNs = symbol.getParentNamespace();
        if (parentNs == null || parentNs.isGlobal()) {
            return func.getName();
        }

        // Build qualified name: Namespace::FunctionName
        // Handle nested namespaces by walking up the chain
        List<String> namespaces = new ArrayList<>();

        Namespace ns = parentNs;
        while (ns != null && !ns.isGlobal()) {
            String nsName = ns.getName();
            // Skip Ghidra internal namespaces like <EXTERNAL>
            if (nsName != null && !(nsName.startsWith("<") && nsName.endsWith(">"))) {
                namespaces.add(0, nsName);  // prepend
            }
            ns = ns.getParentNamespace();
        }

        if (namespaces.isEmpty()) {
            return func.getName();
        }

        StringBuilder qualifiedName = new StringBuilder();
        for (String nsName : namespaces) {
            if (qualifiedName.length() > 0) {
                qualifiedName.append("::");
            }
            qualifiedName.append(nsName);
        }
        qualifiedName.append("::");
        qualifiedName.append(func.getName());

        return qualifiedName.toString();
    }
}
