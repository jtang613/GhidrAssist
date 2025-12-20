package ghidrassist.mcp2.tools;

import ghidra.program.model.listing.Program;
import ghidra.program.model.address.Address;
import ghidra.util.Msg;
import com.google.gson.JsonObject;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Automatically injects binary context (filename, address) into tool arguments
 * when they're missing but likely needed.
 *
 * This reduces friction in the ReAct loop - the LLM doesn't need to explicitly
 * provide the current program or location for every tool call.
 */
public class BinaryContextInjector {

    private final Program currentProgram;
    private final Address currentAddress;

    // Tools that commonly need filename
    private static final Set<String> FILENAME_TOOLS = new HashSet<>(Arrays.asList(
        "get_function_at",
        "get_function_by_name",
        "get_functions",
        "get_function_signature",
        "decompile_function",
        "get_xrefs_to",
        "get_xrefs_from",
        "get_strings",
        "get_imports",
        "get_exports",
        "get_sections",
        "analyze_function",
        "find_pattern",
        "search_bytes"
    ));

    // Tools that commonly need address
    private static final Set<String> ADDRESS_TOOLS = new HashSet<>(Arrays.asList(
        "get_function_at",
        "get_instruction_at",
        "get_data_at",
        "get_xrefs_to",
        "get_xrefs_from",
        "decompile_at",
        "disassemble_at",
        "analyze_at"
    ));

    /**
     * Create injector with current Ghidra context.
     *
     * @param currentProgram Current program (can be null if no program open)
     * @param currentAddress Current address/location (can be null if no location)
     */
    public BinaryContextInjector(Program currentProgram, Address currentAddress) {
        this.currentProgram = currentProgram;
        this.currentAddress = currentAddress;
    }

    /**
     * Enhance tool arguments by injecting missing context.
     *
     * @param toolName Name of the tool being called
     * @param arguments Original arguments from LLM
     * @return Enhanced arguments with injected context
     */
    public JsonObject enhanceArguments(String toolName, JsonObject arguments) {
        if (arguments == null) {
            arguments = new JsonObject();
        }

        // Make a copy to avoid modifying original
        JsonObject enhanced = arguments.deepCopy();

        // Inject filename if missing and tool needs it
        if (shouldInjectFilename(toolName, enhanced)) {
            String filename = getFilename();
            if (filename != null) {
                enhanced.addProperty("filename", filename);
                Msg.debug(this, String.format("Auto-injected filename '%s' for tool '%s'", filename, toolName));
            }
        }

        // Inject address if missing and tool needs it
        if (shouldInjectAddress(toolName, enhanced)) {
            String address = getAddressString();
            if (address != null) {
                enhanced.addProperty("address", address);
                Msg.debug(this, String.format("Auto-injected address '%s' for tool '%s'", address, toolName));
            }
        }

        return enhanced;
    }

    /**
     * Check if we should inject filename for this tool call.
     */
    private boolean shouldInjectFilename(String toolName, JsonObject arguments) {
        // Don't inject if already present
        if (arguments.has("filename") || arguments.has("file") || arguments.has("binary")) {
            return false;
        }

        // Check if tool commonly needs filename
        if (!FILENAME_TOOLS.contains(toolName.toLowerCase())) {
            return false;
        }

        // Don't inject if no program available
        if (currentProgram == null) {
            return false;
        }

        return true;
    }

    /**
     * Check if we should inject address for this tool call.
     */
    private boolean shouldInjectAddress(String toolName, JsonObject arguments) {
        // Don't inject if already present
        if (arguments.has("address") || arguments.has("addr") || arguments.has("location")) {
            return false;
        }

        // Check if tool commonly needs address
        if (!ADDRESS_TOOLS.contains(toolName.toLowerCase())) {
            return false;
        }

        // Don't inject if no address available
        if (currentAddress == null) {
            return false;
        }

        return true;
    }

    /**
     * Get filename from current program.
     */
    private String getFilename() {
        if (currentProgram == null) {
            return null;
        }

        return currentProgram.getName();
    }

    /**
     * Get address string from current location.
     */
    private String getAddressString() {
        if (currentAddress == null) {
            return null;
        }

        return currentAddress.toString();
    }

    /**
     * Update the current program context (e.g., if program changed).
     */
    public static BinaryContextInjector fromProgram(Program program, Address address) {
        return new BinaryContextInjector(program, address);
    }

    /**
     * Check if context is available (has program or address).
     */
    public boolean hasContext() {
        return currentProgram != null || currentAddress != null;
    }

    /**
     * Get description of available context for logging/debugging.
     */
    public String getContextDescription() {
        StringBuilder desc = new StringBuilder();

        if (currentProgram != null) {
            desc.append("Program: ").append(currentProgram.getName());
        }

        if (currentAddress != null) {
            if (desc.length() > 0) {
                desc.append(", ");
            }
            desc.append("Address: ").append(currentAddress);
        }

        if (desc.length() == 0) {
            desc.append("No context available");
        }

        return desc.toString();
    }
}
