package ghidrassist.tools.native_;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidrassist.tools.api.Tool;
import ghidrassist.tools.api.ToolProvider;
import ghidrassist.tools.api.ToolResult;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * Tool provider for Ghidra context query tools.
 * These are read-only tools that query the current Ghidra state.
 *
 * Tools provided:
 * - get_current_function: Get information about the function at the current cursor location
 * - get_current_address: Get the current cursor address
 */
public class GhidraToolProvider implements ToolProvider {

    private static final String PROVIDER_NAME = "Ghidra";
    private static final String TOOL_PREFIX = "ga_";

    private Program currentProgram;
    private Address currentAddress;

    @Override
    public String getProviderName() {
        return PROVIDER_NAME;
    }

    @Override
    public List<Tool> getTools() {
        List<Tool> tools = new ArrayList<>();

        // ga.get_current_function
        tools.add(new NativeTool(
                TOOL_PREFIX + "get_current_function",
                "Get information about the function at the current cursor location. " +
                "Returns the function name, address, signature, and basic metadata.",
                createEmptySchema(),
                PROVIDER_NAME
        ));

        // ga.get_current_address
        tools.add(new NativeTool(
                TOOL_PREFIX + "get_current_address",
                "Get the current cursor address in hexadecimal format.",
                createEmptySchema(),
                PROVIDER_NAME
        ));

        return tools;
    }

    @Override
    public CompletableFuture<ToolResult> executeTool(String name, JsonObject args) {
        return CompletableFuture.supplyAsync(() -> {
            if (currentProgram == null) {
                return ToolResult.error("No program context set");
            }

            try {
                switch (name) {
                    case TOOL_PREFIX + "get_current_function":
                        return executeGetCurrentFunction();
                    case TOOL_PREFIX + "get_current_address":
                        return executeGetCurrentAddress();
                    default:
                        return ToolResult.error("Unknown tool: " + name);
                }
            } catch (Exception e) {
                Msg.error(this, "Tool execution failed: " + e.getMessage(), e);
                return ToolResult.error("Tool failed: " + e.getMessage());
            }
        });
    }

    private ToolResult executeGetCurrentFunction() {
        if (currentAddress == null) {
            return ToolResult.error("No current address set");
        }

        FunctionManager funcManager = currentProgram.getFunctionManager();
        Function function = funcManager.getFunctionContaining(currentAddress);

        if (function == null) {
            return ToolResult.error("No function found at current address: " + currentAddress);
        }

        JsonObject result = new JsonObject();
        result.addProperty("name", function.getName());
        result.addProperty("address", function.getEntryPoint().toString());
        result.addProperty("signature", function.getSignature().getPrototypeString());
        result.addProperty("calling_convention", function.getCallingConventionName());
        result.addProperty("is_thunk", function.isThunk());
        result.addProperty("parameter_count", function.getParameterCount());
        result.addProperty("stack_frame_size", function.getStackFrame().getFrameSize());

        // Source type indicates if user-defined, imported, analysis, etc.
        SourceType sourceType = function.getSymbol().getSource();
        result.addProperty("source_type", sourceType.toString());

        // Get comment if present
        String comment = function.getComment();
        if (comment != null && !comment.isEmpty()) {
            result.addProperty("comment", comment);
        }

        // Body address range
        result.addProperty("body_start", function.getBody().getMinAddress().toString());
        result.addProperty("body_end", function.getBody().getMaxAddress().toString());

        return ToolResult.success(result.toString());
    }

    private ToolResult executeGetCurrentAddress() {
        if (currentAddress == null) {
            return ToolResult.error("No current address set");
        }

        JsonObject result = new JsonObject();
        result.addProperty("address", currentAddress.toString());
        result.addProperty("offset", "0x" + Long.toHexString(currentAddress.getOffset()));

        return ToolResult.success(result.toString());
    }

    @Override
    public boolean handlesTool(String name) {
        return (TOOL_PREFIX + "get_current_function").equals(name) ||
               (TOOL_PREFIX + "get_current_address").equals(name);
    }

    @Override
    public void setContext(Program program) {
        this.currentProgram = program;
    }

    /**
     * Set the current address context.
     * @param address Current address in Ghidra
     */
    public void setAddress(Address address) {
        this.currentAddress = address;
    }

    /**
     * Set both program and address context.
     */
    public void setContext(Program program, Address address) {
        this.currentProgram = program;
        this.currentAddress = address;
    }

    // Helper to create empty parameter schema
    private JsonObject createEmptySchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        schema.add("properties", new JsonObject());
        return schema;
    }
}
