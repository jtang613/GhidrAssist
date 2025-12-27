package ghidrassist.tools.native_;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidrassist.core.ActionExecutor;
import ghidrassist.tools.api.Tool;
import ghidrassist.tools.api.ToolProvider;
import ghidrassist.tools.api.ToolResult;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * Tool provider for Ghidra action tools.
 * These tools modify the program (rename, retype, etc.).
 *
 * Tools provided:
 * - rename_function: Rename a function
 * - rename_variable: Rename a variable
 * - retype_variable: Change variable data type
 * - auto_create_struct: Automatically create a structure from variable usage
 */
public class ActionToolProvider implements ToolProvider {

    private static final String PROVIDER_NAME = "Actions";
    private static final String TOOL_PREFIX = "ga_";
    private static final Gson gson = new Gson();

    private Program currentProgram;
    private Address currentAddress;

    // Tool definitions - keys are the base names (without prefix)
    private static final Map<String, ActionToolDef> ACTION_TOOLS = new HashMap<>();

    static {
        // rename_function
        ACTION_TOOLS.put("rename_function", new ActionToolDef(
                "rename_function",
                "Rename a function at the current address",
                createSchema(
                        Map.of("new_name", prop("string", "The new name for the function")),
                        List.of("new_name")
                )
        ));

        // rename_variable
        ACTION_TOOLS.put("rename_variable", new ActionToolDef(
                "rename_variable",
                "Rename a local variable or parameter in the current function",
                createSchema(
                        Map.of(
                                "var_name", prop("string", "Current variable name"),
                                "new_name", prop("string", "New name for the variable")
                        ),
                        List.of("var_name", "new_name")
                )
        ));

        // retype_variable
        ACTION_TOOLS.put("retype_variable", new ActionToolDef(
                "retype_variable",
                "Change the data type of a local variable or parameter",
                createSchema(
                        Map.of(
                                "var_name", prop("string", "Variable name to retype"),
                                "new_type", prop("string", "New data type (e.g., 'int', 'char *', 'struct MyStruct *')")
                        ),
                        List.of("var_name", "new_type")
                )
        ));

        // auto_create_struct
        ACTION_TOOLS.put("auto_create_struct", new ActionToolDef(
                "auto_create_struct",
                "Automatically create a structure based on how a pointer variable is used in the function",
                createSchema(
                        Map.of("var_name", prop("string", "Pointer variable to analyze for structure creation")),
                        List.of("var_name")
                )
        ));
    }

    @Override
    public String getProviderName() {
        return PROVIDER_NAME;
    }

    @Override
    public List<Tool> getTools() {
        List<Tool> tools = new ArrayList<>();
        for (ActionToolDef def : ACTION_TOOLS.values()) {
            // Add prefix to tool name
            tools.add(new NativeTool(TOOL_PREFIX + def.name, def.description, def.inputSchema, PROVIDER_NAME));
        }
        return tools;
    }

    @Override
    public CompletableFuture<ToolResult> executeTool(String name, JsonObject args) {
        return CompletableFuture.supplyAsync(() -> {
            // Strip prefix to get base name
            String baseName = name.startsWith(TOOL_PREFIX) ? name.substring(TOOL_PREFIX.length()) : name;

            if (!ACTION_TOOLS.containsKey(baseName)) {
                return ToolResult.error("Unknown action tool: " + name);
            }

            if (currentProgram == null) {
                return ToolResult.error("No program context set");
            }

            if (currentAddress == null) {
                return ToolResult.error("No address context set");
            }

            try {
                Msg.info(this, "Executing action tool: " + name + " with args: " + args);

                // Convert JsonObject to JSON string for ActionExecutor
                String argsJson = gson.toJson(args);

                // Execute the action using base name (ActionExecutor doesn't know about prefix)
                ActionExecutor.executeAction(baseName, argsJson, currentProgram, currentAddress);

                return ToolResult.success("Action '" + name + "' executed successfully");

            } catch (Exception e) {
                Msg.error(this, "Action tool execution failed: " + e.getMessage(), e);
                return ToolResult.error("Action failed: " + e.getMessage());
            }
        });
    }

    @Override
    public boolean handlesTool(String name) {
        // Check with prefix
        if (name.startsWith(TOOL_PREFIX)) {
            String baseName = name.substring(TOOL_PREFIX.length());
            return ACTION_TOOLS.containsKey(baseName);
        }
        return false;
    }

    @Override
    public void setContext(Program program) {
        this.currentProgram = program;
        Msg.debug(this, "Set program context: " + (program != null ? program.getName() : "null"));
    }

    /**
     * Set the current address context for actions.
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

    // Helper methods for creating JSON schemas

    private static JsonObject createSchema(Map<String, JsonObject> properties, List<String> required) {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");

        JsonObject propsObj = new JsonObject();
        for (Map.Entry<String, JsonObject> entry : properties.entrySet()) {
            propsObj.add(entry.getKey(), entry.getValue());
        }
        schema.add("properties", propsObj);

        if (!required.isEmpty()) {
            JsonArray reqArray = new JsonArray();
            for (String req : required) {
                reqArray.add(req);
            }
            schema.add("required", reqArray);
        }

        return schema;
    }

    private static JsonObject prop(String type, String description) {
        JsonObject prop = new JsonObject();
        prop.addProperty("type", type);
        prop.addProperty("description", description);
        return prop;
    }

    // Inner class for tool definitions
    private static class ActionToolDef {
        final String name;
        final String description;
        final JsonObject inputSchema;

        ActionToolDef(String name, String description, JsonObject inputSchema) {
            this.name = name;
            this.description = description;
            this.inputSchema = inputSchema;
        }
    }
}
