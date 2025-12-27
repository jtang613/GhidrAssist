package ghidrassist.tools.api;

import com.google.gson.JsonObject;
import ghidra.program.model.listing.Program;

import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * Interface for tool sources/providers.
 * Each provider manages a set of tools and handles their execution.
 *
 * Examples of providers:
 * - NativeToolManager: Internal tools (semantic, actions)
 * - MCPToolManager: Tools from MCP servers
 */
public interface ToolProvider {

    /**
     * Get the name of this provider.
     * @return Provider name (e.g., "native", "MCP")
     */
    String getProviderName();

    /**
     * Get all tools provided by this provider.
     * @return List of available tools
     */
    List<Tool> getTools();

    /**
     * Execute a tool by name with the given arguments.
     * @param name Tool name
     * @param args Tool arguments as JSON
     * @return Future containing the tool result
     */
    CompletableFuture<ToolResult> executeTool(String name, JsonObject args);

    /**
     * Check if this provider handles the given tool.
     * @param name Tool name
     * @return true if this provider can execute the tool
     */
    boolean handlesTool(String name);

    /**
     * Set the Ghidra program context for tools that need it.
     * @param program Current Ghidra program (may be null)
     */
    void setContext(Program program);
}
