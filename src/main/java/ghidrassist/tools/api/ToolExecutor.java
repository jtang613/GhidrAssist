package ghidrassist.tools.api;

import com.google.gson.JsonObject;

import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * Interface for executing tools by name.
 * The ToolRegistry implements this interface to provide
 * unified tool execution across all providers.
 */
public interface ToolExecutor {

    /**
     * Execute a tool by name with the given arguments.
     * @param toolName Name of the tool to execute
     * @param args Arguments as JSON object
     * @return Future containing the tool result
     */
    CompletableFuture<ToolResult> execute(String toolName, JsonObject args);

    /**
     * Get all available tools from all providers.
     * @return List of all tools
     */
    List<Tool> getAllTools();
}
