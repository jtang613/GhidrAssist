package ghidrassist.tools.api;

import com.google.gson.JsonObject;

/**
 * Core interface for all tools in the GhidrAssist system.
 * Tools can come from different sources (native, MCP servers, etc.)
 * but all implement this common interface.
 */
public interface Tool {

    /**
     * Get the unique name of this tool.
     * @return Tool name (e.g., "get_semantic_analysis", "rename_function")
     */
    String getName();

    /**
     * Get a human-readable description of what this tool does.
     * @return Tool description
     */
    String getDescription();

    /**
     * Get the JSON schema describing this tool's input parameters.
     * @return JSON schema object
     */
    JsonObject getInputSchema();

    /**
     * Get the source/provider of this tool.
     * @return Source identifier (e.g., "native", "mcp:server-name")
     */
    String getSource();
}
