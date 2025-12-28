package ghidrassist.mcp2.tools;

import com.google.gson.JsonObject;
import ghidrassist.tools.api.Tool;

/**
 * Adapter that wraps MCPTool to implement the unified Tool interface.
 * This allows MCP tools to be used alongside native tools in the ToolRegistry.
 *
 * Tool names are prefixed with the server name (e.g., "servername.toolname")
 * to avoid conflicts between different MCP servers and native tools.
 */
public class MCPToolAdapter implements Tool {

    private final MCPTool mcpTool;
    private final String prefixedName;

    /**
     * Create an adapter with the server-prefixed name.
     *
     * @param mcpTool The underlying MCP tool
     * @param prefixedName The full prefixed name (e.g., "servername.toolname")
     */
    public MCPToolAdapter(MCPTool mcpTool, String prefixedName) {
        this.mcpTool = mcpTool;
        this.prefixedName = prefixedName;
    }

    @Override
    public String getName() {
        return prefixedName;
    }

    /**
     * Get the original (non-prefixed) tool name.
     */
    public String getOriginalName() {
        return mcpTool.getName();
    }

    @Override
    public String getDescription() {
        return mcpTool.getDescription();
    }

    @Override
    public JsonObject getInputSchema() {
        return mcpTool.getInputSchema();
    }

    @Override
    public String getSource() {
        return "mcp:" + mcpTool.getServerName();
    }

    /**
     * Get the underlying MCPTool.
     */
    public MCPTool getMCPTool() {
        return mcpTool;
    }

    @Override
    public String toString() {
        return String.format("MCPToolAdapter{prefixedName='%s', originalName='%s', server='%s'}",
                            prefixedName, mcpTool.getName(), mcpTool.getServerName());
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        MCPToolAdapter that = (MCPToolAdapter) obj;
        return mcpTool != null && mcpTool.equals(that.mcpTool);
    }

    @Override
    public int hashCode() {
        return mcpTool != null ? mcpTool.hashCode() : 0;
    }
}
