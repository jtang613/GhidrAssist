package ghidrassist.tools.native_;

import com.google.gson.JsonObject;
import ghidrassist.mcp2.tools.MCPTool;
import ghidrassist.tools.api.Tool;

/**
 * Adapter that wraps different tool sources to implement the Tool interface.
 * Can wrap MCPTool objects or be constructed directly for action tools.
 */
public class NativeTool implements Tool {

    private final String name;
    private final String description;
    private final JsonObject inputSchema;
    private final String source;

    /**
     * Create a NativeTool from an MCPTool.
     * Used for wrapping semantic query tools.
     */
    public NativeTool(MCPTool mcpTool, String source) {
        this.name = mcpTool.getName();
        this.description = mcpTool.getDescription();
        this.inputSchema = mcpTool.getInputSchema();
        this.source = source;
    }

    /**
     * Create a NativeTool directly.
     * Used for action tools and other native tools.
     */
    public NativeTool(String name, String description, JsonObject inputSchema, String source) {
        this.name = name;
        this.description = description;
        this.inputSchema = inputSchema;
        this.source = source;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getDescription() {
        return description;
    }

    @Override
    public JsonObject getInputSchema() {
        return inputSchema;
    }

    @Override
    public String getSource() {
        return source;
    }

    @Override
    public String toString() {
        return String.format("NativeTool{name='%s', source='%s'}", name, source);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        NativeTool that = (NativeTool) obj;
        return name != null && name.equals(that.name) &&
               source != null && source.equals(that.source);
    }

    @Override
    public int hashCode() {
        return java.util.Objects.hash(name, source);
    }
}
