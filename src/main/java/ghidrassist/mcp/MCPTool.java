package ghidrassist.mcp;

import com.google.gson.JsonObject;

/**
 * Represents an MCP tool with its metadata and schema.
 */
public class MCPTool {
    
    private final String name;
    private final String description;
    private final JsonObject inputSchema;
    
    public MCPTool(String name, String description, JsonObject inputSchema) {
        this.name = name;
        this.description = description;
        this.inputSchema = inputSchema;
    }
    
    public String getName() {
        return name;
    }
    
    public String getDescription() {
        return description;
    }
    
    public JsonObject getInputSchema() {
        return inputSchema;
    }
    
    /**
     * Check if this tool has input parameters
     */
    public boolean hasInputSchema() {
        return inputSchema != null;
    }
    
    /**
     * Get tool signature for LLM function calling
     */
    public JsonObject toFunctionSchema() {
        JsonObject function = new JsonObject();
        function.addProperty("name", name);
        function.addProperty("description", description);
        
        if (inputSchema != null) {
            function.add("parameters", inputSchema);
        } else {
            // Empty parameters schema
            JsonObject emptyParams = new JsonObject();
            emptyParams.addProperty("type", "object");
            emptyParams.add("properties", new JsonObject());
            function.add("parameters", emptyParams);
        }
        
        return function;
    }
    
    @Override
    public String toString() {
        return String.format("MCPTool{name='%s', description='%s', hasSchema=%s}", 
            name, description, hasInputSchema());
    }
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        
        MCPTool mcpTool = (MCPTool) obj;
        return name.equals(mcpTool.name);
    }
    
    @Override
    public int hashCode() {
        return name.hashCode();
    }
}