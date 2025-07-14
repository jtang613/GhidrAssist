package ghidrassist.mcp2.tools;

import com.google.gson.JsonObject;
import com.google.gson.JsonElement;
import java.util.Map;
import java.util.HashMap;

/**
 * Represents an MCP tool discovered from a server.
 * This is server-agnostic and follows the MCP specification.
 */
public class MCPTool {
    
    private String name;
    private String description;
    private JsonObject inputSchema;
    private String serverName;      // Which server provides this tool
    
    // Default constructor for adapter
    public MCPTool() {
    }
    
    public MCPTool(String name, String description, JsonObject inputSchema, String serverName) {
        this.name = name;
        this.description = description;
        this.inputSchema = inputSchema;
        this.serverName = serverName;
    }
    
    public String getName() {
        return name;
    }
    
    public void setName(String name) {
        this.name = name;
    }
    
    public String getDescription() {
        return description;
    }
    
    public void setDescription(String description) {
        this.description = description;
    }
    
    public JsonObject getInputSchema() {
        return inputSchema;
    }
    
    public void setInputSchema(JsonObject inputSchema) {
        this.inputSchema = inputSchema;
    }
    
    public String getServerName() {
        return serverName;
    }
    
    public void setServerName(String serverName) {
        this.serverName = serverName;
    }
    
    /**
     * Check if this tool has input parameters
     */
    public boolean hasInputSchema() {
        return inputSchema != null && inputSchema.size() > 0;
    }
    
    /**
     * Convert to function schema for LLM function calling
     * This follows the OpenAI function calling format
     */
    public Map<String, Object> toFunctionSchema() {
        Map<String, Object> function = new HashMap<>();
        function.put("type", "function");
        
        Map<String, Object> functionDef = new HashMap<>();
        functionDef.put("name", name);
        functionDef.put("description", description);
        
        if (inputSchema != null) {
            // Convert JsonObject to Map for compatibility
            functionDef.put("parameters", jsonObjectToMap(inputSchema));
        } else {
            // Empty parameters schema
            Map<String, Object> emptyParams = new HashMap<>();
            emptyParams.put("type", "object");
            emptyParams.put("properties", new HashMap<>());
            functionDef.put("parameters", emptyParams);
        }
        
        function.put("function", functionDef);
        return function;
    }
    
    /**
     * Create MCPTool from MCP tools/list response
     */
    public static MCPTool fromToolsListEntry(JsonObject toolEntry, String serverName) {
        String name = toolEntry.has("name") ? toolEntry.get("name").getAsString() : null;
        String description = toolEntry.has("description") ? toolEntry.get("description").getAsString() : "";
        JsonObject inputSchema = toolEntry.has("inputSchema") ? 
            toolEntry.getAsJsonObject("inputSchema") : null;
        
        return new MCPTool(name, description, inputSchema, serverName);
    }
    
    /**
     * Helper method to convert JsonObject to Map recursively
     */
    private Map<String, Object> jsonObjectToMap(JsonObject jsonObject) {
        Map<String, Object> map = new HashMap<>();
        
        for (String key : jsonObject.keySet()) {
            Object value = jsonElementToObject(jsonObject.get(key));
            map.put(key, value);
        }
        
        return map;
    }
    
    /**
     * Helper method to convert JsonElement to Java object
     */
    private Object jsonElementToObject(JsonElement element) {
        if (element.isJsonPrimitive()) {
            if (element.getAsJsonPrimitive().isString()) {
                return element.getAsString();
            } else if (element.getAsJsonPrimitive().isNumber()) {
                return element.getAsNumber();
            } else if (element.getAsJsonPrimitive().isBoolean()) {
                return element.getAsBoolean();
            }
        } else if (element.isJsonObject()) {
            return jsonObjectToMap(element.getAsJsonObject());
        } else if (element.isJsonArray()) {
            com.google.gson.JsonArray array = element.getAsJsonArray();
            java.util.List<Object> list = new java.util.ArrayList<>();
            for (int i = 0; i < array.size(); i++) {
                list.add(jsonElementToObject(array.get(i)));
            }
            return list;
        }
        return null;
    }
    
    @Override
    public String toString() {
        return String.format("MCPTool{name='%s', server='%s', description='%s'}", 
                           name, serverName, description);
    }
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        
        MCPTool mcpTool = (MCPTool) obj;
        return name != null && name.equals(mcpTool.name) && 
               serverName != null && serverName.equals(mcpTool.serverName);
    }
    
    @Override
    public int hashCode() {
        return java.util.Objects.hash(name, serverName);
    }
    
    /**
     * Get a display name that includes the server
     */
    public String getDisplayName() {
        return String.format("%s (%s)", name, serverName);
    }
    
    /**
     * Check if tool name matches (case-insensitive)
     */
    public boolean matchesName(String toolName) {
        return name != null && name.equalsIgnoreCase(toolName);
    }
}