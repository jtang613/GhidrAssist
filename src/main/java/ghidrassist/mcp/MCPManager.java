package ghidrassist.mcp;

import ghidra.util.Msg;
import com.google.gson.JsonObject;
import com.google.gson.JsonArray;

import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.CompletableFuture;

/**
 * Manager for MCP client operations and integration with GhidrAssist.
 * Handles detection, connection, and tool execution coordination.
 */
public class MCPManager {
    
    private static MCPManager instance;
    private MCPClient mcpClient;
    private boolean available;
    
    private MCPManager() {
        this.mcpClient = new MCPClient();
        this.available = false;
    }
    
    /**
     * Get singleton instance
     */
    public static synchronized MCPManager getInstance() {
        if (instance == null) {
            instance = new MCPManager();
        }
        return instance;
    }
    
    /**
     * Detect if GhidraMCP is available and connect
     */
    public boolean detectAndConnect() {
        return detectAndConnect("http://localhost:8080");
    }
    
    /**
     * Detect if GhidraMCP is available at specified URL
     */
    public boolean detectAndConnect(String serverUrl) {
        try {
            boolean connected = mcpClient.connect(serverUrl);
            this.available = connected;
            
            if (connected) {
                Msg.info(this, "GhidraMCP detected and connected successfully");
                List<MCPTool> tools = mcpClient.getAvailableTools();
                Msg.info(this, "Available MCP tools: " + tools.size());
                for (MCPTool tool : tools) {
                    Msg.debug(this, "  - " + tool.getName() + ": " + tool.getDescription());
                }
            } else {
                Msg.debug(this, "GhidraMCP not available at " + serverUrl);
            }
            
            return connected;
        } catch (Exception e) {
            this.available = false;
            Msg.debug(this, "Failed to detect GhidraMCP: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Check if MCP is available
     */
    public boolean isAvailable() {
        return available && mcpClient.isConnected();
    }
    
    /**
     * Get available MCP tools as function schemas for LLM
     */
    public List<Map<String, Object>> getToolsAsFunction() {
        if (!isAvailable()) {
            return new ArrayList<>();
        }
        
        List<Map<String, Object>> functions = new ArrayList<>();
        for (MCPTool tool : mcpClient.getAvailableTools()) {
            Map<String, Object> function = new HashMap<>();
            function.put("type", "function");
            
            // Convert JsonObject to Map for compatibility
            JsonObject functionSchema = tool.toFunctionSchema();
            Map<String, Object> functionMap = new HashMap<>();
            functionMap.put("name", functionSchema.get("name").getAsString());
            functionMap.put("description", functionSchema.get("description").getAsString());
            
            // Convert parameters JsonObject to Map if present
            if (functionSchema.has("parameters")) {
                functionMap.put("parameters", jsonObjectToMap(functionSchema.get("parameters").getAsJsonObject()));
            }
            
            function.put("function", functionMap);
            functions.add(function);
        }
        
        return functions;
    }
    
    /**
     * Execute MCP tool and return result
     */
    public CompletableFuture<MCPToolResult> executeTool(String toolName, JsonObject arguments) {
        if (!isAvailable()) {
            return CompletableFuture.failedFuture(
                new IllegalStateException("MCP is not available"));
        }
        
        return mcpClient.executeTool(toolName, arguments);
    }
    
    /**
     * Get tool by name
     */
    public MCPTool getTool(String name) {
        if (!isAvailable()) {
            return null;
        }
        return mcpClient.getTool(name);
    }
    
    /**
     * Get all available tools
     */
    public List<MCPTool> getAvailableTools() {
        if (!isAvailable()) {
            return new ArrayList<>();
        }
        return mcpClient.getAvailableTools();
    }
    
    /**
     * Check if a specific tool is available
     */
    public boolean hasTools(String... toolNames) {
        if (!isAvailable()) {
            return false;
        }
        
        List<MCPTool> tools = mcpClient.getAvailableTools();
        for (String toolName : toolNames) {
            boolean found = tools.stream().anyMatch(tool -> tool.getName().equals(toolName));
            if (!found) {
                return false;
            }
        }
        return true;
    }
    
    /**
     * Refresh connection and tool list
     */
    public boolean refresh() {
        if (mcpClient.isConnected()) {
            try {
                List<MCPTool> tools = mcpClient.discoverTools();
                Msg.info(this, "Refreshed MCP tools: " + tools.size() + " available");
                return true;
            } catch (Exception e) {
                Msg.error(this, "Failed to refresh MCP tools: " + e.getMessage());
                available = false;
                return false;
            }
        }
        return false;
    }
    
    /**
     * Disconnect from MCP server
     */
    public void disconnect() {
        mcpClient.disconnect();
        available = false;
    }
    
    /**
     * Get connection status info
     */
    public String getStatusInfo() {
        if (!available) {
            return "GhidraMCP not available";
        }
        
        List<MCPTool> tools = mcpClient.getAvailableTools();
        return String.format("Connected to %s (%d tools)", 
            mcpClient.getServerUrl(), tools.size());
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
    private Object jsonElementToObject(com.google.gson.JsonElement element) {
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
            JsonArray array = element.getAsJsonArray();
            List<Object> list = new ArrayList<>();
            for (int i = 0; i < array.size(); i++) {
                list.add(jsonElementToObject(array.get(i)));
            }
            return list;
        }
        return null;
    }
}