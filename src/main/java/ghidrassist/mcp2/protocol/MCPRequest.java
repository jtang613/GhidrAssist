package ghidrassist.mcp2.protocol;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonElement;

/**
 * Represents an MCP JSON-RPC 2.0 request message.
 * Used for tool discovery (tools/list) and tool execution (tools/call).
 */
public class MCPRequest extends MCPMessage {
    
    private final Object id;
    
    public MCPRequest(Object id, String method) {
        super(method);
        this.id = id;
    }
    
    public MCPRequest(Object id, String method, JsonObject params) {
        super(method, params);
        this.id = id;
    }
    
    public Object getId() {
        return id;
    }
    
    @Override
    public String toJson() {
        JsonObject json = new JsonObject();
        json.addProperty("jsonrpc", jsonrpc);
        
        // Only add ID if this is not a notification
        if (!"notification".equals(id)) {
            json.addProperty("id", id.toString());
        }
        
        json.addProperty("method", method);
        
        if (params != null && params.size() > 0) {
            json.add("params", params);
        }
        
        return new Gson().toJson(json);
    }
    
    @Override
    public boolean isValid() {
        return super.isValid() && id != null;
    }
    
    /**
     * Create a tools/list request
     */
    public static MCPRequest createToolsListRequest(Object id) {
        return createToolsListRequest(id, null);
    }
    
    /**
     * Create a tools/list request with cursor for pagination
     */
    public static MCPRequest createToolsListRequest(Object id, String cursor) {
        MCPRequest request = new MCPRequest(id, "tools/list");
        if (cursor != null) {
            request.setParam("cursor", cursor);
        }
        return request;
    }
    
    /**
     * Create a tools/call request
     */
    public static MCPRequest createToolsCallRequest(Object id, String toolName, JsonObject arguments) {
        MCPRequest request = new MCPRequest(id, "tools/call");
        request.setParam("name", toolName);
        if (arguments != null) {
            request.setParam("arguments", arguments);
        }
        return request;
    }
    
    /**
     * Create an initialize request for protocol handshake
     */
    public static MCPRequest createInitializeRequest(Object id, String protocolVersion, String clientInfo) {
        MCPRequest request = new MCPRequest(id, "initialize");
        request.setParam("protocolVersion", protocolVersion);
        
        JsonObject clientInfoObj = new JsonObject();
        clientInfoObj.addProperty("name", "GhidrAssist");
        clientInfoObj.addProperty("version", "1.0.0");
        if (clientInfo != null) {
            clientInfoObj.addProperty("description", clientInfo);
        }
        request.setParam("clientInfo", clientInfoObj);
        
        JsonObject capabilities = new JsonObject();
        capabilities.addProperty("tools", true);
        request.setParam("capabilities", capabilities);
        
        return request;
    }
    
    /**
     * Create an initialized notification (sent after initialize response)
     */
    public static MCPRequest createInitializedNotification() {
        // Notifications don't have IDs in JSON-RPC 2.0
        // The bridge expects "notifications/initialized" method
        return new MCPRequest("notification", "notifications/initialized");
    }
}