package ghidrassist.mcp2.protocol;

import com.google.gson.JsonObject;
import com.google.gson.JsonElement;

/**
 * Base class for all MCP JSON-RPC 2.0 messages.
 * Implements the core JSON-RPC 2.0 message structure.
 */
public abstract class MCPMessage {
    
    public static final String JSONRPC_VERSION = "2.0";
    
    protected String jsonrpc = JSONRPC_VERSION;
    protected String method;
    protected JsonObject params;
    
    public MCPMessage(String method) {
        this.method = method;
        this.params = new JsonObject();
    }
    
    public MCPMessage(String method, JsonObject params) {
        this.method = method;
        this.params = params != null ? params : new JsonObject();
    }
    
    public String getJsonrpc() {
        return jsonrpc;
    }
    
    public String getMethod() {
        return method;
    }
    
    public JsonObject getParams() {
        return params;
    }
    
    public void setParam(String key, String value) {
        params.addProperty(key, value);
    }
    
    public void setParam(String key, JsonElement value) {
        params.add(key, value);
    }
    
    public void setParam(String key, Number value) {
        params.addProperty(key, value);
    }
    
    public void setParam(String key, Boolean value) {
        params.addProperty(key, value);
    }
    
    /**
     * Convert message to JSON string for transmission
     */
    public abstract String toJson();
    
    /**
     * Validate message format
     */
    public boolean isValid() {
        return JSONRPC_VERSION.equals(jsonrpc) && method != null && !method.isEmpty();
    }
}