package ghidrassist.mcp2.protocol;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonElement;
import com.google.gson.JsonArray;

/**
 * Represents an MCP JSON-RPC 2.0 response message.
 * Can contain either a result (success) or an error (failure).
 */
public class MCPResponse {
    
    private String jsonrpc = MCPMessage.JSONRPC_VERSION;
    private Object id;
    private JsonElement result;
    private MCPError error;
    
    public MCPResponse(Object id) {
        this.id = id;
    }
    
    public String getJsonrpc() {
        return jsonrpc;
    }
    
    public Object getId() {
        return id;
    }
    
    public JsonElement getResult() {
        return result;
    }
    
    public void setResult(JsonElement result) {
        this.result = result;
        this.error = null; // Clear error if setting result
    }
    
    public MCPError getError() {
        return error;
    }
    
    public void setError(MCPError error) {
        this.error = error;
        this.result = null; // Clear result if setting error
    }
    
    public void setError(int code, String message, JsonElement data) {
        setError(new MCPError(code, message, data));
    }
    
    public boolean isSuccess() {
        return result != null && error == null;
    }
    
    public boolean isError() {
        return error != null;
    }
    
    public String toJson() {
        JsonObject json = new JsonObject();
        json.addProperty("jsonrpc", jsonrpc);
        json.addProperty("id", id.toString());
        
        if (result != null) {
            json.add("result", result);
        } else if (error != null) {
            json.add("error", error.toJson());
        }
        
        return new Gson().toJson(json);
    }
    
    /**
     * Parse response from JSON string
     */
    public static MCPResponse fromJson(String jsonStr) {
        Gson gson = new Gson();
        JsonObject json = gson.fromJson(jsonStr, JsonObject.class);
        
        Object id = json.has("id") ? json.get("id").getAsString() : null;
        MCPResponse response = new MCPResponse(id);
        
        if (json.has("result")) {
            response.setResult(json.get("result"));
        } else if (json.has("error")) {
            JsonObject errorObj = json.getAsJsonObject("error");
            int code = errorObj.get("code").getAsInt();
            String message = errorObj.get("message").getAsString();
            JsonElement data = errorObj.has("data") ? errorObj.get("data") : null;
            response.setError(code, message, data);
        }
        
        return response;
    }
    
    /**
     * Extract tools array from tools/list response
     */
    public JsonArray getToolsArray() {
        if (isSuccess() && result.isJsonObject()) {
            JsonObject resultObj = result.getAsJsonObject();
            if (resultObj.has("tools") && resultObj.get("tools").isJsonArray()) {
                return resultObj.getAsJsonArray("tools");
            }
        }
        return new JsonArray();
    }
    
    /**
     * Extract tool call result content
     */
    public JsonElement getToolCallResult() {
        if (isSuccess() && result.isJsonObject()) {
            JsonObject resultObj = result.getAsJsonObject();
            if (resultObj.has("content")) {
                return resultObj.get("content");
            }
        }
        return result;
    }
    
    /**
     * Get cursor for pagination in tools/list response
     */
    public String getNextCursor() {
        if (isSuccess() && result.isJsonObject()) {
            JsonObject resultObj = result.getAsJsonObject();
            if (resultObj.has("nextCursor")) {
                return resultObj.get("nextCursor").getAsString();
            }
        }
        return null;
    }
    
    /**
     * Inner class representing JSON-RPC 2.0 error object
     */
    public static class MCPError {
        private int code;
        private String message;
        private JsonElement data;
        
        public MCPError(int code, String message, JsonElement data) {
            this.code = code;
            this.message = message;
            this.data = data;
        }
        
        public int getCode() {
            return code;
        }
        
        public String getMessage() {
            return message;
        }
        
        public JsonElement getData() {
            return data;
        }
        
        public JsonObject toJson() {
            JsonObject json = new JsonObject();
            json.addProperty("code", code);
            json.addProperty("message", message);
            if (data != null) {
                json.add("data", data);
            }
            return json;
        }
        
        @Override
        public String toString() {
            return String.format("MCPError{code=%d, message='%s'}", code, message);
        }
    }
}