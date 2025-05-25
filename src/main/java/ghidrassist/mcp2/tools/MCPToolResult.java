package ghidrassist.mcp2.tools;

/**
 * Result of an MCP tool execution.
 * Similar to the original MCPToolResult but for MCP 2.0.
 */
public class MCPToolResult {
    
    private final boolean success;
    private final String content;
    private final String error;
    
    public MCPToolResult(boolean success, String content, String error) {
        this.success = success;
        this.content = content;
        this.error = error;
    }
    
    /**
     * Create successful result
     */
    public static MCPToolResult success(String content) {
        return new MCPToolResult(true, content, null);
    }
    
    /**
     * Create error result
     */
    public static MCPToolResult error(String error) {
        return new MCPToolResult(false, null, error);
    }
    
    public boolean isSuccess() {
        return success;
    }
    
    public String getContent() {
        return content;
    }
    
    public String getError() {
        return error;
    }
    
    /**
     * Get result as string for display
     */
    public String getResultText() {
        if (success) {
            return content != null ? content : "";
        } else {
            return "Error: " + (error != null ? error : "Unknown error");
        }
    }
    
    @Override
    public String toString() {
        return String.format("MCPToolResult{success=%s, content='%s', error='%s'}", 
            success, content, error);
    }
}