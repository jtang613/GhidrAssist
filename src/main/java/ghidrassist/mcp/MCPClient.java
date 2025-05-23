package ghidrassist.mcp;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import ghidra.util.Msg;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.CompletableFuture;

/**
 * MCP (Model Context Protocol) client for communicating with GhidraMCP server.
 * Handles connection, tool discovery, and tool execution.
 */
public class MCPClient {
    
    private static final String DEFAULT_MCP_SERVER_URL = "http://localhost:8080";
    private static final Duration TIMEOUT = Duration.ofSeconds(30);
    
    private final HttpClient httpClient;
    private final Gson gson;
    private String serverUrl;
    private boolean connected;
    private List<MCPTool> availableTools;
    
    public MCPClient() {
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(TIMEOUT)
            .build();
        this.gson = new Gson();
        this.serverUrl = DEFAULT_MCP_SERVER_URL;
        this.connected = false;
        this.availableTools = new ArrayList<>();
    }
    
    /**
     * Test connection to MCP server
     */
    public boolean connect() {
        return connect(DEFAULT_MCP_SERVER_URL);
    }
    
    /**
     * Connect to MCP server at specified URL
     */
    public boolean connect(String url) {
        this.serverUrl = url;
        
        try {
            // Test connection by making a simple request to the server
            // Even a 404 response confirms the server is running
            if (testServerConnection(url)) {
                this.connected = true;
                // For now, assume basic GhidraMCP tools are available
                this.availableTools = createDefaultTools();
                
                Msg.info(this, "Connected to GhidraMCP server at " + url);
                return true;
            } else {
                this.connected = false;
                this.availableTools.clear();
                return false;
            }
            
        } catch (Exception e) {
            this.connected = false;
            this.availableTools.clear();
            Msg.debug(this, "Failed to connect to MCP server at " + url + ": " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Test if server is responding (even 404 is a valid response)
     */
    private boolean testServerConnection(String url) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(5))
                .GET()
                .build();
            
            HttpResponse<String> response = httpClient.send(request, 
                HttpResponse.BodyHandlers.ofString());
            
            // Any HTTP response (including 404) means server is running
            return response.statusCode() > 0;
            
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Create tool list based on actual GhidraMCP API endpoints
     */
    private List<MCPTool> createDefaultTools() {
        List<MCPTool> tools = new ArrayList<>();
        
        // Core function analysis tools
        tools.add(new MCPTool("get_current_function", 
            "Get information about the currently selected function", null));
        tools.add(new MCPTool("get_current_address", 
            "Get the current cursor address in Ghidra", null));
        tools.add(new MCPTool("list_functions", 
            "List all functions in the program", null));
        tools.add(new MCPTool("decompile_function", 
            "Decompile a function at the specified address", 
            createAddressSchema()));
        tools.add(new MCPTool("disassemble_function", 
            "Disassemble a function at the specified address", 
            createAddressSchema()));
        tools.add(new MCPTool("get_function_by_address", 
            "Get function information by address", 
            createAddressSchema()));
        
        // Renaming tools
        tools.add(new MCPTool("rename_function_by_address", 
            "Rename a function at the specified address", 
            createRenameFunctionSchema()));
        tools.add(new MCPTool("renameFunction", 
            "Rename a function by name", 
            createRenameFunctionByNameSchema()));
        tools.add(new MCPTool("renameData", 
            "Rename data at the specified address", 
            createRenameDataSchema()));
        tools.add(new MCPTool("renameVariable", 
            "Rename a variable in a function", 
            createRenameVariableSchema()));
        
        // Program structure tools
        tools.add(new MCPTool("classes", 
            "Get all class names with optional offset and limit", 
            createOffsetLimitSchema()));
        tools.add(new MCPTool("segments", 
            "List memory segments with optional offset and limit", 
            createOffsetLimitSchema()));
        tools.add(new MCPTool("imports", 
            "List imported functions with optional offset and limit", 
            createOffsetLimitSchema()));
        tools.add(new MCPTool("exports", 
            "List exported functions with optional offset and limit", 
            createOffsetLimitSchema()));
        tools.add(new MCPTool("namespaces", 
            "List namespaces with optional offset and limit", 
            createOffsetLimitSchema()));
        tools.add(new MCPTool("data", 
            "List defined data with optional offset and limit", 
            createOffsetLimitSchema()));
        tools.add(new MCPTool("strings", 
            "List defined strings with optional filter, offset and limit", 
            createStringsSchema()));
        
        // Search tools
        tools.add(new MCPTool("searchFunctions", 
            "Search functions by name with optional offset and limit", 
            createSearchFunctionsSchema()));
        
        // Cross-reference tools
        tools.add(new MCPTool("xrefs_to", 
            "Get cross-references to an address", 
            createXrefsSchema()));
        tools.add(new MCPTool("xrefs_from", 
            "Get cross-references from an address", 
            createXrefsSchema()));
        tools.add(new MCPTool("function_xrefs", 
            "Get cross-references for a function by name", 
            createFunctionXrefsSchema()));
        
        // Comment and annotation tools
        tools.add(new MCPTool("set_decompiler_comment", 
            "Set a comment in the decompiler view", 
            createCommentSchema()));
        tools.add(new MCPTool("set_disassembly_comment", 
            "Set a comment in the disassembly view", 
            createCommentSchema()));
        
        // Advanced analysis tools
        tools.add(new MCPTool("set_function_prototype", 
            "Set the prototype for a function", 
            createPrototypeSchema()));
        tools.add(new MCPTool("set_local_variable_type", 
            "Set the type of a local variable in a function", 
            createVariableTypeSchema()));
        
        return tools;
    }
    
    // Schema creation methods for different parameter types
    
    private JsonObject createAddressSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject properties = new JsonObject();
        
        JsonObject address = new JsonObject();
        address.addProperty("type", "string");
        address.addProperty("description", "Memory address (e.g., '0x401000')");
        properties.add("address", address);
        
        schema.add("properties", properties);
        JsonArray required = new JsonArray();
        required.add("address");
        schema.add("required", required);
        return schema;
    }
    
    private JsonObject createRenameFunctionSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject properties = new JsonObject();
        
        JsonObject functionAddress = new JsonObject();
        functionAddress.addProperty("type", "string");
        functionAddress.addProperty("description", "Function address (e.g., '0x401000')");
        properties.add("function_address", functionAddress);
        
        JsonObject newName = new JsonObject();
        newName.addProperty("type", "string");
        newName.addProperty("description", "New function name");
        properties.add("new_name", newName);
        
        schema.add("properties", properties);
        JsonArray required = new JsonArray();
        required.add("function_address");
        required.add("new_name");
        schema.add("required", required);
        return schema;
    }
    
    private JsonObject createRenameFunctionByNameSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject properties = new JsonObject();
        
        JsonObject oldName = new JsonObject();
        oldName.addProperty("type", "string");
        oldName.addProperty("description", "Current function name");
        properties.add("oldName", oldName);
        
        JsonObject newName = new JsonObject();
        newName.addProperty("type", "string");
        newName.addProperty("description", "New function name");
        properties.add("newName", newName);
        
        schema.add("properties", properties);
        JsonArray required = new JsonArray();
        required.add("oldName");
        required.add("newName");
        schema.add("required", required);
        return schema;
    }
    
    private JsonObject createRenameDataSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject properties = new JsonObject();
        
        JsonObject address = new JsonObject();
        address.addProperty("type", "string");
        address.addProperty("description", "Data address (e.g., '0x401000')");
        properties.add("address", address);
        
        JsonObject newName = new JsonObject();
        newName.addProperty("type", "string");
        newName.addProperty("description", "New data name");
        properties.add("newName", newName);
        
        schema.add("properties", properties);
        JsonArray required = new JsonArray();
        required.add("address");
        required.add("newName");
        schema.add("required", required);
        return schema;
    }
    
    private JsonObject createRenameVariableSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject properties = new JsonObject();
        
        JsonObject functionName = new JsonObject();
        functionName.addProperty("type", "string");
        functionName.addProperty("description", "Function name containing the variable");
        properties.add("functionName", functionName);
        
        JsonObject oldName = new JsonObject();
        oldName.addProperty("type", "string");
        oldName.addProperty("description", "Current variable name");
        properties.add("oldName", oldName);
        
        JsonObject newName = new JsonObject();
        newName.addProperty("type", "string");
        newName.addProperty("description", "New variable name");
        properties.add("newName", newName);
        
        schema.add("properties", properties);
        JsonArray required = new JsonArray();
        required.add("functionName");
        required.add("oldName");
        required.add("newName");
        schema.add("required", required);
        return schema;
    }
    
    private JsonObject createOffsetLimitSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject properties = new JsonObject();
        
        JsonObject offset = new JsonObject();
        offset.addProperty("type", "integer");
        offset.addProperty("description", "Starting offset (default: 0)");
        offset.addProperty("default", 0);
        properties.add("offset", offset);
        
        JsonObject limit = new JsonObject();
        limit.addProperty("type", "integer");
        limit.addProperty("description", "Maximum number of results (default: 100)");
        limit.addProperty("default", 100);
        properties.add("limit", limit);
        
        schema.add("properties", properties);
        return schema;
    }
    
    private JsonObject createStringsSchema() {
        JsonObject schema = createOffsetLimitSchema();
        JsonObject properties = schema.getAsJsonObject("properties");
        
        JsonObject filter = new JsonObject();
        filter.addProperty("type", "string");
        filter.addProperty("description", "Filter string to search for");
        properties.add("filter", filter);
        
        return schema;
    }
    
    private JsonObject createSearchFunctionsSchema() {
        JsonObject schema = createOffsetLimitSchema();
        JsonObject properties = schema.getAsJsonObject("properties");
        
        JsonObject query = new JsonObject();
        query.addProperty("type", "string");
        query.addProperty("description", "Search term for function names");
        properties.add("query", query);
        
        JsonArray required = new JsonArray();
        required.add("query");
        schema.add("required", required);
        return schema;
    }
    
    private JsonObject createXrefsSchema() {
        JsonObject schema = createOffsetLimitSchema();
        JsonObject properties = schema.getAsJsonObject("properties");
        
        JsonObject address = new JsonObject();
        address.addProperty("type", "string");
        address.addProperty("description", "Memory address (e.g., '0x401000')");
        properties.add("address", address);
        
        JsonArray required = new JsonArray();
        required.add("address");
        schema.add("required", required);
        return schema;
    }
    
    private JsonObject createFunctionXrefsSchema() {
        JsonObject schema = createOffsetLimitSchema();
        JsonObject properties = schema.getAsJsonObject("properties");
        
        JsonObject name = new JsonObject();
        name.addProperty("type", "string");
        name.addProperty("description", "Function name");
        properties.add("name", name);
        
        JsonArray required = new JsonArray();
        required.add("name");
        schema.add("required", required);
        return schema;
    }
    
    private JsonObject createCommentSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject properties = new JsonObject();
        
        JsonObject address = new JsonObject();
        address.addProperty("type", "string");
        address.addProperty("description", "Memory address (e.g., '0x401000')");
        properties.add("address", address);
        
        JsonObject comment = new JsonObject();
        comment.addProperty("type", "string");
        comment.addProperty("description", "Comment text");
        properties.add("comment", comment);
        
        schema.add("properties", properties);
        JsonArray required = new JsonArray();
        required.add("address");
        required.add("comment");
        schema.add("required", required);
        return schema;
    }
    
    private JsonObject createPrototypeSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject properties = new JsonObject();
        
        JsonObject functionAddress = new JsonObject();
        functionAddress.addProperty("type", "string");
        functionAddress.addProperty("description", "Function address (e.g., '0x401000')");
        properties.add("function_address", functionAddress);
        
        JsonObject prototype = new JsonObject();
        prototype.addProperty("type", "string");
        prototype.addProperty("description", "Function prototype (e.g., 'int func(char *param1)')");
        properties.add("prototype", prototype);
        
        schema.add("properties", properties);
        JsonArray required = new JsonArray();
        required.add("function_address");
        required.add("prototype");
        schema.add("required", required);
        return schema;
    }
    
    private JsonObject createVariableTypeSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject properties = new JsonObject();
        
        JsonObject functionAddress = new JsonObject();
        functionAddress.addProperty("type", "string");
        functionAddress.addProperty("description", "Function address (e.g., '0x401000')");
        properties.add("function_address", functionAddress);
        
        JsonObject variableName = new JsonObject();
        variableName.addProperty("type", "string");
        variableName.addProperty("description", "Variable name");
        properties.add("variable_name", variableName);
        
        JsonObject newType = new JsonObject();
        newType.addProperty("type", "string");
        newType.addProperty("description", "New variable type (e.g., 'int', 'char*')");
        properties.add("new_type", newType);
        
        schema.add("properties", properties);
        JsonArray required = new JsonArray();
        required.add("function_address");
        required.add("variable_name");
        required.add("new_type");
        schema.add("required", required);
        return schema;
    }
    
    /**
     * Refresh tools list (for future endpoint discovery implementation)
     */
    public List<MCPTool> discoverTools() throws Exception {
        // For now, return the default tools
        // TODO: Implement actual tool discovery when GhidraMCP API is documented
        return createDefaultTools();
    }
    
    /**
     * Execute a tool call on the MCP server using actual GhidraMCP endpoints
     */
    public CompletableFuture<MCPToolResult> executeTool(String toolName, JsonObject arguments) {
        if (!connected) {
            return CompletableFuture.failedFuture(
                new IllegalStateException("Not connected to MCP server"));
        }
        
        return CompletableFuture.supplyAsync(() -> {
            try {
                return executeGhidraMCPTool(toolName, arguments);
            } catch (Exception e) {
                return new MCPToolResult(false, null, e.getMessage());
            }
        });
    }
    
    /**
     * Execute tool using GhidraMCP's specific API endpoints
     */
    private MCPToolResult executeGhidraMCPTool(String toolName, JsonObject arguments) throws Exception {
        String endpoint = serverUrl + "/" + toolName;
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
            .uri(URI.create(endpoint))
            .timeout(TIMEOUT);
        
        // Handle different HTTP methods based on the tool
        if (isPostEndpoint(toolName)) {
            // POST endpoints (renaming, comments, prototypes)
            String postData = buildPostData(toolName, arguments);
            requestBuilder.header("Content-Type", "application/x-www-form-urlencoded")
                         .POST(HttpRequest.BodyPublishers.ofString(postData));
        } else if (toolName.equals("decompile")) {
            // Special case: decompile expects function name in body
            String functionName = arguments.has("name") ? arguments.get("name").getAsString() : "";
            requestBuilder.header("Content-Type", "text/plain")
                         .POST(HttpRequest.BodyPublishers.ofString(functionName));
        } else {
            // GET endpoints with query parameters
            String queryParams = buildQueryParams(arguments);
            if (!queryParams.isEmpty()) {
                endpoint += "?" + queryParams;
                requestBuilder.uri(URI.create(endpoint));
            }
            requestBuilder.GET();
        }
        
        HttpRequest request = requestBuilder.build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        
        if (response.statusCode() == 200) {
            return MCPToolResult.success(response.body());
        } else {
            return MCPToolResult.error("HTTP " + response.statusCode() + ": " + response.body());
        }
    }
    
    /**
     * Check if endpoint requires POST method
     */
    private boolean isPostEndpoint(String toolName) {
        return toolName.equals("renameFunction") || 
               toolName.equals("renameData") || 
               toolName.equals("renameVariable") ||
               toolName.equals("rename_function_by_address") ||
               toolName.equals("set_decompiler_comment") ||
               toolName.equals("set_disassembly_comment") ||
               toolName.equals("set_function_prototype") ||
               toolName.equals("set_local_variable_type") ||
               toolName.equals("decompile");
    }
    
    /**
     * Build POST data for form submission
     */
    private String buildPostData(String toolName, JsonObject arguments) {
        StringBuilder postData = new StringBuilder();
        
        for (String key : arguments.keySet()) {
            if (postData.length() > 0) {
                postData.append("&");
            }
            postData.append(java.net.URLEncoder.encode(key, java.nio.charset.StandardCharsets.UTF_8))
                   .append("=")
                   .append(java.net.URLEncoder.encode(arguments.get(key).getAsString(), java.nio.charset.StandardCharsets.UTF_8));
        }
        
        return postData.toString();
    }
    
    /**
     * Build query parameters for GET requests
     */
    private String buildQueryParams(JsonObject arguments) {
        StringBuilder queryParams = new StringBuilder();
        
        for (String key : arguments.keySet()) {
            if (queryParams.length() > 0) {
                queryParams.append("&");
            }
            queryParams.append(java.net.URLEncoder.encode(key, java.nio.charset.StandardCharsets.UTF_8))
                      .append("=")
                      .append(java.net.URLEncoder.encode(arguments.get(key).getAsString(), java.nio.charset.StandardCharsets.UTF_8));
        }
        
        return queryParams.toString();
    }
    
    /**
     * Check if connected to MCP server
     */
    public boolean isConnected() {
        return connected;
    }
    
    /**
     * Get list of available tools
     */
    public List<MCPTool> getAvailableTools() {
        return new ArrayList<>(availableTools);
    }
    
    /**
     * Get tool by name
     */
    public MCPTool getTool(String name) {
        return availableTools.stream()
            .filter(tool -> tool.getName().equals(name))
            .findFirst()
            .orElse(null);
    }
    
    /**
     * Disconnect from MCP server
     */
    public void disconnect() {
        connected = false;
        availableTools.clear();
    }
    
    /**
     * Set custom server URL
     */
    public void setServerUrl(String url) {
        this.serverUrl = url;
    }
    
    /**
     * Get current server URL
     */
    public String getServerUrl() {
        return serverUrl;
    }
}