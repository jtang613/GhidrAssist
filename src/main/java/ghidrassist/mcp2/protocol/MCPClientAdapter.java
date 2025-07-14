package ghidrassist.mcp2.protocol;

import ghidrassist.mcp2.server.MCPServerConfig;
import ghidrassist.mcp2.tools.MCPTool;
import ghidra.util.Msg;

import com.google.gson.JsonObject;
import com.google.gson.JsonElement;
import com.google.gson.Gson;

import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpAsyncClient;
import io.modelcontextprotocol.client.transport.HttpClientSseClientTransport;
import io.modelcontextprotocol.spec.McpSchema;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * Adapter that wraps the official MCP SDK client to provide compatibility
 * with our existing GhidrAssist MCP architecture.
 */
public class MCPClientAdapter {
    
    private final MCPServerConfig config;
    private volatile McpAsyncClient mcpClient;
    private MCPClientHandler handler;
    private volatile boolean initialized = false;
    private List<MCPTool> discoveredTools = new ArrayList<>();
    
    /**
     * Interface for handling client events (compatibility with existing code)
     */
    public interface MCPClientHandler {
        void onConnected(MCPClientAdapter client);
        void onDisconnected(MCPClientAdapter client);
        void onToolsDiscovered(MCPClientAdapter client, List<MCPTool> tools);
        void onError(MCPClientAdapter client, Throwable error);
    }
    
    public MCPClientAdapter(MCPServerConfig config) {
        this.config = config;
    }
    
    /**
     * Set client event handler
     */
    public void setHandler(MCPClientHandler handler) {
        this.handler = handler;
    }
    
    /**
     * Connect and initialize the MCP client using the official SDK
     */
    public CompletableFuture<Void> connect() {
        return CompletableFuture.runAsync(() -> {
            try {
                // Create transport using official SDK with default settings
                HttpClientSseClientTransport transport = HttpClientSseClientTransport.builder(config.getBaseUrl())
                    .build();
                
                // Build client with our configuration
                McpSchema.ClientCapabilities capabilities = McpSchema.ClientCapabilities.builder()
                    .build();
                
                mcpClient = McpClient.async(transport)
                    .requestTimeout(Duration.ofSeconds(60))
                    .capabilities(capabilities)
                    .build();
                
                Msg.info(this, "MCP async client created with 60s timeout for: " + config.getName());
                
                // Initialize connection (required by SDK)
                mcpClient.initialize().block();
                
                Msg.info(this, "Connected to MCP server using official SDK: " + config.getName());
                
                // Discover tools after initialization
                discoverTools().get();
                
                initialized = true;
                
                // Notify handler on EDT for UI updates
                if (handler != null) {
                    javax.swing.SwingUtilities.invokeLater(() -> handler.onConnected(this));
                }
                
            } catch (Exception e) {
                Msg.error(this, "Failed to connect to MCP server: " + e.getMessage());
                
                // Notify error on EDT for UI updates
                if (handler != null) {
                    javax.swing.SwingUtilities.invokeLater(() -> handler.onError(this, e));
                }
                
                throw new RuntimeException("MCP client connection failed", e);
            }
        });
    }
    
    /**
     * Disconnect from the MCP server
     */
    public CompletableFuture<Void> disconnect() {
        return CompletableFuture.runAsync(() -> {
            try {
                if (mcpClient != null) {
                    mcpClient.closeGracefully().block();
                    mcpClient = null;
                }
                
                initialized = false;
                discoveredTools.clear();
                
                // Notify handler on EDT for UI updates
                if (handler != null) {
                    javax.swing.SwingUtilities.invokeLater(() -> handler.onDisconnected(this));
                }
                
            } catch (Exception e) {
                Msg.error(this, "Error during disconnect: " + e.getMessage());
            }
        });
    }
    
    /**
     * Execute a tool call using the official SDK async client
     */
    public CompletableFuture<JsonElement> executeTool(String toolName, JsonObject arguments) {
        if (!initialized || mcpClient == null) {
            return CompletableFuture.failedFuture(
                new IllegalStateException("Client not initialized"));
        }
        
        // Convert JsonObject to the format expected by the SDK
        McpSchema.CallToolRequest toolCallRequest = new McpSchema.CallToolRequest(
            toolName, 
            convertJsonObjectToMap(arguments)
        );
        
        Msg.debug(this, "Executing tool: " + toolName + " on server: " + config.getName());
        
        // Use async client and convert Mono to CompletableFuture
        return mcpClient.callTool(toolCallRequest)
            .doOnSubscribe(subscription -> Msg.debug(this, "Starting tool execution: " + toolName + " on server: " + config.getName()))
            .doOnNext(result -> Msg.debug(this, "Received tool response: " + toolName))
            .map(result -> {
                Msg.debug(this, "Tool execution completed: " + toolName);
                // Convert result back to JsonElement for compatibility
                Gson gson = new Gson();
                return gson.fromJson(gson.toJson(result.content()), JsonElement.class);
            })
            .doOnError(e -> Msg.error(this, "Tool execution failed for " + toolName + ": " + e.getMessage()))
            .doOnCancel(() -> Msg.warn(this, "Tool execution cancelled: " + toolName))
            .onErrorMap(e -> new RuntimeException("Tool execution failed: " + e.getMessage(), e))
            .toFuture();
    }
    
    /**
     * Get all discovered tools
     */
    public List<MCPTool> getDiscoveredTools() {
        return new ArrayList<>(discoveredTools);
    }
    
    /**
     * Find tool by name
     */
    public MCPTool findTool(String toolName) {
        return discoveredTools.stream()
            .filter(tool -> tool.matchesName(toolName))
            .findFirst()
            .orElse(null);
    }
    
    /**
     * Check if client is connected and initialized
     */
    public boolean isReady() {
        return initialized && mcpClient != null;
    }
    
    /**
     * Get server configuration
     */
    public MCPServerConfig getServerConfig() {
        return config;
    }
    
    /**
     * Get connection status info
     */
    public String getStatusInfo() {
        if (!initialized) {
            return "Disconnected";
        } else {
            return String.format("Connected (%d tools)", discoveredTools.size());
        }
    }
    
    /**
     * Discover available tools using the official SDK
     */
    private CompletableFuture<Void> discoverTools() {
        return CompletableFuture.runAsync(() -> {
            try {
                McpSchema.ListToolsResult toolsResult = mcpClient.listTools().block();
                List<MCPTool> tools = new ArrayList<>();
                
                for (McpSchema.Tool tool : toolsResult.tools()) {
                    // Convert SDK tool to our MCPTool format
                    MCPTool mcpTool = new MCPTool();
                    mcpTool.setName(tool.name());
                    mcpTool.setDescription(tool.description());
                    mcpTool.setServerName(config.getName());
                    
                    // Convert input schema if present
                    if (tool.inputSchema() != null) {
                        Gson gson = new Gson();
                        JsonObject schema = gson.fromJson(gson.toJson(tool.inputSchema()), JsonObject.class);
                        mcpTool.setInputSchema(schema);
                    }
                    
                    tools.add(mcpTool);
                }
                
                discoveredTools = tools;
                Msg.info(this, String.format("Successfully discovered %d tools from %s using official SDK", 
                                            tools.size(), config.getName()));
                
                // Notify handler on EDT for UI updates
                if (handler != null) {
                    javax.swing.SwingUtilities.invokeLater(() -> 
                        handler.onToolsDiscovered(this, tools));
                }
                
            } catch (Exception e) {
                Msg.error(this, "Tool discovery failed with exception: " + e.getMessage());
                throw new RuntimeException("Tool discovery failed", e);
            }
        });
    }
    
    /**
     * Convert JsonObject to Map for SDK compatibility
     */
    private java.util.Map<String, Object> convertJsonObjectToMap(JsonObject jsonObject) {
        Gson gson = new Gson();
        java.lang.reflect.Type type = new com.google.gson.reflect.TypeToken<java.util.Map<String, Object>>(){}.getType();
        return gson.fromJson(jsonObject, type);
    }
}