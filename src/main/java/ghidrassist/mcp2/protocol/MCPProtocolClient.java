package ghidrassist.mcp2.protocol;

import ghidrassist.mcp2.server.MCPServerConfig;
import ghidrassist.mcp2.tools.MCPTool;
import ghidrassist.mcp2.transport.MCPTransport;
import ghidrassist.mcp2.transport.SSETransport;
import ghidra.util.Msg;

import com.google.gson.JsonObject;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicLong;

/**
 * High-level MCP protocol client that manages communication with an MCP server.
 * Handles initialization, tool discovery, and tool execution.
 */
public class MCPProtocolClient {
    
    private final MCPServerConfig config;
    private final MCPTransport transport;
    private final AtomicLong requestIdCounter = new AtomicLong(1);
    
    private boolean initialized = false;
    private List<MCPTool> discoveredTools = new ArrayList<>();
    private MCPClientHandler handler;
    
    /**
     * Interface for handling client events
     */
    public interface MCPClientHandler {
        void onConnected(MCPProtocolClient client);
        void onDisconnected(MCPProtocolClient client);
        void onToolsDiscovered(MCPProtocolClient client, List<MCPTool> tools);
        void onError(MCPProtocolClient client, Throwable error);
    }
    
    public MCPProtocolClient(MCPServerConfig config) {
        this.config = config;
        this.transport = createTransport(config);
        setupTransportHandler();
    }
    
    /**
     * Set client event handler
     */
    public void setHandler(MCPClientHandler handler) {
        this.handler = handler;
    }
    
    /**
     * Connect and initialize the MCP client
     * All operations run on background threads to avoid EDT blocking
     */
    public CompletableFuture<Void> connect() {
        return CompletableFuture.runAsync(() -> {
            try {
                // All operations happen off the EDT
                transport.connect().get();
                initialize().get();
                discoverTools().get();
                
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
                transport.disconnect().get();
                
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
     * Execute a tool call
     */
    public CompletableFuture<JsonElement> executeTool(String toolName, JsonObject arguments) {
        if (!initialized) {
            return CompletableFuture.failedFuture(
                new IllegalStateException("Client not initialized"));
        }
        
        // Find tool
        MCPTool tool = findTool(toolName);
        if (tool == null) {
            return CompletableFuture.failedFuture(
                new IllegalArgumentException("Tool not found: " + toolName));
        }
        
        // Create and send request
        MCPRequest request = MCPRequest.createToolsCallRequest(
            generateRequestId(), toolName, arguments);
        
        return transport.sendRequest(request)
            .thenApply(response -> {
                if (response.isError()) {
                    throw new RuntimeException("Tool execution failed: " + 
                                             response.getError().toString());
                }
                return response.getToolCallResult();
            });
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
        return transport.isConnected() && initialized;
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
        if (!transport.isConnected()) {
            return "Disconnected";
        } else if (!initialized) {
            return "Connecting...";
        } else {
            return String.format("Connected (%d tools)", discoveredTools.size());
        }
    }
    
    /**
     * Initialize the MCP protocol with proper handshake
     * This method runs on background threads to avoid EDT blocking
     */
    private CompletableFuture<Void> initialize() {
        return CompletableFuture.runAsync(() -> {
            try {
                // Step 1: Send initialize request
                MCPRequest initRequest = MCPRequest.createInitializeRequest(
                    generateRequestId(), "2024-11-05", "GhidrAssist MCP Client");
                
                MCPResponse initResponse = transport.sendRequest(initRequest).get();
                if (initResponse.isError()) {
                    throw new RuntimeException("Initialize failed: " + initResponse.getError());
                }
                
                Msg.info(this, "MCP initialize response received from: " + config.getName());
                
                // Step 2: Send initialized notification (no response expected)
                MCPRequest initializedNotification = MCPRequest.createInitializedNotification();
                
                // Send notification without waiting for JSON-RPC response
                try {
                    transport.sendNotification(initializedNotification).get();
                } catch (Exception e) {
                    // Even if notification "fails", we consider initialization complete
                    // as long as the initialize request succeeded
                    Msg.debug(this, "Initialized notification may have failed, but continuing: " + e.getMessage());
                }
                
                initialized = true;
                Msg.info(this, "MCP initialization handshake completed with: " + config.getName());
                
                // Add a small delay to ensure the server processes the notification
                Thread.sleep(100); // 100ms delay - reduced from 500ms
                Msg.info(this, "Initialization delay completed for: " + config.getName());
                
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException("MCP initialization was interrupted", e);
            } catch (Exception e) {
                throw new RuntimeException("MCP initialization failed", e);
            }
        });
    }
    
    /**
     * Discover available tools
     * This method runs on background threads to avoid EDT blocking
     */
    private CompletableFuture<Void> discoverTools() {
        return CompletableFuture.runAsync(() -> {
            try {
                MCPRequest toolsRequest = MCPRequest.createToolsListRequest(generateRequestId());
                
                MCPResponse response = transport.sendRequest(toolsRequest).get();
                
                if (response.isError()) {
                    Msg.error(this, "Tool discovery failed: " + response.getError().toString());
                    throw new RuntimeException("Tool discovery failed: " + 
                                             response.getError().toString());
                }
                
                // Parse tools from response
                JsonArray toolsArray = response.getToolsArray();
                
                List<MCPTool> tools = new ArrayList<>();
                
                for (JsonElement toolElement : toolsArray) {
                    if (toolElement.isJsonObject()) {
                        MCPTool tool = MCPTool.fromToolsListEntry(
                            toolElement.getAsJsonObject(), config.getName());
                        if (tool.getName() != null) {
                            tools.add(tool);
                        }
                    }
                }
                
                discoveredTools = tools;
                Msg.info(this, String.format("Successfully discovered %d tools from %s", 
                                            tools.size(), config.getName()));
                
                // Notify handler on EDT for UI updates
                if (handler != null) {
                    javax.swing.SwingUtilities.invokeLater(() -> 
                        handler.onToolsDiscovered(this, tools));
                } else {
                    Msg.warn(this, "No handler set for tool discovery notifications");
                }
                
            } catch (Exception e) {
                Msg.error(this, "Tool discovery failed with exception: " + e.getMessage());
                throw new RuntimeException("Tool discovery failed", e);
            }
        });
    }
    
    /**
     * Create appropriate transport for the server config
     */
    private MCPTransport createTransport(MCPServerConfig config) {
        switch (config.getTransport()) {
            case SSE:
                return new SSETransport(config);
            case STDIO:
                // TODO: Implement stdio transport
                throw new UnsupportedOperationException("Stdio transport not yet implemented");
            default:
                throw new IllegalArgumentException("Unsupported transport: " + config.getTransport());
        }
    }
    
    /**
     * Setup transport event handling
     */
    private void setupTransportHandler() {
        transport.setHandler(new MCPTransport.MCPTransportHandler() {
            @Override
            public void onConnected() {
                Msg.debug(MCPProtocolClient.this, "Transport connected");
            }
            
            @Override
            public void onDisconnected() {
                Msg.debug(MCPProtocolClient.this, "Transport disconnected");
                initialized = false;
            }
            
            @Override
            public void onResponse(MCPResponse response) {
                Msg.debug(MCPProtocolClient.this, "Received response: " + response.getId());
            }
            
            @Override
            public void onError(Throwable error) {
                Msg.error(MCPProtocolClient.this, "Transport error: " + error.getMessage());
                if (handler != null) {
                    handler.onError(MCPProtocolClient.this, error);
                }
            }
        });
    }
    
    /**
     * Generate unique request ID
     */
    private String generateRequestId() {
        return config.getName() + "_" + requestIdCounter.getAndIncrement();
    }
}