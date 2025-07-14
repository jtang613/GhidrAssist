package ghidrassist.mcp2.tools;

import ghidrassist.mcp2.protocol.MCPClientAdapter;
import ghidrassist.mcp2.server.MCPServerConfig;
import ghidrassist.mcp2.server.MCPServerRegistry;
import ghidra.program.model.listing.Program;
import ghidra.framework.model.DomainObject;
import ghidra.util.Msg;

import com.google.gson.JsonObject;
import com.google.gson.JsonElement;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Manages MCP tools from multiple servers.
 * Handles tool discovery, aggregation, and execution routing.
 */
public class MCPToolManager {
    
    private static MCPToolManager instance;
    
    private final Map<String, MCPClientAdapter> clients = new ConcurrentHashMap<>();
    private final Map<String, MCPTool> allTools = new ConcurrentHashMap<>();
    private MCPToolManagerHandler handler;
    private volatile boolean initialized = false;
    
    /**
     * Interface for handling tool manager events
     */
    public interface MCPToolManagerHandler {
        void onToolsUpdated(List<MCPTool> allTools);
        void onServerConnected(String serverName);
        void onServerDisconnected(String serverName);
        void onServerError(String serverName, Throwable error);
    }
    
    private MCPToolManager() {
        // Private constructor for singleton
    }
    
    /**
     * Get singleton instance
     */
    public static synchronized MCPToolManager getInstance() {
        if (instance == null) {
            instance = new MCPToolManager();
        }
        return instance;
    }
    
    /**
     * Set event handler
     */
    public void setHandler(MCPToolManagerHandler handler) {
        this.handler = handler;
    }
    
    /**
     * Initialize connections to all enabled servers
     * This method is safe to call from any thread including the EDT
     */
    public CompletableFuture<Void> initializeServers() {
        return CompletableFuture.runAsync(() -> {
            // Ensure all work happens off the EDT
            List<MCPServerConfig> enabledServers = MCPServerRegistry.getInstance().getEnabledServers();
            Msg.info(this, String.format("Starting initialization of %d enabled MCP servers", enabledServers.size()));
            
            List<CompletableFuture<Void>> connectionFutures = new ArrayList<>();
            
            for (MCPServerConfig config : enabledServers) {
                Msg.info(this, "Starting connection to server: " + config.getName());
                CompletableFuture<Void> connectionFuture = connectToServer(config);
                connectionFutures.add(connectionFuture);
            }
            
            try {
                // Wait for all connections to complete
                CompletableFuture.allOf(connectionFutures.toArray(new CompletableFuture[0])).get();
                
                initialized = true;
                Msg.info(this, String.format("Initialized %d MCP servers", clients.size()));
                
                // Notify on EDT for UI updates
                javax.swing.SwingUtilities.invokeLater(() -> notifyToolsUpdated());
                
            } catch (Exception e) {
                Msg.error(this, "Failed to initialize MCP servers: " + e.getMessage());
                throw new RuntimeException("MCP server initialization failed", e);
            }
        });
    }
    
    /**
     * Connect to a specific server
     * This method runs all network operations on background threads
     */
    public CompletableFuture<Void> connectToServer(MCPServerConfig config) {
        if (!config.isEnabled()) {
            return CompletableFuture.completedFuture(null);
        }
        
        return CompletableFuture.runAsync(() -> {
            MCPClientAdapter client = new MCPClientAdapter(config);
            client.setHandler(new ClientHandler(config.getName()));
            
            try {
                // Connect and wait for completion off the EDT
                client.connect().get();
                clients.put(config.getName(), client);
                Msg.info(this, "Connected to MCP server: " + config.getName());
            } catch (Exception e) {
                Msg.error(this, "Failed to connect to " + config.getName() + ": " + e.getMessage());
                throw new RuntimeException("Failed to connect to " + config.getName(), e);
            }
        });
    }
    
    /**
     * Disconnect from a specific server
     */
    public CompletableFuture<Void> disconnectFromServer(String serverName) {
        return CompletableFuture.runAsync(() -> {
            MCPClientAdapter client = clients.remove(serverName);
            if (client != null) {
                try {
                    // Disconnect and wait for completion
                    client.disconnect().get();
                    
                    // Remove tools from this server
                    allTools.entrySet().removeIf(entry -> 
                        entry.getValue().getServerName().equals(serverName));
                    
                    // Notify on EDT for UI updates
                    javax.swing.SwingUtilities.invokeLater(() -> notifyToolsUpdated());
                    
                } catch (Exception e) {
                    Msg.error(this, "Error disconnecting from " + serverName + ": " + e.getMessage());
                }
            }
        });
    }
    
    /**
     * Disconnect from all servers
     */
    public CompletableFuture<Void> disconnectAll() {
        return CompletableFuture.runAsync(() -> {
            List<CompletableFuture<Void>> disconnectFutures = new ArrayList<>();
            
            for (String serverName : new ArrayList<>(clients.keySet())) {
                disconnectFutures.add(disconnectFromServer(serverName));
            }
            
            try {
                // Wait for all disconnections to complete
                CompletableFuture.allOf(disconnectFutures.toArray(new CompletableFuture[0])).get();
                
                clients.clear();
                allTools.clear();
                
                // Notify on EDT for UI updates
                javax.swing.SwingUtilities.invokeLater(() -> notifyToolsUpdated());
                
                Msg.info(this, "Disconnected from all MCP servers");
                
            } catch (Exception e) {
                Msg.error(this, "Error disconnecting from servers: " + e.getMessage());
            }
        });
    }
    
    /**
     * Execute a tool call
     */
    public CompletableFuture<MCPToolResult> executeTool(String toolName, JsonObject arguments) {
        MCPTool tool = findTool(toolName);
        if (tool == null) {
            return CompletableFuture.failedFuture(
                new IllegalArgumentException("Tool not found: " + toolName));
        }
        
        MCPClientAdapter client = clients.get(tool.getServerName());
        if (client == null || !client.isReady()) {
            return CompletableFuture.failedFuture(
                new IllegalStateException("Server not available: " + tool.getServerName()));
        }
        
        Msg.debug(this, "MCPToolManager delegating to client: " + tool.getServerName() + " for tool: " + toolName);
        return client.executeTool(toolName, arguments)
            .thenApply(result -> {
                Msg.debug(this, "MCPToolManager received result for tool: " + toolName);
                String content = result != null ? result.toString() : "";
                return MCPToolResult.success(content);
            })
            .exceptionally(throwable -> {
                Msg.error(this, "MCPToolManager caught exception for tool " + toolName + ": " + throwable.getMessage());
                return MCPToolResult.error(throwable.getMessage());
            });
    }
    
    /**
     * Get all available tools from all servers
     */
    public List<MCPTool> getAllTools() {
        return new ArrayList<>(allTools.values());
    }
    
    /**
     * Get tools as function schemas for LLM function calling
     */
    public List<Map<String, Object>> getToolsAsFunction() {
        return allTools.values().stream()
            .map(MCPTool::toFunctionSchema)
            .collect(Collectors.toList());
    }
    
    /**
     * Find tool by name
     */
    public MCPTool findTool(String toolName) {
        return allTools.get(toolName.toLowerCase());
    }
    
    /**
     * Check if the tool manager has been initialized
     */
    public boolean isInitialized() {
        return initialized;
    }
    
    /**
     * Check if any servers are connected
     */
    public boolean hasConnectedServers() {
        return clients.values().stream().anyMatch(MCPClientAdapter::isReady);
    }
    
    /**
     * Get status info for all servers
     */
    public String getStatusInfo() {
        if (clients.isEmpty()) {
            return "No MCP servers configured";
        }
        
        long connectedCount = clients.values().stream()
            .filter(MCPClientAdapter::isReady)
            .count();
        
        return String.format("%d/%d servers connected (%d tools)", 
                           connectedCount, clients.size(), allTools.size());
    }
    
    /**
     * Get connected servers info
     */
    public List<String> getConnectedServers() {
        return clients.entrySet().stream()
            .filter(entry -> entry.getValue().isReady())
            .map(Map.Entry::getKey)
            .collect(Collectors.toList());
    }
    
    /**
     * Refresh connections to all servers
     */
    public CompletableFuture<Void> refreshConnections() {
        return CompletableFuture.runAsync(() -> {
            try {
                // Disconnect all servers first
                disconnectAll().get();
                
                // Then reinitialize
                initializeServers().get();
                
            } catch (Exception e) {
                Msg.error(this, "Error refreshing MCP connections: " + e.getMessage());
                throw new RuntimeException("Failed to refresh MCP connections", e);
            }
        });
    }
    
    /**
     * Notify handler of tools update
     */
    private void notifyToolsUpdated() {
        if (handler != null) {
            handler.onToolsUpdated(getAllTools());
        }
    }
    
    /**
     * Client event handler
     */
    private class ClientHandler implements MCPClientAdapter.MCPClientHandler {
        private final String serverName;
        
        public ClientHandler(String serverName) {
            this.serverName = serverName;
        }
        
        @Override
        public void onConnected(MCPClientAdapter client) {
            if (handler != null) {
                handler.onServerConnected(serverName);
            }
        }
        
        @Override
        public void onDisconnected(MCPClientAdapter client) {
            // Remove tools from this server
            allTools.entrySet().removeIf(entry -> 
                entry.getValue().getServerName().equals(serverName));
            
            // Notify on EDT for UI updates
            javax.swing.SwingUtilities.invokeLater(() -> {
                notifyToolsUpdated();
                
                if (handler != null) {
                    handler.onServerDisconnected(serverName);
                }
            });
        }
        
        @Override
        public void onToolsDiscovered(MCPClientAdapter client, List<MCPTool> tools) {
            
            // Add tools from this server
            for (MCPTool tool : tools) {
                allTools.put(tool.getName().toLowerCase(), tool);
            }
            
            // Notify on EDT for UI updates
            javax.swing.SwingUtilities.invokeLater(() -> notifyToolsUpdated());
        }
        
        @Override
        public void onError(MCPClientAdapter client, Throwable error) {
            if (handler != null) {
                handler.onServerError(serverName, error);
            }
        }
    }
}