package ghidrassist.mcp2.tools;

import ghidrassist.mcp2.protocol.MCPClientAdapter;
import ghidrassist.mcp2.server.MCPServerConfig;
import ghidrassist.mcp2.server.MCPServerRegistry;
import ghidrassist.tools.api.Tool;
import ghidrassist.tools.api.ToolProvider;
import ghidrassist.tools.api.ToolResult;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * Manages MCP tools from multiple servers.
 * Handles tool discovery, aggregation, and execution routing.
 *
 * NOTE: This class now implements ToolProvider and handles ONLY MCP server tools.
 * Native/internal tools (semantic, actions) are now handled by NativeToolManager.
 */
public class MCPToolManager implements ToolProvider {

    private static final String PROVIDER_NAME = "MCP";
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

    // ==================== ToolProvider Interface Implementation ====================

    @Override
    public String getProviderName() {
        return PROVIDER_NAME;
    }

    @Override
    public List<Tool> getTools() {
        // Create adapters with the prefixed names (keys from allTools map)
        return allTools.entrySet().stream()
                .map(entry -> new MCPToolAdapter(entry.getValue(), entry.getKey()))
                .collect(Collectors.toList());
    }

    @Override
    public CompletableFuture<ToolResult> executeTool(String name, JsonObject args) {
        MCPTool tool = findTool(name);
        if (tool == null) {
            return CompletableFuture.completedFuture(
                    ToolResult.error("MCP tool not found: " + name));
        }

        MCPClientAdapter client = clients.get(tool.getServerName());
        if (client == null || !client.isReady()) {
            return CompletableFuture.completedFuture(
                    ToolResult.error("MCP server not available: " + tool.getServerName()));
        }

        // Use the original tool name (without server prefix) when calling the MCP server
        String originalToolName = tool.getName();
        Msg.debug(this, "Executing MCP tool: " + name + " (original: " + originalToolName + ") via server: " + tool.getServerName());
        return client.executeTool(originalToolName, args)
                .thenApply(result -> {
                    String content = result != null ? result.toString() : "";
                    return ToolResult.success(content);
                })
                .exceptionally(throwable -> {
                    Msg.error(this, "MCP tool execution failed: " + throwable.getMessage());
                    return ToolResult.error(throwable.getMessage());
                });
    }

    @Override
    public boolean handlesTool(String name) {
        return findTool(name) != null;
    }

    @Override
    public void setContext(Program program) {
        // MCP tools don't need Ghidra program context
        // This is a no-op for MCPToolManager
    }

    // ==================== Internal MCP Tool Execution ====================

    /**
     * Execute an MCP tool and return MCPToolResult.
     * Internal method used by parallel execution. External callers should use
     * executeTool(String, JsonObject) from the ToolProvider interface.
     */
    private CompletableFuture<MCPToolResult> executeToolMCP(String toolName, JsonObject arguments) {
        MCPTool tool = findTool(toolName);
        if (tool == null) {
            return CompletableFuture.completedFuture(
                MCPToolResult.error("Tool not found: " + toolName));
        }

        MCPClientAdapter client = clients.get(tool.getServerName());
        if (client == null || !client.isReady()) {
            return CompletableFuture.completedFuture(
                MCPToolResult.error("Server not available: " + tool.getServerName()));
        }

        // Use the original tool name (without server prefix) when calling the MCP server
        String originalToolName = tool.getName();
        Msg.debug(this, "MCPToolManager delegating to client: " + tool.getServerName() + " for tool: " + originalToolName);
        return client.executeTool(originalToolName, arguments)
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
    
    // ==================== MCP Server Connection Management ====================

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
    
    // ==================== Parallel Tool Execution ====================

    /**
     * Execute multiple tools in parallel for better performance.
     * Implements BinAssist parity with max 3 concurrent tool executions.
     *
     * @param toolCalls List of tool calls to execute
     * @param maxConcurrent Maximum number of concurrent executions (default: 3)
     * @return CompletableFuture with list of results in original order
     */
    public CompletableFuture<List<MCPToolResult>> executeToolsParallel(
        List<ToolCallRequest> toolCalls,
        int maxConcurrent
    ) {
        if (toolCalls == null || toolCalls.isEmpty()) {
            return CompletableFuture.completedFuture(new ArrayList<>());
        }

        // Track original order
        Map<String, Integer> originalOrder = new HashMap<>();
        for (int i = 0; i < toolCalls.size(); i++) {
            originalOrder.put(toolCalls.get(i).getCallId(), i);
        }

        ExecutorService executor = Executors.newFixedThreadPool(Math.min(maxConcurrent, toolCalls.size()));
        List<CompletableFuture<ToolCallResult>> futures = new ArrayList<>();

        try {
            // Submit all tool calls
            for (ToolCallRequest toolCall : toolCalls) {
                CompletableFuture<ToolCallResult> future = CompletableFuture.supplyAsync(() -> {
                    try {
                        // Execute tool and get MCPToolResult
                        MCPToolResult result = executeToolMCP(toolCall.getToolName(), toolCall.getArguments())
                            .orTimeout(30, TimeUnit.SECONDS)
                            .get();

                        return new ToolCallResult(toolCall.getCallId(), result);

                    } catch (java.util.concurrent.ExecutionException e) {
                        // Check if it's a timeout
                        if (e.getCause() instanceof java.util.concurrent.TimeoutException) {
                            Msg.warn(this, String.format("Tool '%s' timed out after 30 seconds", toolCall.getToolName()));
                            return new ToolCallResult(
                                toolCall.getCallId(),
                                MCPToolResult.error("Tool execution timeout after 30 seconds")
                            );
                        } else {
                            Msg.error(this, String.format("Tool '%s' failed: %s", toolCall.getToolName(), e.getCause().getMessage()));
                            return new ToolCallResult(
                                toolCall.getCallId(),
                                MCPToolResult.error(e.getCause().getMessage())
                            );
                        }
                    } catch (Exception e) {
                        Msg.error(this, String.format("Tool '%s' failed: %s", toolCall.getToolName(), e.getMessage()));
                        return new ToolCallResult(
                            toolCall.getCallId(),
                            MCPToolResult.error(e.getMessage())
                        );
                    }
                }, executor);

                futures.add(future);
            }

            // Wait for all to complete
            return CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                .thenApply(v -> {
                    // Collect results
                    List<ToolCallResult> results = futures.stream()
                        .map(CompletableFuture::join)
                        .collect(Collectors.toList());

                    // Reorder to match original sequence
                    results.sort((a, b) -> {
                        int orderA = originalOrder.getOrDefault(a.getCallId(), Integer.MAX_VALUE);
                        int orderB = originalOrder.getOrDefault(b.getCallId(), Integer.MAX_VALUE);
                        return Integer.compare(orderA, orderB);
                    });

                    Msg.debug(this, String.format("Parallel execution complete: %d tools", results.size()));

                    // Extract MCPToolResults in correct order
                    return results.stream()
                        .map(ToolCallResult::getResult)
                        .collect(Collectors.toList());
                })
                .whenComplete((results, throwable) -> {
                    executor.shutdown();
                });

        } catch (Exception e) {
            executor.shutdown();
            return CompletableFuture.failedFuture(e);
        }
    }

    /**
     * Execute multiple tools in parallel with default concurrency (3).
     */
    public CompletableFuture<List<MCPToolResult>> executeToolsParallel(List<ToolCallRequest> toolCalls) {
        return executeToolsParallel(toolCalls, 3);
    }

    // ========== Helper Classes for Parallel Execution ==========

    /**
     * Represents a tool call request with tracking ID.
     */
    public static class ToolCallRequest {
        private final String callId;
        private final String toolName;
        private final JsonObject arguments;

        public ToolCallRequest(String callId, String toolName, JsonObject arguments) {
            this.callId = callId;
            this.toolName = toolName;
            this.arguments = arguments;
        }

        public String getCallId() {
            return callId;
        }

        public String getToolName() {
            return toolName;
        }

        public JsonObject getArguments() {
            return arguments;
        }
    }

    /**
     * Represents a completed tool call with result.
     */
    private static class ToolCallResult {
        private final String callId;
        private final MCPToolResult result;

        public ToolCallResult(String callId, MCPToolResult result) {
            this.callId = callId;
            this.result = result;
        }

        public String getCallId() {
            return callId;
        }

        public MCPToolResult getResult() {
            return result;
        }
    }

    // ==================== Tool Access Methods ====================

    /**
     * Get all available MCP tools from all connected servers.
     * NOTE: Native tools are now accessed via NativeToolManager.
     */
    public List<MCPTool> getAllMCPTools() {
        return new ArrayList<>(allTools.values());
    }

    /**
     * Get MCP tools as function schemas for LLM function calling.
     * Tool names in the schema are prefixed with server name.
     * NOTE: Native tools should be obtained from NativeToolManager via ToolRegistry.
     */
    public List<Map<String, Object>> getToolsAsFunction() {
        return allTools.entrySet().stream()
            .map(entry -> {
                // Create schema with prefixed name
                Map<String, Object> schema = entry.getValue().toFunctionSchema();
                schema.put("name", entry.getKey()); // Override with prefixed name
                return schema;
            })
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
            handler.onToolsUpdated(getAllMCPTools());
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
            // Remove tools from this server (keys are prefixed with serverName.toLowerCase()_)
            String prefix = serverName.toLowerCase() + "_";
            allTools.entrySet().removeIf(entry -> entry.getKey().startsWith(prefix));

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
            // Add tools from this server with server name prefix
            String prefix = serverName.toLowerCase() + "_";
            for (MCPTool tool : tools) {
                // Create prefixed name for storage and lookup
                String prefixedName = prefix + tool.getName().toLowerCase();
                // Store with prefixed name, but keep original tool reference
                allTools.put(prefixedName, tool);
                Msg.debug(MCPToolManager.this, "Registered MCP tool: " + prefixedName);
            }

            // Notify on EDT for UI updates
            javax.swing.SwingUtilities.invokeLater(() -> notifyToolsUpdated());
        }

        @Override
        public void onResourcesDiscovered(MCPClientAdapter client, java.util.List<ghidrassist.mcp2.resources.MCPResource> resources) {
            // Resources are discovered but not actively managed yet
            // Future enhancement: could add resource management similar to tools
            Msg.debug(MCPToolManager.this, "Discovered " + resources.size() + " resources from " + serverName);
        }

        @Override
        public void onPromptsDiscovered(MCPClientAdapter client, java.util.List<ghidrassist.mcp2.prompts.MCPPrompt> prompts) {
            // Prompts are discovered but not actively managed yet
            // Future enhancement: could add prompt management similar to tools
            Msg.debug(MCPToolManager.this, "Discovered " + prompts.size() + " prompts from " + serverName);
        }

        @Override
        public void onError(MCPClientAdapter client, Throwable error) {
            if (handler != null) {
                handler.onServerError(serverName, error);
            }
        }
    }
}