package ghidrassist.mcp2.transport;

import ghidrassist.mcp2.protocol.MCPRequest;
import ghidrassist.mcp2.protocol.MCPResponse;
import ghidrassist.mcp2.server.MCPServerConfig;
import ghidra.util.Msg;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Server-Sent Events (SSE) transport for MCP communication.
 * Handles HTTP-based communication with MCP servers.
 */
public class SSETransport extends MCPTransport {
    
    private final MCPServerConfig config;
    private final AtomicLong requestIdCounter = new AtomicLong(1);
    private final ConcurrentHashMap<String, CompletableFuture<MCPResponse>> pendingRequests = new ConcurrentHashMap<>();
    
    private HttpURLConnection sseConnection;
    private Thread sseThread;
    private volatile boolean shouldStop = false;
    private volatile String sessionId = null;
    private BufferedReader sseReader = null;
    
    public SSETransport(MCPServerConfig config) {
        this.config = config;
    }
    
    @Override
    public CompletableFuture<Void> connect() {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // Test basic connectivity first
                if (!testConnection()) {
                    throw new RuntimeException("Failed to connect to MCP server at " + config.getUrl());
                }
                
                // Get session ID from SSE endpoint
                if (!obtainSessionId()) {
                    throw new RuntimeException("Failed to obtain session ID from GhidraMCP bridge at " + config.getUrl());
                }
                
                // Mark as connected
                connected = true;
                
                notifyConnected();
                Msg.info(this, "Connected to MCP server: " + config.getName());
                return null;
                
            } catch (Exception e) {
                notifyError(e);
                throw new RuntimeException("Failed to connect to MCP server", e);
            }
        });
    }
    
    @Override
    public CompletableFuture<Void> disconnect() {
        return CompletableFuture.runAsync(() -> {
            shouldStop = true;
            
            // Close SSE reader
            if (sseReader != null) {
                try {
                    sseReader.close();
                } catch (Exception e) {
                    Msg.debug(this, "Error closing SSE reader: " + e.getMessage());
                }
                sseReader = null;
            }
            
            // Close SSE connection
            if (sseConnection != null) {
                sseConnection.disconnect();
                sseConnection = null;
            }
            
            // Interrupt SSE thread
            if (sseThread != null && sseThread.isAlive()) {
                sseThread.interrupt();
                try {
                    sseThread.join(1000); // Wait up to 1 second for thread to finish
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                sseThread = null;
            }
            
            // Complete any pending requests with error
            pendingRequests.values().forEach(future -> 
                future.completeExceptionally(new RuntimeException("Connection closed")));
            pendingRequests.clear();
            
            // Reset state
            sessionId = null;
            connected = false;
            
            notifyDisconnected();
            Msg.info(this, "Disconnected from MCP server: " + config.getName());
        });
    }
    
    @Override
    public CompletableFuture<Void> sendNotification(MCPRequest notification) {
        if (!connected) {
            return CompletableFuture.failedFuture(
                new IllegalStateException("Not connected to MCP server"));
        }
        
        return CompletableFuture.runAsync(() -> {
            try {
                // Send HTTP POST request but don't wait for JSON-RPC response
                sendHttpNotification(notification);
                
            } catch (Exception e) {
                throw new RuntimeException("Failed to send MCP notification", e);
            }
        });
    }
    
    @Override
    public CompletableFuture<MCPResponse> sendRequest(MCPRequest request) {
        if (!connected) {
            return CompletableFuture.failedFuture(
                new IllegalStateException("Not connected to MCP server"));
        }
        
        return CompletableFuture.supplyAsync(() -> {
            try {
                // Send HTTP POST request
                String response = sendHttpRequest(request);
                
                // Parse response
                MCPResponse mcpResponse = MCPResponse.fromJson(response);
                
                // Handle response
                if (mcpResponse.isError()) {
                    throw new RuntimeException("MCP Error: " + mcpResponse.getError().toString());
                }
                
                return mcpResponse;
                
            } catch (Exception e) {
                throw new RuntimeException("Failed to send MCP request", e);
            }
        });
    }
    
    /**
     * Test basic connectivity to the server
     */
    private boolean testConnection() {
        try {
            // Test basic server connectivity
            URL url = new URL(config.getBaseUrl());
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(config.getConnectionTimeout() * 1000);
            conn.setReadTimeout(5000);
            
            int responseCode = conn.getResponseCode();
            conn.disconnect();
            
            // Any HTTP response means server is responding
            Msg.debug(this, "Server connectivity test: HTTP " + responseCode);
            return responseCode > 0;
            
        } catch (Exception e) {
            Msg.debug(this, "Connection test failed: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Test if server supports GhidraMCP bridge protocol
     */
    private boolean testMCPProtocol() {
        try {
            // Test the SSE endpoint (should respond to GET)
            URL sseUrl = new URL(config.getBaseUrl() + "/sse");
            HttpURLConnection sseConn = (HttpURLConnection) sseUrl.openConnection();
            sseConn.setRequestMethod("GET");
            sseConn.setRequestProperty("Accept", "text/event-stream");
            sseConn.setConnectTimeout(config.getConnectionTimeout() * 1000);
            sseConn.setReadTimeout(5000);
            
            int sseResponse = sseConn.getResponseCode();
            
            if (sseResponse != 200) {
                Msg.debug(this, "SSE endpoint test failed: HTTP " + sseResponse);
                sseConn.disconnect();
                return false;
            }
            
            // Try to extract a session ID from the SSE response
            String testSessionId = null;
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                    sseConn.getInputStream(), StandardCharsets.UTF_8))) {
                
                String line;
                int lineCount = 0;
                while ((line = reader.readLine()) != null && lineCount < 10) { // Read max 10 lines
                    lineCount++;
                    if (line.startsWith("data: /messages/?session_id=")) {
                        String endpoint = line.substring("data: ".length());
                        int sessionStart = endpoint.indexOf("session_id=") + "session_id=".length();
                        if (sessionStart > "session_id=".length() - 1) {
                            testSessionId = endpoint.substring(sessionStart);
                            break;
                        }
                    }
                }
            }
            sseConn.disconnect();
            
            boolean protocolSupported = (testSessionId != null);
            Msg.debug(this, "GhidraMCP protocol test - SSE: " + sseResponse + 
                     (protocolSupported ? " - Session ID obtained" : " - No session ID in response"));
            
            return protocolSupported;
            
        } catch (Exception e) {
            Msg.debug(this, "GhidraMCP protocol test failed: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Obtain session ID from SSE endpoint and keep connection alive
     */
    private boolean obtainSessionId() {
        try {
            URL sseUrl = new URL(config.getBaseUrl() + "/sse");
            sseConnection = (HttpURLConnection) sseUrl.openConnection();
            sseConnection.setRequestMethod("GET");
            sseConnection.setRequestProperty("Accept", "text/event-stream");
            sseConnection.setConnectTimeout(config.getConnectionTimeout() * 1000);
            sseConnection.setReadTimeout(0); // No timeout for SSE connection
            
            int responseCode = sseConnection.getResponseCode();
            if (responseCode != 200) {
                Msg.debug(this, "SSE endpoint failed: HTTP " + responseCode);
                return false;
            }
            
            // Create reader but keep connection alive
            sseReader = new BufferedReader(new InputStreamReader(
                    sseConnection.getInputStream(), StandardCharsets.UTF_8));
            
            // Start background thread to keep SSE connection alive and handle events
            startSSEReaderThread();
            
            // Wait a bit for the session ID to be received
            int maxWait = 2000; // 2 seconds - reduced from 5 seconds
            int waited = 0;
            while (sessionId == null && waited < maxWait) {
                try {
                    Thread.sleep(50); // 50ms intervals - reduced from 100ms
                    waited += 50;
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            
            return sessionId != null;
            
        } catch (Exception e) {
            Msg.debug(this, "Failed to obtain session ID: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Start background thread to read SSE events
     */
    private void startSSEReaderThread() {
        sseThread = new Thread(() -> {
            try {
                String line;
                while (!shouldStop && (line = sseReader.readLine()) != null) {
                    Msg.debug(this, "SSE line: " + line);
                    
                    // Look for endpoint data with session ID
                    if (line.startsWith("data: /messages/?session_id=")) {
                        String endpoint = line.substring("data: ".length());
                        // Extract session ID from endpoint
                        int sessionStart = endpoint.indexOf("session_id=") + "session_id=".length();
                        if (sessionStart > "session_id=".length() - 1) {
                            sessionId = endpoint.substring(sessionStart);
                            Msg.debug(this, "Extracted session ID: " + sessionId);
                        }
                    }
                    // Look for actual response data
                    else if (line.startsWith("data: ") && !line.equals("data: ")) {
                        String eventData = line.substring("data: ".length());
                        Msg.info(this, "Received SSE event data: " + eventData);
                        
                        // Try to parse as JSON response
                        try {
                            com.google.gson.JsonObject responseObj = new com.google.gson.Gson().fromJson(eventData, com.google.gson.JsonObject.class);
                            if (responseObj.has("jsonrpc") && responseObj.has("id")) {
                                String responseId = responseObj.get("id").getAsString();
                                Msg.info(this, "Received JSON-RPC response via SSE for ID: " + responseId);
                                
                                // Find and complete the pending request
                                CompletableFuture<MCPResponse> pendingRequest = pendingRequests.remove(responseId);
                                if (pendingRequest != null) {
                                    MCPResponse mcpResponse = MCPResponse.fromJson(eventData);
                                    pendingRequest.complete(mcpResponse);
                                    Msg.info(this, "Completed pending request for ID: " + responseId);
                                } else {
                                    Msg.warn(this, "No pending request found for response ID: " + responseId);
                                }
                            }
                        } catch (Exception e) {
                            Msg.debug(this, "SSE event data is not JSON-RPC: " + eventData);
                        }
                    }
                    
                    // Handle other SSE events as needed
                }
            } catch (Exception e) {
                if (!shouldStop) {
                    Msg.debug(this, "SSE reader thread error: " + e.getMessage());
                }
            }
        });
        sseThread.setDaemon(true);
        sseThread.setName("MCP-SSE-Reader");
        sseThread.start();
    }
    
    /**
     * Send MCP notification to GhidraMCP bridge (no response expected)
     */
    private void sendHttpNotification(MCPRequest notification) throws Exception {
        if (sessionId == null) {
            throw new RuntimeException("No session ID available - connection not properly established");
        }
        
        URL url = new URL(config.getBaseUrl() + "/messages/?session_id=" + sessionId);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        
        // Configure connection for JSON-RPC 2.0 over HTTP
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("Accept", "application/json");
        conn.setConnectTimeout(config.getConnectionTimeout() * 1000);
        conn.setReadTimeout(5000); // Short timeout for notifications
        conn.setDoOutput(true);
        
        // Send the MCP JSON-RPC 2.0 notification
        String jsonNotification = notification.toJson();
        Msg.info(this, "Sending MCP notification (" + notification.getMethod() + "): " + jsonNotification);
        
        try (OutputStreamWriter writer = new OutputStreamWriter(
                conn.getOutputStream(), StandardCharsets.UTF_8)) {
            writer.write(jsonNotification);
            writer.flush();
        }
        
        // Read HTTP response (should be just "Accepted") but don't wait for JSON-RPC response
        int responseCode = conn.getResponseCode();
        if (responseCode != 202 && responseCode != 200) {
            String errorMsg = "HTTP " + responseCode + ": " + conn.getResponseMessage();
            throw new RuntimeException(errorMsg);
        }
        
        StringBuilder httpResponse = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                conn.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                httpResponse.append(line);
            }
        }
        
        Msg.info(this, "HTTP response for notification: " + httpResponse.toString());
        // Note: We don't wait for any SSE response since notifications don't have responses
    }
    
    /**
     * Send MCP request to GhidraMCP bridge via SSE transport
     */
    private String sendHttpRequest(MCPRequest request) throws Exception {
        if (sessionId == null) {
            throw new RuntimeException("No session ID available - connection not properly established");
        }
        
        // Register pending request to wait for SSE response
        String requestId = request.getId().toString();
        CompletableFuture<MCPResponse> responseFeature = new CompletableFuture<>();
        pendingRequests.put(requestId, responseFeature);
        
        URL url = new URL(config.getBaseUrl() + "/messages/?session_id=" + sessionId);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        
        // Configure connection for JSON-RPC 2.0 over HTTP
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("Accept", "application/json");
        conn.setConnectTimeout(config.getConnectionTimeout() * 1000);
        conn.setReadTimeout(config.getRequestTimeout() * 1000);
        conn.setDoOutput(true);
        
        // Send the MCP JSON-RPC 2.0 request directly
        String jsonRequest = request.toJson();
        Msg.info(this, "Sending MCP request " + requestId + " (" + request.getMethod() + "): " + jsonRequest);
        
        try (OutputStreamWriter writer = new OutputStreamWriter(
                conn.getOutputStream(), StandardCharsets.UTF_8)) {
            writer.write(jsonRequest);
            writer.flush();
        }
        
        // Read HTTP response (should be just "Accepted")
        int responseCode = conn.getResponseCode();
        if (responseCode != 202 && responseCode != 200) {
            pendingRequests.remove(requestId); // Clean up on error
            String errorMsg = "HTTP " + responseCode + ": " + conn.getResponseMessage();
            throw new RuntimeException(errorMsg);
        }
        
        StringBuilder httpResponse = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                conn.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                httpResponse.append(line);
            }
        }
        
        Msg.info(this, "HTTP response for " + requestId + ": " + httpResponse.toString());
        
        // Wait for the actual response via SSE
        try {
            MCPResponse mcpResponse = responseFeature.get(config.getRequestTimeout(), java.util.concurrent.TimeUnit.SECONDS);
            return mcpResponse.toJson();
        } catch (java.util.concurrent.TimeoutException e) {
            pendingRequests.remove(requestId); // Clean up on timeout
            throw new RuntimeException("Timeout waiting for SSE response for request: " + requestId);
        } catch (Exception e) {
            pendingRequests.remove(requestId); // Clean up on error
            throw new RuntimeException("Error waiting for SSE response: " + e.getMessage());
        }
    }
    
    /**
     * Convert MCP request to proper JSON-RPC 2.0 format for the bridge
     */
    private String convertMCPRequestToBridgeFormat(MCPRequest request) {
        // The bridge expects proper MCP JSON-RPC 2.0 messages, not chat messages
        // Just return the original MCP request JSON
        return request.toJson();
    }
    
    /**
     * Convert GhidraMCP bridge response to MCP format
     */
    private String convertBridgeResponseToMCPFormat(String bridgeResponse, MCPRequest originalRequest) {
        // If the bridge response is already valid JSON-RPC 2.0, return it as-is
        try {
            com.google.gson.JsonObject responseObj = new com.google.gson.Gson().fromJson(bridgeResponse, com.google.gson.JsonObject.class);
            if (responseObj.has("jsonrpc") && responseObj.has("id")) {
                // Already a valid MCP response
                return bridgeResponse;
            }
        } catch (Exception e) {
            // Not valid JSON, need to convert
        }
        
        // Create a proper MCP response
        com.google.gson.JsonObject mcpResponse = new com.google.gson.JsonObject();
        mcpResponse.addProperty("jsonrpc", "2.0");
        
        // Handle ID properly - it could be string or number
        Object id = originalRequest.getId();
        if (id instanceof String) {
            mcpResponse.addProperty("id", (String) id);
        } else if (id instanceof Number) {
            mcpResponse.addProperty("id", (Number) id);
        } else {
            mcpResponse.addProperty("id", String.valueOf(id));
        }
        
        // Try to parse the bridge response as JSON
        try {
            com.google.gson.JsonElement responseData = new com.google.gson.Gson().fromJson(bridgeResponse, com.google.gson.JsonElement.class);
            mcpResponse.add("result", responseData);
        } catch (Exception e) {
            // If not valid JSON, wrap in a simple result
            com.google.gson.JsonObject result = new com.google.gson.JsonObject();
            result.addProperty("response", bridgeResponse);
            mcpResponse.add("result", result);
        }
        
        return new com.google.gson.Gson().toJson(mcpResponse);
    }
    
    @Override
    public String getTransportType() {
        return "SSE";
    }
    
    @Override
    public String getConnectionInfo() {
        return String.format("SSE transport to %s (timeout: %ds)", 
                           config.getUrl(), config.getConnectionTimeout());
    }
    
    /**
     * Generate unique request ID
     */
    private String generateRequestId() {
        return String.valueOf(requestIdCounter.getAndIncrement());
    }
}