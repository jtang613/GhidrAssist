package ghidrassist.mcp2.transport;

import ghidrassist.mcp2.protocol.MCPRequest;
import ghidrassist.mcp2.protocol.MCPResponse;
import java.util.concurrent.CompletableFuture;

/**
 * Abstract transport layer for MCP communication.
 * Supports different transport mechanisms (SSE, stdio, etc.).
 */
public abstract class MCPTransport {
    
    protected boolean connected = false;
    protected MCPTransportHandler handler;
    
    /**
     * Interface for handling transport events
     */
    public interface MCPTransportHandler {
        void onConnected();
        void onDisconnected();
        void onResponse(MCPResponse response);
        void onError(Throwable error);
    }
    
    /**
     * Set the transport event handler
     */
    public void setHandler(MCPTransportHandler handler) {
        this.handler = handler;
    }
    
    /**
     * Connect to the MCP server
     */
    public abstract CompletableFuture<Void> connect();
    
    /**
     * Disconnect from the MCP server
     */
    public abstract CompletableFuture<Void> disconnect();
    
    /**
     * Send a request to the server
     */
    public abstract CompletableFuture<MCPResponse> sendRequest(MCPRequest request);
    
    /**
     * Send a notification to the server (no response expected)
     */
    public abstract CompletableFuture<Void> sendNotification(MCPRequest notification);
    
    /**
     * Check if transport is connected
     */
    public boolean isConnected() {
        return connected;
    }
    
    /**
     * Get transport type name
     */
    public abstract String getTransportType();
    
    /**
     * Get connection info for debugging
     */
    public abstract String getConnectionInfo();
    
    /**
     * Notify handler of connection
     */
    protected void notifyConnected() {
        connected = true;
        if (handler != null) {
            handler.onConnected();
        }
    }
    
    /**
     * Notify handler of disconnection
     */
    protected void notifyDisconnected() {
        connected = false;
        if (handler != null) {
            handler.onDisconnected();
        }
    }
    
    /**
     * Notify handler of response
     */
    protected void notifyResponse(MCPResponse response) {
        if (handler != null) {
            handler.onResponse(response);
        }
    }
    
    /**
     * Notify handler of error
     */
    protected void notifyError(Throwable error) {
        if (handler != null) {
            handler.onError(error);
        }
    }
}