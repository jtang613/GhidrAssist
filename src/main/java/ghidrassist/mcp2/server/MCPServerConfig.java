package ghidrassist.mcp2.server;

import com.google.gson.Gson;

/**
 * Configuration for an MCP server connection.
 * Stores all necessary information to connect to and manage an MCP server.
 */
public class MCPServerConfig {
    
    public enum TransportType {
        SSE("Server-Sent Events"),
        STDIO("Standard I/O");
        
        private final String displayName;
        
        TransportType(String displayName) {
            this.displayName = displayName;
        }
        
        public String getDisplayName() {
            return displayName;
        }
    }
    
    private String name;                    // Display name (e.g., "GhidraMCP Local")
    private String url;                     // Server URL (e.g., "http://localhost:8081")
    private TransportType transport;        // Transport mechanism
    private int connectionTimeout;          // Connection timeout in seconds
    private int requestTimeout;            // Request timeout in seconds
    private boolean enabled;               // Whether this server is active
    private String description;            // Optional description
    
    // Default constructor for JSON deserialization
    public MCPServerConfig() {
        this.transport = TransportType.SSE;
        this.connectionTimeout = 15;
        this.requestTimeout = 30;
        this.enabled = true;
    }
    
    public MCPServerConfig(String name, String url) {
        this();
        this.name = name;
        this.url = url;
    }
    
    public MCPServerConfig(String name, String url, TransportType transport) {
        this(name, url);
        this.transport = transport;
    }
    
    public MCPServerConfig(String name, String url, TransportType transport, boolean enabled) {
        this(name, url, transport);
        this.enabled = enabled;
    }
    
    // Getters and setters
    
    public String getName() {
        return name;
    }
    
    public void setName(String name) {
        this.name = name;
    }
    
    public String getUrl() {
        return url;
    }
    
    public void setUrl(String url) {
        this.url = url;
    }
    
    public TransportType getTransport() {
        return transport;
    }
    
    public void setTransport(TransportType transport) {
        this.transport = transport;
    }
    
    public int getConnectionTimeout() {
        return connectionTimeout;
    }
    
    public void setConnectionTimeout(int connectionTimeout) {
        this.connectionTimeout = connectionTimeout;
    }
    
    public int getRequestTimeout() {
        return requestTimeout;
    }
    
    public void setRequestTimeout(int requestTimeout) {
        this.requestTimeout = requestTimeout;
    }
    
    public boolean isEnabled() {
        return enabled;
    }
    
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    
    public String getDescription() {
        return description;
    }
    
    public void setDescription(String description) {
        this.description = description;
    }
    
    /**
     * Get the base URL for HTTP connections
     */
    public String getBaseUrl() {
        if (url == null) return null;
        
        // Ensure URL has protocol
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            return "http://" + url;
        }
        return url;
    }
    
    /**
     * Get the host from the URL
     */
    public String getHost() {
        try {
            java.net.URL urlObj = new java.net.URL(getBaseUrl());
            return urlObj.getHost();
        } catch (Exception e) {
            return "localhost";
        }
    }
    
    /**
     * Get the port from the URL
     */
    public int getPort() {
        try {
            java.net.URL urlObj = new java.net.URL(getBaseUrl());
            int port = urlObj.getPort();
            return port != -1 ? port : (urlObj.getProtocol().equals("https") ? 443 : 80);
        } catch (Exception e) {
            return 8081; // Default MCP port
        }
    }
    
    /**
     * Validate configuration
     */
    public boolean isValid() {
        return name != null && !name.trim().isEmpty() &&
               url != null && !url.trim().isEmpty() &&
               transport != null &&
               connectionTimeout > 0 &&
               requestTimeout > 0;
    }
    
    /**
     * Create a copy of this configuration
     */
    public MCPServerConfig copy() {
        MCPServerConfig copy = new MCPServerConfig(name, url, transport);
        copy.setConnectionTimeout(connectionTimeout);
        copy.setRequestTimeout(requestTimeout);
        copy.setEnabled(enabled);
        copy.setDescription(description);
        return copy;
    }
    
    /**
     * Serialize to JSON
     */
    public String toJson() {
        return new Gson().toJson(this);
    }
    
    /**
     * Deserialize from JSON
     */
    public static MCPServerConfig fromJson(String json) {
        return new Gson().fromJson(json, MCPServerConfig.class);
    }
    
    @Override
    public String toString() {
        return String.format("%s (%s) - %s", name, transport.getDisplayName(), 
                           enabled ? "Enabled" : "Disabled");
    }
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        
        MCPServerConfig that = (MCPServerConfig) obj;
        return name != null ? name.equals(that.name) : that.name == null;
    }
    
    @Override
    public int hashCode() {
        return name != null ? name.hashCode() : 0;
    }
    
    /**
     * Create default MCP configuration
     */
    public static MCPServerConfig createGhidrAssistMCPDefault() {
        MCPServerConfig config = new MCPServerConfig("GhidrAssistMCP Local", "http://localhost:8081");
        config.setDescription("Local GhidrAssistMCP server instance");
        config.setTransport(TransportType.SSE);
        return config;
    }
}