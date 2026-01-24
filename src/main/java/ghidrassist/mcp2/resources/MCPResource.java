package ghidrassist.mcp2.resources;

/**
 * Data class representing an MCP resource.
 * Resources are data that can be read by clients from MCP servers.
 */
public class MCPResource {
    private final String uri;
    private final String name;
    private final String description;
    private final String mimeType;

    public MCPResource(String uri, String name, String description, String mimeType) {
        this.uri = uri;
        this.name = name;
        this.description = description;
        this.mimeType = mimeType;
    }

    public String getUri() {
        return uri;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public String getMimeType() {
        return mimeType;
    }

    @Override
    public String toString() {
        return String.format("MCPResource{uri='%s', name='%s', mimeType='%s'}", uri, name, mimeType);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        MCPResource that = (MCPResource) obj;
        return uri != null ? uri.equals(that.uri) : that.uri == null;
    }

    @Override
    public int hashCode() {
        return uri != null ? uri.hashCode() : 0;
    }
}
