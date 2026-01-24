package ghidrassist.mcp2.prompts;

/**
 * Data class representing an argument for an MCP prompt.
 */
public class MCPPromptArgument {
    private final String name;
    private final String description;
    private final Boolean required;

    public MCPPromptArgument(String name, String description, Boolean required) {
        this.name = name;
        this.description = description;
        this.required = required;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public Boolean isRequired() {
        return required != null ? required : false;
    }

    @Override
    public String toString() {
        return String.format("MCPPromptArgument{name='%s', required=%s}", name, required);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        MCPPromptArgument that = (MCPPromptArgument) obj;
        return name != null ? name.equals(that.name) : that.name == null;
    }

    @Override
    public int hashCode() {
        return name != null ? name.hashCode() : 0;
    }
}
