package ghidrassist.mcp2.prompts;

import java.util.ArrayList;
import java.util.List;

/**
 * Data class representing an MCP prompt.
 * Prompts are templated messages that can be sent to LLMs with arguments.
 */
public class MCPPrompt {
    private final String name;
    private final String description;
    private final List<MCPPromptArgument> arguments;

    public MCPPrompt(String name, String description, List<MCPPromptArgument> arguments) {
        this.name = name;
        this.description = description;
        this.arguments = arguments != null ? new ArrayList<>(arguments) : new ArrayList<>();
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public List<MCPPromptArgument> getArguments() {
        return new ArrayList<>(arguments);
    }

    public boolean hasArguments() {
        return !arguments.isEmpty();
    }

    public List<MCPPromptArgument> getRequiredArguments() {
        List<MCPPromptArgument> required = new ArrayList<>();
        for (MCPPromptArgument arg : arguments) {
            if (arg.isRequired()) {
                required.add(arg);
            }
        }
        return required;
    }

    @Override
    public String toString() {
        return String.format("MCPPrompt{name='%s', args=%d}", name, arguments.size());
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        MCPPrompt that = (MCPPrompt) obj;
        return name != null ? name.equals(that.name) : that.name == null;
    }

    @Override
    public int hashCode() {
        return name != null ? name.hashCode() : 0;
    }
}
