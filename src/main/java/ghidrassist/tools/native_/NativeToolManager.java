package ghidrassist.tools.native_;

import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidrassist.AnalysisDB;
import ghidrassist.tools.api.Tool;
import ghidrassist.tools.api.ToolProvider;
import ghidrassist.tools.api.ToolResult;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

/**
 * Manager for all native (internal) tool providers.
 * This is the central point for tools that are built into GhidrAssist,
 * as opposed to tools from external MCP servers.
 *
 * Native tools include:
 * - Ghidra context tools (get_current_function, get_current_address)
 * - Semantic query tools (Graph-RAG)
 * - Action tools (rename, retype, etc.)
 */
public class NativeToolManager implements ToolProvider {

    private static final String PROVIDER_NAME = "native";

    private final List<ToolProvider> nativeProviders = new ArrayList<>();
    private final GhidraToolProvider ghidraToolProvider;
    private final ActionToolProvider actionToolProvider;
    private Program currentProgram;
    private Address currentAddress;

    /**
     * Create a NativeToolManager with the given AnalysisDB.
     * @param analysisDB Database for semantic tools
     */
    public NativeToolManager(AnalysisDB analysisDB) {
        // Create providers that need address context
        this.ghidraToolProvider = new GhidraToolProvider();
        this.actionToolProvider = new ActionToolProvider();

        // Register native tool providers
        nativeProviders.add(ghidraToolProvider);
        nativeProviders.add(new SemanticToolProvider(analysisDB));
        nativeProviders.add(actionToolProvider);

        Msg.info(this, "NativeToolManager initialized with " + nativeProviders.size() + " providers");
    }

    @Override
    public String getProviderName() {
        return PROVIDER_NAME;
    }

    @Override
    public List<Tool> getTools() {
        return nativeProviders.stream()
                .flatMap(p -> p.getTools().stream())
                .collect(Collectors.toList());
    }

    @Override
    public CompletableFuture<ToolResult> executeTool(String name, JsonObject args) {
        for (ToolProvider provider : nativeProviders) {
            if (provider.handlesTool(name)) {
                Msg.debug(this, "Executing native tool '" + name + "' via " + provider.getProviderName());
                return provider.executeTool(name, args);
            }
        }
        return CompletableFuture.completedFuture(
                ToolResult.error("Native tool not found: " + name));
    }

    @Override
    public boolean handlesTool(String name) {
        return nativeProviders.stream().anyMatch(p -> p.handlesTool(name));
    }

    @Override
    public void setContext(Program program) {
        this.currentProgram = program;
        for (ToolProvider provider : nativeProviders) {
            provider.setContext(program);
        }
        // Also propagate address context to providers that need it
        if (currentAddress != null) {
            ghidraToolProvider.setAddress(currentAddress);
            actionToolProvider.setAddress(currentAddress);
        }
        Msg.debug(this, "Updated program context for " + nativeProviders.size() + " native providers");
    }

    /**
     * Set the current address context for tools that need it.
     * @param address Current cursor address in Ghidra
     */
    public void setAddress(Address address) {
        this.currentAddress = address;
        ghidraToolProvider.setAddress(address);
        actionToolProvider.setAddress(address);
        Msg.debug(this, "Updated address context: " + (address != null ? address.toString() : "null"));
    }

    /**
     * Set both program and address context.
     * @param program Current program
     * @param address Current cursor address
     */
    public void setFullContext(Program program, Address address) {
        this.currentProgram = program;
        this.currentAddress = address;
        for (ToolProvider provider : nativeProviders) {
            provider.setContext(program);
        }
        ghidraToolProvider.setContext(program, address);
        actionToolProvider.setContext(program, address);
        Msg.debug(this, "Updated full context: program=" +
                (program != null ? program.getName() : "null") +
                ", address=" + (address != null ? address.toString() : "null"));
    }

    /**
     * Get the current program context.
     */
    public Program getCurrentProgram() {
        return currentProgram;
    }

    /**
     * Get the current address context.
     */
    public Address getCurrentAddress() {
        return currentAddress;
    }

    /**
     * Get all registered native providers.
     */
    public List<ToolProvider> getNativeProviders() {
        return new ArrayList<>(nativeProviders);
    }

    /**
     * Get tool count by provider.
     */
    public String getSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("NativeToolManager: ").append(getTools().size()).append(" total tools\n");
        for (ToolProvider provider : nativeProviders) {
            sb.append("  - ").append(provider.getProviderName())
              .append(": ").append(provider.getTools().size()).append(" tools\n");
        }
        return sb.toString();
    }
}
