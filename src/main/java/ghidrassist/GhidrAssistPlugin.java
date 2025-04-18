package ghidrassist;

import java.lang.reflect.Type;
import java.util.List;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.decompiler.DecompilerLocation;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidrassist.apiprovider.APIProviderConfig;

@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = "GhidrAssist",
    category = PluginCategoryNames.COMMON,
    shortDescription = "GhidrAssist LLM Plugin",
    description = "A plugin that provides code assistance using a language model."
)
public class GhidrAssistPlugin extends ProgramPlugin {
    public enum CodeViewType {
        IS_DECOMPILER,
        IS_DISASSEMBLER,
        UNKNOWN
    }
    private GhidrAssistProvider provider;
    private String lastActiveProvider;

    public GhidrAssistPlugin(PluginTool tool) {
        super(tool);
        String pluginName = getName();
        provider = new GhidrAssistProvider(this, pluginName);
    }

    @Override
    public void init() {
        super.init();

        // Add a menu action for settings
        DockingAction settingsAction = new DockingAction("GhidrAssist Settings", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                showSettingsDialog();
            }
        };
        settingsAction.setMenuBarData(new MenuData(new String[] { "Tools", "GhidrAssist Settings" }, null, "GhidrAssist"));
        tool.addAction(settingsAction);
    }

    @Override
    protected void dispose() {
        if (provider != null) {
            tool.removeComponentProvider(provider);
            provider = null;
        }
        super.dispose();
    }

    private void showSettingsDialog() {
        SettingsDialog dialog = new SettingsDialog(tool.getToolFrame(), "GhidrAssist Settings", this);
        tool.showDialog(dialog);
    }

    @Override
    public void locationChanged(ProgramLocation loc) {
        if (provider != null) {
            provider.getUI().updateLocation(loc);
        }
    }

    public Program getCurrentProgram() {
        return currentProgram;
    }

    public Address getCurrentAddress() {
        if (currentLocation != null) {
            return currentLocation.getAddress();
        }
        return null;
    }

    public Function getCurrentFunction() {
        Program program = getCurrentProgram();
        Address address = getCurrentAddress();

        if (program != null && address != null) {
            FunctionManager functionManager = program.getFunctionManager();
            return functionManager.getFunctionContaining(address);
        }
        return null;
    }

    public String getLastActiveProvider() {
        return lastActiveProvider;
    }
    
    public CodeViewType checkLastActiveCodeView() {
        if (currentLocation instanceof DecompilerLocation) {
            return CodeViewType.IS_DECOMPILER;
        } else if (currentLocation != null) {
            return CodeViewType.IS_DISASSEMBLER;
        } else {
            return CodeViewType.UNKNOWN;
        }
    }

    public static APIProviderConfig getCurrentProviderConfig() {
        // Load the list of API providers from preferences
        String providersJson = Preferences.getProperty("GhidrAssist.APIProviders", "[]");
        Gson gson = new Gson();
        Type listType = new TypeToken<List<APIProviderConfig>>() {}.getType();
        List<APIProviderConfig> apiProviders = gson.fromJson(providersJson, listType);

        // Load the selected provider name
        String selectedProviderName = Preferences.getProperty("GhidrAssist.SelectedAPIProvider", "");
        
        // Load the global API timeout setting
        String apiTimeoutStr = Preferences.getProperty("GhidrAssist.APITimeout", "120");
        Integer apiTimeout = 120; // Default value
        try {
            apiTimeout = Integer.parseInt(apiTimeoutStr);
        } catch (NumberFormatException e) {
            // Use default if there's an error
        }

        for (APIProviderConfig provider : apiProviders) {
            if (provider.getName().equals(selectedProviderName)) {
                // If the provider doesn't have a timeout set, use the global setting
                if (provider.getTimeout() == null) {
                    provider.setTimeout(apiTimeout);
                }
                return provider;
            }
        }

        return null;
    }
    
    public static Integer getGlobalApiTimeout() {
        String apiTimeoutStr = Preferences.getProperty("GhidrAssist.APITimeout", "120");
        try {
            return Integer.parseInt(apiTimeoutStr);
        } catch (NumberFormatException e) {
            return 120; // Default value
        }
    }

	public GhidrAssistPlugin getInstance() {
		return this;
	}
}