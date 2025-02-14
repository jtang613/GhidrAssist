package ghidrassist;

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
import java.lang.reflect.Type;
import java.util.List;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;

/**
 * GhidrAssistPlugin is a Ghidra plugin that provides code assistance using a language model.
 */
@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = "GhidrAssist",
    category = PluginCategoryNames.COMMON,
    shortDescription = "GhidrAssist LLM Plugin",
    description = "A plugin that provides code assistance using a language model."
)
public class GhidrAssistPlugin extends ProgramPlugin {

	private GhidrAssistProvider provider;
    private String lastActiveProvider;
    
    public enum CodeViewType {
        IS_DECOMPILER,
        IS_DISASSEMBLER,
        UNKNOWN
    }

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

    private void showSettingsDialog() {
        SettingsDialog dialog = new SettingsDialog(tool.getToolFrame(), "GhidrAssist Settings");
        tool.showDialog(dialog);
    }

    @Override
    public void locationChanged(ProgramLocation loc) {
        if (provider != null) {
            provider.updateLocation(loc);
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
            Function function = functionManager.getFunctionContaining(address);
            return function;
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
	        // Assume disassembler view if not decompiler
	        return CodeViewType.IS_DISASSEMBLER;
	    } else {
	        return CodeViewType.UNKNOWN;
	    }
	}

    public static APIProvider getCurrentAPIProvider() {
        // Load the list of API providers from preferences
        String providersJson = Preferences.getProperty("GhidrAssist.APIProviders", "[]");
        Gson gson = new Gson();
        Type listType = new TypeToken<List<APIProvider>>() {}.getType();
        List<APIProvider> apiProviders = gson.fromJson(providersJson, listType);

        // Load the selected provider name
        String selectedProviderName = Preferences.getProperty("GhidrAssist.SelectedAPIProvider", "");

        for (APIProvider provider : apiProviders) {
            if (provider.getName().equals(selectedProviderName)) {
                return provider;
            }
        }

        // If not found, return null or handle as needed
        return null;
    }
}
