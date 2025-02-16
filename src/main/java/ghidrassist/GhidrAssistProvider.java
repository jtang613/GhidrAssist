package ghidrassist;

import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.DefaultActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.util.Msg;
import ghidrassist.resources.GhidrAssistIcons;
import ghidrassist.ui.GhidrAssistUI;
import resources.Icons;

public class GhidrAssistProvider extends ComponentProvider {
    private GhidrAssistPlugin plugin;
    private GhidrAssistUI ui;
    private JComponent mainPanel;
    private List<DockingAction> actions;

    public GhidrAssistProvider(GhidrAssistPlugin plugin, String owner) {
        super(plugin.getTool(), owner, owner);
        this.plugin = plugin;
        this.actions = new ArrayList<>();

        buildPanel();
        createActions();
        setIcon(GhidrAssistIcons.ROBOT_ICON);
    }

    private void buildPanel() {
        ui = new GhidrAssistUI(plugin);
        mainPanel = ui.getComponent();
        setVisible(true);
    }

    private void createActions() {
        DockingAction refreshAction = new DockingAction("Refresh GhidrAssist", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                refresh();
            }
        };
        refreshAction.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, null));
        refreshAction.setEnabled(true);
        refreshAction.markHelpUnnecessary();
        actions.add(refreshAction);

        // Add actions to the tool
        for (DockingAction action : actions) {
            plugin.getTool().addLocalAction(this, action);
        }
    }

    public GhidrAssistUI getUI() {
        return ui;
    }
    
    @Override
    public JComponent getComponent() {
        return mainPanel;
    }

    @Override
    public ActionContext getActionContext(MouseEvent event) {
        return new DefaultActionContext(this, mainPanel);
    }

    public void refresh() {
        try {
            Msg.info(this, "GhidrAssist UI refreshed");
        }
        catch (Exception e) {
            Msg.error(this, "Error refreshing GhidrAssist UI", e);
        }
    }
}