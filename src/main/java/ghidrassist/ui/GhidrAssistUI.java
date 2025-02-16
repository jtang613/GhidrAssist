package ghidrassist.ui;

import javax.swing.*;

import ghidra.program.util.ProgramLocation;

import java.awt.*;
import ghidrassist.GhidrAssistPlugin;
import ghidrassist.ui.tabs.*;
import ghidrassist.core.TabController;
import ghidrassist.ui.common.UIConstants;

public class GhidrAssistUI extends JPanel {
    private static final long serialVersionUID = 1L;
	private final GhidrAssistPlugin plugin;
    private final TabController controller;
    private final JTabbedPane tabbedPane;
    private final ExplainTab explainTab;
    private final QueryTab queryTab;
    private final ActionsTab actionsTab;
    private final RAGManagementTab ragManagementTab;

    public GhidrAssistUI(GhidrAssistPlugin plugin) {
        super(new BorderLayout());
        this.plugin = plugin;
        this.controller = new TabController(plugin);
        
        // Initialize components
        this.tabbedPane = new JTabbedPane();
        
        // Create tabs
        this.explainTab = new ExplainTab(controller);
        this.queryTab = new QueryTab(controller);
        this.actionsTab = new ActionsTab(controller);
        this.ragManagementTab = new RAGManagementTab(controller);
        
        // Set tab references in controller
        controller.setExplainTab(explainTab);
        controller.setQueryTab(queryTab);
        controller.setActionsTab(actionsTab);
        controller.setRAGManagementTab(ragManagementTab);
        
        initializeUI();
    }

    private void initializeUI() {
        setBorder(UIConstants.PANEL_BORDER);
        
        // Add tabs
        tabbedPane.addTab("Explain", explainTab);
        tabbedPane.addTab("Custom Query", queryTab);
        tabbedPane.addTab("Actions", actionsTab);
        tabbedPane.addTab("RAG Management", ragManagementTab);
        
        add(tabbedPane, BorderLayout.CENTER);
    }

    public void updateLocation(ProgramLocation loc) {
        if (loc != null && loc.getAddress() != null) {
            explainTab.updateOffset(loc.getAddress().toString());
            controller.updateAnalysis(loc);
        }
    }

    public JComponent getComponent() {
        return this;
    }
}