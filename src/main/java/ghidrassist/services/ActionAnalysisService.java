package ghidrassist.services;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrassist.GhidrAssistPlugin;
import ghidrassist.LlmApi;
import ghidrassist.apiprovider.APIProviderConfig;
import ghidrassist.core.ActionExecutor;
import ghidrassist.core.ActionParser;
import ghidrassist.core.CodeUtils;
import ghidrassist.core.ActionConstants;

import javax.swing.table.DefaultTableModel;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Service for handling automated function analysis with actions.
 * Responsible for analyzing functions with AI tools and managing action execution.
 */
public class ActionAnalysisService {
    
    private final GhidrAssistPlugin plugin;
    private final AtomicInteger activeRequests;
    
    public ActionAnalysisService(GhidrAssistPlugin plugin) {
        this.plugin = plugin;
        this.activeRequests = new AtomicInteger(0);
    }
    
    /**
     * Create an action analysis request for a function
     */
    public ActionAnalysisRequest createAnalysisRequest(Function function, List<String> selectedActions) throws Exception {
        if (function == null) {
            throw new IllegalArgumentException("No function at current location.");
        }
        
        if (selectedActions.isEmpty()) {
            throw new IllegalArgumentException("No actions selected for analysis.");
        }
        
        String code = CodeUtils.getFunctionCode(function, TaskMonitor.DUMMY);
        if (code == null) {
            throw new Exception("Failed to get code from the current function.");
        }
        
        return new ActionAnalysisRequest(function, code, selectedActions);
    }
    
    /**
     * Execute action analysis requests
     */
    public void executeActionAnalysis(ActionAnalysisRequest request, ActionAnalysisHandler handler) throws Exception {
        APIProviderConfig config = GhidrAssistPlugin.getCurrentProviderConfig();
        if (config == null) {
            throw new Exception("No API provider configured.");
        }
        
        LlmApi llmApi = new LlmApi(config, plugin);
        
        // Reset and set the active request counter
        activeRequests.set(request.getSelectedActions().size());
        
        for (String action : request.getSelectedActions()) {
            if (!handler.shouldContinue()) {
                break;
            }
            
            String actionPrompt = ActionConstants.ACTION_PROMPTS.get(action);
            if (actionPrompt != null) {
                String prompt = actionPrompt.replace("{code}", request.getCode());
                List<Map<String, Object>> functions = new ArrayList<>();
                functions.add(getActionFunction(action));
                
                llmApi.sendRequestAsyncWithFunctions(prompt, functions, 
                    createActionResponseHandler(action, handler));
            }
        }
    }
    
    /**
     * Apply selected actions from the analysis results
     */
    public void applyActions(DefaultTableModel model, Program program, Address address) {
        for (int row = 0; row < model.getRowCount(); row++) {
            Boolean isSelected = (Boolean) model.getValueAt(row, 0);
            if (isSelected) {
                applyAction(model, row, program, address);
            }
        }
    }
    
    /**
     * Apply a single action
     */
    private void applyAction(DefaultTableModel model, int row, Program program, Address address) {
        String action = model.getValueAt(row, 1).toString().replace(" ", "_");
        String argumentsJson = model.getValueAt(row, 4).toString();
        
        try {
            ActionExecutor.executeAction(action, argumentsJson, program, address);
            model.setValueAt("Applied", row, 3);
            model.setValueAt(Boolean.FALSE, row, 0);
        } catch (Exception e) {
            model.setValueAt("Failed: " + e.getMessage(), row, 3);
        }
    }
    
    /**
     * Get the function template for a specific action
     */
    private Map<String, Object> getActionFunction(String actionName) {
        for (Map<String, Object> fnTemplate : ActionConstants.FN_TEMPLATES) {
            @SuppressWarnings("unchecked")
            Map<String, Object> functionMap = (Map<String, Object>) fnTemplate.get("function");
            if (functionMap.get("name").equals(actionName)) {
                return fnTemplate;
            }
        }
        return null;
    }
    
    /**
     * Create response handler for action analysis
     */
    private LlmApi.LlmResponseHandler createActionResponseHandler(String action, ActionAnalysisHandler handler) {
        return new LlmApi.LlmResponseHandler() {
            @Override
            public void onStart() {
                handler.onActionStart(action);
            }
            
            @Override
            public void onUpdate(String partialResponse) {
                // Function calls don't have partial updates
            }
            
            @Override
            public void onComplete(String fullResponse) {
                handler.onActionComplete(action, fullResponse);
                
                int remaining = activeRequests.decrementAndGet();
                if (remaining <= 0) {
                    activeRequests.set(0);
                    handler.onAllActionsComplete();
                }
            }
            
            @Override
            public void onError(Throwable error) {
                handler.onActionError(action, error);
                
                int remaining = activeRequests.decrementAndGet();
                if (remaining <= 0) {
                    activeRequests.set(0);
                    handler.onAllActionsComplete();
                }
            }
            
            @Override
            public boolean shouldContinue() {
                return handler.shouldContinue();
            }
        };
    }
    
    /**
     * Parse and display action results
     */
    public void parseAndDisplayActions(String response, DefaultTableModel tableModel) throws Exception {
        ActionParser.parseAndDisplay(response, tableModel);
    }
    
    /**
     * Check if analysis is currently running
     */
    public boolean isAnalysisRunning() {
        return activeRequests.get() > 0;
    }
    
    /**
     * Cancel all running analysis
     */
    public void cancelAnalysis() {
        activeRequests.set(0);
    }
    
    /**
     * Request object for action analysis operations
     */
    public static class ActionAnalysisRequest {
        private final Function function;
        private final String code;
        private final List<String> selectedActions;
        
        public ActionAnalysisRequest(Function function, String code, List<String> selectedActions) {
            this.function = function;
            this.code = code;
            this.selectedActions = new ArrayList<>(selectedActions);
        }
        
        public Function getFunction() { return function; }
        public String getCode() { return code; }
        public List<String> getSelectedActions() { return selectedActions; }
    }
    
    /**
     * Handler interface for action analysis callbacks
     */
    public interface ActionAnalysisHandler {
        void onActionStart(String action);
        void onActionComplete(String action, String response);
        void onActionError(String action, Throwable error);
        void onAllActionsComplete();
        boolean shouldContinue();
    }
}