package ghidrassist.services;

import ghidrassist.AnalysisDB;
import ghidrassist.GhidrAssistPlugin;
import ghidrassist.LlmApi;
import ghidrassist.apiprovider.APIProviderConfig;

/**
 * Service for managing analysis context and program-specific data.
 * Responsible for context storage, retrieval, and management operations.
 */
public class AnalysisDataService {
    
    private final GhidrAssistPlugin plugin;
    private final AnalysisDB analysisDB;
    
    public AnalysisDataService(GhidrAssistPlugin plugin) {
        this.plugin = plugin;
        this.analysisDB = new AnalysisDB();
    }
    
    /**
     * Save context for the current program
     */
    public void saveContext(String context) {
        if (plugin.getCurrentProgram() == null) {
            throw new IllegalStateException("No active program to save context for.");
        }
        
        String programHash = plugin.getCurrentProgram().getExecutableSHA256();
        analysisDB.upsertContext(programHash, context);
    }
    
    /**
     * Get context for the current program
     */
    public String getContext() {
        if (plugin.getCurrentProgram() == null) {
            return getDefaultContext();
        }
        
        String programHash = plugin.getCurrentProgram().getExecutableSHA256();
        String context = analysisDB.getContext(programHash);
        
        if (context == null) {
            return getDefaultContext();
        }
        
        return context;
    }
    
    /**
     * Revert context to default for the current program
     */
    public String revertToDefaultContext() {
        String defaultContext = getDefaultContext();
        
        if (plugin.getCurrentProgram() != null) {
            // Clear custom context, will fall back to default
            String programHash = plugin.getCurrentProgram().getExecutableSHA256();
            analysisDB.upsertContext(programHash, null);
        }
        
        return defaultContext;
    }
    
    /**
     * Check if current program has custom context
     */
    public boolean hasCustomContext() {
        if (plugin.getCurrentProgram() == null) {
            return false;
        }
        
        String programHash = plugin.getCurrentProgram().getExecutableSHA256();
        String context = analysisDB.getContext(programHash);
        return context != null && !context.equals(getDefaultContext());
    }
    
    /**
     * Get default system context
     */
    private String getDefaultContext() {
        APIProviderConfig config = GhidrAssistPlugin.getCurrentProviderConfig();
        if (config == null) {
            return "You are a professional software reverse engineer."; // Fallback
        }
        
        LlmApi llmApi = new LlmApi(config, plugin);
        return llmApi.getSystemPrompt();
    }
    
    /**
     * Get context statistics
     */
    public ContextStats getContextStats() {
        String currentContext = getContext();
        boolean isCustom = hasCustomContext();
        String programName = plugin.getCurrentProgram() != null ? 
            plugin.getCurrentProgram().getName() : "No Program";
        
        return new ContextStats(programName, currentContext.length(), isCustom);
    }
    
    /**
     * Close database resources
     */
    public void close() {
        if (analysisDB != null) {
            analysisDB.close();
        }
    }
    
    /**
     * Statistics about the current context
     */
    public static class ContextStats {
        private final String programName;
        private final int contextLength;
        private final boolean isCustom;
        
        public ContextStats(String programName, int contextLength, boolean isCustom) {
            this.programName = programName;
            this.contextLength = contextLength;
            this.isCustom = isCustom;
        }
        
        public String getProgramName() { return programName; }
        public int getContextLength() { return contextLength; }
        public boolean isCustom() { return isCustom; }
        
        @Override
        public String toString() {
            return String.format("Program: %s, Context: %d chars (%s)", 
                programName, contextLength, isCustom ? "Custom" : "Default");
        }
    }
}