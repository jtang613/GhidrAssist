package ghidrassist.services;

import ghidrassist.GhidrAssistPlugin;
import ghidrassist.LlmApi;
import ghidrassist.RLHFDatabase;
import ghidrassist.apiprovider.APIProviderConfig;

/**
 * Service for handling RLHF (Reinforcement Learning from Human Feedback) operations.
 * Responsible for storing user feedback and managing feedback data.
 */
public class FeedbackService {
    
    private final GhidrAssistPlugin plugin;
    private final RLHFDatabase rlhfDB;
    
    // Cache for last interaction
    private String lastPrompt;
    private String lastResponse;
    
    public FeedbackService(GhidrAssistPlugin plugin) {
        this.plugin = plugin;
        this.rlhfDB = new RLHFDatabase();
    }
    
    /**
     * Cache the last prompt and response for feedback
     */
    public void cacheLastInteraction(String prompt, String response) {
        this.lastPrompt = prompt;
        this.lastResponse = response;
    }
    
    /**
     * Store positive feedback (thumbs up)
     */
    public void storePositiveFeedback() {
        storeFeedback(1);
    }
    
    /**
     * Store negative feedback (thumbs down)
     */
    public void storeNegativeFeedback() {
        storeFeedback(0);
    }
    
    /**
     * Store feedback with specified rating
     */
    public void storeFeedback(int feedback) {
        if (lastPrompt == null || lastResponse == null) {
            throw new IllegalStateException("No recent interaction to provide feedback for.");
        }
        
        APIProviderConfig config = GhidrAssistPlugin.getCurrentProviderConfig();
        if (config == null) {
            throw new IllegalStateException("No API provider configured.");
        }
        
        LlmApi llmApi = new LlmApi(config, plugin);
        String modelName = config.getModel();
        String systemContext = llmApi.getSystemPrompt();
        
        rlhfDB.storeFeedback(modelName, lastPrompt, systemContext, lastResponse, feedback);
    }
    
    /**
     * Check if there's a recent interaction available for feedback
     */
    public boolean hasPendingFeedback() {
        return lastPrompt != null && lastResponse != null;
    }
    
    /**
     * Clear cached interaction (e.g., after feedback is provided)
     */
    public void clearCachedInteraction() {
        lastPrompt = null;
        lastResponse = null;
    }
    
    /**
     * Get feedback statistics
     */
    public FeedbackStats getFeedbackStats() {
        // Note: This would require extending RLHFDatabase with stats methods
        // For now, return basic info
        return new FeedbackStats(hasPendingFeedback());
    }
    
    /**
     * Get the last cached prompt (for debugging/info)
     */
    public String getLastPrompt() {
        return lastPrompt;
    }
    
    /**
     * Get the last cached response (for debugging/info)
     */
    public String getLastResponse() {
        return lastResponse;
    }
    
    /**
     * Close database resources
     */
    public void close() {
        if (rlhfDB != null) {
            rlhfDB.close();
        }
    }
    
    /**
     * Statistics about feedback state
     */
    public static class FeedbackStats {
        private final boolean hasPendingFeedback;
        
        public FeedbackStats(boolean hasPendingFeedback) {
            this.hasPendingFeedback = hasPendingFeedback;
        }
        
        public boolean hasPendingFeedback() { return hasPendingFeedback; }
        
        @Override
        public String toString() {
            return String.format("Feedback: %s", 
                hasPendingFeedback ? "Available" : "No pending feedback");
        }
    }
}