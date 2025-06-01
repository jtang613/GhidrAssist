package ghidrassist.core;

import ghidrassist.AnalysisDB;
import ghidrassist.GhidrAssistPlugin;
import ghidrassist.LlmApi;
import ghidrassist.apiprovider.APIProvider;
import ghidrassist.apiprovider.APIProviderConfig;
import ghidrassist.apiprovider.ChatMessage;
import ghidrassist.apiprovider.exceptions.APIProviderException;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Handles API provider management and low-level API calls.
 * Focused solely on provider configuration and basic API interactions.
 */
public class LlmApiClient {
    private APIProvider provider;
    private final AnalysisDB analysisDB;
    private final GhidrAssistPlugin plugin;
    
    private final String DEFAULT_SYSTEM_PROMPT = 
            "You are a professional software reverse engineer specializing in cybersecurity. You are intimately \n"
            + "familiar with x86_64, ARM, PPC and MIPS architectures. You are an expert C and C++ developer.\n"
            + "You are an expert Python and Rust developer. You are familiar with common frameworks and libraries \n"
            + "such as WinSock, OpenSSL, MFC, etc. You are an expert in TCP/IP network programming and packet analysis.\n"
            + "You always respond to queries in a structured format using Markdown styling for headings and lists. \n"
            + "You format code blocks using back-tick code-fencing.\n";
            
    private final String FUNCTION_PROMPT = "USE THE PROVIDED TOOLS WHEN NECESSARY. YOU ALWAYS RESPOND WITH TOOL CALLS WHEN POSSIBLE.";

    public LlmApiClient(APIProviderConfig config, GhidrAssistPlugin plugin) {
        this.provider = config.createProvider();
        this.analysisDB = new AnalysisDB();
        this.plugin = plugin;
        
        // Get the global API timeout and set it if the provider doesn't have one
        if (provider != null && provider.getTimeout() == null) {
            Integer timeout = GhidrAssistPlugin.getGlobalApiTimeout();
            provider.setTimeout(timeout);
        }
    }

    public String getSystemPrompt() {
        return this.DEFAULT_SYSTEM_PROMPT;
    }

    public GhidrAssistPlugin getPlugin() {
        return plugin;
    }

    public String getCurrentContext() {
        if (plugin.getCurrentProgram() != null) {
            String programHash = plugin.getCurrentProgram().getExecutableSHA256();
            String context = analysisDB.getContext(programHash);
            if (context != null) {
                return context;
            }
        }
        return DEFAULT_SYSTEM_PROMPT;
    }
    
    /**
     * Create messages for regular chat completion
     */
    public List<ChatMessage> createChatMessages(String prompt) {
        String systemUser = ChatMessage.ChatMessageRole.SYSTEM;
        if (isO1OrO3Model()) {
            systemUser = ChatMessage.ChatMessageRole.USER;
        }
        
        List<ChatMessage> messages = new ArrayList<>();
        messages.add(new ChatMessage(systemUser, getCurrentContext()));
        messages.add(new ChatMessage(ChatMessage.ChatMessageRole.USER, prompt));
        return messages;
    }
    
    /**
     * Create messages for function calling
     */
    public List<ChatMessage> createFunctionMessages(String prompt) {
        String systemUser = ChatMessage.ChatMessageRole.SYSTEM;
        if (isO1OrO3Model()) {
            systemUser = ChatMessage.ChatMessageRole.USER;
        }

        List<ChatMessage> messages = new ArrayList<>();
        messages.add(new ChatMessage(ChatMessage.ChatMessageRole.USER, prompt));
        return messages;
    }
    
    /**
     * Check if the current model is O1 or O3 series (which handle system prompts differently)
     */
    private boolean isO1OrO3Model() {
        return provider != null && (
            provider.getModel().startsWith("o1-") || 
            provider.getModel().startsWith("o3-") || 
            provider.getModel().startsWith("o4-")
        );
    }
    
    /**
     * Stream chat completion
     */
    public void streamChatCompletion(List<ChatMessage> messages, LlmApi.LlmResponseHandler handler) 
            throws APIProviderException {
        if (provider == null) {
            throw new IllegalStateException("LLM provider is not initialized.");
        }
        provider.streamChatCompletion(messages, handler);
    }
    
    /**
     * Create chat completion with functions
     */
    public String createChatCompletionWithFunctions(List<ChatMessage> messages, List<Map<String, Object>> functions) 
            throws APIProviderException {
        if (provider == null) {
            throw new IllegalStateException("LLM provider is not initialized.");
        }
        return provider.createChatCompletionWithFunctions(messages, functions);
    }
    
    /**
     * Create chat completion with functions - returns full response including finish_reason
     */
    public String createChatCompletionWithFunctionsFullResponse(List<ChatMessage> messages, List<Map<String, Object>> functions) 
            throws APIProviderException {
        if (provider == null) {
            throw new IllegalStateException("LLM provider is not initialized.");
        }
        return provider.createChatCompletionWithFunctionsFullResponse(messages, functions);
    }
    
    /**
     * Check if provider is available
     */
    public boolean isProviderAvailable() {
        return provider != null;
    }
    
    /**
     * Get provider name for logging/error handling
     */
    public String getProviderName() {
        return provider != null ? provider.getName() : "Unknown";
    }
    
    /**
     * Get provider model for logging/error handling
     */
    public String getProviderModel() {
        return provider != null ? provider.getModel() : "Unknown";
    }
}