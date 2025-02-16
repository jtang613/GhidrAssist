package ghidrassist;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import javax.swing.SwingWorker;

import ghidra.util.Msg;
import ghidrassist.apiprovider.APIProvider;
import ghidrassist.apiprovider.APIProviderConfig;
import ghidrassist.apiprovider.ChatMessage;

public class LlmApi {
    private APIProvider provider;
    private final AnalysisDB analysisDB;
    private final GhidrAssistPlugin plugin;
    private final Object streamLock = new Object();
    private volatile boolean isStreaming = false;
    
    // Pattern for matching complete <think> blocks and opening/closing tags
    private static final Pattern COMPLETE_THINK_PATTERN = Pattern.compile("<think>.*?</think>", Pattern.DOTALL);
    
    private final String DEFAULT_SYSTEM_PROMPT = 
            "You are a professional software reverse engineer specializing in cybersecurity. You are intimately \n"
            + "familiar with x86_64, ARM, PPC and MIPS architectures. You are an expert C and C++ developer.\n"
            + "You are an expert Python and Rust developer. You are familiar with common frameworks and libraries \n"
            + "such as WinSock, OpenSSL, MFC, etc. You are an expert in TCP/IP network programming and packet analysis.\n"
            + "You always respond to queries in a structured format using Markdown styling for headings and lists. \n"
            + "You format code blocks using back-tick code-fencing.\n";
            
    private final String FUNCTION_PROMPT = "USE THE PROVIDED TOOLS WHEN NECESSARY. YOU ALWAYS RESPOND WITH TOOL CALLS WHEN POSSIBLE.";
    private final String FORMAT_PROMPT = 
        "The output MUST strictly adhere to the following JSON format, do not include any other text.\n" +
        "The example format is as follows. Please make sure the parameter type is correct. If no function call is needed, please make tool_calls an empty list '[]'.\n" +
        "```\n" +
        "{\n" +
        "    \"tool_calls\": [\n" +
        "    {\"name\": \"rename_function\", \"arguments\": {\"new_name\": \"new_name\"}},\n" +
        "    ... (more tool calls as required)\n" +
        "    ]\n" +
        "}\n" +
        "```\n" +
        "REMEMBER, YOU MUST ALWAYS PRODUCE A JSON LIST OF TOOL_CALLS!";

    public LlmApi(APIProviderConfig config, GhidrAssistPlugin plugin) {
        this.provider = config.createProvider();
        this.analysisDB = new AnalysisDB();
        this.plugin = plugin;
    }

    public String getSystemPrompt() {
        return this.DEFAULT_SYSTEM_PROMPT;
    }

    private String getCurrentContext() {
        if (plugin.getCurrentProgram() != null) {
            String programHash = plugin.getCurrentProgram().getExecutableSHA256();
            String context = analysisDB.getContext(programHash);
            if (context != null) {
                return context;
            }
        }
        return DEFAULT_SYSTEM_PROMPT;
    }
    
    private static class StreamingResponseFilter {
        private StringBuilder buffer = new StringBuilder();
        private StringBuilder visibleBuffer = new StringBuilder();
        private boolean insideThinkBlock = false;
        
        public String processChunk(String chunk) {
            if (chunk == null) {
                return null;
            }
            
            buffer.append(chunk);
            
            // Process the buffer until we can't anymore
            String currentBuffer = buffer.toString();
            int lastSafeIndex = 0;
            
            for (int i = 0; i < currentBuffer.length(); i++) {
                // Look for start tag
                if (!insideThinkBlock && currentBuffer.startsWith("<think>", i)) {
                    // Append everything up to this point to visible buffer
                    visibleBuffer.append(currentBuffer.substring(lastSafeIndex, i));
                    insideThinkBlock = true;
                    lastSafeIndex = i + 7; // Skip "<think>"
                    i += 6; // Move past "<think>"
                }
                // Look for end tag
                else if (insideThinkBlock && currentBuffer.startsWith("</think>", i)) {
                    insideThinkBlock = false;
                    lastSafeIndex = i + 8; // Skip "</think>"
                    i += 7; // Move past "</think>"
                }
            }
            
            // If we're not in a think block, append any remaining safe content
            if (!insideThinkBlock) {
                visibleBuffer.append(currentBuffer.substring(lastSafeIndex));
                // Clear processed content from buffer
                buffer.setLength(0);
            } else {
                // Keep everything from lastSafeIndex in buffer
                buffer = new StringBuilder(currentBuffer.substring(lastSafeIndex));
            }
            
            return visibleBuffer.toString();
        }
        
        public String getFilteredContent() {
            return visibleBuffer.toString();
        }
    }
    
    private String filterThinkBlocks(String response) {
        if (response == null) {
            return null;
        }
        return COMPLETE_THINK_PATTERN.matcher(response).replaceAll("").trim();
    }
    
    public void sendRequestAsync(String prompt, LlmResponseHandler responseHandler) {
        if (provider == null) {
            Msg.showError(this, null, "Service Error", "LLM provider is not initialized.");
            return;
        }

        // Cancel any existing stream
        cancelCurrentRequest();

        List<ChatMessage> messages = new ArrayList<>();
        messages.add(new ChatMessage(ChatMessage.ChatMessageRole.USER, getCurrentContext()));
        messages.add(new ChatMessage(ChatMessage.ChatMessageRole.USER, prompt));

        if (!responseHandler.shouldContinue()) {
            return;
        }

        try {
            synchronized (streamLock) {
                isStreaming = true;
                StreamingResponseFilter filter = new StreamingResponseFilter();
                
                provider.streamChatCompletion(messages, new LlmResponseHandler() {
                    private boolean isFirst = true;

                    @Override
                    public void onStart() {
                        if (isFirst) {
                            responseHandler.onStart();
                            isFirst = false;
                        }
                    }

                    @Override
                    public void onUpdate(String partialResponse) {
                        String filteredContent = filter.processChunk(partialResponse);
                        if (filteredContent != null && !filteredContent.isEmpty()) {
                            responseHandler.onUpdate(filteredContent);
                        }
                    }

                    @Override
                    public void onComplete(String fullResponse) {
                        synchronized (streamLock) {
                            isStreaming = false;
                        }
                        responseHandler.onComplete(filter.getFilteredContent());
                    }

                    @Override
                    public void onError(Throwable error) {
                        synchronized (streamLock) {
                            isStreaming = false;
                        }
                        if (!error.getMessage().contains("cancelled")) {
                            Msg.showError(LlmApi.this, null, "LLM Error", "An error occurred: " + error.getMessage());
                        }
                        responseHandler.onError(error);
                    }

                    @Override
                    public boolean shouldContinue() {
                        return responseHandler.shouldContinue();
                    }
                });
            }
        } catch (Exception e) {
            responseHandler.onError(e);
        }
    }

    public void sendRequestAsyncWithFunctions(String prompt, List<Map<String, Object>> functions, LlmResponseHandler responseHandler) {
        if (provider == null) {
            Msg.showError(this, null, "Service Error", "LLM provider is not initialized.");
            return;
        }

        List<ChatMessage> messages = new ArrayList<>();
        messages.add(new ChatMessage(ChatMessage.ChatMessageRole.USER, 
            getCurrentContext() + "\n" + FUNCTION_PROMPT + "\n" + FORMAT_PROMPT));
        messages.add(new ChatMessage(ChatMessage.ChatMessageRole.USER, prompt));

        // Create a background task
        SwingWorker<Void, String> worker = new SwingWorker<>() {
            @Override
            protected Void doInBackground() {
                try {
                    synchronized (streamLock) {
                        isStreaming = true;
                    }
                    
                    responseHandler.onStart();
                    String response = provider.createChatCompletionWithFunctions(messages, functions);
                    
                    if (responseHandler.shouldContinue()) {
                        String filteredResponse = filterThinkBlocks(response);
                        responseHandler.onComplete(filteredResponse);
                    }
                } catch (IOException e) {
                    if (responseHandler.shouldContinue()) {
                        responseHandler.onError(e);
                    }
                } finally {
                    synchronized (streamLock) {
                        isStreaming = false;
                    }
                }
                return null;
            }

            @Override
            protected void done() {
                try {
                    get(); // Check for exceptions
                } catch (Exception e) {
                    if (responseHandler.shouldContinue()) {
                        responseHandler.onError(e);
                    }
                }
            }
        };

        worker.execute();
    }

    public void cancelCurrentRequest() {
        synchronized (streamLock) {
            isStreaming = false;
        }
    }

    public interface LlmResponseHandler {
        void onStart();
        void onUpdate(String partialResponse);
        void onComplete(String fullResponse);
        void onError(Throwable error);
        default boolean shouldContinue() {
            return true;
        }
    }
}