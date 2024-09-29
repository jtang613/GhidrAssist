package ghidrassist;

import com.fasterxml.jackson.databind.JsonNode;
import com.launchableinc.openai.completion.chat.*;
import com.launchableinc.openai.service.OpenAiService;
import ghidra.util.Msg;
import io.reactivex.Flowable;
import io.reactivex.schedulers.Schedulers;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.atomic.AtomicBoolean;

public class LlmApi {

    private OpenAiService service;
    private APIProvider provider;

    private final String SYSTEM_PROMPT =  
			"    You are a professional software reverse engineer specializing in cybersecurity. You are intimately \n"
			+ "    familiar with x86_64, ARM, PPC and MIPS architectures. You are an expert C and C++ developer.\n"
			+ "    You are an expert Python and Rust developer. You are familiar with common frameworks and libraries \n"
			+ "    such as WinSock, OpenSSL, MFC, etc. You are an expert in TCP/IP network programming and packet analysis.\n"
			+ "    You always respond to queries in a structured format using Markdown styling for headings and lists. \n"
			+ "    You format code blocks using back-tick code-fencing.\\n";
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
    
    public LlmApi(APIProvider provider) {
    	this.provider = provider;
        this.service = new CustomOpenAiService(this.provider.getKey(), this.provider.getUrl()).getOpenAiService();
    }

    public String getSystemPrompt() {
    	return this.SYSTEM_PROMPT;
    }
    
    public void sendRequestAsyncWithFunctions(String prompt, List<Map<String, Object>> functions, LlmResponseHandler responseHandler) {
        if (service == null) {
            Msg.showError(this, null, "Service Error", "OpenAI service is not initialized.");
            return;
        }

        List<ChatMessage> messages = new ArrayList<>();
        ChatMessage systemMessage = new ChatMessage(ChatMessageRole.SYSTEM.value(), this.SYSTEM_PROMPT + "\n" + this.FUNCTION_PROMPT + "\n" + this.FORMAT_PROMPT);
        messages.add(systemMessage);

        ChatMessage userMessage = new ChatMessage(ChatMessageRole.USER.value(), prompt);
        messages.add(userMessage);

        // Build the ChatCompletionRequest with functions
        ChatCompletionRequest chatCompletionRequest = ChatCompletionRequest.builder()
                .model(this.provider.getModel())
                .messages(messages)
                .maxTokens(Integer.parseInt(this.provider.getMaxTokens()))
                //.temperature(0.7)
                .functions(functions)
                .functionCall(null) // Let the assistant decide
                .build();

        // Execute the request asynchronously
        CompletableFuture.supplyAsync(() -> {
            try {
                return service.createChatCompletion(chatCompletionRequest);
            } catch (Exception e) {
                throw new CompletionException(e);
            }
        }).thenAccept(chatCompletionResult -> {
            if (!responseHandler.shouldContinue()) {  // Check if the process should continue after receiving the result
                return;
            }
            if (chatCompletionResult != null && !chatCompletionResult.getChoices().isEmpty()) {
                ChatMessage message = chatCompletionResult.getChoices().get(0).getMessage();
                if (message.getFunctionCall() != null) {
                    // Handle function call
                    String functionName = message.getFunctionCall().getName();
                    JsonNode arguments = message.getFunctionCall().getArguments();
                    String fullResponse = "{ \"name\": \"" + functionName + "\", \"arguments\": " + arguments.toString() + " }";
                    responseHandler.onComplete(fullResponse);
                } else {
                    responseHandler.onComplete(message.getContent());
                }
            } else {
                responseHandler.onError(new Exception("Empty response from LLM."));
            }
        }).exceptionally(throwable -> {
            responseHandler.onError(throwable);
            return null;
        });
    }

    public void sendRequestAsync(String prompt, LlmResponseHandler responseHandler) {
        if (service == null) {
            Msg.showError(this, null, "Service Error", "OpenAI service is not initialized.");
            return;
        }

        List<ChatMessage> messages = new ArrayList<>();
        ChatMessage systemMessage = new ChatMessage(ChatMessageRole.SYSTEM.value(), this.SYSTEM_PROMPT  );
        messages.add(systemMessage);

        ChatMessage userMessage = new ChatMessage(ChatMessageRole.USER.value(), prompt);
        messages.add(userMessage);

        ChatCompletionRequest chatCompletionRequest = ChatCompletionRequest
                .builder()
                .model(this.provider.getModel())
                .messages(messages)
                .maxTokens(Integer.parseInt(this.provider.getMaxTokens()))
                //.temperature(0.7)
                .stream(true) // Enable streaming
                .build();

        Flowable<ChatCompletionChunk> flowable = service.streamChatCompletion(chatCompletionRequest);

        AtomicBoolean isFirst = new AtomicBoolean(true);
        StringBuilder responseBuilder = new StringBuilder();

        flowable.subscribe(
                chunk -> {
                	if (responseHandler.shouldContinue()) {
	                    ChatMessage delta = chunk.getChoices().get(0).getMessage();
	                    if (delta.getContent() != null) {
	                        if (isFirst.getAndSet(false)) {
	                            responseHandler.onStart();
	                        }
	                        responseBuilder.append(delta.getContent());
	                        responseHandler.onUpdate(responseBuilder.toString());
	                    }
                	} else {
                        // Query was cancelled, stop further execution
                        flowable.unsubscribeOn(Schedulers.io());
                    }
                },
                error -> {
                    Msg.showError(this, null, "LLM Error", "An error occurred: " + error.getMessage());
                    responseHandler.onError(error);
                },
                () -> {
                    responseHandler.onComplete(responseBuilder.toString());
                }
        );
    }

    public interface LlmResponseHandler {
        void onStart();
        void onUpdate(String partialResponse);
        void onComplete(String fullResponse);
        void onError(Throwable error);
        // This method checks if the process should continue or stop
        default boolean shouldContinue() {
            return true; // Override this method for cancellation logic
        }
    }
}
