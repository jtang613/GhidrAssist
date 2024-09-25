package ghidrassist;

import com.launchableinc.openai.completion.chat.*;
import com.launchableinc.openai.service.OpenAiService;
import ghidra.util.Msg;
import io.reactivex.Flowable;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

public class LlmApi {

    private OpenAiService service;
    private APIProvider provider;

    private final String SYSTEM_PROMPT =  
			"You are a professional software reverse engineer specializing in cybersecurity. " +
            "You are intimately familiar with x86_64, ARM, PPC and MIPS architectures. " +
            "You are an expert C and C++ developer. " +
            "You always respond to queries in a structured format using Markdown styling for headings and lists. " +
            "You format code blocks using back-tick code-fencing.";
    
    public LlmApi(APIProvider provider) {
    	this.provider = provider;
        this.service = new CustomOpenAiService(this.provider.getKey(), this.provider.getUrl()).getOpenAiService();
    }

    public String getSystemPrompt() {
    	return this.SYSTEM_PROMPT;
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
                .temperature(0.7)
                .stream(true) // Enable streaming
                .build();

        Flowable<ChatCompletionChunk> flowable = service.streamChatCompletion(chatCompletionRequest);

        AtomicBoolean isFirst = new AtomicBoolean(true);
        StringBuilder responseBuilder = new StringBuilder();

        flowable.subscribe(
                chunk -> {
                    ChatMessage delta = chunk.getChoices().get(0).getMessage();
                    if (delta.getContent() != null) {
                        if (isFirst.getAndSet(false)) {
                            responseHandler.onStart();
                        }
                        responseBuilder.append(delta.getContent());
                        responseHandler.onUpdate(responseBuilder.toString());
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
    }
}
