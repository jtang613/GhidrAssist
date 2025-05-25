package ghidrassist.apiprovider;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.gson.JsonArray;

public class ChatMessage {
    private String role;
    private String content;
    private FunctionCall functionCall;
    private JsonArray toolCalls;  // For assistant messages with tool calls
    private String toolCallId;   // For tool response messages

    public ChatMessage(String role, String content) {
        this.role = role;
        this.content = content;
    }

    public String getRole() {
        return role;
    }

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }

    public FunctionCall getFunctionCall() {
        return functionCall;
    }

    public void setFunctionCall(FunctionCall functionCall) {
        this.functionCall = functionCall;
    }

    public JsonArray getToolCalls() {
        return toolCalls;
    }

    public void setToolCalls(JsonArray toolCalls) {
        this.toolCalls = toolCalls;
    }

    public String getToolCallId() {
        return toolCallId;
    }

    public void setToolCallId(String toolCallId) {
        this.toolCallId = toolCallId;
    }

    public static class FunctionCall {
        private String name;
        private JsonNode arguments;

        public String getName() {
            return name;
        }

        public JsonNode getArguments() {
            return arguments;
        }
    }

    public static class ChatMessageRole {
        public static final String SYSTEM = "system";
        public static final String USER = "user";
        public static final String ASSISTANT = "assistant";
        public static final String FUNCTION = "function";
        public static final String TOOL = "tool";
    }
}