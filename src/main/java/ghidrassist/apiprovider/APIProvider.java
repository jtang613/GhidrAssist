package ghidrassist.apiprovider;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import ghidrassist.LlmApi;
import okhttp3.OkHttpClient;

public abstract class APIProvider {
    public enum ProviderType {
        OPENAI,
        ANTHROPIC,
        OLLAMA,
        OPENWEBUI,
        LMSTUDIO
    }

    protected final String name;
    protected final String model;
    protected final Integer maxTokens;
    protected final String url;
    protected final String key;
    protected final boolean disableTlsVerification;
    protected final ProviderType type;
    protected final OkHttpClient client;

    public APIProvider(String name, ProviderType type, String model, Integer maxTokens, 
                      String url, String key, boolean disableTlsVerification) {
        this.name = name;
        this.type = type;
        this.model = model;
        this.maxTokens = maxTokens;
        this.url = url.endsWith("/") ? url : url + "/";
        this.key = key;
        this.disableTlsVerification = disableTlsVerification;
        this.client = buildClient();
    }

    // Getters
    public String getName() { return name; }
    public ProviderType getType() { return type; }
    public String getModel() { return model; }
    public Integer getMaxTokens() { return maxTokens; }
    public String getUrl() { return url; }
    public String getKey() { return key; }
    public boolean isDisableTlsVerification() { return disableTlsVerification; }

    protected abstract OkHttpClient buildClient();
    public abstract String createChatCompletion(List<ChatMessage> messages) throws IOException;
    public abstract void streamChatCompletion(List<ChatMessage> messages, LlmApi.LlmResponseHandler handler) throws IOException;
    public abstract String createChatCompletionWithFunctions(List<ChatMessage> messages, List<Map<String, Object>> functions) throws IOException;
    public abstract List<String> getAvailableModels() throws IOException;
    //public abstract double[] getEmbeddings(String text) throws IOException;
    public abstract void getEmbeddingsAsync(String text, EmbeddingCallback callback);

    
    public double[] getEmbeddings(String text) throws IOException {
        CompletableFuture<double[]> future = new CompletableFuture<>();
        
        getEmbeddingsAsync(text, new EmbeddingCallback() {
            @Override
            public void onSuccess(double[] embedding) {
                future.complete(embedding);
            }
            
            @Override
            public void onError(Throwable error) {
                future.completeExceptionally(error);
            }
        });
        
        try {
            return future.get(30, TimeUnit.SECONDS);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            throw new IOException("Failed to get embeddings: " + e.getMessage(), e);
        }
    }

    public interface EmbeddingCallback {
        void onSuccess(double[] embedding);
        void onError(Throwable error);
    }
}