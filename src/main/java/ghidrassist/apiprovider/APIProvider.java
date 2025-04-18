package ghidrassist.apiprovider;

import java.io.IOException;
import java.time.Duration;
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

    protected String name;
    protected String model;
    protected Integer maxTokens;
    protected String url;
    protected String key;
    protected boolean disableTlsVerification;
    protected ProviderType type;
    protected OkHttpClient client;
    protected Duration timeout;

    public APIProvider(String name, ProviderType type, String model, Integer maxTokens, 
                      String url, String key, boolean disableTlsVerification, Integer timeout2) {
        this.name = name;
        this.type = type;
        this.model = model;
        this.maxTokens = maxTokens;
        this.url = url.endsWith("/") ? url : url + "/";
        this.key = key;
        this.disableTlsVerification = disableTlsVerification;
        this.timeout = Duration.ofSeconds(timeout2);
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
	public void setTimeout(Integer timeout2) { this.timeout = Duration.ofSeconds(timeout2); }
	public Integer getTimeout() { return this.timeout.toSecondsPart(); }

    
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