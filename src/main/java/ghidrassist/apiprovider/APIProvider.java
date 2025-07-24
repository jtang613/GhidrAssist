package ghidrassist.apiprovider;

import java.io.IOException;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import javax.net.ssl.SSLException;

import ghidrassist.LlmApi;
import ghidrassist.apiprovider.capabilities.ChatProvider;
import ghidrassist.apiprovider.exceptions.*;
import okhttp3.OkHttpClient;
import okhttp3.Response;

public abstract class APIProvider implements ChatProvider {
    public enum ProviderType {
        OPENAI,
        ANTHROPIC,
        OLLAMA,
        OPENWEBUI,
        LMSTUDIO,
        AZURE_OPENAI
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
    protected RetryHandler retryHandler;

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
        this.retryHandler = new RetryHandler(3, this);
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
    public abstract String createChatCompletion(List<ChatMessage> messages) throws APIProviderException;
    public abstract void streamChatCompletion(List<ChatMessage> messages, LlmApi.LlmResponseHandler handler) throws APIProviderException;
    public abstract String createChatCompletionWithFunctions(List<ChatMessage> messages, List<Map<String, Object>> functions) throws APIProviderException;
    public abstract String createChatCompletionWithFunctionsFullResponse(List<ChatMessage> messages, List<Map<String, Object>> functions) throws APIProviderException;
    public abstract List<String> getAvailableModels() throws APIProviderException;
    public abstract void getEmbeddingsAsync(String text, EmbeddingCallback callback);
	public void setTimeout(Integer timeout2) { this.timeout = Duration.ofSeconds(timeout2); }
	public Integer getTimeout() { return this.timeout.toSecondsPart(); }

    
    public double[] getEmbeddings(String text) throws APIProviderException {
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
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new StreamCancelledException(name, "get_embeddings", 
                StreamCancelledException.CancellationReason.USER_REQUESTED, e);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof APIProviderException) {
                throw (APIProviderException) cause;
            }
            throw new APIProviderException(APIProviderException.ErrorCategory.SERVICE_ERROR, 
                name, "get_embeddings", "Failed to get embeddings: " + e.getMessage());
        } catch (TimeoutException e) {
            throw new APIProviderException(APIProviderException.ErrorCategory.TIMEOUT, 
                name, "get_embeddings", "Embedding request timed out");
        }
    }

    public interface EmbeddingCallback {
        void onSuccess(double[] embedding);
        void onError(Throwable error);
    }
    
    /**
     * Handle network-related exceptions and convert to appropriate APIProviderException
     */
    protected APIProviderException handleNetworkError(Exception e, String operation) {
        if (e instanceof SocketTimeoutException) {
            return new NetworkException(name, operation, NetworkException.NetworkErrorType.TIMEOUT, e);
        } else if (e instanceof SSLException) {
            return new NetworkException(name, operation, NetworkException.NetworkErrorType.SSL_ERROR, e);
        } else if (e instanceof ConnectException) {
            return new NetworkException(name, operation, NetworkException.NetworkErrorType.CONNECTION_FAILED, e);
        } else if (e instanceof UnknownHostException) {
            return new NetworkException(name, operation, NetworkException.NetworkErrorType.DNS_ERROR, e);
        } else if (e instanceof IOException && e.getMessage() != null && 
                   e.getMessage().toLowerCase().contains("connection")) {
            return new NetworkException(name, operation, NetworkException.NetworkErrorType.CONNECTION_LOST, e);
        }
        
        // Default network error
        return new NetworkException(name, operation, "Network error: " + e.getMessage());
    }
    
    /**
     * Handle HTTP response errors and convert to appropriate APIProviderException
     */
    protected APIProviderException handleHttpError(Response response, String operation) {
        int statusCode = response.code();
        String responseBody = null;
        
        try {
            if (response.body() != null) {
                responseBody = response.body().string();
            }
        } catch (IOException e) {
            // Ignore errors reading response body
        }
        
        return handleHttpError(response, responseBody, operation);
    }
    
    /**
     * Handle HTTP response errors with preread response body
     */
    protected APIProviderException handleHttpError(Response response, String responseBody, String operation) {
        int statusCode = response.code();
        String apiErrorCode = extractApiErrorCode(responseBody);
        String errorMessage = extractErrorMessage(responseBody, statusCode);
        
        switch (statusCode) {
            case 401:
                return new AuthenticationException(name, operation, statusCode, apiErrorCode, 
                    errorMessage != null ? errorMessage : "Invalid or missing API key");
                    
            case 403:
                return new AuthenticationException(name, operation, statusCode, apiErrorCode, 
                    errorMessage != null ? errorMessage : "API key does not have sufficient permissions");
                    
            case 429:
                Integer retryAfter = extractRetryAfter(response, responseBody);
                return new RateLimitException(name, operation, statusCode, apiErrorCode, 
                    errorMessage != null ? errorMessage : "Rate limit exceeded", retryAfter);
                    
            case 400:
                if (errorMessage != null && errorMessage.toLowerCase().contains("model")) {
                    return new ModelException(name, operation, ModelException.ModelErrorType.MODEL_NOT_FOUND, 
                        statusCode, apiErrorCode);
                } else if (errorMessage != null && errorMessage.toLowerCase().contains("context")) {
                    return new ModelException(name, operation, ModelException.ModelErrorType.CONTEXT_LENGTH_EXCEEDED, 
                        statusCode, apiErrorCode);
                } else if (errorMessage != null && errorMessage.toLowerCase().contains("token")) {
                    return new ModelException(name, operation, ModelException.ModelErrorType.TOKEN_LIMIT_EXCEEDED, 
                        statusCode, apiErrorCode);
                }
                return new APIProviderException(APIProviderException.ErrorCategory.CONFIGURATION, 
                    name, operation, statusCode, apiErrorCode, 
                    errorMessage != null ? errorMessage : "Bad request");
                    
            case 404:
                if (operation.contains("model")) {
                    return new ModelException(name, operation, ModelException.ModelErrorType.MODEL_NOT_FOUND, 
                        statusCode, apiErrorCode);
                }
                return new APIProviderException(APIProviderException.ErrorCategory.CONFIGURATION, 
                    name, operation, statusCode, apiErrorCode, 
                    errorMessage != null ? errorMessage : "Resource not found");
                    
            case 500:
            case 502:
            case 503:
            case 504:
                return new APIProviderException(APIProviderException.ErrorCategory.SERVICE_ERROR, 
                    name, operation, statusCode, apiErrorCode, 
                    errorMessage != null ? errorMessage : "Service error", true, null, null);
                    
            default:
                return new APIProviderException(APIProviderException.ErrorCategory.SERVICE_ERROR, 
                    name, operation, statusCode, apiErrorCode, 
                    errorMessage != null ? errorMessage : "HTTP error " + statusCode);
        }
    }
    
    /**
     * Extract API error code from response body (provider-specific)
     */
    protected String extractApiErrorCode(String responseBody) {
        // Default implementation - subclasses should override for provider-specific logic
        return null;
    }
    
    /**
     * Extract error message from response body (provider-specific)
     */
    protected String extractErrorMessage(String responseBody, int statusCode) {
        // Default implementation - subclasses should override for provider-specific logic
        if (responseBody != null && !responseBody.isEmpty()) {
            // Try to extract a simple error message
            if (responseBody.contains("\"message\"")) {
                try {
                    int start = responseBody.indexOf("\"message\"") + 10;
                    int end = responseBody.indexOf("\"", start + 1);
                    if (end > start) {
                        return responseBody.substring(start + 1, end);
                    }
                } catch (Exception e) {
                    // Ignore parsing errors
                }
            }
            
            // Fallback: return truncated response body
            return responseBody.length() > 200 ? responseBody.substring(0, 200) + "..." : responseBody;
        }
        
        return null;
    }
    
    /**
     * Extract retry-after value from response
     */
    protected Integer extractRetryAfter(Response response, String responseBody) {
        // Check Retry-After header
        String retryAfterHeader = response.header("Retry-After");
        if (retryAfterHeader != null) {
            try {
                return Integer.parseInt(retryAfterHeader);
            } catch (NumberFormatException e) {
                // Ignore parsing errors
            }
        }
        
        // Check for retry-after in response body (provider-specific)
        if (responseBody != null && responseBody.contains("retry")) {
            // Basic parsing - subclasses should override for provider-specific logic
            try {
                java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("\"retry.*?(\\d+)");
                java.util.regex.Matcher matcher = pattern.matcher(responseBody);
                if (matcher.find()) {
                    return Integer.parseInt(matcher.group(1));
                }
            } catch (Exception e) {
                // Ignore parsing errors
            }
        }
        
        return null; // No retry-after information found
    }
    
    /**
     * Execute an HTTP request with retry logic for handling rate limits and transient errors
     */
    protected Response executeWithRetry(okhttp3.Request request, String operationName) throws APIProviderException {
        return retryHandler.executeWithRetryCallable(() -> {
            Response response = client.newCall(request).execute();
            if (!response.isSuccessful()) {
                throw handleHttpError(response, operationName);
            }
            return response;
        }, operationName);
    }
    
}