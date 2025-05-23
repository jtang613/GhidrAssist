package ghidrassist.apiprovider.capabilities;

import ghidrassist.apiprovider.APIProvider;

/**
 * Interface for providers that support text embeddings.
 * Not all providers support this capability.
 */
public interface EmbeddingProvider {
    
    /**
     * Generate embeddings for text asynchronously
     * @param text The text to embed
     * @param callback Callback to handle the embedding result
     */
    void getEmbeddingsAsync(String text, APIProvider.EmbeddingCallback callback);
    
    /**
     * Check if this provider supports embeddings
     * @return true if embeddings are supported
     */
    default boolean supportsEmbeddings() {
        return true;
    }
}