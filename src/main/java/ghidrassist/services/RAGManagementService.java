package ghidrassist.services;

import ghidrassist.core.RAGDocumentInfo;
import ghidrassist.core.RAGEngine;
import ghidrassist.core.SearchResult;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Service for managing RAG (Retrieval Augmented Generation) documents.
 * Responsible for document ingestion, deletion, and listing operations.
 */
public class RAGManagementService {
    
    /**
     * Add documents to the RAG index
     */
    public void addDocuments(File[] files) throws IOException {
        if (files == null || files.length == 0) {
            throw new IllegalArgumentException("No files provided for ingestion.");
        }
        
        RAGEngine.ingestDocuments(Arrays.asList(files));
    }
    
    /**
     * Delete selected documents from the RAG index
     */
    public void deleteDocuments(List<String> fileNames) throws IOException {
        if (fileNames == null || fileNames.isEmpty()) {
            throw new IllegalArgumentException("No documents selected for deletion.");
        }
        
        for (String fileName : fileNames) {
            RAGEngine.deleteDocument(fileName);
        }
    }
    
    /**
     * Get list of indexed files
     */
    public List<String> getIndexedFiles() throws IOException {
        return RAGEngine.listIndexedFiles();
    }
    
    /**
     * Check if the RAG index is available and working
     */
    public boolean isRAGAvailable() {
        try {
            RAGEngine.listIndexedFiles();
            return true;
        } catch (IOException e) {
            return false;
        }
    }
    
    /**
     * Get RAG index statistics
     */
    public RAGIndexStats getIndexStats() throws IOException {
        List<String> files = getIndexedFiles();
        int chunkCount = RAGEngine.getTotalChunkCount();
        int embeddingCount = RAGEngine.getEmbeddingCount();
        return new RAGIndexStats(files.size(), chunkCount, embeddingCount, files);
    }

    /**
     * Get detailed document list with metadata (filename, size, chunk count).
     */
    public List<RAGDocumentInfo> getIndexedDocumentsWithInfo() throws IOException {
        List<RAGDocumentInfo> docs = new ArrayList<>();
        List<String> files = getIndexedFiles();

        for (String filename : files) {
            long size = RAGEngine.getDocumentSize(filename);
            int chunks = RAGEngine.getChunkCount(filename);
            docs.add(new RAGDocumentInfo(filename, size, chunks));
        }

        return docs;
    }

    /**
     * Perform hybrid search (combines vector and keyword search).
     */
    public List<SearchResult> searchHybrid(String query, int maxResults) throws Exception {
        return RAGEngine.hybridSearch(query, maxResults);
    }

    /**
     * Perform semantic (vector-based) search.
     */
    public List<SearchResult> searchSemantic(String query, int maxResults) throws Exception {
        return RAGEngine.semanticSearch(query, maxResults);
    }

    /**
     * Perform keyword (BM25) search.
     */
    public List<SearchResult> searchKeyword(String query, int maxResults) throws Exception {
        return RAGEngine.search(query, maxResults);
    }

    /**
     * Clear all documents from the RAG index
     */
    public void clearAllDocuments() throws IOException {
        RAGEngine.clearIndex();
    }

    /**
     * Statistics about the RAG index
     */
    public static class RAGIndexStats {
        private final int totalFiles;
        private final int totalChunks;
        private final int totalEmbeddings;
        private final List<String> fileNames;

        public RAGIndexStats(int totalFiles, int totalChunks, int totalEmbeddings, List<String> fileNames) {
            this.totalFiles = totalFiles;
            this.totalChunks = totalChunks;
            this.totalEmbeddings = totalEmbeddings;
            this.fileNames = fileNames;
        }

        public int getTotalFiles() { return totalFiles; }
        public int getTotalChunks() { return totalChunks; }
        public int getTotalEmbeddings() { return totalEmbeddings; }
        public List<String> getFileNames() { return fileNames; }

        @Override
        public String toString() {
            return String.format("RAG Index: %d files, %d chunks, %d embeddings",
                    totalFiles, totalChunks, totalEmbeddings);
        }
    }
}