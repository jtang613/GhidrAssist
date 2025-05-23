package ghidrassist.services;

import ghidrassist.core.RAGEngine;

import java.io.File;
import java.io.IOException;
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
        return new RAGIndexStats(files.size(), files);
    }
    
    /**
     * Clear all documents from the RAG index
     */
    public void clearAllDocuments() throws IOException {
        List<String> allFiles = getIndexedFiles();
        deleteDocuments(allFiles);
    }
    
    /**
     * Statistics about the RAG index
     */
    public static class RAGIndexStats {
        private final int totalFiles;
        private final List<String> fileNames;
        
        public RAGIndexStats(int totalFiles, List<String> fileNames) {
            this.totalFiles = totalFiles;
            this.fileNames = fileNames;
        }
        
        public int getTotalFiles() { return totalFiles; }
        public List<String> getFileNames() { return fileNames; }
        
        @Override
        public String toString() {
            return String.format("RAG Index: %d files indexed", totalFiles);
        }
    }
}