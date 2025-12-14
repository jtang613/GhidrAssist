package ghidrassist.core;

/**
 * Information about an indexed RAG document.
 */
public class RAGDocumentInfo {
    private String filename;
    private long sizeBytes;
    private int chunkCount;

    public RAGDocumentInfo(String filename, long sizeBytes, int chunkCount) {
        this.filename = filename;
        this.sizeBytes = sizeBytes;
        this.chunkCount = chunkCount;
    }

    public String getFilename() {
        return filename;
    }

    public long getSizeBytes() {
        return sizeBytes;
    }

    public int getChunkCount() {
        return chunkCount;
    }

    /**
     * Get formatted file size string (e.g., "5.6 KB", "1.2 MB").
     */
    public String getFormattedSize() {
        if (sizeBytes < 0) {
            return "N/A";
        }
        if (sizeBytes < 1024) {
            return sizeBytes + " B";
        } else if (sizeBytes < 1024 * 1024) {
            return String.format("%.1f KB", sizeBytes / 1024.0);
        } else if (sizeBytes < 1024 * 1024 * 1024) {
            return String.format("%.1f MB", sizeBytes / (1024.0 * 1024));
        } else {
            return String.format("%.1f GB", sizeBytes / (1024.0 * 1024 * 1024));
        }
    }
}
