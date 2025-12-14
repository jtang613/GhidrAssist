package ghidrassist.core;

/**
 * Search result from RAG queries.
 */
public class SearchResult {
    private String filename;
    private String snippet;
    private double score;
    private int chunkId;

    public SearchResult(String filename, String snippet, double score, int chunkId) {
        this.filename = filename;
        this.snippet = snippet;
        this.score = score;
        this.chunkId = chunkId;
    }

    public String getFilename() { return filename; }
    public String getSnippet() { return snippet; }
    public double getScore() { return score; }
    public int getChunkId() { return chunkId; }
}
