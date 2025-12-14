package ghidrassist.core;

import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.standard.StandardAnalyzer;
import org.apache.lucene.document.*;
import org.apache.lucene.index.*;
import org.apache.lucene.queryparser.classic.QueryParser;
import org.apache.lucene.search.*;
import org.apache.lucene.search.similarities.BM25Similarity;
import org.apache.lucene.store.*;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

import ghidra.framework.preferences.Preferences;
import ghidrassist.GAUtils;
import ghidrassist.GhidrAssistPlugin;
import ghidrassist.apiprovider.APIProvider;
import ghidrassist.apiprovider.APIProviderConfig;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

public class RAGEngine {
    private static Directory indexDirectory;
    private static Analyzer analyzer;
    private static IndexWriter indexWriter;
    private static ReentrantLock indexLock = new ReentrantLock();
    private static final int MAX_SNIPPET_LENGTH = 500;
    private static final int MAX_CACHE_SIZE = 1000; // Adjust based on your needs
    private static Cache<String, double[]> embeddingCache = CacheBuilder.newBuilder()
        .maximumSize(MAX_CACHE_SIZE)
        .expireAfterWrite(24, TimeUnit.HOURS)
        .build();

    static {
        try {
            initialize();
        } catch (IOException e) {
            throw new RuntimeException("Failed to initialize RAGEngine", e);
        }
    }

    private static void initialize() throws IOException {
        String indexPath = Preferences.getProperty("GhidrAssist.LuceneIndexPath", "");
        GAUtils.OperatingSystem os = GAUtils.OperatingSystem.detect();

        if (indexPath == null || indexPath.isEmpty()) {
            indexPath = GAUtils.getDefaultLucenePath(os);
            System.out.println("No index path specified. Using default: " + indexPath);
            Files.createDirectories(Paths.get(indexPath));
        }
        
        initializeIndex(indexPath);
    }

    private static void initializeIndex(String indexPath) throws IOException {
        Path path = Paths.get(indexPath);
        indexDirectory = FSDirectory.open(path);
        analyzer = new StandardAnalyzer();
        IndexWriterConfig config = new IndexWriterConfig(analyzer);
        indexWriter = new IndexWriter(indexDirectory, config);

        // Load persisted embeddings into cache
        loadEmbeddingsFromIndex();
    }

    /**
     * Load embeddings from Lucene index into memory cache.
     * Called during initialization to restore embeddings after restart.
     */
    private static void loadEmbeddingsFromIndex() throws IOException {
        indexLock.lock();
        try (DirectoryReader reader = DirectoryReader.open(indexWriter)) {
            StoredFields storedFields = reader.storedFields();
            for (int i = 0; i < reader.maxDoc(); i++) {
                Document doc = storedFields.document(i);
                String filename = doc.get("filename");
                IndexableField chunkIdField = doc.getField("chunk_id");
                String embeddingStr = doc.get("embedding");

                if (filename != null && chunkIdField != null && embeddingStr != null && !embeddingStr.isEmpty()) {
                    int chunkId = chunkIdField.numericValue().intValue();
                    double[] embedding = deserializeEmbedding(embeddingStr);
                    if (embedding != null) {
                        String chunkKey = filename + "_" + chunkId;
                        embeddingCache.put(chunkKey, embedding);
                    }
                }
            }
            System.out.println("Loaded " + embeddingCache.size() + " embeddings from index");
        } finally {
            indexLock.unlock();
        }
    }

    /**
     * Serialize embedding array to string for storage.
     */
    private static String serializeEmbedding(double[] embedding) {
        if (embedding == null || embedding.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < embedding.length; i++) {
            if (i > 0) sb.append(",");
            sb.append(embedding[i]);
        }
        return sb.toString();
    }

    /**
     * Deserialize embedding string back to array.
     */
    private static double[] deserializeEmbedding(String str) {
        if (str == null || str.isEmpty()) {
            return null;
        }
        String[] parts = str.split(",");
        double[] embedding = new double[parts.length];
        for (int i = 0; i < parts.length; i++) {
            embedding[i] = Double.parseDouble(parts[i]);
        }
        return embedding;
    }

    private static APIProvider getProvider() {
        APIProviderConfig config = GhidrAssistPlugin.getCurrentProviderConfig();
        if (config == null) {
            throw new RuntimeException("No API provider configured");
        }
        return config.createProvider();
    }

    public static void ingestDocuments(List<File> files) throws IOException {
        APIProvider provider = getProvider();

        indexLock.lock();
        try {
            for (File file : files) {
                String content = readFileContent(file);
                if (content != null && !content.isEmpty()) {
                    List<String> chunks = chunkContent(content);
                    long fileSize = file.length();  // Store original file size

                    for (int i = 0; i < chunks.size(); i++) {
                        String chunk = chunks.get(i);

                        // Generate embedding synchronously
                        double[] embedding = null;
                        try {
                            embedding = provider.getEmbeddings(chunk);
                        } catch (Exception e) {
                            System.err.println("Warning: Failed to generate embedding for chunk " + i + ": " + e.getMessage());
                        }

                        // Create document with all fields including embedding
                        Document doc = new Document();
                        doc.add(new StringField("filename", file.getName(), Field.Store.YES));
                        doc.add(new IntPoint("chunk_id", i));
                        doc.add(new StoredField("chunk_id", i));
                        doc.add(new StoredField("file_size", fileSize));
                        doc.add(new TextField("content", chunk, Field.Store.YES));

                        // Store embedding as serialized string (persists to disk)
                        if (embedding != null) {
                            String embeddingStr = serializeEmbedding(embedding);
                            doc.add(new StoredField("embedding", embeddingStr));

                            // Also add to cache for immediate use
                            String chunkKey = file.getName() + "_" + i;
                            embeddingCache.put(chunkKey, embedding);
                        }

                        indexWriter.addDocument(doc);
                    }
                }
            }

            indexWriter.commit();
        } finally {
            indexLock.unlock();
        }
    }

    public static List<SearchResult> hybridSearch(String queryStr, int maxResults) throws Exception {
        List<SearchResult> results = new ArrayList<>();
        APIProvider provider = getProvider();

        // Step 1: Generate embedding for the query
        double[] queryEmbedding = provider.getEmbeddings(queryStr);

        // Step 2: Retrieve the closest vector matches
        List<VectorSearchResult> vectorResults = searchSimilar(queryEmbedding, maxResults);

        // Step 3: Run BM25-based keyword search using Lucene
        List<SearchResult> keywordResults = search(queryStr, maxResults);

        // Step 4: Combine both result sets
        results.addAll(vectorResults.stream()
            .map(vr -> new SearchResult(vr.getFilename(), vr.getSnippet(), vr.getScore(), vr.getChunkId()))
            .collect(Collectors.toList()));
        results.addAll(keywordResults);

        // Sort by score and limit results
        return results.stream()
            .sorted((a, b) -> Double.compare(b.getScore(), a.getScore()))
            .limit(maxResults)
            .collect(Collectors.toList());
    }

    private static final double SEMANTIC_MIN_THRESHOLD = 0.50;  // Low floor - just filter noise
    private static final double SEMANTIC_RELATIVE_THRESHOLD = 0.95;  // Must be within 95% of top score
    private static final int SEMANTIC_MAX_RESULTS = 5;  // Hard limit on semantic results

    private static List<VectorSearchResult> searchSimilar(double[] queryEmbedding, int maxResults) {
        // First pass: collect all candidates above minimum threshold, sorted by score
        List<VectorSearchResult> candidates = embeddingCache.asMap().entrySet().stream()
            .map(entry -> {
                String key = entry.getKey();
                double[] embedding = entry.getValue();
                double similarity = cosineSimilarity(queryEmbedding, embedding);

                String[] keyParts = key.split("_");
                String filename = keyParts[0];
                int chunkId = Integer.parseInt(keyParts[1]);

                try {
                    String snippet = getSnippetFromIndex(filename, chunkId);
                    return new VectorSearchResult(filename, snippet, similarity, chunkId);
                } catch (IOException e) {
                    return null;
                }
            })
            .filter(result -> result != null && result.getScore() >= SEMANTIC_MIN_THRESHOLD)
            .sorted((a, b) -> Double.compare(b.getScore(), a.getScore()))
            .collect(Collectors.toList());

        if (candidates.isEmpty()) {
            return candidates;
        }

        // Apply relative threshold: only keep results within 95% of top score
        double topScore = candidates.get(0).getScore();
        double relativeThreshold = topScore * SEMANTIC_RELATIVE_THRESHOLD;

        int limit = Math.min(maxResults, SEMANTIC_MAX_RESULTS);
        return candidates.stream()
            .filter(result -> result.getScore() >= relativeThreshold)
            .limit(limit)
            .collect(Collectors.toList());
    }

    private static double cosineSimilarity(double[] vecA, double[] vecB) {
        double dotProduct = 0.0;
        double normA = 0.0;
        double normB = 0.0;
        for (int i = 0; i < vecA.length; i++) {
            dotProduct += vecA[i] * vecB[i];
            normA += Math.pow(vecA[i], 2);
            normB += Math.pow(vecB[i], 2);
        }
        return dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));
    }

    private static String getSnippetFromIndex(String filename, int chunkId) throws IOException {
        indexLock.lock();
        try (DirectoryReader reader = DirectoryReader.open(indexWriter)) {
            IndexSearcher searcher = new IndexSearcher(reader);
            Query query = new BooleanQuery.Builder()
                    .add(new TermQuery(new Term("filename", filename)), BooleanClause.Occur.MUST)
                    .add(IntPoint.newExactQuery("chunk_id", chunkId), BooleanClause.Occur.MUST)
                    .build();

            TopDocs topDocs = searcher.search(query, 1);
            if (topDocs.totalHits.value == 0) {
                return "";
            }
            StoredFields storedFields = searcher.storedFields();
            Document doc = storedFields.document(topDocs.scoreDocs[0].doc);
            return doc.get("content");
        } finally {
            indexLock.unlock();
        }
    }

    private static List<String> chunkContent(String content) {
        List<String> chunks = new ArrayList<>();
        int start = 0;
        while (start < content.length()) {
            int end = start + 500;
            if (end >= content.length()) {
                chunks.add(content.substring(start));
                break;
            }
            int splitPos = content.indexOf("\n\n", end);
            if (splitPos == -1) {
                chunks.add(content.substring(start));
                break;
            } else {
                chunks.add(content.substring(start, splitPos + 2));
                start = splitPos + 2;
            }
        }
        return chunks;
    }

    private static String readFileContent(File file) throws IOException {
        return new String(Files.readAllBytes(file.toPath()));
    }

    public static List<SearchResult> search(String queryStr, int maxResults) throws Exception {
        List<SearchResult> results = new ArrayList<>();

        indexLock.lock();
        try (DirectoryReader reader = DirectoryReader.open(indexWriter)) {
            IndexSearcher searcher = new IndexSearcher(reader);
            searcher.setSimilarity(new BM25Similarity());

            BooleanQuery.Builder queryBuilder = new BooleanQuery.Builder();

            QueryParser contentParser = new QueryParser("content", analyzer);
            Query contentQuery = contentParser.parse(QueryParser.escape(queryStr));
            queryBuilder.add(new BoostQuery(contentQuery, 2.0f), BooleanClause.Occur.SHOULD);

            QueryParser filenameParser = new QueryParser("filename", analyzer);
            Query filenameQuery = filenameParser.parse(QueryParser.escape(queryStr));
            queryBuilder.add(filenameQuery, BooleanClause.Occur.SHOULD);

            TopDocs topDocs = searcher.search(queryBuilder.build(), maxResults * 3);

            List<ScoreDoc> scoreDocs = Arrays.asList(topDocs.scoreDocs);
            scoreDocs.sort((a, b) -> Float.compare(b.score, a.score));

            Set<String> uniqueFiles = new HashSet<>();
            for (ScoreDoc sd : scoreDocs) {
                Document doc = searcher.storedFields().document(sd.doc);
                String filename = doc.get("filename");
                String content = doc.get("content");
                int chunkId = doc.getField("chunk_id").numericValue().intValue();

                if (!uniqueFiles.contains(filename) && uniqueFiles.size() < maxResults) {
                    String snippet = generateSnippet(content, queryStr);
                    // Normalize BM25 score to 0-1 range using saturation function
                    // This aligns with cosine similarity scoring (also 0-1)
                    double normalizedScore = sd.score / (sd.score + 1.0);
                    results.add(new SearchResult(filename, snippet, normalizedScore, chunkId));
                    uniqueFiles.add(filename);
                }
            }
        } finally {
            indexLock.unlock();
        }

        return results;
    }

    public static List<String> listIndexedFiles() throws IOException {
        List<String> files = new ArrayList<>();
        indexLock.lock();
        try (DirectoryReader reader = DirectoryReader.open(indexWriter)) {
            for (int i = 0; i < reader.maxDoc(); i++) {
            	StoredFields readerStoredFields = reader.storedFields();
            	Document doc = readerStoredFields.document(i);
                String filename = doc.get("filename");
                if (!files.contains(filename)) {
                    files.add(filename);
                }
            }
        } finally {
            indexLock.unlock();
        }
        return files;
    }

    public static void deleteDocument(String filename) throws IOException {
        indexLock.lock();
        try {
            Term term = new Term("filename", filename);
            indexWriter.deleteDocuments(term);
            indexWriter.commit();
            // Also remove embeddings from cache
            embeddingCache.asMap().entrySet().removeIf(entry -> entry.getKey().startsWith(filename + "_"));
        } finally {
            indexLock.unlock();
        }
    }

    /**
     * Get the chunk count for a specific document.
     * @param filename The document filename
     * @return Number of chunks for this document
     */
    public static int getChunkCount(String filename) throws IOException {
        indexLock.lock();
        try (DirectoryReader reader = DirectoryReader.open(indexWriter)) {
            IndexSearcher searcher = new IndexSearcher(reader);
            Query query = new TermQuery(new Term("filename", filename));
            TopDocs topDocs = searcher.search(query, Integer.MAX_VALUE);
            return (int) topDocs.totalHits.value;
        } finally {
            indexLock.unlock();
        }
    }

    /**
     * Get the total chunk count across all documents.
     * @return Total number of chunks in the index
     */
    public static int getTotalChunkCount() throws IOException {
        indexLock.lock();
        try (DirectoryReader reader = DirectoryReader.open(indexWriter)) {
            return reader.numDocs();
        } finally {
            indexLock.unlock();
        }
    }

    /**
     * Get the number of cached embeddings.
     * @return Number of embeddings in cache
     */
    public static int getEmbeddingCount() {
        return (int) embeddingCache.size();
    }

    /**
     * Get the original file size for a document.
     * @param filename The document filename
     * @return File size in bytes, or -1 if not found
     */
    public static long getDocumentSize(String filename) throws IOException {
        indexLock.lock();
        try (DirectoryReader reader = DirectoryReader.open(indexWriter)) {
            IndexSearcher searcher = new IndexSearcher(reader);
            Query query = new TermQuery(new Term("filename", filename));
            TopDocs topDocs = searcher.search(query, 1);
            if (topDocs.totalHits.value > 0) {
                Document doc = searcher.storedFields().document(topDocs.scoreDocs[0].doc);
                IndexableField sizeField = doc.getField("file_size");
                if (sizeField != null) {
                    return sizeField.numericValue().longValue();
                }
            }
            return -1; // Not found or no size stored (legacy documents)
        } finally {
            indexLock.unlock();
        }
    }

    /**
     * Perform semantic (vector) search using embeddings.
     * @param queryStr The search query
     * @param maxResults Maximum number of results
     * @return List of search results
     */
    public static List<SearchResult> semanticSearch(String queryStr, int maxResults) throws Exception {
        APIProvider provider = getProvider();
        double[] queryEmbedding = provider.getEmbeddings(queryStr);
        List<VectorSearchResult> vectorResults = searchSimilar(queryEmbedding, maxResults);
        return vectorResults.stream()
            .map(vr -> new SearchResult(vr.getFilename(), vr.getSnippet(), vr.getScore(), vr.getChunkId()))
            .collect(Collectors.toList());
    }

    /**
     * Clear the entire index and embedding cache.
     */
    public static void clearIndex() throws IOException {
        indexLock.lock();
        try {
            indexWriter.deleteAll();
            indexWriter.commit();
            embeddingCache.invalidateAll();
        } finally {
            indexLock.unlock();
        }
    }

    private static String generateSnippet(String content, String query) {
        String[] queryTerms = query.toLowerCase().split("\s+");
        int bestPosition = content.length();
        for (String term : queryTerms) {
            int pos = content.toLowerCase().indexOf(term);
            if (pos != -1 && pos < bestPosition) {
                bestPosition = pos;
            }
        }

        int start = Math.max(0, bestPosition - MAX_SNIPPET_LENGTH / 2);
        int end = Math.min(content.length(), start + MAX_SNIPPET_LENGTH);
        String snippet = content.substring(start, end);

        if (start > 0) snippet = "..." + snippet;
        if (end < content.length()) snippet = snippet + "...";

        return snippet;
    }
}

class EmbeddingData {
    private double[] embedding;
    private String provider;

    public EmbeddingData(double[] embedding, String provider) {
        this.embedding = embedding;
        this.provider = provider;
    }

    public double[] getEmbedding() {
        return embedding;
    }

    public String getProvider() {
        return provider;
    }
}

class VectorSearchResult {
    private String filename;
    private String snippet;
    private double score;
    private int chunkId;

    public VectorSearchResult(String filename, String snippet, double score, int chunkId) {
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
