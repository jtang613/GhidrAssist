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
import ghidrassist.apiprovider.APIProvider.EmbeddingCallback;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
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
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<IOException> error = new AtomicReference<>();
        
        indexLock.lock();
        try {
            for (File file : files) {
                String content = readFileContent(file);
                if (content != null && !content.isEmpty()) {
                    List<String> chunks = chunkContent(content);
                    for (int i = 0; i < chunks.size(); i++) {
                        String chunk = chunks.get(i);
                        Document doc = new Document();
                        doc.add(new StringField("filename", file.getName(), Field.Store.YES));
                        doc.add(new IntPoint("chunk_id", i));
                        doc.add(new StoredField("chunk_id", i));
                        doc.add(new TextField("content", chunk, Field.Store.YES));
                        indexWriter.addDocument(doc);

                        final int chunkIndex = i;
                        provider.getEmbeddingsAsync(chunk, new EmbeddingCallback() {
                            @Override
                            public void onSuccess(double[] embedding) {
                                String chunkKey = file.getName() + "_" + chunkIndex;
                                embeddingCache.put(chunkKey, embedding);
                                if (chunkIndex == chunks.size() - 1) {
                                    latch.countDown();
                                }
                            }
                            
                            @Override
                            public void onError(Throwable e) {
                                error.set(new IOException("Failed to generate embeddings", e));
                                latch.countDown();
                            }
                        });
                    }
                }
            }
            
            // Wait for embeddings with timeout
            if (!latch.await(2, TimeUnit.MINUTES)) {
                throw new IOException("Timeout waiting for embeddings generation");
            }
            
            if (error.get() != null) {
                throw error.get();
            }
            
            indexWriter.commit();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while generating embeddings", e);
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

    private static List<VectorSearchResult> searchSimilar(double[] queryEmbedding, int maxResults) {
        return embeddingCache.asMap().entrySet().stream()
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
            .filter(result -> result != null && result.getScore() > 0.5)
            .sorted((a, b) -> Double.compare(b.getScore(), a.getScore()))
            .limit(maxResults)
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
                    results.add(new SearchResult(filename, snippet, sd.score/100, chunkId));
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

class SearchResult {
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
