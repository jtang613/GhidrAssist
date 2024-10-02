package ghidrassist;

import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.standard.StandardAnalyzer;
import org.apache.lucene.document.*;
import org.apache.lucene.index.*;
import org.apache.lucene.queryparser.classic.QueryParser;
import org.apache.lucene.search.*;
import org.apache.lucene.search.similarities.BM25Similarity;
import org.apache.lucene.store.*;
import org.apache.lucene.util.BytesRef;

import ghidra.framework.preferences.Preferences;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;
import java.util.concurrent.locks.ReentrantLock;

public class RAGEngine {

    private static Directory indexDirectory;
    private static Analyzer analyzer;
    private static IndexWriter indexWriter;
    private static ReentrantLock indexLock = new ReentrantLock();

    private static final int MAX_SNIPPET_LENGTH = 500;

    static {
        try {
            initialize();
        } catch (IOException e) {
            throw new RuntimeException("Failed to initialize RAGEngine", e);
        }
    }

    private static void initialize() throws IOException {
        String indexPath = Preferences.getProperty("GhidrAssist.LuceneIndexPath", "");
        if (indexPath == null || indexPath.isEmpty()) {
            throw new IOException("Lucene index path is not set in preferences.");
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

    public static void ingestDocuments(List<File> files) throws IOException {
        indexLock.lock();
        try {
            for (File file : files) {
                String content = readFileContent(file);
                if (content != null && !content.isEmpty()) {
                    List<String> chunks = chunkContent(content);
                    for (int i = 0; i < chunks.size(); i++) {
                        Document doc = new Document();
                        doc.add(new StringField("filename", file.getName(), Field.Store.YES));
                        doc.add(new IntPoint("chunk_id", i));
                        doc.add(new StoredField("chunk_id", i));
                        doc.add(new TextField("content", chunks.get(i), Field.Store.YES));
                        indexWriter.addDocument(doc);
                    }
                }
            }
            indexWriter.commit();
        } finally {
            indexLock.unlock();
        }
    }

    private static List<String> chunkContent(String content) {
        List<String> chunks = new ArrayList<>();
        int start = 0;
        while (start < content.length()) {
            int end = start + 1000;
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

    public static void deleteDocument(String fileName) throws IOException {
        indexLock.lock();
        try {
            Term term = new Term("filename", fileName);
            indexWriter.deleteDocuments(term);
            indexWriter.commit();
        } finally {
            indexLock.unlock();
        }
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
                    results.add(new SearchResult(filename, snippet, sd.score, chunkId));
                    uniqueFiles.add(filename);
                }
            }
        } finally {
            indexLock.unlock();
        }

        return results;
    }

    private static String generateSnippet(String content, String query) {
        String[] queryTerms = query.toLowerCase().split("\\s+");
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

    public static List<String> listIndexedFiles() throws IOException {
        List<String> fileNames = new ArrayList<>();

        indexLock.lock();
        try (DirectoryReader reader = DirectoryReader.open(indexWriter)) {
            for (LeafReaderContext context : reader.leaves()) {
                LeafReader leafReader = context.reader();

                Terms terms = leafReader.terms("filename");

                if (terms != null) {
                    TermsEnum termsEnum = terms.iterator();
                    BytesRef byteRef;
                    while ((byteRef = termsEnum.next()) != null) {
                        String fileName = byteRef.utf8ToString();
                        fileNames.add(fileName);
                    }
                }
            }
        } finally {
            indexLock.unlock();
        }

        return fileNames.stream().distinct().collect(Collectors.toList());
    }

    public static void close() {
        indexLock.lock();
        try {
            if (indexWriter != null) {
                indexWriter.close();
            }
            if (indexDirectory != null) {
                indexDirectory.close();
            }
        } catch (Exception e) {
            // Log the exception
        } finally {
            indexLock.unlock();
        }
    }

    private static String readFileContent(File file) throws IOException {
        StringBuilder contentBuilder = new StringBuilder();

        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = br.readLine()) != null) {
                contentBuilder.append(line).append(System.lineSeparator());
            }
        }

        return contentBuilder.toString();
    }

    public static class SearchResult {
        private String fileName;
        private String contentSnippet;
        private float score;
        private int chunkId;

        public SearchResult(String fileName, String contentSnippet, float score, int chunkId) {
            this.fileName = fileName;
            this.contentSnippet = contentSnippet;
            this.score = score;
            this.chunkId = chunkId;
        }

        public String getFileName() {
            return fileName;
        }

        public String getContentSnippet() {
            return contentSnippet;
        }

        public float getScore() {
            return score;
        }

        public int getChunkId() {
            return chunkId;
        }
    }
}