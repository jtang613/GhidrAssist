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

public class RAGEngine {

    private Directory indexDirectory;
    private Analyzer analyzer;
    private IndexWriter indexWriter;

    public RAGEngine() throws IOException {
        // Read the index path from preferences
        String indexPath = Preferences.getProperty("GhidrAssist.LuceneIndexPath", "");
        if (indexPath == null || indexPath.isEmpty()) {
            throw new IOException("Lucene index path is not set in preferences.");
        }
        initializeIndex(indexPath);
    }

    /**
     * Initializes the Lucene index at the specified path.
     */
    public void initializeIndex(String indexPath) throws IOException {
        Path path = Paths.get(indexPath);
        indexDirectory = FSDirectory.open(path);

        analyzer = new StandardAnalyzer();
        IndexWriterConfig config = new IndexWriterConfig(analyzer);

        indexWriter = new IndexWriter(indexDirectory, config);
    }

    /**
     * Ingests and indexes a list of files with chunked content.
     */
    public void ingestDocuments(List<File> files) throws IOException {
        for (File file : files) {
            String content = readFileContent(file);
            if (content != null && !content.isEmpty()) {
                List<String> chunks = chunkContent(content);
                for (int i = 0; i < chunks.size(); i++) {
                    Document doc = new Document();
                    doc.add(new StringField("filename", file.getName(), Field.Store.YES));
                    doc.add(new IntPoint("chunk_id", i)); // Indexed but not stored
                    doc.add(new StoredField("chunk_id", i)); // Stored for retrieval
                    doc.add(new TextField("content", chunks.get(i), Field.Store.YES));
                    indexWriter.addDocument(doc);
                }
            }
        }
        indexWriter.commit();
    }

    /**
     * Splits content into chunks based on the specified criteria.
     */
    private List<String> chunkContent(String content) {
        List<String> chunks = new ArrayList<>();
        int start = 0;
        while (start < content.length()) {
            int end = start + 1000;
            if (end >= content.length()) {
                chunks.add(content.substring(start));
                break;
            }
            // Look for the next "\n\n" after position end
            int splitPos = content.indexOf("\n\n", end);
            if (splitPos == -1) {
                // No more "\n\n", take the rest of the content
                chunks.add(content.substring(start));
                break;
            } else {
                // Include up to splitPos + 2 (length of "\n\n")
                chunks.add(content.substring(start, splitPos + 2));
                start = splitPos + 2;
            }
        }
        return chunks;
    }

    /**
     * Deletes a document and all its related chunks from the index by file name.
     */
    public void deleteDocument(String fileName) throws IOException {
        Term term = new Term("filename", fileName);
        indexWriter.deleteDocuments(term);
        indexWriter.commit();
    }

    /**
     * Searches the index based on a text prompt.
     */
    private static final int MAX_SNIPPET_LENGTH = 500;

    public List<SearchResult> search(String queryStr, int maxResults) throws Exception {
        List<SearchResult> results = new ArrayList<>();

        try (DirectoryReader reader = DirectoryReader.open(indexWriter)) {
            IndexSearcher searcher = new IndexSearcher(reader);

            // Use BM25Similarity for better relevance scoring
            searcher.setSimilarity(new BM25Similarity());

            // Create a multi-field query
            BooleanQuery.Builder queryBuilder = new BooleanQuery.Builder();

            // Add content field query with higher boost
            QueryParser contentParser = new QueryParser("content", analyzer);
            Query contentQuery = contentParser.parse(QueryParser.escape(queryStr));
            queryBuilder.add(new BoostQuery(contentQuery, 2.0f), BooleanClause.Occur.SHOULD);

            // Add filename field query
            QueryParser filenameParser = new QueryParser("filename", analyzer);
            Query filenameQuery = filenameParser.parse(QueryParser.escape(queryStr));
            queryBuilder.add(filenameQuery, BooleanClause.Occur.SHOULD);

            // Execute the query
            TopDocs topDocs = searcher.search(queryBuilder.build(), maxResults * 3); // Fetch more results initially

            // Post-processing for better snippet generation and result ranking
            List<ScoreDoc> scoreDocs = Arrays.asList(topDocs.scoreDocs);
            scoreDocs.sort((a, b) -> Float.compare(b.score, a.score)); // Sort by descending score

            Set<String> uniqueFiles = new HashSet<>();
            for (ScoreDoc sd : scoreDocs) {
                Document doc = searcher.storedFields().document(sd.doc);
                String filename = doc.get("filename");
                String content = doc.get("content");
                int chunkId = doc.getField("chunk_id").numericValue().intValue();

                // Ensure we don't have duplicate files in the results
                if (!uniqueFiles.contains(filename) && uniqueFiles.size() < maxResults) {
                    String snippet = generateSnippet(content, queryStr);
                    results.add(new SearchResult(filename, snippet, sd.score, chunkId));
                    uniqueFiles.add(filename);
                }
            }
        }

        return results;
    }

    private String generateSnippet(String content, String query) {
        // Simple snippet generation: find the first occurrence of any query term
        String[] queryTerms = query.toLowerCase().split("\\s+");
        int bestPosition = content.length();
        for (String term : queryTerms) {
            int pos = content.toLowerCase().indexOf(term);
            if (pos != -1 && pos < bestPosition) {
                bestPosition = pos;
            }
        }

        // Extract snippet around the best position
        int start = Math.max(0, bestPosition - MAX_SNIPPET_LENGTH / 2);
        int end = Math.min(content.length(), start + MAX_SNIPPET_LENGTH);
        String snippet = content.substring(start, end);

        // Add ellipsis if necessary
        if (start > 0) snippet = "..." + snippet;
        if (end < content.length()) snippet = snippet + "...";

        return snippet;
    }

    /**
     * Lists the files currently indexed.
     */
    public List<String> listIndexedFiles() throws IOException {
        List<String> fileNames = new ArrayList<>();

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
        }

        return fileNames.stream().distinct().collect(Collectors.toList());
    }


    /**
     * Closes the index writer and directory.
     */
    public void close() throws IOException {
        if (indexWriter != null) {
            indexWriter.close();
        }
        if (indexDirectory != null) {
            indexDirectory.close();
        }
    }

    /**
     * Reads the content of a file.
     */
    private String readFileContent(File file) throws IOException {
        StringBuilder contentBuilder = new StringBuilder();

        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = br.readLine()) != null) {
                contentBuilder.append(line).append(System.lineSeparator());
            }
        }

        return contentBuilder.toString();
    }

    /**
     * Represents a search result.
     */
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
