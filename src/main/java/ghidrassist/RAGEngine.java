package ghidrassist;

import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.standard.StandardAnalyzer;
import org.apache.lucene.document.*;
import org.apache.lucene.index.*;
import org.apache.lucene.queryparser.classic.QueryParser;
import org.apache.lucene.search.*;
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
     * Ingests and indexes a list of files.
     */
    public void ingestDocuments(List<File> files) throws IOException {
        for (File file : files) {
            String content = readFileContent(file);
            if (content != null && !content.isEmpty()) {
                Document doc = new Document();
                doc.add(new StringField("filename", file.getName(), Field.Store.YES));
                doc.add(new TextField("content", content, Field.Store.YES));
                // You can add more fields if needed
                indexWriter.addDocument(doc);
            }
        }
        indexWriter.commit();
    }

    /**
     * Deletes a document from the index by file name.
     */
    public void deleteDocument(String fileName) throws IOException {
        Term term = new Term("filename", fileName);
        indexWriter.deleteDocuments(term);
        indexWriter.commit();
    }

    /**
     * Searches the index based on a text prompt.
     */
    public List<SearchResult> search(String queryStr, int maxResults) throws Exception {
        List<SearchResult> results = new ArrayList<>();

        try (DirectoryReader reader = DirectoryReader.open(indexWriter)) {
            IndexSearcher searcher = new IndexSearcher(reader);

            // Use QueryParser for text search
            QueryParser parser = new QueryParser("content", analyzer);
            Query query = parser.parse(QueryParser.escape(queryStr));

            TopDocs topDocs = searcher.search(query, maxResults);

            for (ScoreDoc sd : topDocs.scoreDocs) {
                Document doc = searcher.doc(sd.doc);
                String filename = doc.get("filename");
                String content = doc.get("content");
                results.add(new SearchResult(filename, content, sd.score));
            }
        }

        return results;
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

        public SearchResult(String fileName, String contentSnippet, float score) {
            this.fileName = fileName;
            this.contentSnippet = contentSnippet;
            this.score = score;
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
    }
}
