package ghidrassist.services.symgraph;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;

import ghidra.framework.preferences.Preferences;
import ghidra.util.Msg;
import ghidrassist.services.symgraph.SymGraphModels.*;
import okhttp3.*;

/**
 * Service for interacting with the SymGraph API.
 * Provides methods for querying, pushing, and pulling symbols and graph data.
 */
public class SymGraphService {
    private static final String TAG = "SymGraphService";
    private static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");
    private static final int TIMEOUT_SECONDS = 120;  // Increased for large uploads
    private static final int CHUNK_SIZE = 500;  // Symbols/nodes per chunk

    // Retry settings for rate limiting (429 responses)
    private static final int MAX_RETRIES = 5;
    private static final long INITIAL_BACKOFF_MS = 1000;  // 1 second
    private static final long MAX_BACKOFF_MS = 30000;     // 30 seconds

    private final Gson gson;
    private OkHttpClient client;

    /**
     * Progress callback interface for chunked operations.
     */
    public interface ProgressCallback {
        void onProgress(int current, int total, String message);
        boolean isCancelled();
    }

    public SymGraphService() {
        // serializeNulls ensures ALL fields are sent, even if null
        this.gson = new GsonBuilder().serializeNulls().create();
        this.client = buildClient();
    }

    /**
     * Rebuild the HTTP client if settings change (e.g., API URL changed).
     */
    public void rebuildClient() {
        this.client = buildClient();
    }

    private OkHttpClient buildClient() {
        OkHttpClient.Builder builder = new OkHttpClient.Builder()
                .connectTimeout(Duration.ofSeconds(30))
                .readTimeout(Duration.ofSeconds(TIMEOUT_SECONDS))
                .writeTimeout(Duration.ofSeconds(TIMEOUT_SECONDS));

        // For localhost development, allow insecure connections
        String apiUrl = getApiUrl();
        if (apiUrl.contains("localhost") || apiUrl.contains("127.0.0.1")) {
            try {
                // Create a trust manager that does not validate certificate chains
                final javax.net.ssl.TrustManager[] trustAllCerts = new javax.net.ssl.TrustManager[]{
                    new javax.net.ssl.X509TrustManager() {
                        @Override
                        public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {}
                        @Override
                        public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {}
                        @Override
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[]{}; }
                    }
                };

                // Install the all-trusting trust manager
                final javax.net.ssl.SSLContext sslContext = javax.net.ssl.SSLContext.getInstance("SSL");
                sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
                final javax.net.ssl.SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

                builder.sslSocketFactory(sslSocketFactory, (javax.net.ssl.X509TrustManager) trustAllCerts[0]);
                builder.hostnameVerifier((hostname, session) -> true);

                Msg.debug(this, TAG + ": Using insecure SSL for localhost development");
            } catch (Exception e) {
                Msg.warn(this, TAG + ": Failed to configure insecure SSL: " + e.getMessage());
            }
        }

        return builder.build();
    }

    // === Settings helpers ===

    public String getApiUrl() {
        String url = Preferences.getProperty("GhidrAssist.SymGraphAPIUrl", "https://api.symgraph.com");
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    public String getApiKey() {
        return Preferences.getProperty("GhidrAssist.SymGraphAPIKey", "");
    }

    public boolean hasApiKey() {
        String key = getApiKey();
        return key != null && !key.trim().isEmpty();
    }

    // === Unauthenticated Operations ===

    /**
     * Check if a binary exists in SymGraph (unauthenticated).
     */
    public boolean checkBinaryExists(String sha256) throws IOException {
        String url = getApiUrl() + "/api/v1/binaries/" + sha256;
        Msg.debug(this, TAG + ": Checking binary existence: " + url);

        Request request = new Request.Builder()
                .url(url)
                .head()
                .addHeader("Accept", "application/json")
                .addHeader("User-Agent", "GhidrAssist-SymGraph/1.0")
                .build();

        try (Response response = client.newCall(request).execute()) {
            return response.isSuccessful();
        }
    }

    /**
     * Get binary statistics from SymGraph (unauthenticated).
     */
    public BinaryStats getBinaryStats(String sha256) throws IOException {
        String url = getApiUrl() + "/api/v1/binaries/" + sha256 + "/stats";
        Msg.debug(this, TAG + ": Getting binary stats: " + url);

        Request request = new Request.Builder()
                .url(url)
                .get()
                .addHeader("Accept", "application/json")
                .addHeader("User-Agent", "GhidrAssist-SymGraph/1.0")
                .build();

        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                if (response.code() == 404) {
                    return null;
                }
                throw new IOException("Unexpected response: " + response.code());
            }

            String body = response.body().string();
            JsonObject json = JsonParser.parseString(body).getAsJsonObject();

            // Stats may be nested inside a "stats" object
            JsonObject statsJson = json.has("stats") && json.get("stats").isJsonObject()
                    ? json.getAsJsonObject("stats")
                    : json;

            BinaryStats stats = new BinaryStats();
            stats.setSymbolCount(getIntOrDefault(statsJson, "symbol_count", 0));
            stats.setFunctionCount(getIntOrDefault(statsJson, "function_count", 0));
            stats.setGraphNodeCount(getIntOrDefault(statsJson, "graph_node_count", 0));
            stats.setQueryCount(getIntOrDefault(statsJson, "query_count", 0));
            // last_queried_at might be at top level even when stats are nested
            String lastQueried = getStringOrNull(json, "last_queried_at");
            if (lastQueried == null) {
                lastQueried = getStringOrNull(statsJson, "last_queried_at");
            }
            stats.setLastQueriedAt(lastQueried);

            return stats;
        }
    }

    /**
     * Query SymGraph for binary info (unauthenticated).
     */
    public QueryResult queryBinary(String sha256) {
        try {
            boolean exists = checkBinaryExists(sha256);
            if (!exists) {
                return QueryResult.notFound();
            }

            BinaryStats stats = getBinaryStats(sha256);
            if (stats != null) {
                return QueryResult.found(stats);
            } else {
                QueryResult result = new QueryResult();
                result.setExists(true);
                return result;
            }
        } catch (Exception e) {
            Msg.error(this, TAG + ": Query error: " + e.getMessage());
            return QueryResult.error(e.getMessage());
        }
    }

    /**
     * Query SymGraph asynchronously.
     */
    public CompletableFuture<QueryResult> queryBinaryAsync(String sha256) {
        return CompletableFuture.supplyAsync(() -> queryBinary(sha256));
    }

    // === Authenticated Operations ===

    /**
     * Get symbols for a binary (authenticated).
     * @param sha256 SHA256 hash of the binary
     * @param symbolType Optional symbol type filter (e.g., "function", "data", "type"). Pass null for all symbols.
     */
    public List<Symbol> getSymbols(String sha256, String symbolType) throws IOException, SymGraphAuthException {
        checkAuthRequired();

        String url = getApiUrl() + "/api/v1/binaries/" + sha256 + "/symbols";
        if (symbolType != null && !symbolType.isEmpty()) {
            url += "?type=" + symbolType;
        }
        Msg.debug(this, TAG + ": Getting symbols: " + url);

        Request request = new Request.Builder()
                .url(url)
                .get()
                .addHeader("Accept", "application/json")
                .addHeader("X-API-Key", getApiKey())
                .addHeader("User-Agent", "GhidrAssist-SymGraph/1.0")
                .build();

        try (Response response = client.newCall(request).execute()) {
            if (response.code() == 401) {
                throw new SymGraphAuthException("Invalid API key");
            }
            if (response.code() == 404) {
                return new ArrayList<>();
            }
            if (!response.isSuccessful()) {
                throw new IOException("Error getting symbols: " + response.code());
            }

            String body = response.body().string();
            JsonObject json = JsonParser.parseString(body).getAsJsonObject();

            // Handle null or missing symbols safely
            JsonArray symbolsArray = null;
            if (json.has("symbols") && !json.get("symbols").isJsonNull()) {
                symbolsArray = json.getAsJsonArray("symbols");
            } else {
                // Try parsing body as array directly
                JsonElement bodyElement = JsonParser.parseString(body);
                if (bodyElement.isJsonArray()) {
                    symbolsArray = bodyElement.getAsJsonArray();
                }
            }

            // Return empty list if no valid symbols array
            if (symbolsArray == null) {
                return new ArrayList<>();
            }

            List<Symbol> symbols = new ArrayList<>();
            for (JsonElement elem : symbolsArray) {
                JsonObject symObj = elem.getAsJsonObject();
                Symbol symbol = new Symbol();
                symbol.setAddress(getLongOrDefault(symObj, "address", 0));
                symbol.setSymbolType(getStringOrDefault(symObj, "symbol_type", "function"));
                symbol.setName(getStringOrNull(symObj, "name"));
                symbol.setDataType(getStringOrNull(symObj, "data_type"));
                symbol.setConfidence(getDoubleOrDefault(symObj, "confidence", 0.0));
                symbol.setProvenance(getStringOrDefault(symObj, "provenance", "unknown"));
                symbol.setContent(getStringOrNull(symObj, "content"));

                // Parse metadata if present (for variables, comments, structs, enums)
                if (symObj.has("metadata") && !symObj.get("metadata").isJsonNull()) {
                    Map<String, Object> metadata = gson.fromJson(
                            symObj.get("metadata"), new TypeToken<Map<String, Object>>() {}.getType());
                    symbol.setMetadata(metadata);
                }

                symbols.add(symbol);
            }

            return symbols;
        }
    }

    /**
     * Export graph data for a binary (authenticated).
     */
    public GraphExport exportGraph(String sha256) throws IOException, SymGraphAuthException {
        checkAuthRequired();

        String url = getApiUrl() + "/api/v1/binaries/" + sha256 + "/graph/export";
        Msg.debug(this, TAG + ": Exporting graph: " + url);

        Request request = new Request.Builder()
                .url(url)
                .get()
                .addHeader("Accept", "application/json")
                .addHeader("X-API-Key", getApiKey())
                .addHeader("User-Agent", "GhidrAssist-SymGraph/1.0")
                .build();

        try (Response response = client.newCall(request).execute()) {
            if (response.code() == 401) {
                throw new SymGraphAuthException("Invalid API key");
            }
            if (response.code() == 404) {
                return null;
            }
            if (!response.isSuccessful()) {
                throw new IOException("Error exporting graph: " + response.code());
            }

            String body = response.body().string();
            JsonObject json = JsonParser.parseString(body).getAsJsonObject();

            GraphExport export = new GraphExport();
            export.setBinarySha256(getStringOrDefault(json, "binary_sha256", sha256));
            export.setExportVersion(getStringOrDefault(json, "export_version", "1.0"));

            if (json.has("metadata") && json.get("metadata").isJsonObject()) {
                Map<String, Object> metadata = gson.fromJson(
                        json.get("metadata"), new TypeToken<Map<String, Object>>() {}.getType());
                export.setMetadata(metadata);
            }

            List<GraphNode> nodes = new ArrayList<>();
            if (json.has("nodes") && json.get("nodes").isJsonArray()) {
                JsonArray nodesArray = json.getAsJsonArray("nodes");
                for (JsonElement elem : nodesArray) {
                    JsonObject nodeObj = elem.getAsJsonObject();
                    GraphNode node = new GraphNode();
                    node.setId(getStringOrNull(nodeObj, "id"));
                    node.setAddress(getLongOrDefault(nodeObj, "address", 0));
                    node.setNodeType(getStringOrDefault(nodeObj, "node_type", "function"));
                    node.setName(getStringOrNull(nodeObj, "name"));
                    node.setSummary(getStringOrNull(nodeObj, "llm_summary"));

                    // Build properties map from top-level fields AND nested properties
                    // Backend sends RE analysis fields at the top level, not nested in "properties"
                    Map<String, Object> props = new HashMap<>();

                    // First, copy any nested properties object
                    if (nodeObj.has("properties") && nodeObj.get("properties").isJsonObject()) {
                        Map<String, Object> nestedProps = gson.fromJson(
                                nodeObj.get("properties"), new TypeToken<Map<String, Object>>() {}.getType());
                        props.putAll(nestedProps);
                    }

                    // Then parse top-level RE analysis fields (these override nested if present)
                    if (nodeObj.has("raw_content") && !nodeObj.get("raw_content").isJsonNull()) {
                        props.put("raw_content", nodeObj.get("raw_content").getAsString());
                    }
                    if (nodeObj.has("confidence") && !nodeObj.get("confidence").isJsonNull()) {
                        props.put("confidence", nodeObj.get("confidence").getAsDouble());
                    }
                    if (nodeObj.has("security_flags") && !nodeObj.get("security_flags").isJsonNull()) {
                        props.put("security_flags", gson.fromJson(nodeObj.get("security_flags"),
                                new TypeToken<List<String>>() {}.getType()));
                    }
                    if (nodeObj.has("network_apis") && !nodeObj.get("network_apis").isJsonNull()) {
                        props.put("network_apis", gson.fromJson(nodeObj.get("network_apis"),
                                new TypeToken<List<String>>() {}.getType()));
                    }
                    if (nodeObj.has("file_io_apis") && !nodeObj.get("file_io_apis").isJsonNull()) {
                        props.put("file_io_apis", gson.fromJson(nodeObj.get("file_io_apis"),
                                new TypeToken<List<String>>() {}.getType()));
                    }
                    if (nodeObj.has("ip_addresses") && !nodeObj.get("ip_addresses").isJsonNull()) {
                        props.put("ip_addresses", gson.fromJson(nodeObj.get("ip_addresses"),
                                new TypeToken<List<String>>() {}.getType()));
                    }
                    if (nodeObj.has("urls") && !nodeObj.get("urls").isJsonNull()) {
                        props.put("urls", gson.fromJson(nodeObj.get("urls"),
                                new TypeToken<List<String>>() {}.getType()));
                    }
                    if (nodeObj.has("file_paths") && !nodeObj.get("file_paths").isJsonNull()) {
                        props.put("file_paths", gson.fromJson(nodeObj.get("file_paths"),
                                new TypeToken<List<String>>() {}.getType()));
                    }
                    if (nodeObj.has("domains") && !nodeObj.get("domains").isJsonNull()) {
                        props.put("domains", gson.fromJson(nodeObj.get("domains"),
                                new TypeToken<List<String>>() {}.getType()));
                    }
                    if (nodeObj.has("registry_keys") && !nodeObj.get("registry_keys").isJsonNull()) {
                        props.put("registry_keys", gson.fromJson(nodeObj.get("registry_keys"),
                                new TypeToken<List<String>>() {}.getType()));
                    }
                    if (nodeObj.has("risk_level") && !nodeObj.get("risk_level").isJsonNull()) {
                        props.put("risk_level", nodeObj.get("risk_level").getAsString());
                    }
                    if (nodeObj.has("activity_profile") && !nodeObj.get("activity_profile").isJsonNull()) {
                        props.put("activity_profile", nodeObj.get("activity_profile").getAsString());
                    }
                    if (nodeObj.has("analysis_depth") && !nodeObj.get("analysis_depth").isJsonNull()) {
                        props.put("analysis_depth", nodeObj.get("analysis_depth").getAsInt());
                    }

                    node.setProperties(props);
                    nodes.add(node);
                }
            }
            export.setNodes(nodes);

            List<GraphEdge> edges = new ArrayList<>();
            if (json.has("edges") && json.get("edges").isJsonArray()) {
                JsonArray edgesArray = json.getAsJsonArray("edges");
                for (JsonElement elem : edgesArray) {
                    JsonObject edgeObj = elem.getAsJsonObject();
                    GraphEdge edge = new GraphEdge();
                    edge.setSourceAddress(getLongOrDefault(edgeObj, "source_address", 0));
                    edge.setTargetAddress(getLongOrDefault(edgeObj, "target_address", 0));
                    edge.setEdgeType(getStringOrDefault(edgeObj, "edge_type", "calls"));
                    if (edgeObj.has("properties") && edgeObj.get("properties").isJsonObject()) {
                        Map<String, Object> props = gson.fromJson(
                                edgeObj.get("properties"), new TypeToken<Map<String, Object>>() {}.getType());
                        edge.setProperties(props);
                    }
                    edges.add(edge);
                }
            }
            export.setEdges(edges);

            return export;
        }
    }

    /**
     * Push symbols to SymGraph in bulk (authenticated).
     */
    public PushResult pushSymbolsBulk(String sha256, List<Map<String, Object>> symbols) throws IOException, SymGraphAuthException {
        return pushSymbolsBulk(sha256, symbols, null);
    }

    /**
     * Push symbols to SymGraph in bulk with retry support (authenticated).
     */
    public PushResult pushSymbolsBulk(String sha256, List<Map<String, Object>> symbols, ProgressCallback progress) throws IOException, SymGraphAuthException {
        checkAuthRequired();

        String url = getApiUrl() + "/api/v1/binaries/" + sha256 + "/symbols/bulk";
        Msg.debug(this, TAG + ": Pushing " + symbols.size() + " symbols to: " + url);

        Map<String, Object> payload = new HashMap<>();
        payload.put("symbols", symbols);

        RequestBody body = RequestBody.create(gson.toJson(payload), JSON);

        Request request = new Request.Builder()
                .url(url)
                .post(body)
                .addHeader("Content-Type", "application/json")
                .addHeader("Accept", "application/json")
                .addHeader("X-API-Key", getApiKey())
                .addHeader("User-Agent", "GhidrAssist-SymGraph/1.0")
                .build();

        try (Response response = executeWithRetry(request, progress)) {
            if (response.code() == 401) {
                throw new SymGraphAuthException("Invalid API key");
            }
            if (!response.isSuccessful()) {
                String errorBody = response.body() != null ? response.body().string() : "Unknown error";
                return PushResult.failure("Error pushing symbols: " + response.code() + " - " + errorBody);
            }

            String responseBody = response.body().string();
            JsonObject json = JsonParser.parseString(responseBody).getAsJsonObject();
            int symbolsCreated = getIntOrDefault(json, "symbols_created", symbols.size());

            return PushResult.success(symbolsCreated, 0, 0);
        }
    }

    /**
     * Push symbols in chunks with progress reporting (authenticated).
     * Breaks large symbol sets into smaller chunks to avoid timeouts.
     */
    public PushResult pushSymbolsChunked(String sha256, List<Map<String, Object>> symbols, ProgressCallback progress)
            throws IOException, SymGraphAuthException {
        checkAuthRequired();

        if (symbols.isEmpty()) {
            return PushResult.success(0, 0, 0);
        }

        int totalSymbols = symbols.size();
        int totalPushed = 0;
        int chunkIndex = 0;

        Msg.info(this, TAG + ": Pushing " + totalSymbols + " symbols in chunks of " + CHUNK_SIZE);

        for (int i = 0; i < totalSymbols; i += CHUNK_SIZE) {
            // Check for cancellation
            if (progress != null && progress.isCancelled()) {
                Msg.info(this, TAG + ": Push cancelled by user");
                return PushResult.success(totalPushed, 0, 0);
            }

            int end = Math.min(i + CHUNK_SIZE, totalSymbols);
            List<Map<String, Object>> chunk = symbols.subList(i, end);
            chunkIndex++;

            // Report progress
            if (progress != null) {
                progress.onProgress(i, totalSymbols,
                        String.format("Pushing symbols... %d/%d (chunk %d)", i, totalSymbols, chunkIndex));
            }

            // Push this chunk (with retry support)
            PushResult chunkResult = pushSymbolsBulk(sha256, chunk, progress);
            if (!chunkResult.isSuccess()) {
                return PushResult.failure("Chunk " + chunkIndex + " failed: " + chunkResult.getError());
            }

            totalPushed += chunkResult.getSymbolsPushed();
        }

        // Final progress update
        if (progress != null) {
            progress.onProgress(totalSymbols, totalSymbols, "Symbols complete");
        }

        Msg.info(this, TAG + ": Successfully pushed " + totalPushed + " symbols");
        return PushResult.success(totalPushed, 0, 0);
    }

    /**
     * Import graph data in chunks with progress reporting (authenticated).
     * Splits nodes and edges into manageable chunks.
     */
    @SuppressWarnings("unchecked")
    public PushResult importGraphChunked(String sha256, Map<String, Object> graphData, ProgressCallback progress)
            throws IOException, SymGraphAuthException {
        checkAuthRequired();

        List<Map<String, Object>> nodes = (List<Map<String, Object>>) graphData.get("nodes");
        List<Map<String, Object>> edges = (List<Map<String, Object>>) graphData.get("edges");

        if ((nodes == null || nodes.isEmpty()) && (edges == null || edges.isEmpty())) {
            return PushResult.success(0, 0, 0);
        }

        int totalNodes = nodes != null ? nodes.size() : 0;
        int totalEdges = edges != null ? edges.size() : 0;
        int totalItems = totalNodes + totalEdges;
        int processedItems = 0;
        int totalNodesPushed = 0;
        int totalEdgesPushed = 0;

        Msg.info(this, TAG + ": Pushing " + totalNodes + " nodes and " + totalEdges + " edges");

        // Push nodes in chunks
        if (nodes != null && !nodes.isEmpty()) {
            for (int i = 0; i < totalNodes; i += CHUNK_SIZE) {
                if (progress != null && progress.isCancelled()) {
                    Msg.info(this, TAG + ": Push cancelled by user");
                    return PushResult.success(0, totalNodesPushed, totalEdgesPushed);
                }

                int end = Math.min(i + CHUNK_SIZE, totalNodes);
                List<Map<String, Object>> nodeChunk = nodes.subList(i, end);

                if (progress != null) {
                    progress.onProgress(processedItems, totalItems,
                            String.format("Pushing nodes... %d/%d", i, totalNodes));
                }

                Map<String, Object> chunkData = new HashMap<>();
                chunkData.put("nodes", nodeChunk);
                chunkData.put("edges", new ArrayList<>());

                PushResult result = importGraph(sha256, chunkData, progress);
                if (!result.isSuccess()) {
                    return PushResult.failure("Node chunk failed: " + result.getError());
                }

                totalNodesPushed += result.getNodesPushed();
                processedItems += nodeChunk.size();
            }
        }

        // Push edges in chunks
        if (edges != null && !edges.isEmpty()) {
            for (int i = 0; i < totalEdges; i += CHUNK_SIZE) {
                if (progress != null && progress.isCancelled()) {
                    Msg.info(this, TAG + ": Push cancelled by user");
                    return PushResult.success(0, totalNodesPushed, totalEdgesPushed);
                }

                int end = Math.min(i + CHUNK_SIZE, totalEdges);
                List<Map<String, Object>> edgeChunk = edges.subList(i, end);

                if (progress != null) {
                    progress.onProgress(processedItems, totalItems,
                            String.format("Pushing edges... %d/%d", i, totalEdges));
                }

                Map<String, Object> chunkData = new HashMap<>();
                chunkData.put("nodes", new ArrayList<>());
                chunkData.put("edges", edgeChunk);

                PushResult result = importGraph(sha256, chunkData, progress);
                if (!result.isSuccess()) {
                    return PushResult.failure("Edge chunk failed: " + result.getError());
                }

                totalEdgesPushed += result.getEdgesPushed();
                processedItems += edgeChunk.size();
            }
        }

        // Final progress update
        if (progress != null) {
            progress.onProgress(totalItems, totalItems, "Graph complete");
        }

        Msg.info(this, TAG + ": Successfully pushed " + totalNodesPushed + " nodes, " + totalEdgesPushed + " edges");
        return PushResult.success(0, totalNodesPushed, totalEdgesPushed);
    }

    /**
     * Import graph data to SymGraph (authenticated).
     */
    public PushResult importGraph(String sha256, Map<String, Object> graphData) throws IOException, SymGraphAuthException {
        return importGraph(sha256, graphData, null);
    }

    /**
     * Import graph data to SymGraph with retry support (authenticated).
     */
    public PushResult importGraph(String sha256, Map<String, Object> graphData, ProgressCallback progress) throws IOException, SymGraphAuthException {
        checkAuthRequired();

        String url = getApiUrl() + "/api/v1/binaries/" + sha256 + "/graph/import";
        Msg.debug(this, TAG + ": Importing graph to: " + url);

        RequestBody body = RequestBody.create(gson.toJson(graphData), JSON);

        Request request = new Request.Builder()
                .url(url)
                .post(body)
                .addHeader("Content-Type", "application/json")
                .addHeader("Accept", "application/json")
                .addHeader("X-API-Key", getApiKey())
                .addHeader("User-Agent", "GhidrAssist-SymGraph/1.0")
                .build();

        try (Response response = executeWithRetry(request, progress)) {
            if (response.code() == 401) {
                throw new SymGraphAuthException("Invalid API key");
            }
            if (!response.isSuccessful()) {
                String errorBody = response.body() != null ? response.body().string() : "Unknown error";
                return PushResult.failure("Error importing graph: " + response.code() + " - " + errorBody);
            }

            String responseBody = response.body().string();
            JsonObject json = JsonParser.parseString(responseBody).getAsJsonObject();
            int nodesImported = getIntOrDefault(json, "nodes_imported", 0);
            int edgesImported = getIntOrDefault(json, "edges_imported", 0);

            return PushResult.success(0, nodesImported, edgesImported);
        }
    }

    /**
     * Add a fingerprint to a binary (authenticated).
     * Used for debug symbol matching (BuildID for ELF, PDB GUID for PE).
     */
    public boolean addFingerprint(String sha256, String fpType, String fpValue) throws IOException, SymGraphAuthException {
        checkAuthRequired();

        String url = getApiUrl() + "/api/v1/binaries/" + sha256 + "/fingerprints";
        Msg.debug(this, TAG + ": Adding fingerprint " + fpType + "=" + fpValue);

        JsonObject payload = new JsonObject();
        payload.addProperty("type", fpType);
        payload.addProperty("value", fpValue);

        RequestBody body = RequestBody.create(
                payload.toString(),
                MediaType.parse("application/json")
        );

        Request request = new Request.Builder()
                .url(url)
                .post(body)
                .addHeader("Accept", "application/json")
                .addHeader("X-API-Key", getApiKey())
                .addHeader("User-Agent", "GhidrAssist-SymGraph/1.0")
                .build();

        try (Response response = client.newCall(request).execute()) {
            if (response.code() == 401) {
                throw new SymGraphAuthException("Invalid API key");
            }
            if (response.code() == 409) {
                // Fingerprint already exists - not an error
                Msg.debug(this, TAG + ": Fingerprint already exists");
                return true;
            }
            if (!response.isSuccessful()) {
                Msg.warn(this, TAG + ": Failed to add fingerprint: " + response.code());
                return false;
            }
            Msg.info(this, TAG + ": Added fingerprint: " + fpType + "=" + fpValue);
            return true;
        }
    }

    /**
     * Get all symbols for a binary (authenticated).
     * Convenience overload that fetches all symbol types.
     */
    public List<Symbol> getSymbols(String sha256) throws IOException, SymGraphAuthException {
        return getSymbols(sha256, null);
    }

    /**
     * Get symbols asynchronously.
     */
    public CompletableFuture<List<Symbol>> getSymbolsAsync(String sha256) {
        return getSymbolsAsync(sha256, null);
    }

    /**
     * Get symbols asynchronously with optional type filter.
     * @param sha256 SHA256 hash of the binary
     * @param symbolType Optional symbol type filter (e.g., "function"). Pass null for all symbols.
     */
    public CompletableFuture<List<Symbol>> getSymbolsAsync(String sha256, String symbolType) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return getSymbols(sha256, symbolType);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    /**
     * Push symbols asynchronously.
     */
    public CompletableFuture<PushResult> pushSymbolsBulkAsync(String sha256, List<Map<String, Object>> symbols) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return pushSymbolsBulk(sha256, symbols);
            } catch (Exception e) {
                return PushResult.failure(e.getMessage());
            }
        });
    }

    // === Helper Methods ===

    /**
     * Build conflict entries by comparing local and remote symbols.
     * Filters out remote symbols with default/auto-generated names and applies confidence threshold.
     *
     * @param localSymbols Map of address to local symbol name
     * @param remoteSymbols List of remote symbols from the server
     * @param minConfidence Minimum confidence threshold (0.0-1.0) for remote symbols
     * @return List of conflict entries for the merge UI
     */
    public List<ConflictEntry> buildConflictEntries(Map<Long, String> localSymbols, List<Symbol> remoteSymbols, double minConfidence) {
        List<ConflictEntry> conflicts = new ArrayList<>();
        int skippedDefault = 0;
        int skippedConfidence = 0;

        for (Symbol remoteSym : remoteSymbols) {
            // Comments don't require names - they store text in content, not name
            String symbolType = remoteSym.getSymbolType();
            boolean isComment = "comment".equals(symbolType);

            // Skip remote symbols with default/auto-generated names (but not comments)
            if (!isComment && SymGraphUtils.isDefaultName(remoteSym.getName())) {
                skippedDefault++;
                continue;
            }

            // Skip remote symbols below minimum confidence threshold
            if (remoteSym.getConfidence() < minConfidence) {
                skippedConfidence++;
                continue;
            }

            long addr = remoteSym.getAddress();
            String localName = localSymbols.get(addr);
            boolean localIsDefault = SymGraphUtils.isDefaultName(localName);

            if (localName == null || localIsDefault) {
                // Remote only OR local has default name - NEW (safe to apply)
                conflicts.add(ConflictEntry.createNew(addr, remoteSym));
            } else if (localName.equals(remoteSym.getName())) {
                // Same value - SAME
                conflicts.add(ConflictEntry.createSame(addr, localName, remoteSym));
            } else {
                // Different values (both user-defined) - CONFLICT
                conflicts.add(ConflictEntry.createConflict(addr, localName, remoteSym));
            }
        }

        if (skippedDefault > 0 || skippedConfidence > 0) {
            Msg.info(this, String.format("Filtered out %d default names, %d low confidence symbols",
                    skippedDefault, skippedConfidence));
        }

        return conflicts;
    }

    /**
     * Build conflict entries with default minimum confidence of 0.0.
     */
    public List<ConflictEntry> buildConflictEntries(Map<Long, String> localSymbols, List<Symbol> remoteSymbols) {
        return buildConflictEntries(localSymbols, remoteSymbols, 0.0);
    }

    private void checkAuthRequired() throws SymGraphAuthException {
        if (!hasApiKey()) {
            throw new SymGraphAuthException("SymGraph.ai API key not configured. Add your API key in Settings > General > SymGraph");
        }
    }

    /**
     * Execute an HTTP request with retry logic for rate limiting (429) responses.
     * Uses exponential backoff with jitter.
     *
     * @param request The request to execute
     * @param progress Optional progress callback to report retry status
     * @return The successful response
     * @throws IOException If the request fails after all retries
     */
    @SuppressWarnings("unused")  // lastException preserved for debugging/future use
    private Response executeWithRetry(Request request, ProgressCallback progress) throws IOException {
        int attempt = 0;
        long backoffMs = INITIAL_BACKOFF_MS;
        IOException lastException = null;

        while (attempt < MAX_RETRIES) {
            attempt++;

            Response response;
            try {
                response = client.newCall(request).execute();
            } catch (IOException e) {
                // Network error - log and retry
                Msg.warn(this, TAG + ": Network error on attempt " + attempt + ": " + e.getMessage());
                lastException = e;
                if (attempt >= MAX_RETRIES) {
                    throw new IOException("Network error after " + MAX_RETRIES + " retries: " + e.getMessage(), e);
                }
                // Use backoff for network errors too
                sleepWithBackoff(backoffMs, attempt, progress, "Network error");
                backoffMs = Math.min(backoffMs * 2, MAX_BACKOFF_MS);
                continue;
            }

            if (response.code() != 429) {
                // Not rate limited, return the response
                return response;
            }

            // Read Retry-After header BEFORE closing the response
            String retryAfter = response.header("Retry-After");

            // Close the 429 response body
            response.close();

            if (attempt >= MAX_RETRIES) {
                throw new IOException("Rate limited (429) after " + MAX_RETRIES + " retries. Please try again later.");
            }

            // Check for cancellation before sleeping
            if (progress != null && progress.isCancelled()) {
                throw new IOException("Cancelled during rate limit backoff");
            }

            // Calculate wait time from Retry-After header or use exponential backoff
            long waitMs = backoffMs;
            if (retryAfter != null) {
                try {
                    waitMs = Long.parseLong(retryAfter) * 1000;
                } catch (NumberFormatException e) {
                    // Use default backoff
                }
            }

            // Add jitter (±20%)
            long jitter = (long) (waitMs * 0.2 * (Math.random() - 0.5));
            waitMs = Math.min(waitMs + jitter, MAX_BACKOFF_MS);

            Msg.info(this, TAG + ": Rate limited (429), waiting " + waitMs + "ms before retry " + attempt + "/" + MAX_RETRIES);

            // Update progress to show we're waiting
            if (progress != null) {
                final long finalWaitMs = waitMs;
                final int finalAttempt = attempt;
                progress.onProgress(-1, -1, String.format("Rate limited, retrying in %.1fs (%d/%d)...",
                        finalWaitMs / 1000.0, finalAttempt, MAX_RETRIES));
            }

            try {
                Thread.sleep(waitMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted during rate limit backoff");
            }

            // Exponential backoff for next attempt
            backoffMs = Math.min(backoffMs * 2, MAX_BACKOFF_MS);
        }

        // Should never reach here due to throws in loop, but just in case
        throw new IOException("Failed after " + MAX_RETRIES + " attempts");
    }

    /**
     * Sleep with backoff, updating progress and checking for cancellation.
     */
    private void sleepWithBackoff(long backoffMs, int attempt, ProgressCallback progress, String reason) throws IOException {
        // Add jitter (±20%)
        long jitter = (long) (backoffMs * 0.2 * (Math.random() - 0.5));
        long waitMs = Math.min(backoffMs + jitter, MAX_BACKOFF_MS);

        Msg.info(this, TAG + ": " + reason + ", waiting " + waitMs + "ms before retry " + attempt + "/" + MAX_RETRIES);

        // Update progress to show we're waiting
        if (progress != null) {
            progress.onProgress(-1, -1, String.format("%s, retrying in %.1fs (%d/%d)...",
                    reason, waitMs / 1000.0, attempt, MAX_RETRIES));
        }

        // Check for cancellation before sleeping
        if (progress != null && progress.isCancelled()) {
            throw new IOException("Cancelled during backoff");
        }

        try {
            Thread.sleep(waitMs);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted during backoff");
        }
    }

    // JSON helper methods
    private int getIntOrDefault(JsonObject obj, String key, int defaultValue) {
        return obj.has(key) && !obj.get(key).isJsonNull() ? obj.get(key).getAsInt() : defaultValue;
    }

    private long getLongOrDefault(JsonObject obj, String key, long defaultValue) {
        if (!obj.has(key) || obj.get(key).isJsonNull()) {
            return defaultValue;
        }
        try {
            return obj.get(key).getAsLong();
        } catch (NumberFormatException e) {
            try {
                String value = obj.get(key).getAsString();
                if (value != null && value.startsWith("0x")) {
                    return Long.parseLong(value.substring(2), 16);
                }
                return Long.parseLong(value);
            } catch (Exception ignored) {
                return defaultValue;
            }
        }
    }

    private double getDoubleOrDefault(JsonObject obj, String key, double defaultValue) {
        return obj.has(key) && !obj.get(key).isJsonNull() ? obj.get(key).getAsDouble() : defaultValue;
    }

    private String getStringOrNull(JsonObject obj, String key) {
        return obj.has(key) && !obj.get(key).isJsonNull() ? obj.get(key).getAsString() : null;
    }

    private String getStringOrDefault(JsonObject obj, String key, String defaultValue) {
        return obj.has(key) && !obj.get(key).isJsonNull() ? obj.get(key).getAsString() : defaultValue;
    }

    /**
     * Exception for authentication errors.
     */
    public static class SymGraphAuthException extends Exception {
        private static final long serialVersionUID = 1L;

        public SymGraphAuthException(String message) {
            super(message);
        }
    }
}
