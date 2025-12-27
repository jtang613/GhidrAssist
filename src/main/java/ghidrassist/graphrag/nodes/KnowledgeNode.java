package ghidrassist.graphrag.nodes;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.*;

/**
 * Represents a node in the Binary Knowledge Graph.
 *
 * Each node captures semantic information about a portion of a binary at one of
 * five granularity levels (STATEMENT, BLOCK, FUNCTION, MODULE, BINARY).
 *
 * Nodes contain:
 * - Identity: unique ID, type, address, binary reference
 * - Content: raw decompiled/disassembled content, LLM-generated summary
 * - Metadata: timestamps, analysis depth, staleness
 * - Embeddings: optional vector for semantic search
 * - Security: vulnerability annotations, taint information
 */
public class KnowledgeNode {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    // ========================================
    // Identity fields
    // ========================================

    private String id;                    // UUID for node
    private NodeType type;                // STATEMENT, BLOCK, FUNCTION, MODULE, BINARY
    private Long address;                 // Ghidra address (null for MODULE/BINARY)
    private String binaryId;              // Program hash
    private String name;                  // Function/symbol name if applicable

    // ========================================
    // Content fields
    // ========================================

    private String rawContent;            // Decompiled code / assembly / description
    private String llmSummary;            // Semantic explanation from LLM
    private float confidence;             // Summary confidence 0.0 - 1.0

    // ========================================
    // Embedding for vector search
    // ========================================

    private float[] embedding;            // Optional vector embedding

    // ========================================
    // Security annotations
    // ========================================

    private List<String> securityFlags;   // Vulnerability annotations

    // ========================================
    // Reverse Engineering Features
    // ========================================

    private List<String> networkAPIs;     // Network API calls (socket, send, recv, etc.)
    private List<String> fileIOAPIs;      // File I/O API calls (fopen, fread, fwrite, etc.)
    private List<String> ipAddresses;     // Detected IP addresses in strings
    private List<String> urls;            // Detected URLs in strings
    private List<String> filePaths;       // Detected file paths in strings
    private List<String> domains;         // Detected domain names in strings
    private String activityProfile;       // Computed activity profile (NETWORK_CLIENT, FILE_WRITER, etc.)
    private String riskLevel;             // Computed risk level (LOW, MEDIUM, HIGH)

    // ========================================
    // Metadata
    // ========================================

    private int analysisDepth;            // How many times this node has been analyzed
    private Instant createdAt;
    private Instant updatedAt;
    private boolean isStale;              // Needs re-summarization

    /**
     * Create a new KnowledgeNode with a generated UUID.
     */
    public KnowledgeNode(NodeType type, String binaryId) {
        this.id = UUID.randomUUID().toString();
        this.type = type;
        this.binaryId = binaryId;
        this.confidence = 0.0f;
        this.analysisDepth = 0;
        this.isStale = false;
        this.securityFlags = new ArrayList<>();
        this.createdAt = Instant.now();
        this.updatedAt = Instant.now();
    }

    /**
     * Create a KnowledgeNode with a specific ID (for loading from DB).
     */
    public KnowledgeNode(String id, NodeType type, String binaryId) {
        this.id = id;
        this.type = type;
        this.binaryId = binaryId;
        this.confidence = 0.0f;
        this.analysisDepth = 0;
        this.isStale = false;
        this.securityFlags = new ArrayList<>();
        this.createdAt = Instant.now();
        this.updatedAt = Instant.now();
    }

    // ========================================
    // Factory methods
    // ========================================

    /**
     * Create a function node with address and name.
     */
    public static KnowledgeNode createFunction(String binaryId, long address, String name) {
        KnowledgeNode node = new KnowledgeNode(NodeType.FUNCTION, binaryId);
        node.setAddress(address);
        node.setName(name);
        return node;
    }

    /**
     * Create a binary-level summary node.
     */
    public static KnowledgeNode createBinary(String binaryId, String name) {
        KnowledgeNode node = new KnowledgeNode(NodeType.BINARY, binaryId);
        node.setName(name);
        return node;
    }

    /**
     * Create a module/community node.
     */
    public static KnowledgeNode createModule(String binaryId, String name) {
        KnowledgeNode node = new KnowledgeNode(NodeType.MODULE, binaryId);
        node.setName(name);
        return node;
    }

    /**
     * Create a basic block node.
     */
    public static KnowledgeNode createBlock(String binaryId, long address) {
        KnowledgeNode node = new KnowledgeNode(NodeType.BLOCK, binaryId);
        node.setAddress(address);
        return node;
    }

    // ========================================
    // Embedding serialization
    // ========================================

    /**
     * Serialize embedding to byte array for SQLite storage.
     */
    public byte[] serializeEmbedding() {
        if (embedding == null || embedding.length == 0) {
            return null;
        }
        ByteBuffer buffer = ByteBuffer.allocate(embedding.length * 4);
        for (float f : embedding) {
            buffer.putFloat(f);
        }
        return buffer.array();
    }

    /**
     * Deserialize embedding from byte array.
     */
    public static float[] deserializeEmbedding(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return null;
        }
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        float[] result = new float[bytes.length / 4];
        for (int i = 0; i < result.length; i++) {
            result[i] = buffer.getFloat();
        }
        return result;
    }

    // ========================================
    // Security flags serialization
    // ========================================

    /**
     * Serialize security flags to JSON string for storage.
     */
    public String serializeSecurityFlags() {
        if (securityFlags == null || securityFlags.isEmpty()) {
            return "[]";
        }
        try {
            return OBJECT_MAPPER.writeValueAsString(securityFlags);
        } catch (JsonProcessingException e) {
            return "[]";
        }
    }

    /**
     * Deserialize security flags from JSON string.
     */
    public static List<String> deserializeSecurityFlags(String json) {
        if (json == null || json.isEmpty() || "[]".equals(json)) {
            return new ArrayList<>();
        }
        try {
            return OBJECT_MAPPER.readValue(json, new TypeReference<List<String>>() {});
        } catch (JsonProcessingException e) {
            return new ArrayList<>();
        }
    }

    /**
     * Add a security flag to this node.
     */
    public void addSecurityFlag(String flag) {
        if (securityFlags == null) {
            securityFlags = new ArrayList<>();
        }
        if (!securityFlags.contains(flag)) {
            securityFlags.add(flag);
            markUpdated();
        }
    }

    /**
     * Check if this node has any security flags.
     */
    public boolean hasSecurityFlags() {
        return securityFlags != null && !securityFlags.isEmpty();
    }

    // ========================================
    // State management
    // ========================================

    /**
     * Mark this node as updated and reset staleness.
     */
    public void markUpdated() {
        this.updatedAt = Instant.now();
        this.isStale = false;
    }

    /**
     * Mark this node as stale (needs re-summarization).
     */
    public void markStale() {
        this.isStale = true;
    }

    /**
     * Increment the analysis depth counter.
     */
    public void incrementAnalysisDepth() {
        this.analysisDepth++;
        markUpdated();
    }

    // ========================================
    // Getters and Setters
    // ========================================

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public NodeType getType() {
        return type;
    }

    public void setType(NodeType type) {
        this.type = type;
    }

    public Long getAddress() {
        return address;
    }

    public void setAddress(Long address) {
        this.address = address;
    }

    public String getBinaryId() {
        return binaryId;
    }

    public void setBinaryId(String binaryId) {
        this.binaryId = binaryId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getRawContent() {
        return rawContent;
    }

    public void setRawContent(String rawContent) {
        this.rawContent = rawContent;
    }

    public String getLlmSummary() {
        return llmSummary;
    }

    public void setLlmSummary(String llmSummary) {
        this.llmSummary = llmSummary;
        markUpdated();
    }

    public float getConfidence() {
        return confidence;
    }

    public void setConfidence(float confidence) {
        this.confidence = Math.max(0.0f, Math.min(1.0f, confidence));
    }

    public float[] getEmbedding() {
        return embedding;
    }

    public void setEmbedding(float[] embedding) {
        this.embedding = embedding;
    }

    public List<String> getSecurityFlags() {
        return securityFlags != null ? Collections.unmodifiableList(securityFlags) : Collections.emptyList();
    }

    public void setSecurityFlags(List<String> securityFlags) {
        this.securityFlags = securityFlags != null ? new ArrayList<>(securityFlags) : new ArrayList<>();
    }

    public int getAnalysisDepth() {
        return analysisDepth;
    }

    public void setAnalysisDepth(int analysisDepth) {
        this.analysisDepth = analysisDepth;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Instant updatedAt) {
        this.updatedAt = updatedAt;
    }

    public boolean isStale() {
        return isStale;
    }

    public void setStale(boolean stale) {
        isStale = stale;
    }

    // ========================================
    // Reverse Engineering Feature Getters/Setters
    // ========================================

    public List<String> getNetworkAPIs() {
        return networkAPIs != null ? Collections.unmodifiableList(networkAPIs) : Collections.emptyList();
    }

    public void setNetworkAPIs(List<String> networkAPIs) {
        this.networkAPIs = networkAPIs != null ? new ArrayList<>(networkAPIs) : new ArrayList<>();
    }

    public List<String> getFileIOAPIs() {
        return fileIOAPIs != null ? Collections.unmodifiableList(fileIOAPIs) : Collections.emptyList();
    }

    public void setFileIOAPIs(List<String> fileIOAPIs) {
        this.fileIOAPIs = fileIOAPIs != null ? new ArrayList<>(fileIOAPIs) : new ArrayList<>();
    }

    public List<String> getIPAddresses() {
        return ipAddresses != null ? Collections.unmodifiableList(ipAddresses) : Collections.emptyList();
    }

    public void setIPAddresses(List<String> ipAddresses) {
        this.ipAddresses = ipAddresses != null ? new ArrayList<>(ipAddresses) : new ArrayList<>();
    }

    public List<String> getURLs() {
        return urls != null ? Collections.unmodifiableList(urls) : Collections.emptyList();
    }

    public void setURLs(List<String> urls) {
        this.urls = urls != null ? new ArrayList<>(urls) : new ArrayList<>();
    }

    public List<String> getFilePaths() {
        return filePaths != null ? Collections.unmodifiableList(filePaths) : Collections.emptyList();
    }

    public void setFilePaths(List<String> filePaths) {
        this.filePaths = filePaths != null ? new ArrayList<>(filePaths) : new ArrayList<>();
    }

    public List<String> getDomains() {
        return domains != null ? Collections.unmodifiableList(domains) : Collections.emptyList();
    }

    public void setDomains(List<String> domains) {
        this.domains = domains != null ? new ArrayList<>(domains) : new ArrayList<>();
    }

    public String getActivityProfile() {
        return activityProfile;
    }

    public void setActivityProfile(String activityProfile) {
        this.activityProfile = activityProfile;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(String riskLevel) {
        this.riskLevel = riskLevel;
    }

    /**
     * Check if this node has any detected network activity.
     */
    public boolean hasNetworkActivity() {
        return (networkAPIs != null && !networkAPIs.isEmpty()) ||
               (ipAddresses != null && !ipAddresses.isEmpty()) ||
               (urls != null && !urls.isEmpty()) ||
               (domains != null && !domains.isEmpty());
    }

    /**
     * Check if this node has any detected file activity.
     */
    public boolean hasFileActivity() {
        return (fileIOAPIs != null && !fileIOAPIs.isEmpty()) ||
               (filePaths != null && !filePaths.isEmpty());
    }

    /**
     * Apply security features from extraction to this node.
     */
    public void applySecurityFeatures(ghidrassist.graphrag.extraction.SecurityFeatures features) {
        if (features == null) {
            return;
        }

        this.networkAPIs = new ArrayList<>(features.getNetworkAPIs());
        this.fileIOAPIs = new ArrayList<>(features.getFileIOAPIs());
        this.ipAddresses = new ArrayList<>(features.getIPAddresses());
        this.urls = new ArrayList<>(features.getURLs());
        this.filePaths = new ArrayList<>(features.getFilePaths());
        this.domains = new ArrayList<>(features.getDomains());
        this.activityProfile = features.getActivityProfile();
        this.riskLevel = features.getRiskLevel();
    }

    // ========================================
    // RE Feature Serialization (for database storage)
    // ========================================

    public String serializeNetworkAPIs() {
        return serializeStringList(networkAPIs);
    }

    public String serializeFileIOAPIs() {
        return serializeStringList(fileIOAPIs);
    }

    public String serializeIPAddresses() {
        return serializeStringList(ipAddresses);
    }

    public String serializeURLs() {
        return serializeStringList(urls);
    }

    public String serializeFilePaths() {
        return serializeStringList(filePaths);
    }

    public String serializeDomains() {
        return serializeStringList(domains);
    }

    private String serializeStringList(List<String> list) {
        if (list == null || list.isEmpty()) {
            return "[]";
        }
        try {
            return OBJECT_MAPPER.writeValueAsString(list);
        } catch (JsonProcessingException e) {
            return "[]";
        }
    }

    public static List<String> deserializeStringList(String json) {
        if (json == null || json.isEmpty() || "[]".equals(json)) {
            return new ArrayList<>();
        }
        try {
            return OBJECT_MAPPER.readValue(json, new TypeReference<List<String>>() {});
        } catch (JsonProcessingException e) {
            return new ArrayList<>();
        }
    }

    // ========================================
    // Display methods
    // ========================================

    /**
     * Get a display label for this node (for UI/logging).
     */
    public String getDisplayLabel() {
        if (name != null && !name.isEmpty()) {
            return String.format("%s: %s", type.getDisplayName(), name);
        } else if (address != null) {
            return String.format("%s @ 0x%x", type.getDisplayName(), address);
        } else {
            return String.format("%s [%s]", type.getDisplayName(), id.substring(0, 8));
        }
    }

    @Override
    public String toString() {
        return getDisplayLabel();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KnowledgeNode that = (KnowledgeNode) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
