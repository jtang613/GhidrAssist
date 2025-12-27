package ghidrassist.graphrag.extraction;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.*;

/**
 * Container for security-relevant features extracted from a function.
 *
 * Captures:
 * - Network API calls (socket, send, recv, etc.)
 * - File I/O API calls (fopen, fread, fwrite, etc.)
 * - String references (IPs, URLs, file paths, domains)
 * - Activity profile classification
 * - Risk level assessment
 */
public class SecurityFeatures {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    // API call tracking
    private final Set<String> networkAPIs = new LinkedHashSet<>();
    private final Set<String> fileIOAPIs = new LinkedHashSet<>();
    private final Set<String> cryptoAPIs = new LinkedHashSet<>();
    private final Set<String> processAPIs = new LinkedHashSet<>();

    // Dangerous function tracking (function name -> vulnerability type)
    private final Map<String, String> dangerousFunctions = new LinkedHashMap<>();

    // String reference tracking
    private final Set<String> ipAddresses = new LinkedHashSet<>();
    private final Set<String> urls = new LinkedHashSet<>();
    private final Set<String> filePaths = new LinkedHashSet<>();
    private final Set<String> domains = new LinkedHashSet<>();
    private final Set<String> registryKeys = new LinkedHashSet<>();

    // Computed fields
    private String activityProfile;
    private String riskLevel;

    // ========================================
    // API Call Tracking
    // ========================================

    public void addNetworkAPI(String apiName) {
        if (apiName != null && !apiName.isEmpty()) {
            networkAPIs.add(apiName);
        }
    }

    public void addFileIOAPI(String apiName) {
        if (apiName != null && !apiName.isEmpty()) {
            fileIOAPIs.add(apiName);
        }
    }

    public void addCryptoAPI(String apiName) {
        if (apiName != null && !apiName.isEmpty()) {
            cryptoAPIs.add(apiName);
        }
    }

    public void addProcessAPI(String apiName) {
        if (apiName != null && !apiName.isEmpty()) {
            processAPIs.add(apiName);
        }
    }

    // ========================================
    // Dangerous Function Tracking
    // ========================================

    public void addDangerousFunction(String functionName, String vulnerabilityType) {
        if (functionName != null && !functionName.isEmpty() && vulnerabilityType != null) {
            dangerousFunctions.put(functionName, vulnerabilityType);
        }
    }

    public boolean hasDangerousFunctions() {
        return !dangerousFunctions.isEmpty();
    }

    public Map<String, String> getDangerousFunctions() {
        return Collections.unmodifiableMap(dangerousFunctions);
    }

    /**
     * Get unique vulnerability types from dangerous functions.
     */
    public Set<String> getVulnerabilityTypes() {
        return new LinkedHashSet<>(dangerousFunctions.values());
    }

    // ========================================
    // String Reference Tracking
    // ========================================

    public void addIPAddress(String ip) {
        if (ip != null && !ip.isEmpty()) {
            ipAddresses.add(ip);
        }
    }

    public void addURL(String url) {
        if (url != null && !url.isEmpty()) {
            urls.add(url);
        }
    }

    public void addFilePath(String path) {
        if (path != null && !path.isEmpty()) {
            filePaths.add(path);
        }
    }

    public void addDomain(String domain) {
        if (domain != null && !domain.isEmpty()) {
            domains.add(domain);
        }
    }

    public void addRegistryKey(String key) {
        if (key != null && !key.isEmpty()) {
            registryKeys.add(key);
        }
    }

    // ========================================
    // Query Methods
    // ========================================

    public boolean hasNetworkAPIs() {
        return !networkAPIs.isEmpty();
    }

    public boolean hasFileIOAPIs() {
        return !fileIOAPIs.isEmpty();
    }

    public boolean hasCryptoAPIs() {
        return !cryptoAPIs.isEmpty();
    }

    public boolean hasProcessAPIs() {
        return !processAPIs.isEmpty();
    }

    public boolean hasIPAddresses() {
        return !ipAddresses.isEmpty();
    }

    public boolean hasURLs() {
        return !urls.isEmpty();
    }

    public boolean hasFilePaths() {
        return !filePaths.isEmpty();
    }

    public boolean hasDomains() {
        return !domains.isEmpty();
    }

    public boolean hasRegistryKeys() {
        return !registryKeys.isEmpty();
    }

    public boolean hasSystemPaths() {
        return filePaths.stream().anyMatch(p ->
            p.startsWith("/etc") ||
            p.startsWith("/root") ||
            p.startsWith("/var") ||
            p.toLowerCase().contains("\\windows") ||
            p.toLowerCase().contains("\\system32") ||
            p.toLowerCase().contains("\\programdata")
        );
    }

    public boolean isEmpty() {
        return networkAPIs.isEmpty() && fileIOAPIs.isEmpty() &&
               cryptoAPIs.isEmpty() && processAPIs.isEmpty() &&
               dangerousFunctions.isEmpty() &&
               ipAddresses.isEmpty() && urls.isEmpty() &&
               filePaths.isEmpty() && domains.isEmpty() &&
               registryKeys.isEmpty();
    }

    // ========================================
    // Activity Profile Calculation
    // ========================================

    /**
     * Calculate the activity profile based on detected APIs.
     * Returns a classification like NETWORK_CLIENT, NETWORK_SERVER, FILE_WRITER, etc.
     */
    public void calculateActivityProfile() {
        List<String> profiles = new ArrayList<>();

        // Network patterns
        if (hasNetworkAPIs()) {
            // Server indicators: listen, accept, WSAAccept, AcceptSecurityContext
            boolean hasServerOps = networkAPIs.stream().anyMatch(a -> {
                String lower = a.toLowerCase();
                return lower.equals("listen") || lower.equals("accept") ||
                       lower.equals("wsaaccept") || lower.equals("acceptsecuritycontext") ||
                       lower.contains("_accept");
            });

            // Client connection indicators: connect, WSAConnect*, WinHttpConnect, InternetConnect
            boolean hasClientConnect = networkAPIs.stream().anyMatch(a -> {
                String lower = a.toLowerCase();
                return lower.equals("connect") || lower.startsWith("wsaconnect") ||
                       lower.equals("winhttpconnect") || lower.equals("internetconnect") ||
                       lower.contains("internetconnecta") || lower.contains("internetconnectw") ||
                       lower.equals("ssl_connect");
            });

            // Send/receive indicators
            boolean hasSend = networkAPIs.stream().anyMatch(a -> {
                String lower = a.toLowerCase();
                return lower.contains("send") || lower.contains("wsasend") ||
                       lower.equals("winhttpwritedata") || lower.equals("internetwritefile") ||
                       lower.equals("ssl_write");
            });
            boolean hasRecv = networkAPIs.stream().anyMatch(a -> {
                String lower = a.toLowerCase();
                return lower.contains("recv") || lower.contains("wsarecv") ||
                       lower.equals("winhttpreaddata") || lower.equals("internetreadfile") ||
                       lower.equals("ssl_read");
            });

            // HTTP client indicators
            boolean hasHttpClient = networkAPIs.stream().anyMatch(a -> {
                String lower = a.toLowerCase();
                return lower.contains("httpopen") || lower.contains("httpsend") ||
                       lower.contains("winhttp") || lower.contains("internet") ||
                       lower.contains("curl_");
            });

            // Classify network activity
            if (hasServerOps) {
                profiles.add("NETWORK_SERVER");
            }
            if (hasClientConnect || hasHttpClient) {
                profiles.add("NETWORK_CLIENT");
            }
            if ((hasSend || hasRecv) && !profiles.contains("NETWORK_SERVER") && !profiles.contains("NETWORK_CLIENT")) {
                profiles.add("NETWORK_IO");
            }
        }

        // DNS patterns
        if (hasNetworkAPIs() && networkAPIs.stream().anyMatch(a -> {
            String lower = a.toLowerCase();
            return lower.contains("getaddrinfo") || lower.contains("gethostbyname") ||
                   lower.contains("gethostbyaddr") || lower.contains("getnameinfo") ||
                   lower.contains("gethostname");
        })) {
            profiles.add("DNS_RESOLVER");
        }

        // File I/O patterns
        if (hasFileIOAPIs()) {
            // Read indicators
            boolean hasRead = fileIOAPIs.stream().anyMatch(a -> {
                String lower = a.toLowerCase();
                return lower.equals("read") || lower.equals("pread") ||
                       lower.equals("fread") || lower.equals("fgets") || lower.equals("fgetc") ||
                       lower.equals("getc") || lower.equals("fscanf") ||
                       lower.contains("readfile") || lower.contains("internetreadfile") ||
                       lower.equals("mapviewoffile");
            });

            // Write indicators
            boolean hasWrite = fileIOAPIs.stream().anyMatch(a -> {
                String lower = a.toLowerCase();
                return lower.equals("write") || lower.equals("pwrite") ||
                       lower.equals("fwrite") || lower.equals("fputs") || lower.equals("fputc") ||
                       lower.equals("putc") || lower.equals("fprintf") ||
                       lower.contains("writefile") || lower.contains("internetwritefile") ||
                       lower.contains("copyfile") || lower.contains("movefile");
            });

            // Delete/modify indicators
            boolean hasDelete = fileIOAPIs.stream().anyMatch(a -> {
                String lower = a.toLowerCase();
                return lower.contains("delete") || lower.equals("remove") ||
                       lower.equals("unlink") || lower.contains("removedirectory");
            });

            // Classify file activity
            if (hasRead && hasWrite) {
                profiles.add("FILE_RW");
            } else if (hasWrite) {
                profiles.add("FILE_WRITER");
            } else if (hasRead) {
                profiles.add("FILE_READER");
            }

            if (hasDelete) {
                profiles.add("FILE_DELETER");
            }
        }

        // Crypto patterns
        if (hasCryptoAPIs()) {
            boolean hasEncrypt = cryptoAPIs.stream().anyMatch(a ->
                a.toLowerCase().contains("encrypt"));
            boolean hasDecrypt = cryptoAPIs.stream().anyMatch(a ->
                a.toLowerCase().contains("decrypt"));
            boolean hasHash = cryptoAPIs.stream().anyMatch(a -> {
                String lower = a.toLowerCase();
                return lower.contains("hash") || lower.contains("md5") ||
                       lower.contains("sha1") || lower.contains("sha256") ||
                       lower.contains("digest");
            });

            if (hasEncrypt && hasDecrypt) {
                profiles.add("CRYPTO_CIPHER");
            } else if (hasEncrypt) {
                profiles.add("CRYPTO_ENCRYPT");
            } else if (hasDecrypt) {
                profiles.add("CRYPTO_DECRYPT");
            } else if (hasHash) {
                profiles.add("CRYPTO_HASH");
            } else {
                profiles.add("CRYPTO_USER");
            }
        }

        // Process patterns
        if (hasProcessAPIs()) {
            boolean hasInject = processAPIs.stream().anyMatch(a -> {
                String lower = a.toLowerCase();
                return lower.contains("writeprocessmemory") || lower.contains("createremotethread") ||
                       lower.contains("virtualalloc");
            });

            if (hasInject) {
                profiles.add("PROCESS_INJECTOR");
            } else {
                profiles.add("PROCESS_SPAWNER");
            }
        }

        // Combined patterns indicating potential data exfiltration
        if (hasNetworkAPIs() && hasFileIOAPIs()) {
            profiles.add("MIXED_IO");
        }

        if (profiles.isEmpty()) {
            this.activityProfile = "NONE";
        } else {
            this.activityProfile = String.join(", ", profiles);
        }
    }

    // ========================================
    // Risk Level Calculation
    // ========================================

    /**
     * Calculate risk level based on detected features.
     * Returns LOW, MEDIUM, or HIGH.
     */
    public void calculateRiskLevel() {
        int score = 0;

        // Network indicators
        if (hasNetworkAPIs()) score += 2;
        if (hasIPAddresses()) score += 3;  // Hardcoded IPs = suspicious
        if (hasURLs()) score += 2;
        if (hasDomains()) score += 1;

        // File I/O indicators
        if (hasFileIOAPIs()) score += 1;
        if (hasSystemPaths()) score += 3;  // System paths = suspicious

        // Crypto/process indicators
        if (hasCryptoAPIs()) score += 1;
        if (hasProcessAPIs()) score += 2;

        // Registry access (Windows)
        if (hasRegistryKeys()) score += 2;

        // Dangerous functions (vulnerability risks)
        if (hasDangerousFunctions()) {
            score += 3;  // Any dangerous function is a significant risk
            // Buffer overflow and command injection are especially critical
            Set<String> vulnTypes = getVulnerabilityTypes();
            if (vulnTypes.contains("BUFFER_OVERFLOW_RISK") ||
                vulnTypes.contains("COMMAND_INJECTION_RISK")) {
                score += 2;
            }
        }

        // Combined patterns (exfiltration potential)
        if (hasNetworkAPIs() && hasFileIOAPIs()) {
            score += 2;
        }

        // Network + crypto = potential secure C2
        if (hasNetworkAPIs() && hasCryptoAPIs()) {
            score += 2;
        }

        if (score >= 6) {
            this.riskLevel = "HIGH";
        } else if (score >= 3) {
            this.riskLevel = "MEDIUM";
        } else {
            this.riskLevel = "LOW";
        }
    }

    // ========================================
    // Security Flags Generation
    // ========================================

    /**
     * Generate security flags based on detected features.
     * These flags are stored in the graph_nodes.security_flags field.
     *
     * @return List of security flag strings
     */
    public List<String> generateSecurityFlags() {
        List<String> flags = new ArrayList<>();

        // Activity-based flags
        if (hasNetworkAPIs()) {
            flags.add("NETWORK_CAPABLE");
            String profile = getActivityProfile();
            if (profile != null) {
                if (profile.contains("NETWORK_SERVER")) {
                    flags.add("ACCEPTS_CONNECTIONS");
                }
                if (profile.contains("NETWORK_CLIENT")) {
                    flags.add("INITIATES_CONNECTIONS");
                }
                if (profile.contains("DNS_RESOLVER")) {
                    flags.add("PERFORMS_DNS_LOOKUP");
                }
            }
        }

        if (hasFileIOAPIs()) {
            flags.add("FILE_IO_CAPABLE");
            String profile = getActivityProfile();
            if (profile != null) {
                if (profile.contains("FILE_WRITER") || profile.contains("FILE_RW")) {
                    flags.add("WRITES_FILES");
                }
                if (profile.contains("FILE_READER") || profile.contains("FILE_RW")) {
                    flags.add("READS_FILES");
                }
                if (profile.contains("FILE_DELETER")) {
                    flags.add("DELETES_FILES");
                }
            }
        }

        if (hasCryptoAPIs()) {
            flags.add("USES_CRYPTO");
            String profile = getActivityProfile();
            if (profile != null) {
                if (profile.contains("CRYPTO_ENCRYPT")) {
                    flags.add("ENCRYPTS_DATA");
                }
                if (profile.contains("CRYPTO_DECRYPT")) {
                    flags.add("DECRYPTS_DATA");
                }
            }
        }

        if (hasProcessAPIs()) {
            flags.add("SPAWNS_PROCESSES");
            String profile = getActivityProfile();
            if (profile != null && profile.contains("PROCESS_INJECTOR")) {
                flags.add("PROCESS_INJECTION_CAPABLE");
            }
        }

        // Dangerous function flags (vulnerability indicators)
        if (hasDangerousFunctions()) {
            flags.add("CALLS_DANGEROUS_FUNCTIONS");
            // Add specific vulnerability type flags
            for (String vulnType : getVulnerabilityTypes()) {
                flags.add(vulnType);
            }
        }

        // String reference flags
        if (hasIPAddresses()) {
            flags.add("CONTAINS_HARDCODED_IPS");
        }
        if (hasURLs()) {
            flags.add("CONTAINS_URLS");
        }
        if (hasDomains()) {
            flags.add("CONTAINS_DOMAINS");
        }
        if (hasRegistryKeys()) {
            flags.add("ACCESSES_REGISTRY");
        }
        if (hasSystemPaths()) {
            flags.add("ACCESSES_SYSTEM_PATHS");
        }

        // Combined pattern flags
        if (hasNetworkAPIs() && hasFileIOAPIs()) {
            flags.add("POTENTIAL_DATA_EXFILTRATION");
        }
        if (hasNetworkAPIs() && hasCryptoAPIs()) {
            flags.add("ENCRYPTED_NETWORK_COMMS");
        }
        if (hasNetworkAPIs() && hasDangerousFunctions()) {
            flags.add("NETWORK_WITH_VULN_RISK");
        }

        // Risk level flag
        String risk = getRiskLevel();
        if ("HIGH".equals(risk)) {
            flags.add("HIGH_RISK");
        } else if ("MEDIUM".equals(risk)) {
            flags.add("MEDIUM_RISK");
        }

        return flags;
    }

    // ========================================
    // Getters
    // ========================================

    public Set<String> getNetworkAPIs() {
        return Collections.unmodifiableSet(networkAPIs);
    }

    public Set<String> getFileIOAPIs() {
        return Collections.unmodifiableSet(fileIOAPIs);
    }

    public Set<String> getCryptoAPIs() {
        return Collections.unmodifiableSet(cryptoAPIs);
    }

    public Set<String> getProcessAPIs() {
        return Collections.unmodifiableSet(processAPIs);
    }

    public Set<String> getIPAddresses() {
        return Collections.unmodifiableSet(ipAddresses);
    }

    public Set<String> getURLs() {
        return Collections.unmodifiableSet(urls);
    }

    public Set<String> getFilePaths() {
        return Collections.unmodifiableSet(filePaths);
    }

    public Set<String> getDomains() {
        return Collections.unmodifiableSet(domains);
    }

    public Set<String> getRegistryKeys() {
        return Collections.unmodifiableSet(registryKeys);
    }

    public String getActivityProfile() {
        if (activityProfile == null) {
            calculateActivityProfile();
        }
        return activityProfile;
    }

    public String getRiskLevel() {
        if (riskLevel == null) {
            calculateRiskLevel();
        }
        return riskLevel;
    }

    // ========================================
    // Serialization
    // ========================================

    /**
     * Convert to JSON for tool output.
     */
    public String toJson() {
        try {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("activity_profile", getActivityProfile());
            map.put("risk_level", getRiskLevel());

            if (!networkAPIs.isEmpty()) {
                map.put("network_apis", new ArrayList<>(networkAPIs));
            }
            if (!fileIOAPIs.isEmpty()) {
                map.put("file_io_apis", new ArrayList<>(fileIOAPIs));
            }
            if (!cryptoAPIs.isEmpty()) {
                map.put("crypto_apis", new ArrayList<>(cryptoAPIs));
            }
            if (!processAPIs.isEmpty()) {
                map.put("process_apis", new ArrayList<>(processAPIs));
            }
            if (!ipAddresses.isEmpty()) {
                map.put("ip_addresses", new ArrayList<>(ipAddresses));
            }
            if (!urls.isEmpty()) {
                map.put("urls", new ArrayList<>(urls));
            }
            if (!filePaths.isEmpty()) {
                map.put("file_paths", new ArrayList<>(filePaths));
            }
            if (!domains.isEmpty()) {
                map.put("domains", new ArrayList<>(domains));
            }
            if (!registryKeys.isEmpty()) {
                map.put("registry_keys", new ArrayList<>(registryKeys));
            }

            return OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(map);
        } catch (JsonProcessingException e) {
            return "{}";
        }
    }

    /**
     * Serialize lists to JSON strings for storage.
     */
    public String serializeNetworkAPIs() {
        return serializeSet(networkAPIs);
    }

    public String serializeFileIOAPIs() {
        return serializeSet(fileIOAPIs);
    }

    public String serializeIPAddresses() {
        return serializeSet(ipAddresses);
    }

    public String serializeURLs() {
        return serializeSet(urls);
    }

    public String serializeFilePaths() {
        return serializeSet(filePaths);
    }

    public String serializeDomains() {
        return serializeSet(domains);
    }

    private String serializeSet(Set<String> set) {
        if (set == null || set.isEmpty()) {
            return "[]";
        }
        try {
            return OBJECT_MAPPER.writeValueAsString(new ArrayList<>(set));
        } catch (JsonProcessingException e) {
            return "[]";
        }
    }

    @Override
    public String toString() {
        return String.format("SecurityFeatures[profile=%s, risk=%s, netAPIs=%d, fileAPIs=%d, ips=%d, urls=%d, paths=%d]",
            getActivityProfile(), getRiskLevel(),
            networkAPIs.size(), fileIOAPIs.size(),
            ipAddresses.size(), urls.size(), filePaths.size());
    }
}
