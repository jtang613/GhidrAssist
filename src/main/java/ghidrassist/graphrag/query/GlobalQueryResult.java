package ghidrassist.graphrag.query;

import java.util.*;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

/**
 * Result of a global query across all communities in a binary.
 * Aggregates insights from all detected communities using map-reduce pattern.
 */
public class GlobalQueryResult {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    // Metadata
    private String binaryId;
    private int communityCount;
    private int totalFunctions;

    // Community results (ranked by security relevance, then size)
    private List<CommunityInsight> communities;

    // Aggregated findings
    private Map<String, Integer> securityFlagCounts;  // FLAG -> count across all communities
    private List<String> attackSurface;               // Entry points, dangerous functions
    private List<String> keyFindings;                 // Top insights

    public GlobalQueryResult(String binaryId) {
        this.binaryId = binaryId;
        this.communityCount = 0;
        this.totalFunctions = 0;
        this.communities = new ArrayList<>();
        this.securityFlagCounts = new HashMap<>();
        this.attackSurface = new ArrayList<>();
        this.keyFindings = new ArrayList<>();
    }

    // Nested class for per-community insights
    public static class CommunityInsight {
        private String communityId;
        private String communityName;
        private int memberCount;
        private List<String> keyFunctions;      // Top functions (named, security-relevant)
        private List<String> securityFlags;     // Aggregated from members
        private String summary;                 // Community summary if available
        private int securityScore;              // For ranking

        public CommunityInsight(String communityId, String communityName) {
            this.communityId = communityId;
            this.communityName = communityName;
            this.memberCount = 0;
            this.keyFunctions = new ArrayList<>();
            this.securityFlags = new ArrayList<>();
            this.summary = null;
            this.securityScore = 0;
        }

        // Getters and setters
        public String getCommunityId() { return communityId; }
        public void setCommunityId(String communityId) { this.communityId = communityId; }

        public String getCommunityName() { return communityName; }
        public void setCommunityName(String communityName) { this.communityName = communityName; }

        public int getMemberCount() { return memberCount; }
        public void setMemberCount(int memberCount) { this.memberCount = memberCount; }

        public List<String> getKeyFunctions() { return keyFunctions; }
        public void setKeyFunctions(List<String> keyFunctions) { this.keyFunctions = keyFunctions; }

        public List<String> getSecurityFlags() { return securityFlags; }
        public void setSecurityFlags(List<String> securityFlags) { this.securityFlags = securityFlags; }

        public String getSummary() { return summary; }
        public void setSummary(String summary) { this.summary = summary; }

        public int getSecurityScore() { return securityScore; }
        public void setSecurityScore(int securityScore) { this.securityScore = securityScore; }

        public void addKeyFunction(String function) {
            if (!keyFunctions.contains(function)) {
                keyFunctions.add(function);
            }
        }

        public void addSecurityFlag(String flag) {
            if (!securityFlags.contains(flag)) {
                securityFlags.add(flag);
            }
        }
    }

    // Getters and setters
    public String getBinaryId() { return binaryId; }
    public void setBinaryId(String binaryId) { this.binaryId = binaryId; }

    public int getCommunityCount() { return communityCount; }
    public void setCommunityCount(int communityCount) { this.communityCount = communityCount; }

    public int getTotalFunctions() { return totalFunctions; }
    public void setTotalFunctions(int totalFunctions) { this.totalFunctions = totalFunctions; }

    public List<CommunityInsight> getCommunities() { return communities; }
    public void setCommunities(List<CommunityInsight> communities) { this.communities = communities; }

    public Map<String, Integer> getSecurityFlagCounts() { return securityFlagCounts; }
    public void setSecurityFlagCounts(Map<String, Integer> securityFlagCounts) {
        this.securityFlagCounts = securityFlagCounts;
    }

    public List<String> getAttackSurface() { return attackSurface; }
    public void setAttackSurface(List<String> attackSurface) { this.attackSurface = attackSurface; }

    public List<String> getKeyFindings() { return keyFindings; }
    public void setKeyFindings(List<String> keyFindings) { this.keyFindings = keyFindings; }

    // Mutators
    public void addCommunity(CommunityInsight insight) {
        communities.add(insight);
        communityCount = communities.size();
    }

    public void incrementSecurityFlag(String flag) {
        securityFlagCounts.merge(flag, 1, Integer::sum);
    }

    public void addAttackSurfaceFunction(String function) {
        if (!attackSurface.contains(function)) {
            attackSurface.add(function);
        }
    }

    public void addKeyFinding(String finding) {
        keyFindings.add(finding);
    }

    /**
     * Generate formatted output for tool response.
     *
     * @param includeMembers If true, include full member lists for each community
     * @return JSON-formatted string
     */
    public String toToolOutput(boolean includeMembers) {
        Map<String, Object> output = new LinkedHashMap<>();

        // Metadata
        output.put("binary_id", binaryId);
        output.put("community_count", communityCount);
        output.put("total_functions", totalFunctions);

        // Security summary (sorted by count descending)
        if (!securityFlagCounts.isEmpty()) {
            Map<String, Integer> sortedFlags = new LinkedHashMap<>();
            securityFlagCounts.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                .forEach(e -> sortedFlags.put(e.getKey(), e.getValue()));
            output.put("security_summary", sortedFlags);
        }

        // Attack surface
        if (!attackSurface.isEmpty()) {
            output.put("attack_surface", attackSurface);
        }

        // Communities (limit details for large outputs)
        List<Map<String, Object>> communityList = new ArrayList<>();
        for (CommunityInsight insight : communities) {
            Map<String, Object> comm = new LinkedHashMap<>();
            comm.put("name", insight.getCommunityName());
            comm.put("member_count", insight.getMemberCount());

            if (!insight.getSecurityFlags().isEmpty()) {
                comm.put("security_flags", insight.getSecurityFlags());
            }

            // Only include key functions (top 5) unless includeMembers is true
            List<String> funcs = insight.getKeyFunctions();
            if (!funcs.isEmpty()) {
                if (includeMembers) {
                    comm.put("key_functions", funcs);
                } else {
                    comm.put("key_functions", funcs.subList(0, Math.min(5, funcs.size())));
                }
            }

            if (insight.getSummary() != null) {
                comm.put("summary", insight.getSummary());
            }

            communityList.add(comm);
        }
        output.put("communities", communityList);

        // Key findings
        if (!keyFindings.isEmpty()) {
            output.put("key_findings", keyFindings);
        }

        return GSON.toJson(output);
    }

    /**
     * Simple toString for logging.
     */
    @Override
    public String toString() {
        return String.format("GlobalQueryResult[binary=%s, communities=%d, functions=%d]",
                binaryId, communityCount, totalFunctions);
    }
}
