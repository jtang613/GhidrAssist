package ghidrassist.graphrag.nodes;

/**
 * Types of nodes in the Binary Knowledge Graph.
 *
 * The graph uses a 4-level semantic hierarchy:
 * <pre>
 * Level 2: BINARY         - Overall binary summary
 * Level 1: MODULE         - Communities of related functions (Leiden-detected)
 * Level 1: COMMUNITY      - Detected community grouping
 * Level 0: FUNCTION       - Complete functions with decompiled code + summaries
 * </pre>
 */
public enum NodeType {
    /**
     * Complete function with decompiled code and summary.
     * Primary unit of analysis for most queries.
     */
    FUNCTION(0, "Function"),

    /**
     * Community/module of related functions detected via Leiden algorithm.
     * Represents subsystems and logical groupings.
     */
    MODULE(1, "Module"),

    /**
     * Detected community grouping of related functions.
     * Same level as MODULE - represents functional groupings.
     */
    COMMUNITY(1, "Community"),

    /**
     * Top-level binary summary.
     * Overall program semantics and attack surface.
     */
    BINARY(2, "Binary");

    private final int level;
    private final String displayName;

    NodeType(int level, String displayName) {
        this.level = level;
        this.displayName = displayName;
    }

    /**
     * Get the hierarchy level (0 = finest, 4 = coarsest).
     */
    public int getLevel() {
        return level;
    }

    /**
     * Get the human-readable display name.
     */
    public String getDisplayName() {
        return displayName;
    }

    /**
     * Check if this node type is at a finer granularity than another.
     */
    public boolean isFinerThan(NodeType other) {
        return this.level < other.level;
    }

    /**
     * Check if this node type is at a coarser granularity than another.
     */
    public boolean isCoarserThan(NodeType other) {
        return this.level > other.level;
    }

    /**
     * Parse a node type from its string representation.
     */
    public static NodeType fromString(String value) {
        if (value == null) {
            return null;
        }
        try {
            return valueOf(value.toUpperCase());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
