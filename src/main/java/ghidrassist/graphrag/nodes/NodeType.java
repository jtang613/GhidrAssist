package ghidrassist.graphrag.nodes;

/**
 * Types of nodes in the Binary Knowledge Graph.
 *
 * The graph uses a 5-level semantic hierarchy:
 * <pre>
 * Level 4: BINARY         - Overall binary summary
 * Level 3: MODULE         - Communities of related functions (Leiden-detected)
 * Level 2: FUNCTION       - Complete functions with decompiled code + summaries
 * Level 1: BLOCK          - Basic blocks, loop bodies, conditionals
 * Level 0: STATEMENT      - Individual lines / instructions
 * </pre>
 */
public enum NodeType {
    /**
     * Individual statement or instruction level.
     * Finest granularity for specific operation semantics.
     */
    STATEMENT(0, "Statement"),

    /**
     * Basic block level - loop bodies, conditionals, etc.
     * Captures logical purpose of code sections.
     */
    BLOCK(1, "Block"),

    /**
     * Complete function with decompiled code and summary.
     * Primary unit of analysis for most queries.
     */
    FUNCTION(2, "Function"),

    /**
     * Community/module of related functions detected via Leiden algorithm.
     * Represents subsystems and logical groupings.
     */
    MODULE(3, "Module"),

    /**
     * Top-level binary summary.
     * Overall program semantics and attack surface.
     */
    BINARY(4, "Binary");

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
