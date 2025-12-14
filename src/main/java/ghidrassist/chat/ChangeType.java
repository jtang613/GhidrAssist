package ghidrassist.chat;

/**
 * Enumeration of possible change types when editing chat content.
 */
public enum ChangeType {
    /** Content was modified */
    MODIFIED("modified"),

    /** Message was deleted */
    DELETED("deleted"),

    /** New message was added */
    ADDED("added"),

    /** Message order changed (reserved for future use) */
    MOVED("moved");

    private final String value;

    ChangeType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    @Override
    public String toString() {
        return value;
    }
}
