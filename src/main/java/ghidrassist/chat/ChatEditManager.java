package ghidrassist.chat;

import ghidrassist.chat.util.RoleNormalizer;

import java.util.*;
import java.util.regex.*;

/**
 * Manages chunk-based edit tracking for chat conversations.
 * Generates editable markdown with embedded chunk markers and
 * detects changes when content is saved.
 */
public class ChatEditManager {

    private Map<String, PersistedChatMessage> messageMap;
    private Map<String, String> originalChunks;
    private String chatTitle;
    private int conversationPairCount;

    private static final Pattern CHUNK_PATTERN =
            Pattern.compile("<!-- CHUNK:([^>]+) -->\\s*\\n(.*?)(?=<!-- CHUNK:|$)", Pattern.DOTALL);
    private static final Pattern TITLE_PATTERN =
            Pattern.compile("^#\\s+(.+?)\\s*$", Pattern.MULTILINE);
    private static final Pattern HEADER_PATTERN =
            Pattern.compile("^\\s*##?#?\\s*(\\w+)", Pattern.MULTILINE);

    public ChatEditManager() {
        this.messageMap = new HashMap<>();
        this.originalChunks = new HashMap<>();
        this.chatTitle = "";
        this.conversationPairCount = 0;
    }

    /**
     * Convert chat messages to editable markdown with embedded chunk tracking.
     *
     * @param chatName The chat session name
     * @param messages List of persisted chat messages
     * @return Markdown string with chunk markers
     */
    public String generateEditableContent(String chatName, List<PersistedChatMessage> messages) {
        messageMap.clear();
        originalChunks.clear();
        chatTitle = chatName != null ? chatName : "Untitled";
        conversationPairCount = 0;

        StringBuilder content = new StringBuilder();
        content.append("# ").append(chatTitle).append("\n\n");

        for (int i = 0; i < messages.size(); i++) {
            PersistedChatMessage msg = messages.get(i);

            // Add separator between conversation pairs
            if ("user".equalsIgnoreCase(msg.getRole()) && conversationPairCount > 0) {
                content.append("---\n\n");
            }

            String chunkMarkdown = msg.toMarkdownChunk();

            // Store for change detection
            messageMap.put(msg.getChunkId(), msg);
            originalChunks.put(msg.getChunkId(), chunkMarkdown);

            content.append(chunkMarkdown);

            if ("user".equalsIgnoreCase(msg.getRole())) {
                conversationPairCount++;
            }
        }

        return content.toString();
    }

    /**
     * Detect changes between original and edited content.
     *
     * @param editedContent The edited markdown content
     * @return List of detected changes
     */
    public List<ChatChange> parseEditedContent(String editedContent) {
        List<ChatChange> changes = new ArrayList<>();

        // 1. Check for title changes
        String editedTitle = extractTitle(editedContent);
        if (editedTitle != null && !editedTitle.equals(chatTitle)) {
            changes.add(ChatChange.titleModified(chatTitle, editedTitle));
        }

        // 2. Extract chunks from edited content
        Map<String, String> editedChunks = extractChunks(editedContent);

        Set<String> originalIds = originalChunks.keySet();
        Set<String> editedIds = editedChunks.keySet();

        // 3. Detect deletions
        for (String chunkId : originalIds) {
            if (!editedIds.contains(chunkId)) {
                PersistedChatMessage msg = messageMap.get(chunkId);
                if (msg != null) {
                    changes.add(ChatChange.deleted(chunkId, msg.getDbId(), msg.getContent()));
                }
            }
        }

        // 4. Detect modifications
        for (String chunkId : editedIds) {
            if (originalIds.contains(chunkId)) {
                PersistedChatMessage msg = messageMap.get(chunkId);
                if (msg != null) {
                    String original = msg.getContent();
                    String edited = editedChunks.get(chunkId);
                    if (!Objects.equals(original, edited)) {
                        changes.add(ChatChange.modified(
                                chunkId, msg.getDbId(), original, edited,
                                msg.getRole(),
                                msg.getTimestamp() != null ? msg.getTimestamp().toString() : null
                        ));
                    }
                }
            }
        }

        // 5. Detect additions (new content without markers)
        List<ParsedBlock> newBlocks = extractNewContent(editedContent);
        for (ParsedBlock block : newBlocks) {
            changes.add(ChatChange.added(
                    block.content, block.role,
                    block.timestamp != null ? block.timestamp : "edited",
                    messageMap.size()
            ));
        }

        return changes;
    }

    /**
     * Extract ALL messages from edited markdown for full rebuild.
     * This is the primary method used for saving - handles both
     * chunk-marked and unmarked content.
     *
     * @param editedContent The edited markdown content
     * @return List of extracted messages in order
     */
    public List<ExtractedMessage> extractAllMessages(String editedContent) {
        List<ExtractedMessage> messages = new ArrayList<>();

        // Split by chunk markers
        String[] parts = editedContent.split("(<!-- CHUNK:[^>]+ -->)");
        Matcher markerMatcher = Pattern.compile("<!-- CHUNK:([^>]+) -->").matcher(editedContent);

        List<String> chunkIds = new ArrayList<>();
        while (markerMatcher.find()) {
            chunkIds.add(markerMatcher.group(1));
        }

        // Process parts (parts[0] is before first marker, skip it)
        for (int i = 0; i < chunkIds.size() && i + 1 < parts.length; i++) {
            String chunkContent = parts[i + 1];

            // Parse header for role
            Matcher headerMatch = HEADER_PATTERN.matcher(chunkContent);
            if (headerMatch.find()) {
                String roleText = headerMatch.group(1).toLowerCase();
                String role = RoleNormalizer.normalize(roleText);

                // Extract content (skip header line)
                String[] lines = chunkContent.split("\n");
                StringBuilder contentBuilder = new StringBuilder();
                boolean foundHeader = false;
                for (String line : lines) {
                    if (!foundHeader && line.matches("\\s*##?#?\\s*\\w+.*")) {
                        foundHeader = true;
                        continue;
                    }
                    if (foundHeader) {
                        contentBuilder.append(line).append("\n");
                    }
                }

                String content = contentBuilder.toString().trim();
                // Remove trailing separators
                while (content.endsWith("---")) {
                    content = content.substring(0, content.length() - 3).trim();
                }

                if (!content.isEmpty()) {
                    ExtractedMessage msg = new ExtractedMessage();
                    msg.role = role;
                    msg.content = content;
                    msg.timestamp = "edited";
                    msg.dbId = null;
                    messages.add(msg);
                }
            }
        }

        // Fallback: header-based extraction if no chunks found
        if (messages.isEmpty()) {
            messages = extractByHeaders(editedContent);
        }

        return messages;
    }

    // Helper methods

    private String extractTitle(String content) {
        Matcher matcher = TITLE_PATTERN.matcher(content);
        if (matcher.find()) {
            return matcher.group(1).trim();
        }
        return null;
    }

    private Map<String, String> extractChunks(String content) {
        Map<String, String> chunks = new HashMap<>();
        Matcher matcher = CHUNK_PATTERN.matcher(content);

        while (matcher.find()) {
            String chunkId = matcher.group(1);
            String chunkContent = matcher.group(2).trim();

            // Skip header line, remove trailing separators
            String[] lines = chunkContent.split("\n");
            if (lines.length > 1) {
                StringBuilder contentLines = new StringBuilder();
                boolean skippedHeader = false;
                for (String line : lines) {
                    if (!skippedHeader && line.matches("\\s*##?#?\\s*\\w+.*")) {
                        skippedHeader = true;
                        continue;
                    }
                    contentLines.append(line).append("\n");
                }
                String extracted = contentLines.toString().trim();
                while (extracted.endsWith("---") || extracted.endsWith("\n")) {
                    if (extracted.endsWith("---")) {
                        extracted = extracted.substring(0, extracted.length() - 3).trim();
                    } else if (extracted.endsWith("\n")) {
                        extracted = extracted.substring(0, extracted.length() - 1);
                    }
                }
                chunks.put(chunkId, extracted);
            }
        }

        return chunks;
    }

    private List<ParsedBlock> extractNewContent(String content) {
        // Look for content that has headers but no chunk markers
        // This is a simplified implementation - full version would be more robust
        List<ParsedBlock> newBlocks = new ArrayList<>();

        // Find headers that are NOT preceded by chunk markers
        Pattern unmarkedHeaderPattern = Pattern.compile(
                "(?<!<!-- CHUNK:[^>]+ -->\\s*\\n)##\\s+(User|Assistant|Error|Edited)\\s*\\([^)]*\\)\\s*\\n(.*?)(?=##\\s+|$)",
                Pattern.DOTALL | Pattern.CASE_INSENSITIVE
        );

        Matcher matcher = unmarkedHeaderPattern.matcher(content);
        while (matcher.find()) {
            String role = RoleNormalizer.normalize(matcher.group(1));
            String blockContent = matcher.group(2).trim();

            // Clean up separators
            while (blockContent.endsWith("---")) {
                blockContent = blockContent.substring(0, blockContent.length() - 3).trim();
            }

            if (!blockContent.isEmpty()) {
                ParsedBlock block = new ParsedBlock();
                block.role = role;
                block.content = blockContent;
                block.timestamp = "edited";
                newBlocks.add(block);
            }
        }

        return newBlocks;
    }

    private List<ExtractedMessage> extractByHeaders(String content) {
        List<ExtractedMessage> messages = new ArrayList<>();

        // Pattern for ## User or ## Assistant headers with timestamp
        Pattern headerPattern = Pattern.compile(
                "##\\s+(User|Assistant|Error|Edited)\\s*(?:\\([^)]*\\))?\\s*\\n(.*?)(?=##\\s+(User|Assistant|Error|Edited)|$)",
                Pattern.DOTALL | Pattern.CASE_INSENSITIVE
        );

        Matcher matcher = headerPattern.matcher(content);
        while (matcher.find()) {
            String role = RoleNormalizer.normalize(matcher.group(1));
            String msgContent = matcher.group(2).trim();

            // Clean up separators
            while (msgContent.endsWith("---")) {
                msgContent = msgContent.substring(0, msgContent.length() - 3).trim();
            }

            if (!msgContent.isEmpty()) {
                ExtractedMessage msg = new ExtractedMessage();
                msg.role = role;
                msg.content = msgContent;
                msg.timestamp = "edited";
                messages.add(msg);
            }
        }

        return messages;
    }

    /**
     * Helper class for extracted messages during save.
     */
    public static class ExtractedMessage {
        public String role;
        public String content;
        public String timestamp;
        public Integer dbId;

        @Override
        public String toString() {
            return String.format("ExtractedMessage{role='%s', content='%s...'}",
                    role, content != null && content.length() > 20 ? content.substring(0, 20) : content);
        }
    }

    /**
     * Helper class for parsed blocks.
     */
    private static class ParsedBlock {
        String role;
        String content;
        String timestamp;
    }

    // Getters

    public String getChatTitle() {
        return chatTitle;
    }

    public Map<String, PersistedChatMessage> getMessageMap() {
        return Collections.unmodifiableMap(messageMap);
    }

    /**
     * Reset the manager state.
     */
    public void reset() {
        messageMap.clear();
        originalChunks.clear();
        chatTitle = "";
        conversationPairCount = 0;
    }
}
