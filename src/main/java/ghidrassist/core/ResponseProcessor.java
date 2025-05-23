package ghidrassist.core;

import java.util.regex.Pattern;

/**
 * Handles response processing including streaming filters and thinking block removal.
 * Focused solely on text processing and filtering logic.
 */
public class ResponseProcessor {
    
    // Pattern for matching complete <think> blocks and opening/closing tags
    private static final Pattern COMPLETE_THINK_PATTERN = Pattern.compile("<think>.*?</think>", Pattern.DOTALL);
    
    /**
     * Create a new streaming filter for processing chunks
     */
    public StreamingResponseFilter createStreamingFilter() {
        return new StreamingResponseFilter();
    }
    
    /**
     * Filter thinking blocks from a complete response
     */
    public String filterThinkBlocks(String response) {
        if (response == null) {
            return null;
        }
        return COMPLETE_THINK_PATTERN.matcher(response).replaceAll("").trim();
    }
    
    /**
     * Streaming filter that processes chunks of text and removes thinking blocks in real-time
     */
    public static class StreamingResponseFilter {
        private StringBuilder buffer = new StringBuilder();
        private StringBuilder visibleBuffer = new StringBuilder();
        private boolean insideThinkBlock = false;
        
        /**
         * Process a chunk of streaming text, filtering out thinking blocks
         * @param chunk The text chunk to process
         * @return The filtered content that should be displayed, or null if nothing to display
         */
        public String processChunk(String chunk) {
            if (chunk == null) {
                return null;
            }
            
            buffer.append(chunk);
            
            // Process the buffer until we can't anymore
            String currentBuffer = buffer.toString();
            int lastSafeIndex = 0;
            
            for (int i = 0; i < currentBuffer.length(); i++) {
                // Look for start tag
                if (!insideThinkBlock && currentBuffer.startsWith("<think>", i)) {
                    // Append everything up to this point to visible buffer
                    visibleBuffer.append(currentBuffer.substring(lastSafeIndex, i));
                    insideThinkBlock = true;
                    lastSafeIndex = i + 7; // Skip "<think>"
                    i += 6; // Move past "<think>"
                }
                // Look for end tag
                else if (insideThinkBlock && currentBuffer.startsWith("</think>", i)) {
                    insideThinkBlock = false;
                    lastSafeIndex = i + 8; // Skip "</think>"
                    i += 7; // Move past "</think>"
                }
            }
            
            // If we're not in a think block, append any remaining safe content
            if (!insideThinkBlock) {
                visibleBuffer.append(currentBuffer.substring(lastSafeIndex));
                // Clear processed content from buffer
                buffer.setLength(0);
            } else {
                // Keep everything from lastSafeIndex in buffer
                buffer = new StringBuilder(currentBuffer.substring(lastSafeIndex));
            }
            
            return visibleBuffer.toString();
        }
        
        /**
         * Get the complete filtered content processed so far
         */
        public String getFilteredContent() {
            return visibleBuffer.toString();
        }
        
        /**
         * Reset the filter state for reuse
         */
        public void reset() {
            buffer.setLength(0);
            visibleBuffer.setLength(0);
            insideThinkBlock = false;
        }
        
        /**
         * Check if currently inside a thinking block
         */
        public boolean isInsideThinkBlock() {
            return insideThinkBlock;
        }
    }
}