package ghidrassist.core;

import com.vladsch.flexmark.html.HtmlRenderer;
import com.vladsch.flexmark.html2md.converter.FlexmarkHtmlConverter;
import com.vladsch.flexmark.parser.Parser;
import com.vladsch.flexmark.util.ast.Document;
import com.vladsch.flexmark.util.data.MutableDataSet;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MarkdownHelper {
    private final Parser parser;
    private final HtmlRenderer renderer;
    private final FlexmarkHtmlConverter htmlToMdConverter;
    
    public MarkdownHelper() {
        MutableDataSet options = new MutableDataSet();
        options.set(HtmlRenderer.SOFT_BREAK, "<br />\n");
        this.parser = Parser.builder(options).build();
        this.renderer = HtmlRenderer.builder(options).build();
        this.htmlToMdConverter = FlexmarkHtmlConverter.builder().build();
    }
    
    /**
     * Convert Markdown text to HTML for display
     * Includes feedback buttons in the HTML output
     * 
     * @param markdown The markdown text to convert
     * @return HTML representation of the markdown
     */
    public String markdownToHtml(String markdown) {
        if (markdown == null) {
            return "";
        }
        
        Document document = parser.parse(markdown);
        String html = renderer.render(document);
        
        // Add feedback buttons
        String feedbackLinks = "<br><div style=\"text-align: center; color: grey; font-size: 18px;\">" +
            "<a href='thumbsup'>&#128077;</a> | <a href='thumbsdown'>&#128078;</a></div>";
            
        return "<html><body>" + html + feedbackLinks + "</body></html>";
    }
    
    /**
     * Convert Markdown text to HTML without adding feedback buttons
     * Used for preview or when feedback isn't needed
     * 
     * @param markdown The markdown text to convert
     * @return HTML representation of the markdown
     */
    public String markdownToHtmlSimple(String markdown) {
        if (markdown == null) {
            return "";
        }
        
        Document document = parser.parse(markdown);
        String html = renderer.render(document);
        
        return "<html><body>" + html + "</body></html>";
    }
    
    /**
     * Convert HTML to Markdown
     * 
     * @param html The HTML to convert
     * @return Markdown representation of the HTML
     */
    public String htmlToMarkdown(String html) {
        if (html == null || html.isEmpty()) {
            return "";
        }
        
        // Remove feedback buttons if present
        html = removeFeedbackButtons(html);
        
        // Remove html wrapper tags if present
        html = removeHtmlWrapperTags(html);
        
        // Use flexmark converter for the HTML to Markdown conversion
        return htmlToMdConverter.convert(html);
    }
    
    /**
     * Extract markdown from a response that might be in various formats
     * 
     * @param response The response to extract markdown from
     * @return Extracted markdown content
     */
    public String extractMarkdownFromLlmResponse(String response) {
        if (response == null || response.isEmpty()) {
            return "";
        }
        
        // Check if it's HTML
        if (response.toLowerCase().contains("<html>") || response.toLowerCase().contains("<body>")) {
            return htmlToMarkdown(response);
        }
        
        // Otherwise, assume it's already markdown or plain text
        return response;
    }
    
    /**
     * Remove feedback buttons from HTML string
     */
    private String removeFeedbackButtons(String html) {
        // Pattern to match the feedback buttons div
        Pattern feedbackPattern = Pattern.compile("<br><div style=\"text-align: center; color: grey; font-size: 18px;\">.*?</div>");
        Matcher matcher = feedbackPattern.matcher(html);
        return matcher.replaceAll("");
    }
    
    /**
     * Remove HTML and BODY wrapper tags
     */
    private String removeHtmlWrapperTags(String html) {
        return html.replaceAll("(?i)<html>|</html>|<body>|</body>", "");
    }
}