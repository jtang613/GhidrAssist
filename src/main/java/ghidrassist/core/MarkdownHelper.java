package ghidrassist.core;

import com.vladsch.flexmark.html.HtmlRenderer;
import com.vladsch.flexmark.parser.Parser;
import com.vladsch.flexmark.util.ast.Document;
import com.vladsch.flexmark.util.data.MutableDataSet;

public class MarkdownHelper {
    private final Parser parser;
    private final HtmlRenderer renderer;
    
    public MarkdownHelper() {
        MutableDataSet options = new MutableDataSet();
        options.set(HtmlRenderer.SOFT_BREAK, "<br />\n");
        this.parser = Parser.builder(options).build();
        this.renderer = HtmlRenderer.builder(options).build();
    }
    
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
}
