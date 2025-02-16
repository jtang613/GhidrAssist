package ghidrassist.ui.common;

import javax.swing.JTextField;
import java.awt.Color;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;

public class PlaceholderTextField extends JTextField {
    private boolean showingPlaceholder;
    private final String placeholder;
    private final Color placeholderColor;
    private final Color textColor;

    public PlaceholderTextField(String placeholder, int columns) {
        super(columns);
        this.placeholder = placeholder;
        this.showingPlaceholder = true;
        this.placeholderColor = UIConstants.PLACEHOLDER_COLOR;
        this.textColor = getForeground();
        
        setupPlaceholder();
    }

    private void setupPlaceholder() {
        setText(placeholder);
        setForeground(placeholderColor);

        addFocusListener(new FocusListener() {
            @Override
            public void focusGained(FocusEvent e) {
                if (showingPlaceholder) {
                    showingPlaceholder = false;
                    setText("");
                    setForeground(textColor);
                }
            }

            @Override
            public void focusLost(FocusEvent e) {
                if (getText().isEmpty()) {
                    showingPlaceholder = true;
                    setText(placeholder);
                    setForeground(placeholderColor);
                }
            }
        });
    }

    @Override
    public String getText() {
        return showingPlaceholder ? "" : super.getText();
    }
}
