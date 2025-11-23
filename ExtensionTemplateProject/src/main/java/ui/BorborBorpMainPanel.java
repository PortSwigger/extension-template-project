package ui;

import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.SuiteTab;
import scanner.IssueManager;

import javax.swing.*;
import java.awt.*;

public class BorborBorpMainPanel extends JPanel implements SuiteTab {
    private final SecurityScannerPanel scannerPanel;

    public BorborBorpMainPanel(IssueManager issueManager) {
        setLayout(new BorderLayout());
        scannerPanel = new SecurityScannerPanel(issueManager);
        add(scannerPanel, BorderLayout.CENTER);
    }

    @Override
    public String title() {
        return "Security Scanner";
    }

    @Override
    public Component uiComponent() {
        return this;
    }

    @Override
    public Selection selectedContent() {
        return null;
    }
}
