import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import scanner.IssueManager;
import scanner.SecurityScanner;
import ui.BorborBorpMainPanel;

public class Extension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("BorborBorp Security Scanner");

        // Initialize issue manager
        IssueManager issueManager = new IssueManager();

        // Register HTTP handler for scanning
        SecurityScanner scanner = new SecurityScanner(api, issueManager);
        api.http().registerHttpHandler(scanner);

        // Register UI tab
        BorborBorpMainPanel mainPanel = new BorborBorpMainPanel(issueManager);
        api.userInterface().registerSuiteTab("Security Scanner", mainPanel);

        // Log initialization
        api.logging().logToOutput("BorborBorp Security Scanner initialized successfully!");
        api.logging().logToOutput("Scanning for:");
        api.logging().logToOutput("  - Insecure HTTP headers");
        api.logging().logToOutput("  - Missing security headers");
        api.logging().logToOutput("  - Outdated JavaScript libraries");
        api.logging().logToOutput("  - Insecure cookie configurations");
        api.logging().logToOutput("  - CORS misconfigurations");
        api.logging().logToOutput("  - Dangerous JavaScript patterns");
        api.logging().logToOutput("  - Exposed credentials");
    }
}