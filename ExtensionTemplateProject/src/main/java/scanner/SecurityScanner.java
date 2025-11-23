package scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import scanner.checkers.HeaderSecurityChecker;
import scanner.checkers.LibraryChecker;

import java.util.List;

public class SecurityScanner implements HttpHandler {
    private final MontoyaApi api;
    private final IssueManager issueManager;
    private final HeaderSecurityChecker headerChecker;
    private final LibraryChecker libraryChecker;

    public SecurityScanner(MontoyaApi api, IssueManager issueManager) {
        this.api = api;
        this.issueManager = issueManager;
        this.headerChecker = new HeaderSecurityChecker();
        this.libraryChecker = new LibraryChecker();
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        // Run scanning in background to avoid slowing down traffic
        new Thread(() -> scanResponse(responseReceived)).start();
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private void scanResponse(HttpResponseReceived responseReceived) {
        try {
            HttpRequest request = responseReceived.initiatingRequest();
            HttpResponse response = responseReceived;
            String url = request.url();

            // Only scan HTML responses
            String contentType = response.headerValue("Content-Type");
            if (contentType != null && contentType.toLowerCase().contains("text/html")) {
                // Check headers
                List<SecurityIssue> headerIssues = headerChecker.checkHeaders(url, response);
                for (SecurityIssue issue : headerIssues) {
                    if (issueManager.addIssue(issue)) {
                        api.logging().logToOutput(String.format("Found issue: %s", issue.toString()));
                    }
                }

                // Check for outdated libraries
                List<SecurityIssue> libraryIssues = libraryChecker.checkLibraries(url, response);
                for (SecurityIssue issue : libraryIssues) {
                    if (issueManager.addIssue(issue)) {
                        api.logging().logToOutput(String.format("Found issue: %s", issue.toString()));
                    }
                }
            }

            // Check JavaScript files
            if (contentType != null && (contentType.toLowerCase().contains("javascript") ||
                                       contentType.toLowerCase().contains("application/x-javascript"))) {
                List<SecurityIssue> libraryIssues = libraryChecker.checkLibraries(url, response);
                for (SecurityIssue issue : libraryIssues) {
                    if (issueManager.addIssue(issue)) {
                        api.logging().logToOutput(String.format("Found issue: %s", issue.toString()));
                    }
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Error scanning response: " + e.getMessage());
        }
    }
}
