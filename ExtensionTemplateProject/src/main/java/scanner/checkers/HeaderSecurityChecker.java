package scanner.checkers;

import burp.api.montoya.http.message.responses.HttpResponse;
import scanner.SecurityIssue;

import java.util.ArrayList;
import java.util.List;

public class HeaderSecurityChecker {

    public List<SecurityIssue> checkHeaders(String url, HttpResponse response) {
        List<SecurityIssue> issues = new ArrayList<>();

        // Check for missing security headers
        if (!response.hasHeader("X-Frame-Options") && !response.hasHeader("Content-Security-Policy")) {
            issues.add(new SecurityIssue(
                url,
                "Missing Clickjacking Protection",
                "The response does not include X-Frame-Options or CSP frame-ancestors directive, making it vulnerable to clickjacking attacks.",
                SecurityIssue.Severity.MEDIUM,
                "No X-Frame-Options or CSP frame-ancestors header found",
                "Headers"
            ));
        }

        if (!response.hasHeader("X-Content-Type-Options")) {
            issues.add(new SecurityIssue(
                url,
                "Missing X-Content-Type-Options",
                "The response does not include X-Content-Type-Options header, allowing MIME type sniffing attacks.",
                SecurityIssue.Severity.LOW,
                "No X-Content-Type-Options header found",
                "Headers"
            ));
        }

        if (!response.hasHeader("Strict-Transport-Security") && url.startsWith("https://")) {
            issues.add(new SecurityIssue(
                url,
                "Missing HSTS Header",
                "The HTTPS response does not include Strict-Transport-Security header, allowing potential downgrade attacks.",
                SecurityIssue.Severity.MEDIUM,
                "No Strict-Transport-Security header found on HTTPS response",
                "Headers"
            ));
        }

        if (!response.hasHeader("Content-Security-Policy")) {
            issues.add(new SecurityIssue(
                url,
                "Missing Content-Security-Policy",
                "The response does not include a Content-Security-Policy header, increasing risk of XSS attacks.",
                SecurityIssue.Severity.MEDIUM,
                "No Content-Security-Policy header found",
                "Headers"
            ));
        }

        if (!response.hasHeader("Referrer-Policy")) {
            issues.add(new SecurityIssue(
                url,
                "Missing Referrer-Policy",
                "The response does not include a Referrer-Policy header, potentially leaking sensitive information in the Referer header.",
                SecurityIssue.Severity.LOW,
                "No Referrer-Policy header found",
                "Headers"
            ));
        }

        if (!response.hasHeader("Permissions-Policy")) {
            issues.add(new SecurityIssue(
                url,
                "Missing Permissions-Policy",
                "The response does not include a Permissions-Policy header to control browser features.",
                SecurityIssue.Severity.INFO,
                "No Permissions-Policy header found",
                "Headers"
            ));
        }

        // Check for insecure header values
        String serverHeader = response.headerValue("Server");
        if (serverHeader != null && !serverHeader.isEmpty()) {
            if (serverHeader.matches(".*\\d+\\.\\d+.*")) {
                issues.add(new SecurityIssue(
                    url,
                    "Server Version Disclosure",
                    "The Server header reveals version information that could aid attackers.",
                    SecurityIssue.Severity.LOW,
                    "Server: " + serverHeader,
                    "Headers"
                ));
            }
        }

        String xPoweredBy = response.headerValue("X-Powered-By");
        if (xPoweredBy != null && !xPoweredBy.isEmpty()) {
            issues.add(new SecurityIssue(
                url,
                "Technology Stack Disclosure",
                "The X-Powered-By header reveals technology information that could aid attackers.",
                SecurityIssue.Severity.LOW,
                "X-Powered-By: " + xPoweredBy,
                "Headers"
            ));
        }

        // Check for insecure cookie settings
        List<String> setCookieHeaders = response.headers().stream()
            .filter(header -> header.name().equalsIgnoreCase("Set-Cookie"))
            .map(header -> header.value())
            .toList();

        for (String cookieValue : setCookieHeaders) {
            if (!cookieValue.toLowerCase().contains("httponly")) {
                issues.add(new SecurityIssue(
                    url,
                    "Cookie Without HttpOnly Flag",
                    "A cookie is set without the HttpOnly flag, making it accessible to JavaScript and vulnerable to XSS attacks.",
                    SecurityIssue.Severity.MEDIUM,
                    "Set-Cookie: " + cookieValue,
                    "Headers"
                ));
            }

            if (url.startsWith("https://") && !cookieValue.toLowerCase().contains("secure")) {
                issues.add(new SecurityIssue(
                    url,
                    "Cookie Without Secure Flag",
                    "A cookie is set over HTTPS without the Secure flag, allowing it to be sent over insecure HTTP connections.",
                    SecurityIssue.Severity.MEDIUM,
                    "Set-Cookie: " + cookieValue,
                    "Headers"
                ));
            }

            if (!cookieValue.toLowerCase().contains("samesite")) {
                issues.add(new SecurityIssue(
                    url,
                    "Cookie Without SameSite Attribute",
                    "A cookie is set without the SameSite attribute, making it vulnerable to CSRF attacks.",
                    SecurityIssue.Severity.MEDIUM,
                    "Set-Cookie: " + cookieValue,
                    "Headers"
                ));
            }
        }

        // Check for CORS misconfigurations
        String acao = response.headerValue("Access-Control-Allow-Origin");
        if ("*".equals(acao)) {
            String acac = response.headerValue("Access-Control-Allow-Credentials");
            if ("true".equalsIgnoreCase(acac)) {
                issues.add(new SecurityIssue(
                    url,
                    "Insecure CORS Configuration",
                    "The response allows any origin (*) with credentials, which is a severe security misconfiguration.",
                    SecurityIssue.Severity.HIGH,
                    "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
                    "Headers"
                ));
            } else {
                issues.add(new SecurityIssue(
                    url,
                    "Permissive CORS Policy",
                    "The response allows requests from any origin (*), which may be overly permissive.",
                    SecurityIssue.Severity.LOW,
                    "Access-Control-Allow-Origin: *",
                    "Headers"
                ));
            }
        }

        return issues;
    }
}
