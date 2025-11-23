package scanner.checkers;

import burp.api.montoya.http.message.responses.HttpResponse;
import scanner.SecurityIssue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LibraryChecker {

    private static final Map<String, LibrarySignature> LIBRARY_SIGNATURES = new HashMap<>();

    static {
        // jQuery
        LIBRARY_SIGNATURES.put("jquery", new LibrarySignature(
            "jQuery",
            Pattern.compile("jquery[.-]([0-9.]+)(?:\\.min)?\\.js", Pattern.CASE_INSENSITIVE),
            "3.7.1",
            "https://jquery.com/"
        ));

        // Angular
        LIBRARY_SIGNATURES.put("angular", new LibrarySignature(
            "AngularJS",
            Pattern.compile("angular(?:[.-]([0-9.]+))?(?:\\.min)?\\.js", Pattern.CASE_INSENSITIVE),
            "1.8.3",
            "https://angularjs.org/"
        ));

        // React
        LIBRARY_SIGNATURES.put("react", new LibrarySignature(
            "React",
            Pattern.compile("react(?:[.-]([0-9.]+))?(?:\\.min)?\\.js", Pattern.CASE_INSENSITIVE),
            "18.2.0",
            "https://reactjs.org/"
        ));

        // Vue.js
        LIBRARY_SIGNATURES.put("vue", new LibrarySignature(
            "Vue.js",
            Pattern.compile("vue(?:[.-]([0-9.]+))?(?:\\.min)?\\.js", Pattern.CASE_INSENSITIVE),
            "3.4.0",
            "https://vuejs.org/"
        ));

        // Bootstrap
        LIBRARY_SIGNATURES.put("bootstrap", new LibrarySignature(
            "Bootstrap",
            Pattern.compile("bootstrap(?:[.-]([0-9.]+))?(?:\\.min)?\\.js", Pattern.CASE_INSENSITIVE),
            "5.3.2",
            "https://getbootstrap.com/"
        ));

        // Lodash
        LIBRARY_SIGNATURES.put("lodash", new LibrarySignature(
            "Lodash",
            Pattern.compile("lodash(?:[.-]([0-9.]+))?(?:\\.min)?\\.js", Pattern.CASE_INSENSITIVE),
            "4.17.21",
            "https://lodash.com/"
        ));

        // Moment.js
        LIBRARY_SIGNATURES.put("moment", new LibrarySignature(
            "Moment.js",
            Pattern.compile("moment(?:[.-]([0-9.]+))?(?:\\.min)?\\.js", Pattern.CASE_INSENSITIVE),
            "2.30.0",
            "https://momentjs.com/"
        ));

        // Backbone.js
        LIBRARY_SIGNATURES.put("backbone", new LibrarySignature(
            "Backbone.js",
            Pattern.compile("backbone(?:[.-]([0-9.]+))?(?:\\.min)?\\.js", Pattern.CASE_INSENSITIVE),
            "1.4.1",
            "https://backbonejs.org/"
        ));

        // Underscore.js
        LIBRARY_SIGNATURES.put("underscore", new LibrarySignature(
            "Underscore.js",
            Pattern.compile("underscore(?:[.-]([0-9.]+))?(?:\\.min)?\\.js", Pattern.CASE_INSENSITIVE),
            "1.13.6",
            "https://underscorejs.org/"
        ));
    }

    public List<SecurityIssue> checkLibraries(String url, HttpResponse response) {
        List<SecurityIssue> issues = new ArrayList<>();
        String body = response.bodyToString();

        // Check script tags for library references
        Pattern scriptPattern = Pattern.compile("<script[^>]*src=[\"']([^\"']+)[\"'][^>]*>", Pattern.CASE_INSENSITIVE);
        Matcher scriptMatcher = scriptPattern.matcher(body);

        while (scriptMatcher.find()) {
            String scriptSrc = scriptMatcher.group(1);
            issues.addAll(checkScriptSource(url, scriptSrc));
        }

        // Check inline script content for library version comments
        Pattern inlineScriptPattern = Pattern.compile("<script[^>]*>(.*?)</script>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
        Matcher inlineMatcher = inlineScriptPattern.matcher(body);

        while (inlineMatcher.find()) {
            String scriptContent = inlineMatcher.group(1);
            issues.addAll(checkInlineScript(url, scriptContent));
        }

        // Check for known vulnerable patterns in body
        issues.addAll(checkVulnerablePatterns(url, body));

        return issues;
    }

    private List<SecurityIssue> checkScriptSource(String url, String scriptSrc) {
        List<SecurityIssue> issues = new ArrayList<>();

        for (LibrarySignature signature : LIBRARY_SIGNATURES.values()) {
            Matcher matcher = signature.pattern.matcher(scriptSrc);
            if (matcher.find()) {
                String version = matcher.groupCount() > 0 ? matcher.group(1) : null;

                if (version != null && !version.isEmpty()) {
                    if (isOutdated(version, signature.latestVersion)) {
                        issues.add(new SecurityIssue(
                            url,
                            "Outdated " + signature.name + " Library",
                            String.format("The application is using %s version %s. Latest version is %s. Outdated libraries may contain known vulnerabilities.",
                                signature.name, version, signature.latestVersion),
                            SecurityIssue.Severity.MEDIUM,
                            scriptSrc,
                            "Libraries"
                        ));
                    }
                } else {
                    issues.add(new SecurityIssue(
                        url,
                        signature.name + " Library Detected",
                        String.format("The application is using %s but version could not be determined. Latest version is %s.",
                            signature.name, signature.latestVersion),
                        SecurityIssue.Severity.INFO,
                        scriptSrc,
                        "Libraries"
                    ));
                }
            }
        }

        return issues;
    }

    private List<SecurityIssue> checkInlineScript(String url, String scriptContent) {
        List<SecurityIssue> issues = new ArrayList<>();

        // Check for version comments like /*! jQuery v1.11.1 */
        Pattern versionPattern = Pattern.compile("/\\*!?\\s*([A-Za-z.]+)\\s+v?([0-9.]+)", Pattern.CASE_INSENSITIVE);
        Matcher matcher = versionPattern.matcher(scriptContent);

        if (matcher.find()) {
            String libName = matcher.group(1).toLowerCase();
            String version = matcher.group(2);

            for (Map.Entry<String, LibrarySignature> entry : LIBRARY_SIGNATURES.entrySet()) {
                if (libName.contains(entry.getKey())) {
                    LibrarySignature signature = entry.getValue();
                    if (isOutdated(version, signature.latestVersion)) {
                        issues.add(new SecurityIssue(
                            url,
                            "Outdated " + signature.name + " Library (Inline)",
                            String.format("Inline %s version %s detected. Latest version is %s.",
                                signature.name, version, signature.latestVersion),
                            SecurityIssue.Severity.MEDIUM,
                            "Version " + version + " in inline script",
                            "Libraries"
                        ));
                    }
                }
            }
        }

        return issues;
    }

    private List<SecurityIssue> checkVulnerablePatterns(String url, String body) {
        List<SecurityIssue> issues = new ArrayList<>();

        // Check for common vulnerable patterns
        if (body.contains("eval(") || body.contains("Function(")) {
            issues.add(new SecurityIssue(
                url,
                "Dangerous JavaScript Function Usage",
                "The page contains usage of eval() or Function() constructor which can lead to code injection vulnerabilities.",
                SecurityIssue.Severity.HIGH,
                "eval() or Function() detected in page",
                "Code Quality"
            ));
        }

        if (body.matches("(?i).*innerHTML\\s*=.*")) {
            issues.add(new SecurityIssue(
                url,
                "Potential DOM-based XSS",
                "The page uses innerHTML assignment which could lead to DOM-based XSS if user input is not properly sanitized.",
                SecurityIssue.Severity.MEDIUM,
                "innerHTML usage detected",
                "Code Quality"
            ));
        }

        // Check for embedded credentials or API keys
        Pattern apiKeyPattern = Pattern.compile("(?i)(api[_-]?key|apikey|secret|password|token)\\s*[:=]\\s*['\"]([^'\"]{20,})['\"]");
        Matcher apiMatcher = apiKeyPattern.matcher(body);
        if (apiMatcher.find()) {
            issues.add(new SecurityIssue(
                url,
                "Potential Exposed Credentials",
                "The page appears to contain hardcoded API keys, secrets, or credentials in JavaScript code.",
                SecurityIssue.Severity.HIGH,
                "Pattern: " + apiMatcher.group(0).substring(0, Math.min(50, apiMatcher.group(0).length())) + "...",
                "Credentials"
            ));
        }

        return issues;
    }

    private boolean isOutdated(String currentVersion, String latestVersion) {
        try {
            String[] current = currentVersion.split("\\.");
            String[] latest = latestVersion.split("\\.");

            for (int i = 0; i < Math.min(current.length, latest.length); i++) {
                int currentPart = Integer.parseInt(current[i].replaceAll("[^0-9]", ""));
                int latestPart = Integer.parseInt(latest[i].replaceAll("[^0-9]", ""));

                if (currentPart < latestPart) {
                    return true;
                } else if (currentPart > latestPart) {
                    return false;
                }
            }

            return current.length < latest.length;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private static class LibrarySignature {
        final String name;
        final Pattern pattern;
        final String latestVersion;
        final String url;

        LibrarySignature(String name, Pattern pattern, String latestVersion, String url) {
            this.name = name;
            this.pattern = pattern;
            this.latestVersion = latestVersion;
            this.url = url;
        }
    }
}
