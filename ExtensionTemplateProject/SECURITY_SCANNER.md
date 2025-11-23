# BorborBorp Security Scanner

A comprehensive Burp Suite extension that automatically detects low-hanging fruit security vulnerabilities in web applications.

## Features

### 🔍 Automated Security Scanning

The extension passively scans HTTP traffic and identifies:

#### Header Security Issues
- **Missing Security Headers**
  - X-Frame-Options / CSP frame-ancestors (Clickjacking protection)
  - X-Content-Type-Options (MIME sniffing protection)
  - Strict-Transport-Security (HSTS)
  - Content-Security-Policy (XSS protection)
  - Referrer-Policy
  - Permissions-Policy

- **Insecure Header Values**
  - Server version disclosure
  - X-Powered-By technology disclosure
  - Insecure CORS configurations (wildcards with credentials)

- **Cookie Security**
  - Missing HttpOnly flag (XSS vulnerability)
  - Missing Secure flag on HTTPS
  - Missing SameSite attribute (CSRF vulnerability)

#### Outdated Libraries Detection
Detects outdated versions of popular JavaScript libraries:
- jQuery
- AngularJS
- React
- Vue.js
- Bootstrap
- Lodash
- Moment.js
- Backbone.js
- Underscore.js

#### Code Quality Issues
- Dangerous function usage (eval, Function constructor)
- Potential DOM-based XSS (innerHTML usage)
- Exposed credentials/API keys in JavaScript

### 🎯 Key Capabilities

1. **Automatic Deduplication**: Issues are automatically deduplicated by URL + Title + Category to avoid noise

2. **Severity-Based Highlighting**:
   - 🔴 High (Red) - Critical issues requiring immediate attention
   - 🟠 Medium (Orange) - Important security concerns
   - 🟡 Low (Yellow) - Minor security improvements
   - 🔵 Info (Blue) - Informational findings

3. **Rich UI Features**:
   - Sortable table by any column
   - Filter by severity level
   - Detailed issue descriptions
   - Evidence display
   - Statistics dashboard

4. **Non-Intrusive Scanning**:
   - Passive scanning that doesn't modify traffic
   - Background processing to avoid slowing down proxying
   - HTML and JavaScript content type detection

## Installation

1. Build the extension:
   ```bash
   cd ExtensionTemplateProject
   ./gradlew build
   ```

2. Load in Burp Suite:
   - Go to Extensions → Add
   - Select the JAR file from `build/libs/`
   - The extension will appear as "Security Scanner" tab

## Usage

1. **Browse websites through Burp Proxy** - The scanner works automatically on all HTTP traffic

2. **View findings** - Open the "Security Scanner" tab to see all detected issues

3. **Filter results** - Use the dropdown to filter by severity:
   - All Issues
   - High Severity
   - Medium Severity
   - Low Severity
   - Info

4. **View details** - Click any issue in the table to see full description and evidence

5. **Manage issues**:
   - **Refresh**: Reload all issues from memory
   - **Clear All**: Remove all detected issues (requires confirmation)

## Issue Categories

### Headers
Security header misconfigurations and missing protections

### Libraries
Outdated JavaScript libraries with known vulnerabilities

### Code Quality
Dangerous coding patterns that may lead to vulnerabilities

### Credentials
Potential exposed API keys, secrets, or passwords

## Architecture

```
Extension.java - Main extension entry point
├── scanner/
│   ├── SecurityScanner.java - HTTP handler that coordinates scanning
│   ├── IssueManager.java - Deduplication and issue storage
│   ├── SecurityIssue.java - Issue data model
│   └── checkers/
│       ├── HeaderSecurityChecker.java - Header vulnerability detection
│       └── LibraryChecker.java - Outdated library detection
└── ui/
    ├── BorborBorpMainPanel.java - Main UI container
    └── SecurityScannerPanel.java - Issue display table and details
```

## Scanning Logic

1. **HTTP Response Interception**: SecurityScanner implements HttpHandler
2. **Content Type Filtering**: Only scans HTML and JavaScript responses
3. **Parallel Checking**: Both header and library checkers run on applicable content
4. **Deduplication**: IssueManager uses Set with custom equals/hashCode
5. **UI Updates**: Listeners notify UI panel when new issues are found

## Statistics

The status bar shows:
- Total unique issues found
- Count by severity (High/Medium/Low/Info)
- Number of issues currently displayed (after filtering)

## Future Enhancements

Potential additions:
- Export issues to CSV/JSON
- Integration with Burp's native issue tracking
- Custom rule configuration
- Suppress false positives
- Scan scheduling
- Additional vulnerability checks (SQLi patterns, path traversal, etc.)

## License

This extension is part of the BorborBorp project.
