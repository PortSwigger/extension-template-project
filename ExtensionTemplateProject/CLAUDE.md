# Burp Suite Montoya BApp Starter Project

This is a starter project for developing Burp Suite extensions using the Montoya API.

## Project Overview

This project provides a minimal template for creating Burp Suite extensions (BApps) using:
- **Java 21** (or lower)
- **Montoya API 2025.5**
- **Gradle** build system

## Project Structure

```
├── build.gradle.kts          # Gradle build configuration
├── settings.gradle.kts       # Project settings (name: "extension-template-project")
├── src/main/java/
│   └── Extension.java        # Main extension class
├── gradle/                   # Gradle wrapper files
├── gradlew                   # Gradle wrapper script (Unix)
└── gradlew.bat               # Gradle wrapper script (Windows)
```

## Prerequisites
- Java Development Kit (JDK) 21 or lower
- Burp Suite Professional or Community Edition

## BApp Store Acceptance Criteria

**CRITICAL**: To submit your extension to the BApp Store, your extension MUST meet ALL of the following criteria:

### 1. Unique Function
- Extension must perform a unique function
- Should not duplicate existing BApp Store extensions
- Consider modifying existing extensions if idea isn't entirely new

### 2. Clear Name
- Name must clearly describe extension's purpose
- Provide a one-line summary and detailed description

### 3. Security
- Treat HTTP message content as untrusted
- Operate securely during expected usage
- Be cautious with auto-filled data from untrusted sources

### 4. Dependencies
- Include all dependencies for one-click installation
- Avoid version mismatches with underlying tools

### 5. Threading
- Perform slow operations in background threads
- Avoid blocking Swing Event Dispatch Thread
- Protect shared data structures with locks
- Catch and report background thread exceptions

### 6. Clean Unloading
- Release all resources when unloading
- Register unload handler
- Terminate background threads during unloading

### 7. Burp Networking
- Use `Http.issueHttpRequest()` for HTTP requests
- Respect upstream proxy and session handling settings
- Avoid target communication in `ScanCheck.passiveAudit()`

### 8. Offline Support
- Include recent definitions for online services
- Support high-security networks without internet

### 9. Large Project Handling
- Avoid long-term references to transient objects
- Use `Persistence.temporaryFileContext()` for message references
- Be cautious with large result sets

### 10. GUI Parenting
- Create GUI elements as children of main Burp Frame
- Use `SwingUtils.suiteFrame()` to get parent frame

### 11. Montoya API
- Reference `montoya-api` artifact using build tools
- Recommended to use Gradle for new projects

### 12. AI Functionality
- Use dedicated Montoya API methods for AI features
- Follow AI extension best practices
- Handle AI-related traffic through Burp's AI platform

## Basic Extension Structure

The main extension class implements `BurpExtension`:

```java
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class Extension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi montoyaApi) {
        montoyaApi.extension().setName("My Extension");
        // Add your extension logic here
    }
}
```

## Common Extension Features

### Adding Context Menu Items
```java
montoyaApi.userInterface().registerContextMenuItemsProvider(contextMenuItemsProvider);
```

### Creating Custom Tabs
```java
montoyaApi.userInterface().registerSuiteTab(suiteTab);
```

### Adding Settings Panel
```java
SettingsPanelWithData panel = SettingsPanelBuilder.settingsPanel()
    .withPersistence(SettingsPanelPersistence.USER_SETTINGS)
    .withTitle("Extension Settings")
    .withSettings(
        SettingsPanelSetting.stringSetting("API Key", ""),
        SettingsPanelSetting.booleanSetting("Enable Feature", true)
    )
    .build();

montoyaApi.userInterface().registerSettingsPanel(panel);
```

### Logging
```java
montoyaApi.logging().logToOutput("Extension loaded successfully");
montoyaApi.logging().logToError("Error occurred: " + errorMessage);
```

## AI-Powered Extensions

For AI-enhanced extensions, declare enhanced capabilities:

```java
@Override
public EnhancedCapability[] enhancedCapabilities() {
    return new EnhancedCapability[]{EnhancedCapability.AI_FEATURES};
}

@Override
public void initialize(MontoyaApi montoyaApi) {
    if (montoyaApi.ai().isEnabled()) {
        // AI functionality available
        AiService ai = montoyaApi.ai();
        // Use ai.complete() for LLM interactions
    }
}
```

### AI Best Practices
- Always check `ai.isEnabled()` before using AI features
- Escape AI-generated content before displaying to users
- Send only essential data to minimize AI credit usage
- Use structured formats (JSON) for AI requests
- Implement response caching for repeated queries
- Use background threads for AI operations

## Build Configuration

The project uses Gradle with the following key configurations:

- **Java 21 compatibility** - Source and target compatibility set to Java 21
- **UTF-8 encoding** - Ensures proper character handling
- **Fat JAR creation** - Includes all dependencies in the output JAR
- **Montoya API dependency** - Version 2025.5 (compile-only)

## Useful Resources

- **Montoya API Documentation**: https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/MontoyaApi.html
- **API Source Code**: https://github.com/PortSwigger/burp-extensions-montoya-api
- **Example Extensions**: https://github.com/PortSwigger/burp-extensions-montoya-api-examples
- **Extension Development Guide**: https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating

## Common Commands

```bash
# Build the project
./gradlew build

# Create JAR file
./gradlew jar

# Clean build artifacts
./gradlew clean
```