# Development Best Practices

## AI Best Practices

- **Always check `api.ai().isEnabled()` before using AI features.** When
  it returns `false`, your AI code path should no-op gracefully — never
  break a scan because AI was unavailable.
- **Declare `EnhancedCapability.AI_FEATURES`** by overriding
  `BurpExtension.enhancedCapabilities()` to return
  `Set.of(EnhancedCapability.AI_FEATURES)`. Without this declaration,
  `api.ai().isEnabled()` returns `false` even when Burp AI is enabled
  at the suite level — a common source of "why isn't my AI feature
  working?" debugging.
- **Run AI calls on a background thread with a hard timeout.**
  `api.ai().prompt().execute(...)` is synchronous; without a timeout,
  a slow prompt can stall a scan thread indefinitely. A single-thread
  daemon executor with a `Future.get(timeout, ...)` pattern is the
  simplest fix. Shut the executor down in your unloading handler.
- **Escape AI-generated content before displaying it to users.** Model
  output may contain HTML; embedded directly into an `AuditIssue`
  detail string it will render. Validate identifiers with regex; HTML-
  escape any free-form content before interpolation.
- **Use structured (JSON) formats for AI prompts** — ask the model for
  `{"verdict": "KEEP" | "SUPPRESS"}` rather than free-text. Parse with
  Gson. Free-text responses produce flaky results on the long tail of
  model outputs; structured replies fail closed when malformed.
- **Send only essential data to minimize AI credit usage.** Truncate
  request/response bodies to a few hundred bytes; strip cookies and
  other sensitive headers; cache identical prompts.
- **Implement response caching for repeated queries.** Most prompts in
  a passive-scan flow are duplicates (same finding type, same URL
  pattern). A bounded `ConcurrentHashMap` keyed on the prompt content
  is enough.

## Lifecycle and resources

- **Register an `ExtensionUnloadingHandler`** via
  `api.extension().registerUnloadingHandler(...)` and use it to release
  every long-lived resource: `ExecutorService`s (call `shutdown()`),
  Swing `Timer`s (call `stop()`), in-memory registries (call `clear()`),
  caches, file handles. BApp acceptance criterion #6.
- **Catch and log exceptions in background threads.** Burp does not
  surface uncaught exceptions in threads you spawn — they vanish
  silently, hiding bugs. Wrap `Runnable` bodies in try/catch and write
  stack traces to `api.logging().logToError(...)`.

## HTTP request handling

- **Use `api.http().sendRequest(...)`** for outbound HTTP, not
  `java.net.URL` or third-party HTTP clients. Burp's networking honours
  the user's upstream proxy, session-handling rules, and TLS settings.
  BApp criterion #7.
- **Avoid HTTP requests inside `passiveAudit()`.** Passive scan checks
  must be inspection-only.
- **`HttpRequest.httpRequestFromUrl(url)` already inserts a `Host`
  header** derived from the URL. Adding the original request's
  `withAddedHeaders(...)` on top produces a duplicate `Host`. Many
  servers reject duplicate `Host` with a 4xx — this can silently mask
  findings on URL-rebuild checks. Re-attach all original headers
  *except* `Host`:

  ```java
  HttpRequest mutated = HttpRequest.httpRequestFromUrl(newUrl)
          .withMethod(base.method())
          .withBody(base.bodyToString());
  for (HttpHeader header : base.headers()) {
      if (!"host".equalsIgnoreCase(header.name())) {
          mutated = mutated.withAddedHeader(header);
      }
  }
  ```

- **Don't keep long-lived references to `HttpRequestResponse`** values
  passed to your handlers/checks. Use
  `api.persistence().temporaryFileContext()` if you need durable
  references. BApp criterion #9.

## UI

- **Apply Burp's current theme to custom Swing components** via
  `api.userInterface().applyThemeToComponent(component)` before
  registering. Without this, your tab uses Swing defaults and looks
  out of place against a dark Burp.
- **Parent dialogs / popups to the Burp main frame** via
  `api.userInterface().swingUtils().suiteFrame()`. Without it, popups
  land on the wrong monitor in multi-display setups. BApp criterion #10.
- **Don't perform slow operations on the EDT.** Use
  `SwingUtilities.invokeLater(...)` for UI updates from background
  threads, and run any HTTP / AI / I/O on a worker thread.

## Issue construction

- **Montoya has no `Critical` severity** — only `HIGH`, `MEDIUM`,
  `LOW`, `INFORMATION`. If you're porting from the legacy API, map
  `Critical` to `HIGH` (or split the legacy critical findings into
  HIGH-with-CERTAIN-confidence vs HIGH-with-FIRM-confidence).
- **Use `edition.displayName()`**, not the raw enum, when writing the
  edition into log output or issue text. The enum constant
  `BurpSuiteEdition.ENTERPRISE_EDITION` is kept for backward
  compatibility, but `displayName()` returns the current product name
  ("Burp Suite DAST") that customers recognise.

## Code organisation (especially during legacy → Montoya migration)

- **Rewrite by hand, file by file, against an explicit style.**
  Bulk-rewriting a legacy extension via an automation tool tends to
  produce code that compiles but is unreviewable: 600+ LOC files,
  dense inline logic, swallowed exceptions. Soft targets that produce
  reviewable code:
  - methods under 50 lines
  - classes under 250 lines
  - one public entry method per scan check, helpers private below
  - constants (path keywords, payload tables, HTML strings) at the top
  - no swallowed exceptions — every catch logs to
    `api.logging().logToError(...)` with a stack trace
- **An `AbstractPassiveCheck` / `AbstractActiveCheck` base class is
  worth writing** for any extension with more than 2-3 scan checks.
  Centralise exception handling, common state recording, and any
  optional layers (such as AI triage) so individual check files only
  contain detection logic.

## Testing

- **Compile-clean is not the same as behaviourally correct.** When
  refactoring or migrating, always verify findings parity against the
  previous version on a known-vulnerable target (Web Security Academy
  labs, ginandjuice.shop). Detection logic is easy to lose in
  translation.
