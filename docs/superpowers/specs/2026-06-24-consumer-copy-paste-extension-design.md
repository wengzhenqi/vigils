# Consumer Copy/Paste Chrome Extension Design

Date: 2026-06-24

## Goal

Turn the existing Chrome MV3 extension into a consumer-friendly copy/paste guard that works immediately after extension install, without requiring Native Host registration or the Vigils desktop app.

The same extension should still leave a clean enterprise path. Enterprise users can enable an enterprise mode later and connect a provider through one of several possible technologies: Native Host, localhost agent, enterprise HTTPS API, browser Wasm, or another managed provider. Native Host becomes one possible enterprise provider, not a consumer requirement.

## Non-Goals

- Do not implement the new behavior in this design step.
- Do not require ordinary users to install a desktop app, run terminal commands, or register `com.vigil.host`.
- Do not build the full enterprise provider registry in the first implementation. The first implementation should define the interface and configuration shape, with a disabled/mock enterprise provider if needed.
- Do not expose advanced enterprise strategy-chain controls in the first UI.

## Current Context

The current extension already has useful browser-side pieces:

- `content-script.js` listens for paste, debounced input, submit, and contenteditable Enter paths.
- `background.js` manages protected origins, custom site registration, findings logs, tier selection, and Native Host request routing.
- `popup.js` shows recent findings and page protection state.
- `options.js` manages custom protected sites and currently displays Native Host install commands.

The main consumer friction is that `background.js` directly depends on `chrome.runtime.connectNative("com.vigil.host")` for real scanning. If the Native Host is missing or disconnected, the extension fail-closes to `block`, which is correct for security but too heavy for ordinary users.

## Recommended Approach

Use a dual-mode provider architecture.

Consumer mode is the default and uses a browser-local JavaScript scanner. Enterprise mode enables a scanner pipeline that can call an enterprise provider after the local scanner. The pipeline merges provider results by taking the stricter action.

```text
content-script
  paste / input / submit
  collect text + origin + event_kind

background
  receive vigil_check
  load mode and provider configuration
  call scannerPipeline.check(request)

scannerPipeline
  consumer mode:
    consumerJsProvider
  enterprise mode:
    consumerJsProvider + enterpriseProvider
  merge results by strictness

content-script
  show inline confirmation for risks
  apply redact or block action
```

## Architecture

### Module Boundaries

`background.js`

- Own Chrome runtime message handling.
- Own protected site checks, custom site sync, findings log, popup/options messages, and mode state.
- Call `scannerPipeline.check()` instead of directly calling `connectNative`.
- Avoid knowing whether the active provider is JS, Native Host, localhost, HTTPS API, or Wasm.

`scanner-pipeline.js`

- Accept a normalized scan request.
- Select provider chain based on extension mode.
- Run providers with timeout and error handling.
- Merge provider results.
- Return a normalized result for the content script.

`providers/consumer-js-provider.js`

- Browser-local lightweight scanner.
- No Native Host, no network, no desktop dependency.
- Uses local regex rules and redaction helpers.

`providers/enterprise-provider.js`

- Enterprise abstraction entry point.
- First implementation may be disabled or mock-backed.
- Later implementations may route to Native Host, localhost agent, enterprise API, browser Wasm, or another provider.

`redaction-rules.js`

- Define JavaScript detection rules and redaction functions.
- Keep rules deterministic and testable.
- Avoid storing matched raw spans in persistent storage.

`risk-decision.js`

- Map findings into action recommendations.
- Decide which findings are redactable and which are block-only.
- Format user-facing risk labels without exposing raw matched values.

### Scan Request

```js
{
  request_id: string,
  origin: string,
  event_kind: "paste" | "input" | "submit",
  text: string
}
```

### Scan Result

```js
{
  request_id: string,
  action: "allow" | "confirm_redact" | "block",
  findings: [
    {
      kind: string,
      severity: "medium" | "high",
      redactable: boolean
    }
  ],
  redacted_text?: string,
  source: "consumer_js" | "enterprise" | "pipeline",
  error?: string
}
```

The existing Rust protocol uses `allow`, `redact`, and `block`. The consumer extension should use `confirm_redact` internally so the content script knows that user confirmation is required before applying a redaction. If an enterprise provider returns `redact`, the pipeline normalizes it to `confirm_redact` unless policy explicitly says the provider may auto-redact.

## Consumer UX

Consumer mode is automatic. Users install the extension, open a supported AI site, and receive protection without terminal steps or desktop app setup.

### Default Behavior

- No finding: allow the original event.
- Redactable finding: show an inline page confirmation dialog. The primary action is "Redact and continue".
- High-risk finding: show an inline page dialog that explains the risk and blocks the event. It does not offer a direct continue action.

The first implementation should include rules 1 and 2 from the design discussion:

1. The primary action for ordinary redactable risk is "Redact and continue".
2. High-risk content does not offer a direct continue action.

"Allow once" is not part of the first core flow. It can be added later with a second confirmation and stronger policy controls.

### Inline Confirmation

The content script should show a page-level confirmation UI near the active input when possible, falling back to a fixed corner dialog if anchoring is unreliable.

For redactable findings:

```text
Vigils found risky content
Detected: API key, database URL
Original text has not left your browser.

[Redact and continue] [Block]
```

For high-risk findings:

```text
Vigils blocked high-risk content
Detected: private key
This type of secret should not be sent to an AI site.

[Close]
```

If the extension can produce a redacted text but cannot safely write it back into the page input, it should block the original event and provide a "Copy redacted text" action.

### Popup

The popup remains lightweight:

- Show mode: Consumer Guard, Enterprise Guard, or Enterprise issue.
- Show whether the current page is protected.
- Show recent findings metadata: time, origin, action, finding kinds.
- Do not show raw text or raw matched values.
- Link to settings.

### Options Page

The options page should stop presenting Native Host install commands as the default path.

Recommended sections:

- Protection mode:
  - Consumer mode, default.
  - Enterprise mode, off by default.
- Consumer mode:
  - Explain that detection runs in the browser and text does not leave the browser.
  - Manage protected sites and custom sites.
- Enterprise connection:
  - Hidden or collapsed until enterprise mode is enabled.
  - Provider type selector prepared for Native Host, localhost, HTTPS API, Wasm, or custom.
    The first implementation may show these as not yet configured.
  - Data policy: `local_only`, `metadata_only`, or `raw_allowed`.

## Scanner Rules

First consumer provider should cover common high-confidence risks.

Redactable findings:

- OpenAI API key.
- Anthropic API key.
- Google API key.
- GitHub token.
- GitLab token.
- Slack webhook.
- Stripe secret key.
- AWS access key id.
- JWT.
- `.env` style secret assignment.
- Database URL containing `user:password@`.

Block-only findings:

- PEM private key.
- Redaction failure.
- Redacted text still matches a scanner rule after re-scan.
- Enterprise provider result with action `block`.

The JS scanner is intentionally lighter than the existing Rust scanner. It is meant to remove the install barrier, not fully replace enterprise-grade detection.

## Pipeline Semantics

Action strictness:

```text
block > confirm_redact > allow
```

Consumer mode:

```text
request -> consumerJsProvider -> result
```

Enterprise mode:

```text
request -> consumerJsProvider -> enterpriseProvider -> merge stricter result
```

If providers disagree, the stricter result wins. A provider may add findings to the result, but persistent UI and logs must only store finding metadata, not raw matched values.

## Enterprise Provider Interface

Enterprise mode should not be designed as "Native Host mode". It should be a provider interface.

Provider types planned for future support:

- `native_host`: Chrome Native Messaging, including the current `com.vigil.host` path.
- `localhost`: a local app or agent exposed on localhost.
- `https_api`: enterprise-managed service.
- `wasm`: browser-local advanced scanner.
- `disabled`: explicit first implementation state when no enterprise provider is configured.

Enterprise data policy:

- `local_only`: do not send raw text outside the browser. Only local providers are allowed.
- `metadata_only`: send origin, event kind, length bucket, local finding kinds, and policy metadata. Do not send raw text.
- `raw_allowed`: enterprise provider may receive raw text. UI must make this explicit before enabling.

First implementation should store enterprise settings but can leave real provider implementations disabled. The important part is keeping the background and pipeline code provider-neutral.

## Error Handling

Consumer mode:

- JS provider exception: block the current event and show "Local detection failed, blocked for safety".
- Redaction failure: block.
- Re-scan after redaction still finds risk: block.
- Cannot write redacted text back to the input: block original event and offer copy-redacted-text if available.

Enterprise mode:

- Enterprise provider not configured: continue using consumer mode and show "Enterprise not configured" in popup/options.
- Enterprise provider configured but unavailable: first implementation should fail closed by default and block the event.
- Enterprise provider timeout: block and record `provider_timeout` metadata.
- Enterprise provider violates configured data policy: do not call the provider; block in enterprise mode and surface a configuration error.

## Privacy And Storage

Consumer mode must not send raw text off-device.

Extension storage may contain:

- Mode.
- Protected site metadata.
- Enterprise provider configuration.
- Data policy.
- Finding log metadata.

Extension storage must not contain:

- Raw page text.
- Redacted text.
- Raw matched values.
- Full text hashes that could be used as dictionary lookup keys.

The in-memory recent findings log should continue to store only timestamp, origin, event kind, action, and finding kinds.

## Migration Plan

1. Add scanner pipeline and provider modules.
2. Add consumer JS rules and redaction helpers.
3. Replace direct background Native Host check path with `scannerPipeline.check()`.
4. Set consumer JS provider as default.
5. Add inline confirmation behavior to content script.
6. Update options page from Native Host install helper to mode and enterprise settings.
7. Update popup to show consumer/enterprise mode state.
8. Keep enterprise provider disabled or mock-backed for the first implementation.
9. Leave current Native Host code in the repository, but stop making it required for normal extension use.

## Testing

Pure function tests:

- Rule detection and redaction for each consumer rule.
- Re-scan fails closed when redacted text still matches.
- Risk decision maps PEM private key to block-only.
- Pipeline merge uses `block > confirm_redact > allow`.
- Enterprise data policy prevents raw text from being sent when not allowed.

Background tests:

- Consumer mode does not call `chrome.runtime.connectNative`.
- Consumer mode returns allow, confirm_redact, or block from the JS provider.
- Enterprise mode with disabled provider behaves according to failure policy.
- Findings log contains no raw text or redacted text.
- Mode and provider settings are validated before use.

Content script tests or manual scenarios:

- Paste token into protected site, confirm dialog appears, redaction writes back.
- Submit text containing a token, confirm dialog appears before submit continues.
- Paste PEM private key, event is blocked and no continue action appears.
- Redaction writeback failure blocks original event.
- Custom protected sites still receive content script injection.

## Open Decisions Resolved

- The first implementation uses one extension, not separate consumer and enterprise extensions.
- Consumer mode is default.
- Consumer mode uses browser-local JS rules first.
- The extension keeps an enterprise provider interface for future integrations.
- First user confirmation flow includes "Redact and continue" for redactable risks and block-only behavior for high-risk content.
- "Allow once" is deferred.
