# Changelog

## 1.3.2 - 2026-10-17

- Match Unicode and punycode selected domains consistently, including subdomains and nontransitional sharp-s handling.
- Add the Python idna dependency instead of the standard library’s legacy IDNA 2003 mapping; keep browser conversion local and dependency-free.

## 1.3.1 - 2026-10-17

- Recover ordinary paired and complete-batch export failures, including combined audit and stdout failures, so corrected destinations can be retried.
- Reserve all final names exclusively and preserve existing, replaced or concurrently edited files during cleanup.
- Prepare all sources and serialized results before publishing any output; reject duplicate batch filenames and audit aliases.

## 1.3.0 - 2026-10-17

- Add exact RFC 6901 redact_paths and drop_paths to Python and the dependency-free browser
- Apply paths against original array indices with drop precedence and escaped slash/tilde keys
- Add value-free path actions and shared Python/browser regression fixtures

## 1.2.0 - 2026-09-07

- Align Python and browser scrubbing with shared fixtures and add side-by-side strict-sharing previews with retained-field summaries.
- Added regression coverage for the audited behavior and invalid inputs.

## 1.1.0 - 2026-08-10

- Added a self-contained local drag-and-drop interface with explicit before/after previews.
- Added reusable JSON policy import/export and opt-in email, token, and local-path detectors.
- Added value-free review queues containing rule and structural-path evidence without matched values.
- Added collision-safe multi-file CLI processing, per-file audits, and a combined batch audit.

## 1.0.0 - 2026-08-03

- Added local sanitization for Tabitha Workspaces and generic browser-session JSON exports.
- Added URL credential removal, query-value and fragment redaction, private and selected host hiding, title and text-field redaction, key removal, and explicit allowlists.
- Added value-free audit manifests, deterministic sanitized-output fingerprints, source-safe writes, policy validation, tests, and cross-platform release packaging.
