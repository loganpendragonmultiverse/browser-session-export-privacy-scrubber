# Development contract

Sanitize structured browser-session exports locally with explicit, reviewable rules and without mutating source files.

Preserve value-free audits, conservative defaults, generic JSON compatibility, adapter-specific validation when claimed, no network activity, and mandatory human review. Every feature release must update tests, version metadata, changelog, README claims, repository metadata, release artifacts, and the Forge catalog together.

Version 1.1 adds a self-contained browser interface alongside the Python implementation. The browser surface must remain dependency-free, offline-capable, explicit about sensitive previews, and behaviorally aligned with the documented policy. Detector reports may record rule names and structural paths but never matched values. Batch writes retain the existing no-overwrite guarantee.

## 1.2.0 improvement session

Align Python and browser scrubbing with shared fixtures and add side-by-side strict-sharing previews with retained-field summaries.

The self-contained browser UI and Python engine share fixtures for private/public IPv6, mapped IPv4, noncanonical numeric hosts, percent-encoded/repeated query keys, private-host opt-out, unknown JSON shapes, detectors and strict profiles. --profile strict redacts free-text strings and removes URL paths/query data; field names, structure, numbers/booleans and public hosts remain, so anonymity is not guaranteed. --compare-policy adds value-free retained-field/count comparisons to CLI audits. The browser compares selected and strict policies, imports/exports complete policies and downloads separate sanitized files/audits. --write-browser exports the bundled interface from the installed wheel. Existing URL credential removal, duplicates and fragments are preserved or redacted according to explicit rules; private-host checkbox behavior, IPv6 brackets, malformed-port handling and filename HTML injection are corrected. Desktop/mobile localhost QA passed; file-scheme offline launch is not claimed because the available browser blocks that scheme.

Local formatting, lint, strict types and regression tests pass. Public release completion requires the protected CI/CodeQL matrix, tagged artifacts and matching Forge catalog/detail deployment.

## 1.3.0 acceptance

Redact or drop exact JSON data paths while retaining same-named public fields elsewhere.

Policy JSON accepts redact_paths and drop_paths arrays of exact JSON Pointers, such as {"redact_paths":["/windows/0/tabs/1/title"],"drop_paths":["/private/note"]}. Escape / as ~1 and ~ as ~0 inside a key. Array indices refer to the original input before drops; there are no wildcards (a literal * names a literal key). A parent drop wins; otherwise a parent redaction replaces the whole value. The empty pointer redacts the root; dropping the root is rejected. These rules add targeted removal/redaction, not an exemption from other selected policy rules. Audits contain paths, rule names and counts, never the removed values. Field names, structure and retained content can still identify someone; inspect the sanitized copy.

## Gold Star review — October 17, 2026

Remove private data from browser-session JSON files, then review what changed before sharing a copy.

Logan considers this project complete within its documented local sanitization and human-review purpose. Continue fixes and maintenance, and consider good new ideas. That historical recovery review covered v1.3.1; the catalog records the current reviewed release.

Definition: https://www.loganpendragonforge.com/open-source/?gold=1

## 1.3.1 output recovery

Treat every CLI invocation as one bounded export operation, including all batch outputs and the combined audit. Stage all data, reserve new destinations exclusively, recover only unchanged files created by the command, and preserve source/existing/concurrently edited files. Test both failure directions, later batch and audit failures, corrected-destination retry, duplicate names, aliases, partial writes and stdout failure. Abrupt termination and power-loss atomicity are not claimed.

## Gold recovery reassessment — October 17, 2026

v1.3.1 passed 68 source tests and the same 68 tests against the actual tag-built installed wheel, with 97% source coverage, strict types, formatting/lint, dependency audit, protected Windows/macOS/Linux CI and CodeQL. Chromium desktop/mobile, Firefox and WebKit exercised the wheel-bundled page, targeted redaction, sanitized/audit downloads, policy import/export and two-file batches without application network requests or page errors. Both public distributions match the tagged build, and all three public assets match their GitHub digests. Peer source review covered the recovery implementation and failure/retry regressions. No meaningful remaining gap was identified within the documented purpose. Explicit policies still require human inspection, and ordinary-failure recovery does not promise a multi-file power-loss transaction.

## 1.3.3 browser data and audit contract

Reject browser numbers that cannot be retained safely before preparing any results, including a whole multi-file batch. Direct larger integer IDs to Python; require finite numbers in both interfaces. Bind browser audits to the exact UTF-8 sanitized download bytes, and include normalized policy and version-aware format classification. Preserve Python canonical fingerprints. Reject URL-shaped domain rules while retaining bare IP/IDN rules. Keep both browser bundles identical to the tested engine. Normal protected checks and exact-head review remain release gates.

Python also rejects non-finite float values before output while preserving larger integer IDs. Verify that overflowed JSON numbers and NaN/Infinity inputs fail without creating output files.

## 1.3.4 stdout regression acceptance

Exercise real closed stdout pipes with small and large reports, complete normal output, partial and zero descriptor writes, and in-memory streams. Verify status 2 without an ignored shutdown exception, unchanged source files, and export rollback and corrected-destination retry.
