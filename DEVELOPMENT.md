# Development contract

Sanitize structured browser-session exports locally with explicit, reviewable rules and without mutating source files.

Preserve value-free audits, conservative defaults, generic JSON compatibility, adapter-specific validation when claimed, no network activity, and mandatory human review. Every feature release must update tests, version metadata, changelog, README claims, repository metadata, release artifacts, and the Forge catalog together.

Version 1.1 adds a self-contained browser interface alongside the Python implementation. The browser surface must remain dependency-free, offline-capable, explicit about sensitive previews, and behaviorally aligned with the documented policy. Detector reports may record rule names and structural paths but never matched values. Batch writes retain the existing no-overwrite guarantee.

## 1.2.0 improvement session

Align Python and browser scrubbing with shared fixtures and add side-by-side strict-sharing previews with retained-field summaries.

The self-contained browser UI and Python engine share fixtures for private/public IPv6, mapped IPv4, noncanonical numeric hosts, percent-encoded/repeated query keys, private-host opt-out, unknown JSON shapes, detectors and strict profiles. --profile strict redacts free-text strings and removes URL paths/query data; field names, structure, numbers/booleans and public hosts remain, so anonymity is not guaranteed. --compare-policy adds value-free retained-field/count comparisons to CLI audits. The browser compares selected and strict policies, imports/exports complete policies and downloads separate sanitized files/audits. --write-browser exports the bundled interface from the installed wheel. Existing URL credential removal, duplicates and fragments are preserved or redacted according to explicit rules; private-host checkbox behavior, IPv6 brackets, malformed-port handling and filename HTML injection are corrected. Desktop/mobile localhost QA passed; file-scheme offline launch is not claimed because the available browser blocks that scheme.

Local formatting, lint, strict types and regression tests pass. Public release completion requires the protected CI/CodeQL matrix, tagged artifacts and matching Forge catalog/detail deployment.
