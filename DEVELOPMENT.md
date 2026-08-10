# Development contract

Sanitize structured browser-session exports locally with explicit, reviewable rules and without mutating source files.

Preserve value-free audits, conservative defaults, generic JSON compatibility, adapter-specific validation when claimed, no network activity, and mandatory human review. Every feature release must update tests, version metadata, changelog, README claims, repository metadata, release artifacts, and the Forge catalog together.

Version 1.1 adds a self-contained browser interface alongside the Python implementation. The browser surface must remain dependency-free, offline-capable, explicit about sensitive previews, and behaviorally aligned with the documented policy. Detector reports may record rule names and structural paths but never matched values. Batch writes retain the existing no-overwrite guarantee.
