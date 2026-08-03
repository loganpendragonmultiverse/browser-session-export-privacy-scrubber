# Browser Session Export Privacy Scrubber

[![CI](https://github.com/loganpendragonmultiverse/browser-session-export-privacy-scrubber/actions/workflows/ci.yml/badge.svg)](https://github.com/loganpendragonmultiverse/browser-session-export-privacy-scrubber/actions/workflows/ci.yml)

Create a sanitized copy of a browser-session JSON export before sharing it. The local CLI removes URL credentials, redacts query values and fragments, hides private or selected hosts, optionally redacts title and note fields, drops explicitly named keys, and produces a value-free audit manifest.

## Three-minute start

```bash
python -m pip install .
session-export-scrub export.json --output sanitized.json --audit audit.json
session-export-scrub export.json --output sanitized.json --policy examples/policy.json
```

Tabitha Workspaces version 1 exports are identified explicitly. Other JSON objects and arrays use the generic adapter. The source is read-only and existing output or audit files are never overwritten.

## Policy

Policies can declare `redact_text_keys`, `drop_keys`, `redact_domains`, `query_allowlist`, `redact_fragments`, `redact_private_hosts`, and `redact_all_titles`. Query values are redacted by default; an allowlist preserves only explicitly selected parameters. Localhost, private IP addresses, and `.local` hosts are hidden by default.

## Privacy and limitations

Processing is local with no network requests, storage service, telemetry, or account. The audit records counts, rule settings, adapter, and a sanitized-output fingerprint without retaining original sensitive values.

Structural rules cannot understand every export format or identify secrets hidden in arbitrary prose, encoded payloads, filenames, paths, or unexpected keys. Redaction placeholders remain visibly marked. Always inspect the sanitized copy before sharing it, and never treat the audit as proof that a document is anonymous.

## Development

```bash
python -m pip install -e ".[dev]"
ruff format --check .
ruff check .
mypy src
pytest
python -m pip_audit
python -m build
```

Python 3.10 or newer is supported on Windows, macOS, and Linux. Part of the [Logan Pendragon Forge open-source collection](https://www.loganpendragonforge.com/open-source/). Licensed under the [MIT License](LICENSE).
