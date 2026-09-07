# Browser Session Export Privacy Scrubber

[![CI](https://github.com/loganpendragonmultiverse/browser-session-export-privacy-scrubber/actions/workflows/ci.yml/badge.svg)](https://github.com/loganpendragonmultiverse/browser-session-export-privacy-scrubber/actions/workflows/ci.yml)

Create sanitized copies of browser-session JSON exports before sharing them. The local CLI and dependency-free browser interface remove URL credentials, redact query values and fragments, hide private or selected hosts, optionally detect sensitive text, and produce value-free audit evidence.

## Three-minute start

```bash
python -m pip install .
session-export-scrub export.json --output sanitized.json --audit audit.json
session-export-scrub export.json --output sanitized.json --policy examples/policy.json
session-export-scrub first.json second.json --output-dir sanitized --audit batch-audit.json
```

For a visual workflow, open `web/index.html` in a current browser. Drop one or more exports onto the page, adjust or import a policy, inspect the before/after preview, and download each sanitized file and audit. The page is self-contained and makes no network requests.

Tabitha Workspaces version 1 exports are identified explicitly. Other JSON objects and arrays use the generic adapter. The source is read-only and existing output or audit files are never overwritten.

## Policy

Policies can declare `redact_text_keys`, `drop_keys`, `redact_domains`, `query_allowlist`, `redact_fragments`, `redact_private_hosts`, and `redact_all_titles`. Version 1.1 adds opt-in `detect_emails`, `detect_tokens`, and `detect_paths` rules. Query values are redacted by default; an allowlist preserves only explicitly selected parameters. Localhost, private IP addresses, and `.local` hosts are hidden by default.

Policy JSON files are reusable between sessions and the visual interface. Detector findings contain only the rule, structural JSON path, and action—never the matched sensitive value. Combined batch audits identify inputs by processing order rather than copying source filenames.

## Privacy and limitations

Processing is local with no network requests, storage service, telemetry, or account. The audit records counts, rule settings, adapter, and a sanitized-output fingerprint without retaining original sensitive values.

Detectors are intentionally conservative and can miss or overmatch unusual values. Structural rules cannot understand every export format or identify secrets hidden in encoded payloads, filenames, unexpected keys, or arbitrary prose. Before/after previews contain the original values and should only be used on a trusted device. Always inspect the sanitized copy before sharing it, and never treat an audit as proof that a document is anonymous.

## Current release

Version 1.1.0 adds the local drag-and-drop review interface, reusable policy profiles, opt-in sensitive-text detectors, value-free review queues, and collision-safe batch CLI processing with a combined audit.

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

## Version 1.2.0: reviewed improvements

Align Python and browser scrubbing with shared fixtures and add side-by-side strict-sharing previews with retained-field summaries.

```bash
session-export-scrub --write-browser session-review.html
```

The self-contained browser UI and Python engine share fixtures for private/public IPv6, mapped IPv4, noncanonical numeric hosts, percent-encoded/repeated query keys, private-host opt-out, unknown JSON shapes, detectors and strict profiles. --profile strict redacts free-text strings and removes URL paths/query data; field names, structure, numbers/booleans and public hosts remain, so anonymity is not guaranteed. --compare-policy adds value-free retained-field/count comparisons to CLI audits. The browser compares selected and strict policies, imports/exports complete policies and downloads separate sanitized files/audits. --write-browser exports the bundled interface from the installed wheel. Existing URL credential removal, duplicates and fragments are preserved or redacted according to explicit rules; private-host checkbox behavior, IPv6 brackets, malformed-port handling and filename HTML injection are corrected. Desktop/mobile localhost QA passed; file-scheme offline launch is not claimed because the available browser blocks that scheme.
