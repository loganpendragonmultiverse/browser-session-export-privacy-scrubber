# Browser Session Export Privacy Scrubber

> ⭐ **Gold Star Project**
> I consider this project complete. Fixes, maintenance and good new ideas are still welcome.
> [About Gold Stars](https://www.loganpendragonforge.com/open-source/?gold=1)
>
> Remove private data from browser-session JSON files, then review what changed before sharing a copy.

## What you can do

- Use built-in privacy rules or choose exact fields to remove or redact.
- Review a report that names changed fields without copying their private values.
- Run locally in Python or use the standalone browser page.


## Current release 1.3.3

The browser rejects non-finite numbers and integers outside JavaScript's safe range before showing results or enabling downloads. Use the Python CLI when an export contains larger integer IDs; Python preserves them. Both interfaces require finite numbers.

Browser audits now include the normalized policy, a truthful format label and a SHA-256 fingerprint of the exact sanitized download bytes. The browser records `output_hash_basis: sha256-utf8-sanitized-download`: UTF-8 JSON with two-space indentation, no BOM and no added newline. Python keeps its existing canonical-JSON fingerprint, so hashes from the two interfaces need not match.

Domain rules must be bare hostnames or IP addresses, such as `private.example`, `bücher.example` or `2001:4860:4860::8888`. URL schemes, paths, credentials and ports are rejected instead of silently missing the selected host. Default private-host redaction also recognizes Unicode spellings that normalize to private IP addresses or .local names. Unknown Tabitha versions use the generic JSON label.

## Updates in 1.3.2

Selected-domain redaction matches Unicode and ASCII punycode representations of internationalized domain names, including subdomains. Nontransitional normalization keeps `faß.example` distinct from `fass.example`. Python uses the audited `idna` package for IDNA 2008 / UTS #46 processing; the standalone browser uses its built-in local URL hostname conversion and still needs no network or external scripts. Invalid internationalized policy domains fail with an actionable error; invalid input hostnames are redacted. ASCII/IP behavior and explicit JSON-path rules remain unchanged.

Choose exactly which JSON fields to redact or remove.

Policy JSON accepts redact_paths and drop_paths arrays of exact JSON Pointers, such as {"redact_paths":["/windows/0/tabs/1/title"],"drop_paths":["/private/note"]}. Escape / as ~1 and ~ as ~0 inside a key. Array indices refer to the original input before drops; there are no wildcards (a literal * names a literal key). A parent drop wins; otherwise a parent redaction replaces the whole value. The empty pointer redacts the root; dropping the root is rejected. These rules add targeted removal/redaction, not an exemption from other selected policy rules. Audits contain paths, rule names and counts, never the removed values. Field names, structure and retained content can still identify someone; inspect the sanitized copy.

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

CLI exports stage all requested files, reserve new names exclusively, and remove only unchanged files created by a failed invocation. Correct the destination and retry. Existing files and concurrent changes are preserved; failures that prevent safe cleanup identify the retained paths. This covers ordinary failures, not abrupt process termination or power loss across multiple files. Source files remain read-only.

Tabitha Workspaces version 1 exports are identified explicitly. Other JSON objects and arrays use the generic adapter. The source is read-only and existing output or audit files are never overwritten.

## Policy

Policies can declare `redact_text_keys`, `drop_keys`, `redact_domains`, `query_allowlist`, `redact_fragments`, `redact_private_hosts`, and `redact_all_titles`. Version 1.1 adds opt-in `detect_emails`, `detect_tokens`, and `detect_paths` rules. Query values are redacted by default; an allowlist preserves only explicitly selected parameters. Localhost, private IP addresses, and `.local` hosts are hidden by default.

Policy JSON files are reusable between sessions and the visual interface. Detector findings contain only the rule, structural JSON path, and action—never the matched sensitive value. Combined batch audits identify inputs by processing order rather than copying source filenames.

## Privacy and limitations

Processing is local with no network requests, storage service, telemetry, or account. The audit records counts, rule settings, adapter, and a sanitized-output fingerprint without retaining original sensitive values.

Detectors are intentionally conservative and can miss or overmatch unusual values. Structural rules cannot understand every export format or identify secrets hidden in encoded payloads, filenames, unexpected keys, or arbitrary prose. Before/after previews contain the original values and should only be used on a trusted device. Always inspect the sanitized copy before sharing it, and never treat an audit as proof that a document is anonymous.

## Supported workflows

The current release supports the local review interface, reusable policies, sensitive-text detectors, strict-sharing comparisons and exact data-path rules.

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

## Updates in 1.2.0

Align Python and browser scrubbing with shared fixtures and add side-by-side strict-sharing previews with retained-field summaries.

```bash
session-export-scrub --write-browser session-review.html
```

The self-contained browser UI and Python engine share fixtures for private/public IPv6, mapped IPv4, noncanonical numeric hosts, percent-encoded/repeated query keys, private-host opt-out, unknown JSON shapes, detectors and strict profiles. --profile strict redacts free-text strings and removes URL paths/query data; field names, structure, numbers/booleans and public hosts remain, so anonymity is not guaranteed. --compare-policy adds value-free retained-field/count comparisons to CLI audits. The browser compares selected and strict policies, imports/exports complete policies and downloads separate sanitized files/audits. --write-browser exports the bundled interface from the installed wheel. Existing URL credential removal, duplicates and fragments are preserved or redacted according to explicit rules; private-host checkbox behavior, IPv6 brackets, malformed-port handling and filename HTML injection are corrected. Desktop/mobile localhost QA passed; file-scheme offline launch is not claimed because the available browser blocks that scheme.
