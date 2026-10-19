# Testing

Run `python -m pip install -e ".[dev]"`, then `ruff format --check .`, `ruff check .`, `mypy src`, `pytest`, `python -m pip_audit`, and `python -m build`.

Tests cover Tabitha adapter detection, generic JSON, URL credentials, query allowlists, fragments, private hosts, selected domains, title redaction, dropped fields, opt-in sensitive-text detectors, value-free review queues, source immutability, audit evidence, policy validation, output collisions, single-file CLI behavior, and batch CLI output.

Before release, also open `web/index.html` without a server, drop representative JSON files, import and export a policy, inspect both previews, and download sanitized and audit files. Confirm the browser network panel contains no application requests.

## 1.2.0 regression acceptance

Run the complete existing suite plus the new regression fixtures. Confirm the documented command produces the selected output, malformed input remains actionable, and source files remain unchanged. Align Python and browser scrubbing with shared fixtures and add side-by-side strict-sharing previews with retained-field summaries.

## 1.3.0 acceptance

Redact or drop exact JSON data paths while retaining same-named public fields elsewhere.

Verify Add exact RFC 6901 redact_paths and drop_paths to Python and the dependency-free browser; Apply paths against original array indices with drop precedence and escaped slash/tilde keys; Add value-free path actions and shared Python/browser regression fixtures. Run the full existing quality and build gates; release only through protected PR checks and verified tag artifacts.

## 1.3.1 output recovery

Treat every CLI invocation as one bounded export operation, including all batch outputs and the combined audit. Stage all data, reserve new destinations exclusively, recover only unchanged files created by the command, and preserve source/existing/concurrently edited files. Test both failure directions, later batch and audit failures, corrected-destination retry, duplicate names, aliases, partial writes and stdout failure. Abrupt termination and power-loss atomicity are not claimed.

## 1.3.2 internationalized selected-host regression acceptance

Run shared Python/Node fixtures for Unicode/punycode rules and input hosts, subdomains, suffix boundaries, sharp-s distinctness and unchanged ASCII/IP handling. Verify the rebuilt standalone interface downloads the selected-policy sanitized JSON after applying an internationalized domain rule. Audit shipped dependencies and test the exact installed tag-built wheel.

## 1.3.3 acceptance

Use raw JSON text containing 9007199254740993, negative unsafe IDs and 1e400 to verify a clear Python-guidance error before any browser result or download. Check safe numeric boundaries, Python integer preservation, unknown-version labels, invalid domain policies and valid IP/IDN rules. Compare browser SHA-256 against reference UTF-8 vectors and actual downloaded bytes. Exercise selected/strict audits, multiple files and stale-result clearing in Chromium, Firefox and WebKit using the built bundle.

Python also rejects non-finite float values before output while preserving larger integer IDs. Verify that overflowed JSON numbers and NaN/Infinity inputs fail without creating output files.

## 1.3.4 stdout regression acceptance

Exercise real closed stdout pipes with small and large reports, complete normal output, partial and zero descriptor writes, and in-memory streams. Verify status 2 without an ignored shutdown exception, unchanged source files, and export rollback and corrected-destination retry.
