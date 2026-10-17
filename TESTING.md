# Testing

Run `python -m pip install -e ".[dev]"`, then `ruff format --check .`, `ruff check .`, `mypy src`, `pytest`, `python -m pip_audit`, and `python -m build`.

Tests cover Tabitha adapter detection, generic JSON, URL credentials, query allowlists, fragments, private hosts, selected domains, title redaction, dropped fields, opt-in sensitive-text detectors, value-free review queues, source immutability, audit evidence, policy validation, output collisions, single-file CLI behavior, and batch CLI output.

Before release, also open `web/index.html` without a server, drop representative JSON files, import and export a policy, inspect both previews, and download sanitized and audit files. Confirm the browser network panel contains no application requests.

## 1.2.0 regression acceptance

Run the complete existing suite plus the new regression fixtures. Confirm the documented command produces the selected output, malformed input remains actionable, and source files remain unchanged. Align Python and browser scrubbing with shared fixtures and add side-by-side strict-sharing previews with retained-field summaries.

## 1.3.0 acceptance

Redact or drop exact JSON data paths while retaining same-named public fields elsewhere.

Verify Add exact RFC 6901 redact_paths and drop_paths to Python and the dependency-free browser; Apply paths against original array indices with drop precedence and escaped slash/tilde keys; Add value-free path actions and shared Python/browser regression fixtures. Run the full existing quality and build gates; release only through protected PR checks and verified tag artifacts.
