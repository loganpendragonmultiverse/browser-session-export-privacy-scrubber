# Testing

Run `python -m pip install -e ".[dev]"`, then `ruff format --check .`, `ruff check .`, `mypy src`, `pytest`, `python -m pip_audit`, and `python -m build`.

Tests cover Tabitha adapter detection, generic JSON, URL credentials, query allowlists, fragments, private hosts, selected domains, title redaction, dropped fields, source immutability, audit evidence, policy validation, output collisions, and CLI behavior.
