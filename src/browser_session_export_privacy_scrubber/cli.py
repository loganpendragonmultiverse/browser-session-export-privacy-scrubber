from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import scrub, write_outputs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create a sanitized copy of a browser-session JSON export."
    )
    parser.add_argument("source", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--audit", type=Path)
    args = parser.parse_args(argv)
    try:
        data = json.loads(args.source.read_text(encoding="utf-8"))
        policy = json.loads(args.policy.read_text(encoding="utf-8")) if args.policy else None
        sanitized, report = scrub(data, policy)
        write_outputs(sanitized, args.output, report, args.audit)
        sys.stdout.write(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    except (OSError, UnicodeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0
