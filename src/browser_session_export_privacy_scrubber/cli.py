from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from .core import scrub, write_outputs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create a sanitized copy of a browser-session JSON export."
    )
    parser.add_argument("source", type=Path, nargs="+")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--audit", type=Path)
    args = parser.parse_args(argv)
    try:
        policy = json.loads(args.policy.read_text(encoding="utf-8")) if args.policy else None
        if len(args.source) == 1 and args.output:
            data = json.loads(args.source[0].read_text(encoding="utf-8"))
            sanitized, report = scrub(data, policy)
            write_outputs(sanitized, args.output, report, args.audit)
            result: dict[str, object] = report
        else:
            if args.output or not args.output_dir:
                parser.error("use --output for one source or --output-dir for batch processing")
            args.output_dir.mkdir(parents=True, exist_ok=True)
            reports: list[dict[str, object]] = []
            for source_index, source in enumerate(args.source, start=1):
                data = json.loads(source.read_text(encoding="utf-8"))
                sanitized, report = scrub(data, policy)
                output = args.output_dir / f"{source.stem}.sanitized.json"
                item_audit = args.output_dir / f"{source.stem}.audit.json"
                write_outputs(sanitized, output, report, item_audit)
                reports.append({"source_index": source_index, **report})
            canonical = json.dumps(reports, sort_keys=True, separators=(",", ":")).encode()
            result = {
                "schema_version": 1,
                "project": "browser-session-export-privacy-scrubber",
                "batch_size": len(reports),
                "reports": reports,
                "combined_sha256": hashlib.sha256(canonical).hexdigest(),
                "review_required": True,
            }
            if args.audit:
                if args.audit.exists():
                    raise ValueError(f"audit output already exists: {args.audit}")
                args.audit.parent.mkdir(parents=True, exist_ok=True)
                args.audit.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        sys.stdout.write(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    except (OSError, UnicodeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0
