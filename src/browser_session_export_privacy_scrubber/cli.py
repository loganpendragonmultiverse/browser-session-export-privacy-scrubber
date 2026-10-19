from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import sys
from importlib.resources import files
from pathlib import Path

from .core import output_documents, scrub, strict_policy
from .output import write_new_outputs


def _write_stdout(rendered: str) -> None:
    """Deliver report bytes without leaving a failed buffered write for shutdown."""
    try:
        descriptor = sys.stdout.fileno()
    except (AttributeError, io.UnsupportedOperation):
        sys.stdout.write(rendered)
        sys.stdout.flush()
        return
    pending = memoryview(
        rendered.encode(sys.stdout.encoding or "utf-8", sys.stdout.errors or "strict")
    )
    while pending:
        written = os.write(descriptor, pending)
        if written <= 0:
            raise OSError("stdout accepted no report bytes")
        pending = pending[written:]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create a sanitized copy of a browser-session JSON export."
    )
    parser.add_argument("source", type=Path, nargs="*")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--audit", type=Path)
    parser.add_argument("--profile", choices=("default", "strict"), default="default")
    parser.add_argument(
        "--compare-policy",
        type=Path,
        help="Add value-free comparison with another local policy to the audit",
    )
    parser.add_argument(
        "--write-browser", type=Path, help="Export the self-contained local browser interface"
    )
    args = parser.parse_args(argv)
    try:
        if args.write_browser:
            if args.source or args.write_browser.exists():
                raise ValueError("--write-browser requires a new file and no source inputs")
            write_new_outputs(
                [
                    (
                        args.write_browser,
                        files("browser_session_export_privacy_scrubber")
                        .joinpath("browser.html")
                        .read_text(encoding="utf-8"),
                    )
                ]
            )
            return 0
        if not args.source:
            raise ValueError("provide source exports or --write-browser")
        if args.policy and args.profile != "default":
            raise ValueError("choose --policy or --profile strict")
        policy = (
            json.loads(args.policy.read_text(encoding="utf-8"))
            if args.policy
            else strict_policy()
            if args.profile == "strict"
            else None
        )
        alternate = (
            json.loads(args.compare_policy.read_text(encoding="utf-8"))
            if args.compare_policy
            else None
        )
        if len(args.source) == 1 and args.output:
            data = json.loads(args.source[0].read_text(encoding="utf-8"))
            sanitized, report = scrub(data, policy)
            if args.compare_policy:
                _, comparison = scrub(data, alternate)
                report["policy_comparison"] = {
                    "selected": report["retained_summary"],
                    "alternate": comparison["retained_summary"],
                    "alternate_changes": comparison["changes"],
                }
            documents = output_documents(sanitized, args.output, report, args.audit)
            result: dict[str, object] = report
        else:
            if args.output or not args.output_dir:
                parser.error("use --output for one source or --output-dir for batch processing")
            args.output_dir.mkdir(parents=True, exist_ok=True)
            reports: list[dict[str, object]] = []
            documents = []
            for source_index, source in enumerate(args.source, start=1):
                data = json.loads(source.read_text(encoding="utf-8"))
                sanitized, report = scrub(data, policy)
                output = args.output_dir / f"{source.stem}.sanitized.json"
                item_audit = args.output_dir / f"{source.stem}.audit.json"
                if args.compare_policy:
                    _, comparison = scrub(data, alternate)
                    report["policy_comparison"] = {
                        "selected": report["retained_summary"],
                        "alternate": comparison["retained_summary"],
                        "alternate_changes": comparison["changes"],
                    }
                documents.extend(output_documents(sanitized, output, report, item_audit))
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
                documents.append((args.audit, json.dumps(result, indent=2) + "\n"))
        for path, _ in documents:
            path.parent.mkdir(parents=True, exist_ok=True)

        def deliver() -> None:
            _write_stdout(json.dumps(result, indent=2, ensure_ascii=False) + "\n")

        write_new_outputs(documents, deliver)
    except (OSError, UnicodeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0
