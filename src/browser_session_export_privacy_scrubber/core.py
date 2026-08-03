from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urlsplit, urlunsplit

PROJECT = "browser-session-export-privacy-scrubber"
REDACTED = "[REDACTED]"
DEFAULT_TEXT_KEYS = {"title", "name", "description", "body", "note", "notes", "summary"}
URL_KEYS = {"url", "uri", "href"}


def _validate_policy(policy: dict[str, Any] | None) -> dict[str, Any]:
    data = policy or {}
    if not isinstance(data, dict):
        raise TypeError("policy must be an object")
    result = {
        "redact_text_keys": sorted(set(data.get("redact_text_keys", []))),
        "drop_keys": sorted(set(data.get("drop_keys", []))),
        "redact_domains": sorted(str(item).casefold() for item in data.get("redact_domains", [])),
        "query_allowlist": sorted(str(item) for item in data.get("query_allowlist", [])),
        "redact_fragments": bool(data.get("redact_fragments", True)),
        "redact_private_hosts": bool(data.get("redact_private_hosts", True)),
        "redact_all_titles": bool(data.get("redact_all_titles", False)),
    }
    for key in ("redact_text_keys", "drop_keys", "redact_domains", "query_allowlist"):
        raw = data.get(key, [])
        if not isinstance(raw, list) or any(not isinstance(item, str) or not item for item in raw):
            raise ValueError(f"{key} must contain non-empty strings")
    return result


def _private_host(hostname: str) -> bool:
    if hostname.casefold() in {
        "localhost",
        "localhost.localdomain",
    } or hostname.casefold().endswith(".local"):
        return True
    try:
        address = ipaddress.ip_address(hostname.strip("[]"))
    except ValueError:
        return False
    return address.is_private or address.is_loopback or address.is_link_local


def _domain_match(hostname: str, rules: list[str]) -> bool:
    host = hostname.casefold().rstrip(".")
    return any(host == rule.rstrip(".") or host.endswith("." + rule.rstrip(".")) for rule in rules)


def _scrub_url(value: str, policy: dict[str, Any], counters: dict[str, int]) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        counters["invalid_urls"] += 1
        return REDACTED
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
        counters["non_web_urls"] += 1
        return REDACTED
    hostname = parsed.hostname
    if _domain_match(hostname, policy["redact_domains"]) or (
        policy["redact_private_hosts"] and _private_host(hostname)
    ):
        counters["redacted_hosts"] += 1
        return f"{parsed.scheme}://[REDACTED-HOST]/"
    netloc = hostname
    if parsed.port:
        netloc += f":{parsed.port}"
    if parsed.username or parsed.password:
        counters["removed_credentials"] += 1
    query_segments: list[str] = []
    for segment in parsed.query.split("&") if parsed.query else []:
        name, separator, _value = segment.partition("=")
        if name in policy["query_allowlist"]:
            query_segments.append(segment)
        else:
            query_segments.append(f"{name}={REDACTED}" if separator else name)
            counters["redacted_query_values"] += 1
    fragment = parsed.fragment
    if fragment and policy["redact_fragments"]:
        fragment = REDACTED
        counters["redacted_fragments"] += 1
    return urlunsplit(
        SplitResult(parsed.scheme, netloc, parsed.path, "&".join(query_segments), fragment)
    )


def _walk(value: Any, policy: dict[str, Any], counters: dict[str, int], path: str = "$") -> Any:
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            child_path = f"{path}.{key_text}"
            if key_text in policy["drop_keys"]:
                counters["dropped_fields"] += 1
                continue
            if isinstance(item, str) and key_text.casefold() in URL_KEYS:
                output[key_text] = _scrub_url(item, policy, counters)
            elif isinstance(item, str) and (
                key_text in policy["redact_text_keys"]
                or (policy["redact_all_titles"] and key_text.casefold() in DEFAULT_TEXT_KEYS)
            ):
                output[key_text] = REDACTED
                counters["redacted_text_fields"] += 1
            else:
                output[key_text] = _walk(item, policy, counters, child_path)
        return output
    if isinstance(value, list):
        return [
            _walk(item, policy, counters, f"{path}[{index}]") for index, item in enumerate(value)
        ]
    return copy.deepcopy(value)


def detect_adapter(data: Any) -> str:
    if isinstance(data, dict) and data.get("format") == "tabitha-workspaces" and "library" in data:
        return "tabitha-workspaces-v1"
    return "generic-json"


def scrub(data: Any, policy: dict[str, Any] | None = None) -> tuple[Any, dict[str, Any]]:
    if not isinstance(data, (dict, list)):
        raise TypeError("session export must contain a JSON object or array")
    normalized = _validate_policy(policy)
    counters = {
        "removed_credentials": 0,
        "redacted_query_values": 0,
        "redacted_fragments": 0,
        "redacted_hosts": 0,
        "redacted_text_fields": 0,
        "dropped_fields": 0,
        "invalid_urls": 0,
        "non_web_urls": 0,
    }
    output = _walk(data, normalized, counters)
    canonical = json.dumps(
        output, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()
    report = {
        "schema_version": 1,
        "project": PROJECT,
        "adapter": detect_adapter(data),
        "policy": normalized,
        "changes": counters,
        "output_sha256": hashlib.sha256(canonical).hexdigest(),
        "review_required": True,
        "boundary": "The scrubber applies explicit structural rules; users must inspect the sanitized copy before sharing it.",
    }
    return output, report


def write_outputs(data: Any, output: Path, report: dict[str, Any], audit: Path | None) -> None:
    output = output.resolve()
    if output.exists():
        raise ValueError(f"output already exists: {output}")
    if audit and audit.resolve() == output:
        raise ValueError("audit output must differ from sanitized output")
    if audit and audit.exists():
        raise ValueError(f"audit output already exists: {audit}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if audit:
        audit.parent.mkdir(parents=True, exist_ok=True)
        audit.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
