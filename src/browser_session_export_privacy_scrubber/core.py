from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, unquote, urlsplit, urlunsplit

PROJECT = "browser-session-export-privacy-scrubber"
REDACTED = "[REDACTED]"
DEFAULT_TEXT_KEYS = {"title", "name", "description", "body", "note", "notes", "summary"}
URL_KEYS = {"url", "uri", "href"}
EMAIL_RE = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+", re.IGNORECASE | re.ASCII)
TOKEN_RE = re.compile(
    r"(?:\bBearer\s+)?(?:eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9]{20,}|[A-Za-z0-9_-]{32,})"
)
WINDOWS_PATH_RE = re.compile(r"\b[A-Za-z]:\\(?:[^\\\r\n]+\\)*[^\\\r\n]*")
UNIX_PATH_RE = re.compile(r"(?<![:/])/(?:Users|home|var|tmp)/[^\s\"']+")


def _validate_policy(policy: dict[str, Any] | None) -> dict[str, Any]:
    data = {} if policy is None else policy
    if not isinstance(data, dict):
        raise TypeError("policy must be an object")
    defaults = {
        "redact_fragments": True,
        "redact_private_hosts": True,
        "redact_all_titles": False,
        "detect_emails": False,
        "detect_tokens": False,
        "detect_paths": False,
        "redact_all_strings": False,
        "strip_url_paths": False,
        "drop_query": False,
    }
    lists = ("redact_text_keys", "drop_keys", "redact_domains", "query_allowlist")
    if set(data) - set(defaults) - set(lists):
        raise ValueError("unsupported policy fields")
    result: dict[str, Any] = {}
    for key in lists:
        raw = data.get(key, [])
        if not isinstance(raw, list) or any(not isinstance(v, str) or not v for v in raw):
            raise ValueError(f"{key} must contain non-empty strings")
        result[key] = sorted({v.lower() if key == "redact_domains" else v for v in raw})
    for key, default in defaults.items():
        value = data.get(key, default)
        if not isinstance(value, bool):
            raise TypeError(f"{key} must be a boolean")
        result[key] = value
    return result


def strict_policy() -> dict[str, Any]:
    return _validate_policy(
        {
            "redact_all_titles": True,
            "redact_all_strings": True,
            "strip_url_paths": True,
            "drop_query": True,
        }
    )


PRIVATE_V4 = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
)
PRIVATE_V6 = ("::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32")


def _private_host(hostname: str) -> bool:
    host = unquote(hostname).lower().rstrip(".").strip("[]")
    if (
        host in {"localhost", "localhost.localdomain"}
        or host.endswith(".local")
        or "." not in host
        and ":" not in host
    ):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return bool(re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))*", host))
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    networks = PRIVATE_V4 if address.version == 4 else PRIVATE_V6
    return any(address in ipaddress.ip_network(network) for network in networks)


def _domain_match(hostname: str, rules: list[str]) -> bool:
    host = hostname.casefold().rstrip(".")
    return any(host == rule.rstrip(".") or host.endswith("." + rule.rstrip(".")) for rule in rules)


def _scrub_url(value: str, policy: dict[str, Any], counters: dict[str, int]) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        counters["invalid_urls"] += 1
        return REDACTED
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
        counters["non_web_urls"] += 1
        return REDACTED
    hostname = unquote(parsed.hostname).lower().rstrip(".")
    if _domain_match(hostname, policy["redact_domains"]) or (
        policy["redact_private_hosts"] and _private_host(hostname)
    ):
        counters["redacted_hosts"] += 1
        return f"{parsed.scheme}://[REDACTED-HOST]/"
    netloc = "[" + hostname + "]" if ":" in hostname else hostname
    if port:
        netloc += f":{port}"
    if parsed.username or parsed.password:
        counters["removed_credentials"] += 1
    if parsed.query and policy["drop_query"]:
        counters["removed_query_segments"] += len(parsed.query.split("&"))
    if parsed.path and parsed.path != "/" and policy["strip_url_paths"]:
        counters["redacted_url_paths"] += 1
    query_segments: list[str] = []
    for segment in parsed.query.split("&") if parsed.query and not policy["drop_query"] else []:
        name, separator, _value = segment.partition("=")
        if unquote(name) in policy["query_allowlist"]:
            query_segments.append(segment)
        else:
            query_segments.append(f"{name}={REDACTED}" if separator else name)
            counters["redacted_query_values"] += 1
    fragment = parsed.fragment
    if fragment and policy["redact_fragments"]:
        fragment = REDACTED
        counters["redacted_fragments"] += 1
    return urlunsplit(
        SplitResult(
            parsed.scheme,
            netloc,
            "/" if policy["strip_url_paths"] else parsed.path,
            "&".join(query_segments),
            fragment,
        )
    )


def _review_text(
    value: str,
    policy: dict[str, Any],
    counters: dict[str, int],
    findings: list[dict[str, str]],
    path: str,
) -> str:
    rules: list[tuple[str, re.Pattern[str], str]] = []
    if policy["detect_emails"]:
        rules.append(("email", EMAIL_RE, "[REDACTED-EMAIL]"))
    if policy["detect_tokens"]:
        rules.append(("token", TOKEN_RE, "[REDACTED-TOKEN]"))
    if policy["detect_paths"]:
        rules.extend(
            [
                ("windows_path", WINDOWS_PATH_RE, "[REDACTED-PATH]"),
                ("unix_path", UNIX_PATH_RE, "[REDACTED-PATH]"),
            ]
        )
    output = value
    for rule, pattern, replacement in rules:
        output, count = pattern.subn(replacement, output)
        if count:
            counters[f"detected_{rule}"] += count
            findings.append({"rule": rule, "path": path, "action": "redacted"})
    return output


def _walk(
    value: Any,
    policy: dict[str, Any],
    counters: dict[str, int],
    findings: list[dict[str, str]],
    path: str = "$",
) -> Any:
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
                output[key_text] = _walk(item, policy, counters, findings, child_path)
        return output
    if isinstance(value, list):
        return [
            _walk(item, policy, counters, findings, f"{path}[{index}]")
            for index, item in enumerate(value)
        ]
    if isinstance(value, str):
        if policy["redact_all_strings"]:
            counters["redacted_text_fields"] += 1
            return REDACTED
        return _review_text(value, policy, counters, findings, path)
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
        "removed_query_segments": 0,
        "redacted_url_paths": 0,
        "redacted_query_values": 0,
        "redacted_fragments": 0,
        "redacted_hosts": 0,
        "redacted_text_fields": 0,
        "dropped_fields": 0,
        "invalid_urls": 0,
        "non_web_urls": 0,
        "detected_email": 0,
        "detected_token": 0,
        "detected_windows_path": 0,
        "detected_unix_path": 0,
    }
    findings: list[dict[str, str]] = []
    output = _walk(data, normalized, counters, findings)
    canonical = json.dumps(
        output, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()
    report = {
        "schema_version": 1,
        "project": PROJECT,
        "adapter": detect_adapter(data),
        "policy": normalized,
        "changes": counters,
        "review_queue": findings,
        "output_sha256": hashlib.sha256(canonical).hexdigest(),
        "retained_summary": retained_summary(output),
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


def retained_summary(value: Any) -> dict[str, int]:
    counts = {
        "string_fields": 0,
        "fully_redacted_strings": 0,
        "numeric_fields": 0,
        "boolean_fields": 0,
        "null_fields": 0,
    }

    def walk(item: Any) -> None:
        if isinstance(item, dict):
            for child in item.values():
                walk(child)
        elif isinstance(item, list):
            for child in item:
                walk(child)
        elif isinstance(item, str):
            counts["string_fields"] += 1
            counts["fully_redacted_strings"] += int(item == REDACTED)
        elif isinstance(item, bool):
            counts["boolean_fields"] += 1
        elif isinstance(item, (int, float)):
            counts["numeric_fields"] += 1
        elif item is None:
            counts["null_fields"] += 1

    walk(value)
    return counts
