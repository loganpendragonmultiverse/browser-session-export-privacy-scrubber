import json
from pathlib import Path

import pytest

from browser_session_export_privacy_scrubber.cli import main
from browser_session_export_privacy_scrubber.core import REDACTED, scrub, write_outputs


def sample() -> dict:
    return {
        "format": "tabitha-workspaces",
        "version": 1,
        "library": {
            "collections": [
                {
                    "name": "Tax research",
                    "tabs": [
                        {
                            "title": "Private account",
                            "url": "https://user:pass@example.com/account?id=42&utm=x#state",
                        },
                        {"title": "Router", "url": "http://192.168.1.1/admin"},
                    ],
                }
            ]
        },
    }


def test_scrubs_urls_and_titles_without_mutating_source() -> None:
    source = sample()
    sanitized, report = scrub(source, {"redact_all_titles": True, "query_allowlist": ["utm"]})
    first = sanitized["library"]["collections"][0]["tabs"][0]
    assert first["title"] == REDACTED
    assert first["url"] == "https://example.com/account?id=[REDACTED]&utm=x#[REDACTED]"
    assert "user:pass" not in first["url"]
    assert sanitized["library"]["collections"][0]["tabs"][1]["url"] == "http://[REDACTED-HOST]/"
    assert source["library"]["collections"][0]["tabs"][0]["title"] == "Private account"
    assert report["adapter"] == "tabitha-workspaces-v1"


def test_policy_drop_and_domain_rules() -> None:
    sanitized, report = scrub(
        {"url": "https://sub.example.org/path?a=1", "token": "secret", "other": 3},
        {"drop_keys": ["token"], "redact_domains": ["example.org"]},
    )
    assert sanitized == {"url": "https://[REDACTED-HOST]/", "other": 3}
    assert report["changes"]["dropped_fields"] == 1


def test_invalid_policy_and_non_object_input() -> None:
    with pytest.raises(TypeError, match="object or array"):
        scrub("bad")
    with pytest.raises(ValueError, match="non-empty strings"):
        scrub({}, {"drop_keys": [""]})


def test_opt_in_sensitive_text_detectors_are_value_free() -> None:
    data = {
        "contact": "person@example.com",
        "token": "Bearer eyJheader123.payload456.signature789",
        "location": r"C:\Users\Avery\private.json",
    }
    sanitized, report = scrub(
        data, {"detect_emails": True, "detect_tokens": True, "detect_paths": True}
    )
    assert sanitized["contact"] == "[REDACTED-EMAIL]"
    assert sanitized["token"] == "[REDACTED-TOKEN]"
    assert sanitized["location"] == "[REDACTED-PATH]"
    assert {item["rule"] for item in report["review_queue"]} == {
        "email",
        "token",
        "windows_path",
    }
    assert "person@example.com" not in json.dumps(report)


def test_write_outputs_are_replacement_safe(tmp_path: Path) -> None:
    sanitized, report = scrub(sample())
    output = tmp_path / "sanitized.json"
    audit = tmp_path / "audit.json"
    write_outputs(sanitized, output, report, audit)
    assert json.loads(output.read_text())["format"] == "tabitha-workspaces"
    assert json.loads(audit.read_text())["review_required"] is True
    with pytest.raises(ValueError, match="already exists"):
        write_outputs(sanitized, output, report, None)
    with pytest.raises(ValueError, match="must differ"):
        write_outputs(sanitized, tmp_path / "other.json", report, tmp_path / "other.json")


def test_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    source = tmp_path / "source.json"
    source.write_text(json.dumps(sample()), encoding="utf-8")
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"redact_all_titles": True}), encoding="utf-8")
    output = tmp_path / "sanitized.json"
    audit = tmp_path / "audit.json"
    assert (
        main([str(source), "--output", str(output), "--policy", str(policy), "--audit", str(audit)])
        == 0
    )
    assert json.loads(capsys.readouterr().out)["changes"]["redacted_text_fields"] > 0
    assert main([str(source), "--output", str(output)]) == 2


def test_batch_cli_creates_individual_and_combined_audits(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sources = []
    for name in ("one", "two"):
        source = tmp_path / f"{name}.json"
        source.write_text(json.dumps(sample()), encoding="utf-8")
        sources.append(source)
    output_dir = tmp_path / "batch"
    combined = tmp_path / "combined.json"
    assert (
        main(
            [
                *(str(source) for source in sources),
                "--output-dir",
                str(output_dir),
                "--audit",
                str(combined),
            ]
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    assert report["batch_size"] == 2
    assert len(report["combined_sha256"]) == 64
    assert (output_dir / "one.sanitized.json").exists()
    assert (output_dir / "two.audit.json").exists()
    assert json.loads(combined.read_text())["review_required"] is True
