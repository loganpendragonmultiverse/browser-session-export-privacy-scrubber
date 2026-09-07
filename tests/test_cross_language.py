import copy
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from browser_session_export_privacy_scrubber.cli import main
from browser_session_export_privacy_scrubber.core import scrub, strict_policy

ROOT = Path(__file__).resolve().parents[1]
CASES = json.loads((ROOT / "tests/shared-fixtures.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", CASES, ids=[x["name"] for x in CASES])
def test_shared_behavior(case):
    node = shutil.which("node")
    if not node:
        pytest.skip("Cross-language acceptance requires Node.js")
    original = copy.deepcopy(case["input"])
    output, report = scrub(original, case["policy"])
    code = "const fs=require('fs'),engine=require(process.argv[1]);const c=JSON.parse(fs.readFileSync(0,'utf8'));process.stdout.write(JSON.stringify(engine.sanitize(c.input,c.policy)));"
    result = subprocess.run(
        [node, "-e", code, str(ROOT / "web/core.js")],
        input=json.dumps(case),
        text=True,
        capture_output=True,
        check=True,
    )
    browser = json.loads(result.stdout)
    assert browser["output"] == output
    assert browser["audit"]["changes"] == report["changes"]
    assert browser["audit"]["review_queue"] == report["review_queue"]
    assert browser["audit"]["retained_summary"] == report["retained_summary"]
    assert original == case["input"]
    if case["name"] == "ipv6-private":
        assert all("REDACTED-HOST" in value for value in output.values())
    if case["name"] == "strict":
        assert (
            output["custom"] == "[REDACTED]" and output["url"] == "https://example.test/#[REDACTED]"
        )
    if case["name"] == "encoded-and-duplicate-query":
        assert "%70age=2&token=[REDACTED]&token=[REDACTED]" in output["url"]


def test_bundle_matches_tested_engine():
    html = (ROOT / "web/index.html").read_text(encoding="utf-8")
    for name in ("core", "ui"):
        assert (ROOT / ("web/" + name + ".js")).read_text(encoding="utf-8") in html
    assert "<script src=" not in html


@pytest.mark.parametrize(
    "policy", [[], False, {"detect_emails": "yes"}, {"drop_keys": None}, {"unknown": True}]
)
def test_invalid_policy_types(policy):
    with pytest.raises((TypeError, ValueError)):
        scrub({}, policy)


def test_cli_strict_comparison_is_value_free(tmp_path, capsys):
    source = tmp_path / "source.json"
    source.write_text(
        json.dumps({"custom": "PRIVATE-CANARY", "url": "https://example.test/private"})
    )
    alternate = tmp_path / "alternate.json"
    alternate.write_text(json.dumps(strict_policy()))
    output = tmp_path / "out.json"
    assert main([str(source), "--output", str(output), "--compare-policy", str(alternate)]) == 0
    audit = json.loads(capsys.readouterr().out)
    assert "PRIVATE-CANARY" not in json.dumps(audit)
    assert audit["policy_comparison"]["alternate"]["fully_redacted_strings"] == 1
    assert (
        main([str(source), "--output", str(tmp_path / "strict.json"), "--profile", "strict"]) == 0
    )
    assert "PRIVATE-CANARY" not in (tmp_path / "strict.json").read_text()
    assert (
        main(
            [
                str(source),
                "--output",
                str(tmp_path / "bad.json"),
                "--profile",
                "strict",
                "--policy",
                str(alternate),
            ]
        )
        == 2
    )


def test_export_bundled_browser(tmp_path):
    target = tmp_path / "review.html"
    assert main(["--write-browser", str(target)]) == 0
    assert target.read_text(encoding="utf-8") == (ROOT / "web/index.html").read_text(
        encoding="utf-8"
    )
    assert main(["--write-browser", str(target)]) == 2
    assert main([]) == 2
