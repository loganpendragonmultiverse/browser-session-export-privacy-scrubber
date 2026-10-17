import json
from pathlib import Path

import pytest

from browser_session_export_privacy_scrubber.cli import main
from browser_session_export_privacy_scrubber.core import scrub


@pytest.mark.parametrize("rule", ["bücher.example", "xn--bcher-kva.example", "BÜCHER.EXAMPLE."])
@pytest.mark.parametrize("host", ["bücher.example", "xn--bcher-kva.example", "sub.bücher.example"])
def test_idn_domains_match_both_representations(rule: str, host: str) -> None:
    output, audit = scrub({"url": "https://" + host + "/private"}, {"redact_domains": [rule]})
    assert output == {"url": "https://[REDACTED-HOST]/"}
    assert audit["changes"]["redacted_hosts"] == 1


def test_idn_suffix_boundary_and_sharp_s() -> None:
    output, _ = scrub(
        {
            "url": "https://faß.example/private",
            "uri": "https://fass.example/x",
            "href": "https://faß.example.evil.test/x",
        },
        {"redact_domains": ["xn--fa-hia.example"]},
    )
    assert output["url"] == "https://[REDACTED-HOST]/"
    assert output["uri"] == "https://fass.example/x"
    assert output["href"] == "https://faß.example.evil.test/x"


def test_invalid_internationalized_policy_and_url() -> None:
    with pytest.raises(ValueError, match="invalid internationalized domain"):
        scrub({}, {"redact_domains": ["bücher.example/path"]})
    output, audit = scrub({"url": "https://xn--invalid-/secret"})
    assert output == {"url": "[REDACTED]"}
    assert audit["changes"]["invalid_urls"] == 1


def test_cli_idn_downloadable_outputs(tmp_path: Path) -> None:
    source, policy, output, audit = [
        tmp_path / name for name in ("source.json", "policy.json", "out.json", "audit.json")
    ]
    source.write_text(json.dumps({"url": "https://xn--fa-hia.example/IDN-PRIVATE-CANARY"}))
    policy.write_text(json.dumps({"redact_domains": ["faß.example"]}))
    original = source.read_bytes()
    assert (
        main([str(source), "--policy", str(policy), "--output", str(output), "--audit", str(audit)])
        == 0
    )
    assert json.loads(output.read_text()) == {"url": "https://[REDACTED-HOST]/"}
    assert "IDN-PRIVATE-CANARY" not in audit.read_text()
    assert source.read_bytes() == original
