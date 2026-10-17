import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from browser_session_export_privacy_scrubber.cli import main
from browser_session_export_privacy_scrubber.core import scrub

ROOT = Path(__file__).parents[1]


def browser(code, data):
    node = shutil.which("node")
    if not node:
        pytest.skip("Browser acceptance requires Node.js")
    source = (
        "const fs=require('fs'),e=require(process.argv[1]),data=JSON.parse(fs.readFileSync(0,'utf8'));"
        + code
    )
    return json.loads(
        subprocess.check_output(
            [node, "-e", source, str(ROOT / "web/core.js")],
            input=json.dumps(data),
            text=True,
            encoding="utf-8",
        )
    )


@pytest.mark.parametrize(
    "raw",
    [
        '{"id":9007199254740993}',
        '{"id":-9007199254740993}',
        '{"id":1e400}',
        '{"nested":[{"id":9007199254740993}]}',
    ],
)
def test_browser_rejects_unrepresentable_numbers_before_output(raw):
    result = browser(
        "try{e.sanitize(JSON.parse(data),{});process.stdout.write(JSON.stringify({accepted:true}));}catch(error){process.stdout.write(JSON.stringify({error:error.message}));}",
        raw,
    )
    assert "Python" in result["error"] and "safely" in result["error"]


def test_safe_numbers_and_python_large_integer():
    data = {"high": 9007199254740991, "low": -9007199254740991, "decimal": 1.25, "flag": True}
    result = browser("process.stdout.write(JSON.stringify(e.sanitize(data,{})));", data)
    assert result["output"] == data
    assert scrub({"id": 9007199254740993})[0]["id"] == 9007199254740993


@pytest.mark.parametrize(
    "text", ["", "abc", "é😀\n", "x" * 55, "x" * 56, "x" * 64, "long-é😀" * 1000]
)
def test_browser_sha256_matches_utf8_reference(text):
    result = browser("process.stdout.write(JSON.stringify(e.sha256(data)));", text)
    assert result == hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_browser_audit_binds_exact_download_and_policy():
    data = {"title": "PRIVATE-CANARY", "public": "é😀", "nested": [3]}
    result = browser(
        "const r=e.sanitize(data,{redact_all_titles:true});process.stdout.write(JSON.stringify({result:r,download:e.serializeOutput(r.output)}));",
        data,
    )
    report = result["result"]["audit"]
    assert report["output_sha256"] == hashlib.sha256(result["download"].encode("utf-8")).hexdigest()
    assert report["output_hash_basis"] == "sha256-utf8-sanitized-download"
    assert report["policy"]["redact_all_titles"] is True
    assert report["adapter"] == "generic-json"
    assert "PRIVATE-CANARY" not in json.dumps(report)
    changed = browser(
        "const r=e.sanitize(data,{});process.stdout.write(JSON.stringify(r.audit));", data
    )
    assert report["output_sha256"] != changed["output_sha256"]


@pytest.mark.parametrize(
    "version,library,expected",
    [
        (1, {}, "tabitha-workspaces-v1"),
        (999, {}, "generic-json"),
        (True, {}, "generic-json"),
        (None, {}, "generic-json"),
        (1, None, "generic-json"),
        (1, [], "generic-json"),
    ],
)
def test_truthful_adapter_matches_both_engines(version, library, expected):
    data = {"format": "tabitha-workspaces", "version": version, "library": library}
    assert scrub(data)[1]["adapter"] == expected
    assert (
        browser("process.stdout.write(JSON.stringify(e.sanitize(data,{}).audit));", data)["adapter"]
        == expected
    )


@pytest.mark.parametrize(
    "domain",
    [
        "https://private.example",
        "private.example/path",
        "private.example:443",
        " private.example",
        "user@private.example",
        "private.example?x=1",
        "private.example#private",
        "private.example\\path",
        "bücher.example/path",
        ".",
    ],
)
def test_url_shaped_domain_policy_is_rejected(domain):
    with pytest.raises(ValueError, match="bare hostname"):
        scrub({"url": "https://private.example/private"}, {"redact_domains": [domain]})
    result = browser(
        "try{e.sanitize({}, {redact_domains:[data]});process.stdout.write(JSON.stringify({accepted:true}));}catch(error){process.stdout.write(JSON.stringify({error:error.message}));}",
        domain,
    )
    assert "bare hostname" in result["error"]


@pytest.mark.parametrize(
    "rule,url",
    [
        ("8.8.8.8", "https://8.8.8.8/private"),
        ("2001:4860:4860::8888", "https://[2001:4860:4860:0:0:0:0:8888]/private"),
        ("[2001:4860:4860::8888]", "https://[2001:4860:4860::8888]/private"),
        ("bücher.example", "https://xn--bcher-kva.example/private"),
    ],
)
def test_bare_domain_and_ip_rules_remain_supported(rule, url):
    data = {"url": url}
    policy = {"redact_domains": [rule], "redact_private_hosts": False}
    assert scrub(data, policy)[0] == {"url": "https://[REDACTED-HOST]/"}
    result = browser(
        "process.stdout.write(JSON.stringify(e.sanitize(data.input,data.policy)));",
        {"input": data, "policy": policy},
    )
    assert result["output"] == {"url": "https://[REDACTED-HOST]/"}


@pytest.mark.parametrize(
    "raw", ['{"n":1e400}', '{"n":NaN}', '{"n":Infinity}', '{"nested":[-Infinity]}']
)
def test_python_rejects_nonfinite_json_before_outputs(tmp_path, capsys, raw):
    source, output, audit = [
        tmp_path / name for name in ("source.json", "clean.json", "audit.json")
    ]
    source.write_text(raw)
    before = source.read_bytes()
    assert main([str(source), "--output", str(output), "--audit", str(audit)]) == 2
    assert "non-finite" in capsys.readouterr().err
    assert not output.exists() and not audit.exists()
    assert source.read_bytes() == before


@pytest.mark.parametrize("host", ["１９２.１６８.１.１", "１２７.０.０.１", "router.ｌｏｃａｌ"])
def test_normalized_private_hosts_are_redacted_by_default(host):
    data = {"url": "https://" + host + "/private"}
    assert scrub(data)[0] == {"url": "https://[REDACTED-HOST]/"}
    result = browser("process.stdout.write(JSON.stringify(e.sanitize(data,{})));", data)
    assert result["output"] == {"url": "https://[REDACTED-HOST]/"}
    assert scrub(data, {"redact_private_hosts": False})[0] == data
    retained = browser(
        "process.stdout.write(JSON.stringify(e.sanitize(data,{redact_private_hosts:false})));", data
    )
    assert retained["output"] == data
