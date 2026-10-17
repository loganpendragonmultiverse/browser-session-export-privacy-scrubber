import copy
import json

import pytest

from browser_session_export_privacy_scrubber.core import scrub


def test_exact_paths_preserve_same_named_public_field_and_input():
    source = {
        "public": {"note": "Keep"},
        "private": {"note": "SECRET-PRIVATE"},
        "items": ["zero", "SECRET-DROP", "two", "SECRET-REDACT"],
    }
    original = copy.deepcopy(source)
    output, audit = scrub(
        source, {"redact_paths": ["/private/note", "/items/3"], "drop_paths": ["/items/1"]}
    )
    assert output == {
        "public": {"note": "Keep"},
        "private": {"note": "[REDACTED]"},
        "items": ["zero", "two", "[REDACTED]"],
    }
    assert source == original and "SECRET-" not in json.dumps(audit)
    assert audit["changes"]["redacted_path_values"] == 2
    assert audit["changes"]["dropped_path_values"] == 1


@pytest.mark.parametrize(
    "policy",
    [
        {"redact_paths": ["not-a-pointer"]},
        {"drop_paths": [""]},
        {"redact_paths": ["/bad~2escape"]},
        {"redact_paths": [None]},
        {"drop_paths": "/value"},
    ],
)
def test_invalid_path_policy_rejected(policy):
    with pytest.raises((TypeError, ValueError)):
        scrub({}, policy)


def test_explicit_root_and_literal_asterisk():
    assert scrub({"value": "secret"}, {"redact_paths": [""]})[0] == "[REDACTED]"
    assert scrub({"*": "secret", "other": "keep"}, {"drop_paths": ["/*"]})[0] == {"other": "keep"}
