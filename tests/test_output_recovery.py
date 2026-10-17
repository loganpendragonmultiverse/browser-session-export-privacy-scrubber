from __future__ import annotations

import importlib
import json
import os
from pathlib import Path

import pytest

from browser_session_export_privacy_scrubber import output
from browser_session_export_privacy_scrubber.cli import main


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("index", [0, 1])
def test_late_write_failure_rolls_back_and_retries(tmp_path, monkeypatch, reverse, index):
    pair = [(tmp_path / "report.json", "report"), (tmp_path / "state.json", "state")]
    if reverse:
        pair.reverse()
    original = output._write_final
    count = 0

    def fail(item):
        nonlocal count
        current = count
        count += 1
        if current == index:
            assert item.fd is not None
            item.written = os.write(item.fd, item.data[:2])
            raise OSError("synthetic late write failure")
        return original(item)

    with monkeypatch.context() as patch:
        patch.setattr(output, "_write_final", fail)
        with pytest.raises(OSError, match="synthetic"):
            output.write_new_outputs(pair)
    assert not any(p.exists() for p, _ in pair)
    assert not list(tmp_path.glob(".forge-output-*"))
    output.write_new_outputs(pair)
    assert [p.read_text() for p, _ in pair] == [v for _, v in pair]


@pytest.mark.parametrize("index", [0, 1])
def test_existing_collision_is_preserved(tmp_path, index):
    pair = [(tmp_path / "report.json", "new-report"), (tmp_path / "state.json", "new-state")]
    pair[index][0].write_text("existing")
    with pytest.raises(ValueError, match="already exists"):
        output.write_new_outputs(pair)
    assert pair[index][0].read_text() == "existing"
    assert not pair[1 - index][0].exists()


def test_collision_after_preflight_never_overwrites(tmp_path, monkeypatch):
    pair = [(tmp_path / "one", "one"), (tmp_path / "two", "two")]
    original = output.os.open

    def collide(path, flags, *args, **kwargs):
        if Path(path) == pair[1][0] and flags & os.O_EXCL:
            pair[1][0].write_text("concurrent")
        return original(path, flags, *args, **kwargs)

    monkeypatch.setattr(output.os, "open", collide)
    with pytest.raises(FileExistsError):
        output.write_new_outputs(pair)
    assert not pair[0][0].exists()
    assert pair[1][0].read_text() == "concurrent"


def test_changed_new_file_is_preserved_on_rollback(tmp_path, monkeypatch):
    pair = [(tmp_path / "one", "one"), (tmp_path / "two", "two")]
    original = output._write_final

    def change(item):
        if item.path == pair[1][0]:
            pair[0][0].write_text("concurrent edit")
            raise OSError("synthetic")
        return original(item)

    monkeypatch.setattr(output, "_write_final", change)
    with pytest.raises(OSError, match="kept changed"):
        output.write_new_outputs(pair)
    assert pair[0][0].read_text() == "concurrent edit"
    assert not pair[1][0].exists()


def test_stdout_failure_rolls_back_new_state(tmp_path):
    path = tmp_path / "state"

    def broken():
        raise BrokenPipeError("consumer closed")

    with pytest.raises(BrokenPipeError):
        output.write_new_outputs([(path, "state")], deliver=broken)
    assert not path.exists()


def fixture(tmp_path):
    sources = []
    for name in ("one", "two"):
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps({"url": "https://user:pass@example.com/?secret=private"}))
        sources.append(path)
    return sources


def arguments(tmp_path, sources, batch):
    if batch:
        return [
            *(str(p) for p in sources),
            "--output-dir",
            str(tmp_path / "batch"),
            "--audit",
            str(tmp_path / "combined.json"),
        ]
    return [
        str(sources[0]),
        "--output",
        str(tmp_path / "clean.json"),
        "--audit",
        str(tmp_path / "audit.json"),
    ]


@pytest.mark.parametrize("batch", [False, True])
@pytest.mark.parametrize("index", [0, 1, -1])
def test_cli_partial_write_and_retry(tmp_path, monkeypatch, capsys, batch, index):
    sources = fixture(tmp_path)
    before = [p.read_bytes() for p in sources]
    args = arguments(tmp_path, sources, batch)
    total = 5 if batch else 2
    failure = total - 1 if index == -1 else index
    original = output._write_final
    count = 0

    def fail(item):
        nonlocal count
        current = count
        count += 1
        if current == failure:
            item.written = os.write(item.fd, item.data[:3])
            raise OSError("synthetic partial write")
        original(item)

    with monkeypatch.context() as patch:
        patch.setattr(output, "_write_final", fail)
        assert main(args) == 2
    capsys.readouterr()
    assert sorted(p.name for p in tmp_path.rglob("*") if p.is_file()) == ["one.json", "two.json"]
    assert [p.read_bytes() for p in sources] == before
    assert main(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["review_required"]
    if batch:
        assert result["batch_size"] == 2
        assert len(list((tmp_path / "batch").glob("*.json"))) == 4
    else:
        assert "user:pass" not in (tmp_path / "clean.json").read_text()
    assert not list(tmp_path.rglob(".forge-output-*"))


@pytest.mark.skipif(
    os.name != "posix" or getattr(os, "geteuid", lambda: 0)() == 0,
    reason="requires non-admin POSIX permission boundary",
)
@pytest.mark.parametrize("batch", [False, True])
@pytest.mark.parametrize("blocked", ["output", "audit"])
def test_real_permission_failure_corrected_destination_retry(tmp_path, capsys, batch, blocked):
    sources = fixture(tmp_path)
    before = [p.read_bytes() for p in sources]
    ro = tmp_path / "readonly"
    ro.mkdir()
    args = arguments(tmp_path, sources, batch)
    flag = ("--output-dir" if batch else "--output") if blocked == "output" else "--audit"
    args[args.index(flag) + 1] = str(ro if batch and blocked == "output" else ro / "result.json")
    ro.chmod(0o555)
    try:
        assert main(args) == 2
        capsys.readouterr()
        assert sorted(p.name for p in tmp_path.rglob("*") if p.is_file()) == [
            "one.json",
            "two.json",
        ]
    finally:
        ro.chmod(0o755)
    assert main(args) == 0
    capsys.readouterr()
    assert [p.read_bytes() for p in sources] == before


@pytest.mark.parametrize("problem", ["duplicate", "alias", "malformed", "existing"])
def test_late_batch_problem_publishes_nothing(tmp_path, capsys, problem):
    sources = fixture(tmp_path)
    args = arguments(tmp_path, sources, True)
    if problem == "duplicate":
        args.insert(1, str(sources[0]))
    elif problem == "alias":
        args[-1] = str(tmp_path / "batch" / "two.sanitized.json")
    elif problem == "malformed":
        sources[1].write_text("{")
    else:
        (tmp_path / "combined.json").write_text("keep")
    before = {str(p): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    assert main(args) == 2
    capsys.readouterr()
    assert {str(p): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()} == before


def test_stdout_cli_failure_recovers_batch(tmp_path, monkeypatch, capsys):
    sources = fixture(tmp_path)

    class Broken:
        def write(self, text):
            return len(text)

        def flush(self):
            raise BrokenPipeError("synthetic flush failure")

    module = importlib.import_module("browser_session_export_privacy_scrubber.cli")
    with monkeypatch.context() as patch:
        patch.setattr(module.sys, "stdout", Broken())
        assert main(arguments(tmp_path, sources, True)) == 2
    capsys.readouterr()
    assert sorted(p.name for p in tmp_path.rglob("*") if p.is_file()) == ["one.json", "two.json"]


def test_missing_parent_and_aliases(tmp_path):
    with pytest.raises(ValueError, match="directory"):
        output.write_new_outputs([(tmp_path / "missing" / "one", "one")])
    with pytest.raises(ValueError, match="distinct"):
        output.write_new_outputs([(tmp_path / "one", "one"), (tmp_path / "." / "one", "two")])


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink fixture")
def test_dangling_symlink_is_not_overwritten(tmp_path):
    path = tmp_path / "one"
    path.symlink_to(tmp_path / "missing")
    with pytest.raises(ValueError, match="already exists"):
        output.write_new_outputs([(path, "one")])
    assert path.is_symlink()


def test_short_write_and_no_progress_cleanup(tmp_path, monkeypatch):
    original = output.os.write
    with monkeypatch.context() as patch:
        patch.setattr(output.os, "write", lambda fd, data: original(fd, data[:2]))
        output.write_new_outputs([(tmp_path / "short", "complete")])
    assert (tmp_path / "short").read_text() == "complete"
    with monkeypatch.context() as patch:
        patch.setattr(output.os, "write", lambda fd, data: 0)
        with pytest.raises(OSError, match="no progress"):
            output.write_new_outputs([(tmp_path / "zero", "complete")])
    assert not (tmp_path / "zero").exists()


def test_replaced_output_is_preserved(tmp_path):
    pair = [(tmp_path / "one", "one"), (tmp_path / "two", "two")]

    def replace_after_close():
        # Windows prevents replacing a file while its writer is still open.
        # Replacement after close exercises the same rollback identity guard.
        replacement = tmp_path / "replacement"
        replacement.write_text("concurrent replacement")
        replacement.replace(pair[0][0])
        raise OSError("synthetic")

    with pytest.raises(OSError, match="kept changed"):
        output.write_new_outputs(pair, deliver=replace_after_close)
    assert pair[0][0].read_text() == "concurrent replacement"
    assert not pair[1][0].exists()


def test_cli_output_cannot_replace_source(tmp_path, capsys):
    sources = fixture(tmp_path)
    before = sources[0].read_bytes()
    assert main([str(sources[0]), "--output", str(sources[0])]) == 2
    capsys.readouterr()
    assert sources[0].read_bytes() == before
