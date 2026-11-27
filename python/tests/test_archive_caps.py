"""Round-4 archive-cap tests (R4-1): caps and ordering for zip reads.

Every whole-archive-entry read in the handlers must go through the shared
``apkscan._read_entry`` helper (or stream), the zip-slip check must run
before any entry data is read, and an over-cap entry must be refused with
the env-var name in the error. Jar-free: everything here uses synthetic
zips built in tmp_path.
"""

from __future__ import annotations

import re
import zipfile
from pathlib import Path

import pytest

from android_re_mcp.handlers import apkscan
from android_re_mcp.handlers.apkops import ApkOpsHandler


@pytest.fixture()
def two_mb_zip(tmp_path, monkeypatch):
    """A zip with a 2 MB entry under a 1 MB env cap, plus control entries."""
    monkeypatch.setenv("ANDROID_RE_MCP_MAX_ENTRY_MB", "1")
    p = tmp_path / "two-mb.zip"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("big.bin", b"\0" * (2 * 1024 * 1024))
        z.writestr("ok.txt", "hello")
        z.writestr("../escape.bin", "slip")
    return p


def _extract(handler_zip, entry, out, monkeypatch, **extra):
    monkeypatch.chdir(handler_zip.parent)
    h = ApkOpsHandler()
    args = {"zip_path": str(handler_zip), "entries": [entry], "output_dir": str(out)}
    args.update(extra)
    return h.zip_extract(args)


# ── ordering: refusals happen before any entry data is read ──────────────

def test_zip_slip_refused_before_any_read(two_mb_zip, tmp_path, monkeypatch):
    def boom(self, name, *a, **kw):  # noqa: ANN001
        raise AssertionError("z.read() ran for a refused slip entry")

    monkeypatch.setattr(zipfile.ZipFile, "read", boom)
    out = _extract(two_mb_zip, "../escape.bin", tmp_path / "out", monkeypatch)
    res = out["output"]["results"][0]
    assert res["ok"] is False
    assert res["error"] == "zip-slip refused"
    assert not (tmp_path / "escape.bin").exists()


def test_over_cap_entry_refused_before_any_read(two_mb_zip, tmp_path, monkeypatch):
    seen: list[object] = []
    orig_read = zipfile.ZipFile.read

    def spy(self, name, *a, **kw):  # noqa: ANN001
        seen.append(name)
        return orig_read(self, name, *a, **kw)

    monkeypatch.setattr(zipfile.ZipFile, "read", spy)
    out = _extract(two_mb_zip, "big.bin", tmp_path / "out", monkeypatch)
    res = out["output"]["results"][0]
    assert res["ok"] is False
    assert "entry cap" in res["error"]
    assert "ANDROID_RE_MCP_MAX_ENTRY_MB" in res["error"]
    assert seen == [], "the oversized entry was read into memory"
    assert not (tmp_path / "out" / "big.bin").exists()


def test_missing_entry_still_reports_not_found(two_mb_zip, tmp_path, monkeypatch):
    out = _extract(two_mb_zip, "no-such-entry.bin", tmp_path / "out", monkeypatch)
    res = out["output"]["results"][0]
    assert res["ok"] is False
    assert res["error"] == "entry not found"


# ── streaming: accepted entries never use ZipFile.read ───────────────────

def test_accepted_entry_streams_without_read(two_mb_zip, tmp_path, monkeypatch):
    def boom(self, name, *a, **kw):  # noqa: ANN001
        raise AssertionError("z.read() ran; extraction must stream via z.open()")

    monkeypatch.setattr(zipfile.ZipFile, "read", boom)
    out = _extract(two_mb_zip, "ok.txt", tmp_path / "out", monkeypatch)
    res = out["output"]["results"][0]
    assert res["ok"] is True
    assert res["bytes"] == 5
    assert (tmp_path / "out" / "ok.txt").read_bytes() == b"hello"


def test_accepted_entry_lands_with_exact_bytes(two_mb_zip, tmp_path, monkeypatch):
    out = _extract(two_mb_zip, "ok.txt", tmp_path / "out", monkeypatch)
    assert out["output"]["results"][0]["path"].endswith("ok.txt")


# ── the shared cap helpers ───────────────────────────────────────────────

def test_entry_cap_mb_env_semantics(monkeypatch):
    monkeypatch.delenv("ANDROID_RE_MCP_MAX_ENTRY_MB", raising=False)
    assert apkscan.entry_cap_mb() == apkscan.DEFAULT_ENTRY_CAP_MB
    monkeypatch.setenv("ANDROID_RE_MCP_MAX_ENTRY_MB", "7")
    assert apkscan.entry_cap_mb() == 7
    monkeypatch.setenv("ANDROID_RE_MCP_MAX_ENTRY_MB", "0")
    assert apkscan.entry_cap_mb() == 0
    monkeypatch.setenv("ANDROID_RE_MCP_MAX_ENTRY_MB", "junk")
    assert apkscan.entry_cap_mb() == apkscan.DEFAULT_ENTRY_CAP_MB
    monkeypatch.setenv("ANDROID_RE_MCP_MAX_ENTRY_MB", "-3")
    assert apkscan.entry_cap_mb() == apkscan.DEFAULT_ENTRY_CAP_MB


def test_entry_over_cap_rule():
    info = zipfile.ZipInfo("x.bin")
    info.file_size = 300 * 1024 * 1024
    info.compress_size = 300 * 1024 * 1024
    assert apkscan.entry_over_cap(info, 256) is True
    assert apkscan.entry_over_cap(info, 0) is False, "0 must disable the cap"
    info.file_size = 4
    info.compress_size = 4
    assert apkscan.entry_over_cap(info, 256) is False


def test_read_entry_returns_none_over_cap(tmp_path):
    p = tmp_path / "z.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("big.bin", b"\0" * (2 * 1024 * 1024))
        z.writestr("ok.txt", "hello")
    with zipfile.ZipFile(p) as z:
        assert apkscan._read_entry(z, z.getinfo("big.bin"), 1) is None
        assert apkscan._read_entry(z, z.getinfo("ok.txt"), 1) == b"hello"
        assert apkscan._read_entry(z, z.getinfo("big.bin"), 0) is not None


# ── R4-2: symlinks in the output folder must not redirect writes ─────────

def _link_fixture(tmp_path, link_target):
    """out/link → ../victim/<name>; a zip whose entry writes through it."""
    out = tmp_path / "out"
    out.mkdir()
    victim = tmp_path / "victim"
    victim.mkdir()
    (out / "link").symlink_to(link_target)
    p = tmp_path / "link-pwn.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("link", "pwned")
        z.writestr("link/pwn.txt", "pwned")
        z.writestr("ok.txt", "hello")
    return p


def test_symlinked_parent_outside_dest_refused(tmp_path, monkeypatch):
    p = _link_fixture(tmp_path, "../victim")
    monkeypatch.chdir(tmp_path)
    h = ApkOpsHandler()
    out = h.zip_extract({"zip_path": str(p), "entries": ["link/pwn.txt"],
                         "output_dir": str(tmp_path / "out")})
    res = out["output"]["results"][0]
    assert res["ok"] is False
    assert res["error"] == "path escapes the output folder"
    assert not (tmp_path / "victim" / "pwn.txt").exists()


def test_symlinked_parent_refused_before_any_read(tmp_path, monkeypatch):
    p = _link_fixture(tmp_path, "../victim")
    monkeypatch.chdir(tmp_path)

    def boom(self, name, *a, **kw):  # noqa: ANN001
        raise AssertionError("z.read() ran for a refused symlink escape")

    monkeypatch.setattr(zipfile.ZipFile, "read", boom)
    h = ApkOpsHandler()
    out = h.zip_extract({"zip_path": str(p), "entries": ["link/pwn.txt"],
                         "output_dir": str(tmp_path / "out")})
    assert out["output"]["results"][0]["ok"] is False


def test_benign_entry_still_extracts_after_symlink_refusal(tmp_path, monkeypatch):
    p = _link_fixture(tmp_path, "../victim")
    monkeypatch.chdir(tmp_path)
    h = ApkOpsHandler()
    out = h.zip_extract({"zip_path": str(p), "entries": ["link/pwn.txt", "ok.txt"],
                         "output_dir": str(tmp_path / "out")})
    results = out["output"]["results"]
    assert results[0]["ok"] is False
    assert results[1]["ok"] is True
    assert (tmp_path / "out" / "ok.txt").read_bytes() == b"hello"


def test_symlink_at_final_component_refused(tmp_path, monkeypatch):
    # out/link → ../victim/missing.txt (dangling): open() would create it outside
    p = _link_fixture(tmp_path, "../victim/missing.txt")
    monkeypatch.chdir(tmp_path)
    h = ApkOpsHandler()
    out = h.zip_extract({"zip_path": str(p), "entries": ["link"],
                         "output_dir": str(tmp_path / "out")})
    res = out["output"]["results"][0]
    assert res["ok"] is False
    assert res["error"] == "symlink in the way"
    assert not (tmp_path / "victim" / "missing.txt").exists()


# ── no raw whole-entry reads may reappear in the handlers ────────────────

_RAW_READ = re.compile(r"\b(?:zf|z|zfile)\.read\(")
_HANDLER_FILES = (
    "apkops.py", "dex.py", "flutter.py", "native.py",
    "static.py", "device.py", "apkdiff.py", "googleservices.py",
)


def test_no_raw_whole_entry_reads_outside_the_shared_helper():
    handlers = Path(apkscan.__file__).parent
    for name in _HANDLER_FILES:
        src = (handlers / name).read_text(encoding="utf-8")
        hits = [line.strip() for line in src.splitlines() if _RAW_READ.search(line)]
        if name == "apkscan.py":
            assert hits == ["return zf.read(info)"], hits
        else:
            assert hits == [], f"{name} reads whole entries directly: {hits}"
