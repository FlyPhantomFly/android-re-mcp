"""Round-4 archive-cap tests (R4-1): caps and ordering for zip reads.

Every whole-archive-entry read in the handlers must go through the shared
``apkscan._read_entry`` helper (or stream), the zip-slip check must run
before any entry data is read, and an over-cap entry must be refused with
the env-var name in the error. Jar-free: everything here uses synthetic
zips built in tmp_path.
"""

from __future__ import annotations

import hashlib
import os
import zipfile
from pathlib import Path

import pytest

from android_re_mcp.handlers import apkscan
from android_re_mcp.handlers.apkops import ApkOpsHandler
from android_re_mcp.handlers.dex import DexHandler


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


# ── T18: zip_update cleans up its partial .tmp on every failure path ─────

def _corrupted_zip(tmp_path):
    """A stored 8 MB entry with one flipped byte mid-file: streaming it
    raises Bad CRC-32 part-way through the write."""
    apk = tmp_path / "a.apk"
    with zipfile.ZipFile(apk, "w", zipfile.ZIP_STORED) as z:
        z.writestr("classes.dex", b"dex\n035\0" + b"\x01" * 100)
        z.writestr("assets/a.bin", b"A" * (8 * 1024 * 1024))
        z.writestr("assets/b.txt", b"tail")
    raw = bytearray(apk.read_bytes())
    i = raw.index(b"A" * 1024) + 4 * 1024 * 1024
    raw[i] ^= 0xFF
    apk.write_bytes(bytes(raw))
    return apk


def test_zip_update_corrupt_entry_error_no_tmp_left_original_untouched(tmp_path):
    apk = _corrupted_zip(tmp_path)
    payload = tmp_path / "x.txt"
    payload.write_text("hello")
    before = hashlib.sha256(apk.read_bytes()).hexdigest()
    out = ApkOpsHandler().zip_update({
        "zip_path": str(apk),
        "ops": [{"op": "add", "entry_path": "assets/x.txt", "from_file": str(payload)}]})
    assert out["status"] == "error"
    assert "Bad CRC" in out["error"]
    assert hashlib.sha256(apk.read_bytes()).hexdigest() == before, "the archive was modified"
    assert not Path(str(apk) + ".tmp").exists(), "a partial .tmp was left behind"


def test_zip_update_unwritable_output_dir_no_tmp_left(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("running as root: a read-only directory cannot provoke the write error")
    apk = _zip_fixture(tmp_path)
    payload = tmp_path / "x.txt"
    payload.write_text("hello")
    readonly = tmp_path / "ro"
    readonly.mkdir()
    readonly.chmod(0o500)
    out = ApkOpsHandler().zip_update({
        "zip_path": str(apk), "output_apk": str(readonly / "out.apk"),
        "ops": [{"op": "add", "entry_path": "assets/x.txt", "from_file": str(payload)}]})
    assert out["status"] == "error"
    assert not Path(str(readonly / "out.apk.tmp")).exists()
    assert not Path(str(readonly / "out.apk")).exists()


# ── no raw whole-entry reads may reappear in the handlers (AST scan) ─────

def test_no_raw_whole_entry_reads_outside_the_shared_helper():
    """AST scan over every handler file, any variable name.

    Flags ``<zipvar>.read(<arg>)`` and ``<zipvar>.open(<x>).read()`` where
    the receiver is bound to ``zipfile.ZipFile(...)`` / ``open_apk(...)`` /
    ``_open_zip(...)`` (with-item or assignment) or is a function
    parameter named like an archive. The one read inside
    ``apkscan._read_entry`` is the only one allowed.
    """
    import ast

    handlers = Path(apkscan.__file__).parent
    zip_param_names = {"zf", "z", "zfile", "zin", "archive", "apk", "zp"}
    callee_suffixes = ("ZipFile", "open_apk", "_open_zip")
    offenders: list[str] = []

    for path in sorted(handlers.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        zip_vars = set(zip_param_names)
        helper_span = None
        for node in ast.walk(tree):
            if isinstance(node, ast.With):
                for item in node.items:
                    call = item.context_expr
                    if (isinstance(call, ast.Call)
                            and ast.unparse(call.func).endswith(callee_suffixes)
                            and isinstance(item.optional_vars, ast.Name)):
                        zip_vars.add(item.optional_vars.id)
            elif isinstance(node, ast.Assign):
                call = node.value
                if (isinstance(call, ast.Call)
                        and ast.unparse(call.func).endswith(callee_suffixes)):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            zip_vars.add(target.id)
            elif (isinstance(node, ast.FunctionDef) and path.name == "apkscan.py"
                    and node.name == "_read_entry"):
                helper_span = (node.lineno, node.end_lineno)
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            recv = node.func.value
            is_zip_recv = (
                (isinstance(recv, ast.Name) and recv.id in zip_vars)
                or (isinstance(recv, ast.Call)
                    and ast.unparse(recv.func).endswith("ZipFile"))
            )
            if node.func.attr != "read" or not is_zip_recv:
                continue
            is_whole_entry = bool(node.args) or (
                isinstance(recv, ast.Call)
                and isinstance(recv.func, ast.Attribute)
                and recv.func.attr == "open"
            )
            if not is_whole_entry:
                continue
            if (helper_span is not None
                    and helper_span[0] <= node.lineno <= helper_span[1]):
                continue  # the one sanctioned read inside apkscan._read_entry
            offenders.append(f"{path.name}:{node.lineno}: {ast.unparse(node)[:80]}")

    assert offenders == [], "raw whole-entry zip reads outside apkscan._read_entry:\n" + "\n".join(offenders)


# ── R5-1: zip_update and dex_swap stream instead of loading the archive ──

def _zip_fixture(tmp_path):
    """classes.dex + a 2 MB zero entry + a STORED resources.arsc."""
    p = tmp_path / "a.apk"
    with zipfile.ZipFile(p, "w") as z:
        zi = zipfile.ZipInfo("classes.dex", date_time=(2026, 1, 1, 0, 0, 0))
        zi.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(zi, b"dex\n035\0" + b"\x01" * 100)
        zi_big = zipfile.ZipInfo("assets/big.bin", date_time=(2026, 1, 1, 0, 0, 0))
        zi_big.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(zi_big, b"\0" * (2 * 1024 * 1024))
        zi_arsc = zipfile.ZipInfo("resources.arsc", date_time=(2026, 1, 1, 0, 0, 0))
        zi_arsc.compress_type = zipfile.ZIP_STORED
        z.writestr(zi_arsc, b"ARSC" + b"\0" * 40)
    return p


def _listing(p):
    with zipfile.ZipFile(p) as z:
        return {i.filename: (i.compress_type, f"{i.CRC:08x}") for i in z.infolist()}, \
            [i.filename for i in z.infolist()]


def test_zip_update_streams_untouched_over_cap_entry(tmp_path, monkeypatch):
    monkeypatch.setenv("ANDROID_RE_MCP_MAX_ENTRY_MB", "1")
    fixture = _zip_fixture(tmp_path)
    payload = tmp_path / "x.txt"
    payload.write_text("hello")
    out_zip = tmp_path / "out.apk"
    before, _ = _listing(fixture)
    out = ApkOpsHandler().zip_update({
        "zip_path": str(fixture), "output_apk": str(out_zip),
        "ops": [{"op": "add", "entry_path": "assets/x.txt", "from_file": str(payload)}]})
    assert out["status"] == "ok"
    assert out["output"].get("errors", []) == []
    after, order = _listing(out_zip)
    # the untouched 2 MB entry copied byte-identical despite being over the cap
    assert after["assets/big.bin"] == before["assets/big.bin"]
    assert after["resources.arsc"][0] == 0, "STORED must stay STORED"
    assert "assets/x.txt" in order and order[0] == "classes.dex"


def test_zip_update_replace_over_cap_entry_refused_with_cap_message(tmp_path, monkeypatch):
    monkeypatch.setenv("ANDROID_RE_MCP_MAX_ENTRY_MB", "1")
    fixture = _zip_fixture(tmp_path)
    out_zip = tmp_path / "out.apk"
    out = ApkOpsHandler().zip_update({
        "zip_path": str(fixture), "output_apk": str(out_zip),
        "ops": [{"op": "replace", "entry_path": "assets/big.bin", "content": "small now"}]})
    assert out["status"] == "ok"  # zip_update keeps working; the op lands in errors
    (err,) = out["output"]["errors"]
    assert "entry cap" in err["error"]
    assert "ANDROID_RE_MCP_MAX_ENTRY_MB" in err["error"]
    # the over-cap entry still streams to the output untouched
    before, _ = _listing(fixture)
    after, _ = _listing(out_zip)
    assert after["assets/big.bin"] == before["assets/big.bin"]


def test_zip_update_patch_over_cap_entry_refused_with_cap_message(tmp_path, monkeypatch):
    monkeypatch.setenv("ANDROID_RE_MCP_MAX_ENTRY_MB", "1")
    fixture = _zip_fixture(tmp_path)
    out = ApkOpsHandler().zip_update({
        "zip_path": str(fixture), "output_apk": str(tmp_path / "out.apk"),
        "ops": [{"op": "patch", "entry_path": "assets/big.bin",
                 "byte_offset": 0, "expected_hex": "00", "replacement_hex": "ff"}]})
    (err,) = out["output"]["errors"]
    assert "entry cap" in err["error"]
    assert "ANDROID_RE_MCP_MAX_ENTRY_MB" in err["error"]


def test_zip_update_preserves_semantics_on_mixed_fixture(tmp_path, monkeypatch):
    fixture = _zip_fixture(tmp_path)
    out_zip = tmp_path / "out.apk"
    before, _ = _listing(fixture)
    payload = tmp_path / "x.txt"
    payload.write_text("hello")
    out = ApkOpsHandler().zip_update({
        "zip_path": str(fixture), "output_apk": str(out_zip),
        "ops": [{"op": "add", "entry_path": "assets/x.txt", "from_file": str(payload)},
                {"op": "patch", "entry_path": "classes.dex",
                 "byte_offset": 8, "expected_hex": "01", "replacement_hex": "ff"}]})
    assert out["status"] == "ok" and out["output"].get("errors", []) == []
    after, order = _listing(out_zip)
    assert order == ["classes.dex", "assets/big.bin", "resources.arsc", "assets/x.txt"]
    assert after["resources.arsc"] == before["resources.arsc"]  # STORED, same CRC
    assert after["assets/big.bin"] == before["assets/big.bin"]  # untouched
    with zipfile.ZipFile(out_zip) as z:
        assert z.read("classes.dex")[:9] == b"dex\n035\0" + b"\xff"  # the patch landed
    assert out["output"]["final_sha256"] == hashlib.sha256(out_zip.read_bytes()).hexdigest()


def test_dex_swap_untouched_over_cap_entry_streams(tmp_path, monkeypatch):
    monkeypatch.setenv("ANDROID_RE_MCP_MAX_ENTRY_MB", "1")
    fixture = _zip_fixture(tmp_path)
    new_dex = tmp_path / "new.dex"
    new_dex.write_bytes(b"dex\n035\0" + b"\x02" * 80)
    out_apk = tmp_path / "out.apk"
    before, _ = _listing(fixture)
    out = DexHandler().dex_swap({"apk_path": str(fixture), "dex_path": str(new_dex),
                                 "entry_name": "classes.dex", "output_apk": str(out_apk)})
    assert out["status"] == "ok"
    after, order = _listing(out_apk)
    assert order == ["classes.dex", "assets/big.bin", "resources.arsc"]
    assert after["assets/big.bin"] == before["assets/big.bin"], "over-cap entry copied untouched"
    assert after["resources.arsc"][0] == 0, "STORED must stay STORED"
    with zipfile.ZipFile(out_apk) as z:
        assert z.read("classes.dex") == new_dex.read_bytes()


def test_dex_swap_over_cap_target_is_replaced_without_being_read(tmp_path, monkeypatch):
    """The swap target's own bytes are never read, so the cap does not apply.

    Decided 2026-11-27: matching, when dex_swap has to guess the entry,
    goes through the capped _find_dex_entry; an explicit entry_name is
    replaced blind, so an over-cap target swaps fine.
    """
    monkeypatch.setenv("ANDROID_RE_MCP_MAX_ENTRY_MB", "1")
    apk = tmp_path / "a.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("classes.dex", b"dex\n035\0" + b"\x01" * (2 * 1024 * 1024))
    new_dex = tmp_path / "new.dex"
    new_dex.write_bytes(b"dex\n035\0" + b"\x02" * 80)
    out = DexHandler().dex_swap({"apk_path": str(apk), "dex_path": str(new_dex),
                                 "entry_name": "classes.dex", "output_apk": str(tmp_path / "o.apk")})
    assert out["status"] == "ok"
    with zipfile.ZipFile(tmp_path / "o.apk") as z:
        assert z.read("classes.dex") == new_dex.read_bytes()


_VMHWM_CHILD_ZIP_UPDATE = """
import sys


def hwm():
    for line in open("/proc/self/status"):
        if line.startswith("VmHWM"):
            return int(line.split()[1]) // 1024


base = hwm()
from android_re_mcp.handlers.apkops import ApkOpsHandler
r = ApkOpsHandler().zip_update({
    "zip_path": sys.argv[1],
    "ops": [{"op": "add", "entry_path": "assets/x.txt", "from_file": sys.argv[2]}],
    "output_apk": sys.argv[3]})
print(f"{base} {hwm()} {r.get('status')} {r.get('error', '')}")
"""

_VMHWM_CHILD_DEX_SWAP = """
import sys


def hwm():
    for line in open("/proc/self/status"):
        if line.startswith("VmHWM"):
            return int(line.split()[1]) // 1024


base = hwm()
from android_re_mcp.handlers.dex import DexHandler
r = DexHandler().dex_swap({
    "apk_path": sys.argv[1], "dex_path": sys.argv[2],
    "entry_name": "classes.dex", "output_apk": sys.argv[3]})
print(f"{base} {hwm()} {r.get('status')} {r.get('error', '')}")
"""


def _proc_status_available() -> bool:
    """The VmHWM peak comes from Linux procfs; off Linux the memory
    tests cannot measure anything."""
    return Path("/proc/self/status").exists()


_proc_ok = pytest.mark.skipif(not _proc_status_available(),
                              reason="/proc/self/status does not exist here "
                                     "(Linux procfs): the VmHWM peak cannot be read")


def _run_vmhwm_child(code, *args):
    """Run the handler in a fresh child; return (baseline_mb, peak_mb, tail).

    VmHWM from /proc/self/status inside the child: a child can inherit its
    parent's ru_maxrss peak, so the parent cannot measure this honestly.
    """
    import os
    import subprocess
    import sys as _sys

    src_root = Path(apkscan.__file__).parent.parent
    env = dict(os.environ)
    env["PYTHONPATH"] = str(src_root) + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run([_sys.executable, "-c", code, *map(str, args)],
                          env=env, capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stderr[-2000:]
    base, peak, *tail = proc.stdout.split()
    return int(base), int(peak), " ".join(tail)


@_proc_ok
def test_zip_update_300mb_entry_stays_under_60mb_growth(tmp_path, monkeypatch):
    monkeypatch.delenv("ANDROID_RE_MCP_MAX_ENTRY_MB", raising=False)  # default cap: 256
    payload = tmp_path / "x.txt"
    payload.write_text("hello")
    apk = tmp_path / "a.apk"
    with zipfile.ZipFile(apk, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("classes.dex", b"dex\n035\0" + b"\x01" * 100)
        z.writestr("assets/big.bin", b"\0" * (300 * 1024 * 1024))
    base, peak, tail = _run_vmhwm_child(_VMHWM_CHILD_ZIP_UPDATE, apk, payload, tmp_path / "out.apk")
    assert tail == "ok", tail
    assert peak - base < 60, f"peak grew {peak - base} MB (baseline {base}, peak {peak}); " \
                             "the 300 MB entry was held in memory"


@_proc_ok
def test_dex_swap_300mb_entry_stays_under_60mb_growth(tmp_path, monkeypatch):
    monkeypatch.delenv("ANDROID_RE_MCP_MAX_ENTRY_MB", raising=False)  # default cap: 256
    new_dex = tmp_path / "new.dex"
    new_dex.write_bytes(b"dex\n035\0" + b"\x02" * 80)
    apk = tmp_path / "a.apk"
    with zipfile.ZipFile(apk, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("classes.dex", b"dex\n035\0" + b"\x01" * 100)
        z.writestr("assets/big.bin", b"\0" * (300 * 1024 * 1024))
    base, peak, tail = _run_vmhwm_child(_VMHWM_CHILD_DEX_SWAP, apk, new_dex, tmp_path / "out.apk")
    assert tail == "ok", tail
    assert peak - base < 60, f"peak grew {peak - base} MB (baseline {base}, peak {peak}); " \
                             "the 300 MB entry was held in memory"

