"""Hermetic + jar-gated tests for the E-PY-17 dex surgery tools.

The dexfile-cli jar (~/tools/dexfile-cli.jar) gates the real round-trip
net (assemble → info → patch → convert), mirroring how the quark tests
skip without the engine. Everything else — ops validation, missing-tool
honesty, .bak discipline, the caps logic, and the pure-Python dex_swap —
runs with fakes only.
"""

import json
import os
import zipfile
from pathlib import Path

import pytest

from android_re_mcp.handlers import dex as dex_mod
from android_re_mcp.handlers.dex import DexHandler

# captured before the autouse isolated_env fixture repoints HOME per test
REAL_TOOLS_DIR = os.environ.get("ANDROID_RE_MCP_TOOLS_DIR") or str(Path.home() / "tools")

FIXTURE_SMALI = """.class public Lcom/poc/Loader;
.super Ljava/lang/Object;

.method public static getMessage()Ljava/lang/String;
    .locals 1

    const-string v0, "hello-original"

    return-object v0
.end method
"""

JAR_AVAILABLE = (Path(REAL_TOOLS_DIR) / dex_mod._JAR_NAME).is_file() and dex_mod.shutil.which("java") is not None

ROUNDTRIP = pytest.mark.skipif(not JAR_AVAILABLE, reason="dexfile-cli.jar / java not available")


@pytest.fixture
def real_tools(monkeypatch):
    """Jar-gated tests run against the real ~/tools (the autouse fixture repoints HOME)."""
    monkeypatch.setenv("ANDROID_RE_MCP_TOOLS_DIR", REAL_TOOLS_DIR)


@pytest.fixture
def fake_tools(tmp_path, monkeypatch):
    """Point tools_dir at an empty dir → every tool reports missing_tool."""
    monkeypatch.setattr(dex_mod, "tools_dir", lambda: tmp_path / "empty-tools")
    return tmp_path


@pytest.fixture
def fake_run(monkeypatch):
    """Fake the CLI runner: success with a canned result, recording argv + ops content."""
    calls = {}

    def fake(tool, cli_args):
        calls["tool"] = tool
        calls["cli_args"] = cli_args
        calls["ops_json"] = None
        if "--ops" in cli_args:
            ops_file = cli_args[cli_args.index("--ops") + 1]
            calls["ops_json"] = json.loads(Path(ops_file).read_text())
        return {"status": "ok", "tool": tool, "result": {"out": "fake"}}

    monkeypatch.setattr(DexHandler, "_run", staticmethod(fake))
    return calls


# ── missing_tool honesty (all seven) ──────────────────────────────────────

def test_all_tools_missing_without_jar(fake_tools, tmp_path):
    h = DexHandler()
    smali = tmp_path / "x.smali"
    smali.write_text(FIXTURE_SMALI)
    cases = [
        ("dex_info", {"dex_path": str(tmp_path / "a.dex")}),
        ("dex_extract", {"apk_path": str(tmp_path / "a.apk")}),
        ("dex_convert", {"in_path": str(tmp_path / "a.dex")}),
        ("dex_patch", {"dex_path": str(tmp_path / "a.dex"), "ops": [{"op": "rename", "target": "class", "class": "a.B", "new_name": "a.C"}]}),
        ("dex_assemble", {"smali_text": FIXTURE_SMALI}),
        ("dex_split", {"dex_path": str(tmp_path / "a.dex")}),
        ("dex_swap", {"apk_path": str(tmp_path / "a.apk"), "dex_path": str(tmp_path / "a.dex")}),
    ]
    for tool, args in cases[:6]:  # dex_swap is pure Python — no jar needed
        result = getattr(h, tool)(args)
        assert result["status"] == "missing_tool", tool
        assert "--setup" in result["hint"] or "install_tool" in result["hint"] or "java" in result["error"]


def test_dex_swap_needs_no_jar(tmp_path):
    # the zip rewrite is stdlib — it works even when the jar is absent
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("AndroidManifest.xml", "<manifest/>")
        z.writestr("classes.dex", b"\x00old-dex-bytes")
    patched = tmp_path / "classes.dex"
    patched.write_bytes(b"\x00new-dex-bytes")
    out = DexHandler().dex_swap({"apk_path": str(apk), "dex_path": str(patched)})
    assert out["status"] == "ok"
    with zipfile.ZipFile(apk) as z:
        assert z.read("classes.dex") == b"\x00new-dex-bytes"
        assert z.read("AndroidManifest.xml") == b"<manifest/>"  # other entries byte-identical


def test_dex_swap_preserves_entry_compression(tmp_path):
    # resources.arsc must stay STORED (uncompressed) or modern Android refuses it
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("AndroidManifest.xml", "<manifest/>")  # default DEFLATED
        stored = zipfile.ZipInfo("resources.arsc")
        stored.compress_type = zipfile.ZIP_STORED
        z.writestr(stored, b"\x00arsc-bytes")
        z.writestr("classes.dex", b"\x00old")
    patched = tmp_path / "classes.dex"
    patched.write_bytes(b"\x00new")
    out = DexHandler().dex_swap({"apk_path": str(apk), "dex_path": str(patched)})
    assert out["status"] == "ok"
    with zipfile.ZipFile(apk) as z:
        assert z.getinfo("resources.arsc").compress_type == zipfile.ZIP_STORED
        assert z.read("resources.arsc") == b"\x00arsc-bytes"
        assert z.read("classes.dex") == b"\x00new"


# ── ops validation (hermetic) ─────────────────────────────────────────────

def test_ops_validation_rejects_unknown_op():
    err = DexHandler._validate_ops([{"op": "delete-everything"}])
    assert err and "replace-const-string" in err  # names the valid set


def test_ops_validation_rejects_missing_fields():
    err = DexHandler._validate_ops([{"op": "replace-const-string", "old": "a"}])
    assert err and "new" in err


def test_ops_validation_rejects_bad_flags():
    err = DexHandler._validate_ops([{"op": "flip-flags", "class": "a.B", "set": ["NOT_A_FLAG"]}])
    assert err and "PUBLIC" in err


def test_ops_validation_accepts_all_supported():
    ops = [
        {"op": "replace-const-string", "old": "a", "new": "b"},
        {"op": "rename", "target": "class", "class": "a.B", "new_name": "a.C"},
        {"op": "rename", "target": "method", "class": "a.B", "name": "m", "new_name": "n"},
        {"op": "retarget-invoke", "class": "a.B", "name": "m", "to_class": "x.Y"},
        {"op": "flip-flags", "class": "a.B", "method": "m", "set": ["STATIC"], "clear": ["FINAL"]},
        {"op": "flip-flags", "class": "a.B", "set": ["0x1000"]},
        {"op": "replace-method-body", "class": "a.B", "method": "m", "smali": ".locals 0\\nreturn-void"},
    ]
    assert DexHandler._validate_ops(ops) is None


# ── .bak discipline + fast loop plumbing (hermetic, faked CLI) ────────────

def test_patch_writes_bak_once_and_passes_ops_file(fake_run, tmp_path):
    dex = tmp_path / "app.dex"
    dex.write_bytes(b"dex\n035\x00fake")
    h = DexHandler()
    ops = [{"op": "replace-const-string", "old": "a", "new": "b"}]

    first = h.dex_patch({"dex_path": str(dex), "ops": ops})
    assert first["status"] == "ok"
    bak = Path(str(dex) + ".bak")
    assert bak.exists() and bak.read_bytes() == b"dex\n035\x00fake"

    bak.write_bytes(b"modified-by-nothing")  # sentinel: second patch must NOT overwrite
    second = h.dex_patch({"dex_path": str(dex), "ops": ops})
    assert second["status"] == "ok"
    assert bak.read_bytes() == b"modified-by-nothing"

    # the ops file was written as JSON content (never a path argument to the guard);
    # the handler cleans it up afterwards, so the fake runner snapshots the content
    assert fake_run["tool"] == "dex_patch"
    assert fake_run["ops_json"] == ops


def test_patch_output_path_skips_bak(fake_run, tmp_path):
    dex = tmp_path / "app.dex"
    dex.write_bytes(b"data")
    out = tmp_path / "out.dex"
    result = DexHandler().dex_patch({"dex_path": str(dex), "ops": [{"op": "rename", "target": "class", "class": "a", "new_name": "b"}], "output_path": str(out)})
    assert result["status"] == "ok"
    assert not Path(str(dex) + ".bak").exists()
    assert "next_step" in result["result"]


# ── caps logic (hermetic, faked CLI) ──────────────────────────────────────

def test_dex_info_caps_classes_list(monkeypatch):
    def fake(tool, cli_args):
        return {"status": "ok", "tool": "dex_info",
                "result": {"version": "DEX035", "classes_list": [f"c{i}" for i in range(300)],
                           "classes_list_total": 300}}

    monkeypatch.setattr(DexHandler, "_run", staticmethod(fake))
    monkeypatch.setenv("ANDROID_RE_MCP_MAX_OUTPUT_LINES", "50")
    out = DexHandler().dex_info({"dex_path": "/x/a.dex", "classes": True})["result"]
    assert len(out["classes_list"]) == 50
    assert out["truncated"] is True
    assert out["total"] == 300


# ── guard wiring ──────────────────────────────────────────────────────────

def test_guard_refuses_dash_dex_path(tmp_path):
    from android_re_mcp import guard

    with pytest.raises(guard.GuardError):
        guard.check_path("--help", "dex_path", "dex_info")


def test_guard_allows_dex_paths_in_allowed_dirs(tmp_path, monkeypatch):
    from android_re_mcp import guard

    monkeypatch.setenv("ANDROID_RE_MCP_ALLOWED_DIRS", str(tmp_path))
    dex = tmp_path / "a.dex"
    dex.write_bytes(b"dex\n035\x00")
    guard.check_path(str(dex), "dex_path", "dex_info")
    guard.check_path(str(dex), "in_path", "dex_convert")


# ── the real round-trip net (jar-gated — the upstream-safety net) ─────────

@ROUNDTRIP
def test_roundtrip_assemble_info_patch_convert(tmp_path, real_tools):
    h = DexHandler()
    smali = tmp_path / "Loader.smali"
    smali.write_text(FIXTURE_SMALI)

    assembled = h.dex_assemble({"path": str(smali), "output_path": str(tmp_path / "loader.dex")})
    assert assembled["status"] == "ok" and assembled["result"]["class"] == "com.poc.Loader"

    info = h.dex_info({"dex_path": str(tmp_path / "loader.dex")})
    assert info["result"]["version"] == "DEX035" and info["result"]["counts"]["classes"] == 1

    patched = h.dex_patch({
        "dex_path": str(tmp_path / "loader.dex"),
        "ops": [{"op": "replace-const-string", "old": "hello-original", "new": "hello-patched"}],
        "output_path": str(tmp_path / "loader-patched.dex"),
    })
    assert patched["status"] == "ok"
    assert patched["result"]["ops"][0]["matched"] == 1

    converted = h.dex_convert({"in_path": str(tmp_path / "loader-patched.dex"),
                               "target_version": "041",
                               "output_path": str(tmp_path / "loader.container")})
    assert converted["status"] == "ok"

    container_info = h.dex_info({"dex_path": str(tmp_path / "loader.container")})
    assert container_info["result"]["container"] is True


@ROUNDTRIP
def test_roundtrip_swap_into_apk(tmp_path, real_tools):
    h = DexHandler()
    smali = tmp_path / "Loader.smali"
    smali.write_text(FIXTURE_SMALI)
    h.dex_assemble({"path": str(smali), "output_path": str(tmp_path / "loader.dex")})

    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("AndroidManifest.xml", "<manifest/>")
        z.writestr("classes.dex", (tmp_path / "loader.dex").read_bytes())
    h.dex_patch({"dex_path": str(tmp_path / "loader.dex"),
                 "ops": [{"op": "replace-const-string", "old": "hello-original", "new": "hello-patched"}],
                 "output_path": str(tmp_path / "loader-patched.dex")})
    swapped = h.dex_swap({"apk_path": str(apk), "dex_path": str(tmp_path / "loader-patched.dex"),
                          "output_apk": str(tmp_path / "app-signed.apk")})
    assert swapped["status"] == "ok"
    with zipfile.ZipFile(tmp_path / "app-signed.apk") as z:
        assert z.read("classes.dex") == (tmp_path / "loader-patched.dex").read_bytes()
        assert z.read("AndroidManifest.xml") == b"<manifest/>"
