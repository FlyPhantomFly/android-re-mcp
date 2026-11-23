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
    # The patch/convert handlers now check the jar before side effects; a
    # faked _run alone would still hit the isolated HOME's empty tools dir.
    monkeypatch.setattr(
        DexHandler, "_require", staticmethod(lambda tool: ("/fake/dexfile-cli.jar", "/fake/java"))
    )

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


def test_patch_missing_jar_does_not_write_bak(fake_tools, tmp_path):
    """A missing-tool call must not leave a .bak next to the input."""
    dex = tmp_path / "app.dex"
    dex.write_bytes(b"dex\n035\x00fake")
    result = DexHandler().dex_patch({
        "dex_path": str(dex),
        "ops": [{"op": "rename", "target": "class", "class": "a", "new_name": "b"}],
    })
    assert result["status"] == "missing_tool"
    assert not Path(str(dex) + ".bak").exists()


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


# ── convert default target (hermetic, faked CLI) ──────────────────────────

def test_convert_default_target_by_magic(fake_run, tmp_path):
    """vdex/cdex inputs default to 037 (API 28+ era); flat dex stays 035."""
    h = DexHandler()

    vdex = tmp_path / "base.vdex"
    vdex.write_bytes(b"vdex\x0010\x00" + b"\x00" * 16)
    out_v = h.dex_convert({"in_path": str(vdex)})
    args_v = fake_run["cli_args"]
    assert args_v[args_v.index("--to") + 1] == "037"
    assert "037" in out_v["note"] and "target_version" in out_v["note"]

    cdex = tmp_path / "base.cdex"
    cdex.write_bytes(b"cdex001\x00" + b"\x00" * 16)
    h.dex_convert({"in_path": str(cdex)})
    args_c = fake_run["cli_args"]
    assert args_c[args_c.index("--to") + 1] == "037"

    flat = tmp_path / "plain.dex"
    flat.write_bytes(b"dex\n035\x00" + b"\x00" * 16)
    h.dex_convert({"in_path": str(flat)})
    args_f = fake_run["cli_args"]
    assert args_f[args_f.index("--to") + 1] == "035"

    # an explicit target_version always wins, whatever the magic says
    h.dex_convert({"in_path": str(vdex), "target_version": "035"})
    args_e = fake_run["cli_args"]
    assert args_e[args_e.index("--to") + 1] == "035"

    # an unreadable/missing input must not crash the default pick
    version, note = DexHandler._default_target(str(tmp_path / "nope.vdex"))
    assert (version, note) == ("035", None)


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


# ── dex_validate / dex_merge / cdex opt-in (E-PY-19) ──────────────────────

@ROUNDTRIP
def test_dex_validate_clean_dex(tmp_path, real_tools):
    h = DexHandler()
    smali = tmp_path / "Loader.smali"
    smali.write_text(
        ".class public Lcom/poc/Loader;\n.super Ljava/lang/Object;\n\n"
        ".method public static getMessage()Ljava/lang/String;\n    .locals 1\n\n"
        '    const-string v0, "hi"\n\n    return-object v0\n.end method\n')
    h.dex_assemble({"path": str(smali), "output_path": str(tmp_path / "l.dex")})
    out = h.dex_validate({"dex_path": str(tmp_path / "l.dex")})["result"]
    assert out["ok"] is True and out["classes_checked"] == 1
    assert out["methods_analyzed"] == 1
    assert out["issues"] == []
    assert "framework classes" in out["note"] and "unknown" in out["note"]


@ROUNDTRIP
def test_dex_validate_missing_class_is_honest(tmp_path, real_tools):
    h = DexHandler()
    result = h.dex_validate({"dex_path": str(tmp_path / "nope.dex")})
    assert result["status"] == "error"


@ROUNDTRIP
def test_dex_merge_two_classes(tmp_path, real_tools):
    h = DexHandler()
    for name in ("Loader", "Second"):
        smali = tmp_path / f"{name}.smali"
        smali.write_text(
            f".class public Lcom/poc/{name};\n.super Ljava/lang/Object;\n")
        h.dex_assemble({"path": str(smali), "output_path": str(tmp_path / f"{name.lower()}.dex")})
    merged = h.dex_merge({
        "dex_paths": [str(tmp_path / "loader.dex"), str(tmp_path / "second.dex")],
        "output_path": str(tmp_path / "merged.dex")})["result"]
    assert merged["classes"] == 2
    info = h.dex_info({"dex_path": str(tmp_path / "merged.dex")})["result"]
    assert info["counts"]["classes"] == 2
    assert "split the inputs first" in merged["next_step"]


@ROUNDTRIP
def test_dex_merge_duplicate_class_is_honest(tmp_path, real_tools):
    h = DexHandler()
    smali = tmp_path / "Loader.smali"
    smali.write_text(
        ".class public Lcom/poc/Loader;\n.super Ljava/lang/Object;\n\n"
        ".method public static getMessage()Ljava/lang/String;\n    .locals 1\n\n"
        '    const-string v0, "hi"\n\n    return-object v0\n.end method\n')
    h.dex_assemble({"path": str(smali), "output_path": str(tmp_path / "loader.dex")})
    result = h.dex_merge({
        "dex_paths": [str(tmp_path / "loader.dex"), str(tmp_path / "loader.dex")],
        "output_path": str(tmp_path / "merged.dex")})
    assert result["status"] == "error"
    assert "duplicate class" in result["error"]


def test_dex_merge_needs_two_paths():
    result = DexHandler().dex_merge({"dex_paths": ["one.dex"]})
    assert result["status"] == "error" and "at least two" in result["error"]


def test_cdex_write_requires_opt_in():
    h = DexHandler()
    result = h.dex_convert({"in_path": "/x/a.dex", "target_version": "cdex001"})
    assert result["status"] == "error" and "allow_unloadable=true" in result["error"]


def test_cdex_and_validate_schemas_are_truthful():
    from android_re_mcp.server import TOOL_SCHEMAS

    by_name = {schema["name"]: schema for schema in TOOL_SCHEMAS}
    convert = by_name["dex_convert"]["inputSchema"]["properties"]
    assert "cdex001" in convert["target_version"]["enum"]
    # The handler chooses 037/035 from the input magic when the argument is
    # absent; a schema default of 035 would bypass that smart default.
    assert "default" not in convert["target_version"]
    assert "Omit for the smart default" in convert["target_version"]["description"]
    validate = by_name["dex_validate"]["inputSchema"]["properties"]
    assert "dex_path" in validate and "apk_path" not in validate


@ROUNDTRIP
def test_dex_validate_unknown_hierarchy_is_not_flagged(tmp_path, real_tools):
    """A ref resolved through a framework super is inexact, not broken."""
    h = DexHandler()
    smali = tmp_path / "Inherit.smali"
    smali.write_text(
        ".class public Lcom/poc/Inherit;\n.super Ljava/lang/Object;\n\n"
        ".method public call()Ljava/lang/String;\n    .locals 1\n\n"
        "    invoke-virtual {p0}, Lcom/poc/Inherit;->toString()Ljava/lang/String;\n\n"
        "    move-result-object v0\n\n    return-object v0\n.end method\n")
    h.dex_assemble({"path": str(smali), "output_path": str(tmp_path / "i.dex")})
    out = h.dex_validate({"dex_path": str(tmp_path / "i.dex")})["result"]
    assert out["ok"] is True
    assert out["issues"] == []
    assert out["references_unknown"] >= 1


@ROUNDTRIP
def test_dex_validate_flags_super_interface_and_truncates(tmp_path, real_tools):
    h = DexHandler()
    smali_a = tmp_path / "A.smali"
    smali_a.write_text(
        ".class public interface abstract Lcom/poc/A;\n.super Ljava/lang/Object;\n")
    h.dex_assemble({"path": str(smali_a), "output_path": str(tmp_path / "a.dex")})
    paths = [str(tmp_path / "a.dex")]
    for name in ("B", "C"):
        smali = tmp_path / f"{name}.smali"
        smali.write_text(f".class public Lcom/poc/{name};\n.super Lcom/poc/A;\n")
        h.dex_assemble({"path": str(smali), "output_path": str(tmp_path / f"{name.lower()}.dex")})
        paths.append(str(tmp_path / f"{name.lower()}.dex"))
    h.dex_merge({"dex_paths": paths, "output_path": str(tmp_path / "all.dex")})
    out = h.dex_validate({"dex_path": str(tmp_path / "all.dex"), "max_issues": 1})["result"]
    assert out["ok"] is False
    assert out["issues_total"] == 2
    assert out["issues_shown"] == 1 and out["truncated"] is True
    assert out["issues"][0]["kind"] == "super_is_interface"
    assert "raise max_issues" in out["hint"]


@ROUNDTRIP
def test_dex_merge_allow_cdex_writes_cdex(tmp_path, real_tools):
    h = DexHandler()
    paths = []
    for name in ("One", "Two"):
        smali = tmp_path / f"{name}.smali"
        smali.write_text(f".class public Lcom/poc/{name};\n.super Ljava/lang/Object;\n")
        out_path = tmp_path / f"{name.lower()}.dex"
        h.dex_assemble({"path": str(smali), "output_path": str(out_path)})
        paths.append(str(out_path))
    merged = h.dex_merge({"dex_paths": paths,
                          "output_path": str(tmp_path / "merged.cdex"),
                          "allow_cdex": True})["result"]
    assert merged["target_version"] == "CDEX001"
    assert merged["cdex_written"] is True
    info = h.dex_info({"dex_path": str(tmp_path / "merged.cdex")})["result"]
    assert info["version"] == "CDEX001" and info["compact"] is True


@ROUNDTRIP
def test_cdex_write_opt_in_succeeds_with_note(tmp_path, real_tools):
    h = DexHandler()
    smali = tmp_path / "Loader.smali"
    smali.write_text(
        ".class public Lcom/poc/Loader;\n.super Ljava/lang/Object;\n\n"
        ".method public static getMessage()Ljava/lang/String;\n    .locals 1\n\n"
        '    const-string v0, "hi"\n\n    return-object v0\n.end method\n')
    h.dex_assemble({"path": str(smali), "output_path": str(tmp_path / "l.dex")})
    out = h.dex_convert({"in_path": str(tmp_path / "l.dex"),
                         "target_version": "cdex001", "allow_unloadable": True,
                         "output_path": str(tmp_path / "l.cdex")})
    assert out["status"] == "ok"
    assert out["result"]["converted"][0]["to"] == "CDEX001"
    assert "not PathClassLoader-loadable" in out["note"]
