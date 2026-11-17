"""Hermetic tests for the apk_decompile_java apktool fallback (jadx unavailable).

The contract: when jadx is missing the call still succeeds via apktool,
flagged honestly (engine + fallback + note); when both are missing it is
a missing_tool; jadx errors pass through unchanged.
"""

from android_re_mcp.handlers import static as static_mod
from android_re_mcp.handlers.static import StaticHandler


class _Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _check(name: str, jadx: bool, apktool: bool):
    def fake(tool):
        return {"jadx": jadx, "apktool": apktool}.get(tool, False)

    return fake


def test_jadx_available_uses_jadx(monkeypatch):
    seen = {}

    def fake_run(cmd, **_k):
        seen["cmd"] = cmd
        return _Proc(0, stdout="jadx ok")

    monkeypatch.setattr(static_mod, "_check_tool", _check(None, jadx=True, apktool=True))
    monkeypatch.setattr(static_mod.subprocess, "run", fake_run)
    result = StaticHandler().apk_decompile_java({"apk_path": "/x/notes.apk"})
    assert result["status"] == "ok"
    assert result["tool"] == "jadx"
    assert result["output"]["engine"] == "jadx"
    assert result["output"]["out_dir"] == "/x/notes_jadx"
    assert seen["cmd"][0] == "jadx"


def test_jadx_missing_falls_back_to_apktool(monkeypatch):
    seen = {}

    def fake_run(cmd, **_k):
        seen["cmd"] = cmd
        return _Proc(0, stdout="apktool ok")

    monkeypatch.setattr(static_mod, "_check_tool", _check(None, jadx=False, apktool=True))
    monkeypatch.setattr(static_mod.subprocess, "run", fake_run)
    result = StaticHandler().apk_decompile_java({"apk_path": "/x/notes.apk"})
    assert result["status"] == "ok"
    assert result["tool"] == "apk_decompile_java"
    assert result["output"]["engine"] == "apktool (jadx unavailable)"
    assert result["output"]["fallback"] is True
    assert "smali" in result["output"]["note"]
    assert "--setup" in result["output"]["note"]
    assert result["output"]["out_dir"] == "/x/notes_apktool"
    assert seen["cmd"][0] == "apktool"  # mode defaults to full (smali + resources)


def test_both_missing_is_missing_tool(monkeypatch):
    monkeypatch.setattr(static_mod, "_check_tool", _check(None, jadx=False, apktool=False))
    result = StaticHandler().apk_decompile_java({"apk_path": "/x/notes.apk"})
    assert result["status"] == "missing_tool"
    assert "neither jadx nor apktool" in result["error"]
    assert "--setup" in result["hint"]


def test_apktool_failure_passes_through(monkeypatch):
    monkeypatch.setattr(static_mod, "_check_tool", _check(None, jadx=False, apktool=True))
    monkeypatch.setattr(static_mod.subprocess, "run", lambda *a, **k: _Proc(1, stderr="apktool boom"))
    result = StaticHandler().apk_decompile_java({"apk_path": "/x/notes.apk"})
    assert result["status"] == "error"
    assert "apktool boom" in result["error"]


def test_jadx_failure_does_not_fall_back(monkeypatch):
    # jadx present but broken is a jadx problem — honest error, no silent engine swap
    monkeypatch.setattr(static_mod, "_check_tool", _check(None, jadx=True, apktool=True))
    monkeypatch.setattr(static_mod.subprocess, "run", lambda *a, **k: _Proc(1, stderr="jadx boom"))
    result = StaticHandler().apk_decompile_java({"apk_path": "/x/notes.apk"})
    assert result["status"] == "error"
    assert result["tool"] == "jadx"
    assert "jadx boom" in result["error"]
