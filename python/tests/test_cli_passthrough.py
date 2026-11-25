"""Jar-free CLI argv passthrough tests for the non-dex MCP tools.

Mirrors ``test_dex_passthrough.py``: each case sets one schema argument and
asserts the matching CLI fragment in the argv the handler builds, faked at the
subprocess boundary; the reverse case asserts an omitted argument emits no
fragment. A subprocess-reaching AST guard classifies every tool, so a new
tool that shells out cannot ship unclassified.
"""

from __future__ import annotations

import ast
import io
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from android_re_mcp import handlers as handlers_pkg
from android_re_mcp.handlers import device as device_mod
from android_re_mcp.handlers import native as native_mod
from android_re_mcp.handlers import network as network_mod
from android_re_mcp.handlers import static as static_mod
from android_re_mcp.server import TOOL_SCHEMAS
import test_dex_passthrough as dex_passthrough

HANDLERS_DIR = Path(handlers_pkg.__file__).parent
_SUBPROCESS_CALLS = {"run", "call", "check_call", "check_output", "Popen"}

# (tool, argument, value, argv fragment) — a list fragment must appear as an
# exact subsequence; a string fragment must be a substring of one element.
CASES = [
    ("adb_shell", "serial", "emulator-5", ["-s", "emulator-5"]),
    ("adb_install", "serial", "emulator-5", ["-s", "emulator-5"]),
    ("adb_pull", "serial", "emulator-5", ["-s", "emulator-5"]),
    ("adb_push", "serial", "emulator-5", ["-s", "emulator-5"]),
    ("adb_ui_dump", "serial", "emulator-5", ["-s", "emulator-5"]),
    ("adb_logcat_start", "serial", "emulator-5", ["-s", "emulator-5"]),
    ("adb_logcat_start", "filter", "crash:E *:S", ["logcat", "crash:E *:S"]),
    ("scrcpy_start", "serial", "emulator-5", ["--serial", "emulator-5"]),
    ("scrcpy_start", "bitrate", 8, ["--video-bit-rate=8M"]),
    ("scrcpy_start", "max_fps", 60, ["--max-fps=60"]),
    ("scrcpy_start", "record_file", "/x/rec.mp4", ["--record", "/x/rec.mp4"]),
    ("scrcpy_start", "no_display", True, ["--no-display"]),
    ("scrcpy_screenshot", "serial", "emulator-5", ["-s", "emulator-5"]),
    ("native_disasm", "n_instructions", 7, "pd 7 @ sym.main"),
    ("native_disasm", "mode", "graph", "agf @ sym.main"),
    ("native_disasm", "mode", "pseudocode", "pdg @ sym.main"),
    ("mitm_start", "port", 9999, ["-p", "9999"]),
    ("apk_decompile", "mode", "resources_only", ["--no-src"]),
    ("apk_decompile", "mode", "smali_only", ["--no-res"]),
]

# Minimal valid arguments per tool; "{SO}" is replaced with a real .so file
# because native_disasm checks existence before building argv.
BASE = {
    "adb_shell": {"command": "pm list packages -3"},
    "adb_install": {"apk_path": "/x/a.apk"},
    "adb_pull": {"remote": "/sdcard/x", "local": "/x/x"},
    "adb_push": {"local": "/x/x", "remote": "/sdcard/x"},
    "adb_ui_dump": {},
    "adb_logcat_start": {},
    "scrcpy_start": {},
    "scrcpy_screenshot": {},
    "native_disasm": {"so_path": "{SO}", "target": "main"},
    "mitm_start": {},
    "apk_decompile": {"apk_path": "/x/a.apk"},
}

# Required/positional arguments of the covered tools: forwarding is proven by
# the base call itself (they are always in argv) or by a dedicated test.
PROP_EXEMPT = {"apk_path", "command", "remote", "local", "so_path", "target", "output_path"}

# Other tools whose handler path reaches subprocess, each with the reason it
# has no parametrized cases here (the drift checker still proves every schema
# property is read).
EXEMPT_ARGV = {
    "apk_decompile_java": "positional apk_path; engine fallback covered by test_decompile_fallback",
    "apk_identify": "required positional only; apkid integration",
    "apk_scan_secrets": "required positional only; apkleaks integration",
    "android_api_extractor": "positional paths; output_format picks an output writer, not argv",
    "search_strings": "both args required (rg -e/--); no optional flags",
    "objection_run": "positional package/command; requires an objection install",
    "frida_server_push": "abi/hluda select the binary, remote_path is an adb positional",
    "native_strings": "strings binary with pure-Python fallback; covered by test_native_inventory",
    "native_exports": "readelf/nm positionals; covered by test_native_inventory",
    "il2cpp_dump": "positional apk/abi; Il2CppDumper integration-gated",
    "apk_read_signature": "positional only; apksigner/openssl parsing",
    "apk_build_check": "positional smali_dir/apk_path; multi-step integration lint",
    "resource_table_list": "aapt2 positional; package/type_name filter the parsed table",
    "blutter_extract": "positional paths; requires a blutter install",
    "inject_gadget": "pure-Python zip surgery; paths select entries, not argv",
    "mitm_read_flows": "filters ride a generated mitmdump --script, not argv",
    "mitm_export_har": "capture/output positionals via the mitmproxy io library",
    "rasp_identify": "positional only",
    "hermes_decode": "positional paths; bundled decoder pipeline",
    "apk_rebuild_sign": "positional smali_dir; apktool build + sign pipeline",
    "apk_sign": "positional; keystore resolved from config",
    "adb_devices": "no arguments; single adb positional",
}

_CLASSES = {
    "adb_shell": device_mod.DeviceHandler,
    "adb_install": device_mod.DeviceHandler,
    "adb_pull": device_mod.DeviceHandler,
    "adb_push": device_mod.DeviceHandler,
    "adb_ui_dump": device_mod.DeviceHandler,
    "adb_logcat_start": device_mod.DeviceHandler,
    "scrcpy_start": device_mod.DeviceHandler,
    "scrcpy_screenshot": device_mod.DeviceHandler,
    "native_disasm": native_mod.NativeHandler,
    "mitm_start": network_mod.NetworkHandler,
    "apk_decompile": static_mod.StaticHandler,
}


# ── subprocess-reaching analysis (the classification guard) ───────────────

def _argv_tools() -> set[str]:
    """Tools whose handler path reaches subprocess.run/call/Popen."""
    functions: dict[str, list[ast.FunctionDef]] = {}
    for path in sorted(HANDLERS_DIR.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                functions.setdefault(node.name, []).append(node)

    def calls_subprocess(fn: ast.FunctionDef) -> bool:
        for node in ast.walk(fn):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in _SUBPROCESS_CALLS:
                    value = node.func.value
                    if isinstance(value, ast.Name) and value.id in ("subprocess", "sp"):
                        return True
                    if isinstance(value, ast.Attribute) and value.attr == "subprocess":
                        return True
        return False

    def callee_names(fn: ast.FunctionDef) -> set[str]:
        out: set[str] = set()
        for node in ast.walk(fn):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    out.add(node.func.id)
                elif isinstance(node.func, ast.Attribute):
                    out.add(node.func.attr)
        return out

    reaches = {name: any(calls_subprocess(fn) for fn in fns) for name, fns in functions.items()}
    for _ in range(10):
        changed = False
        for name, fns in functions.items():
            if reaches[name]:
                continue
            for fn in fns:
                if any(reaches.get(callee, False) for callee in callee_names(fn)):
                    reaches[name] = True
                    changed = True
        if not changed:
            break
    return {schema["name"] for schema in TOOL_SCHEMAS if reaches.get(schema["name"], False)}


# ── fakes ─────────────────────────────────────────────────────────────────

def _prepare(tool: str, monkeypatch, calls: dict) -> None:
    if tool in ("adb_shell", "adb_install", "adb_pull", "adb_push", "adb_ui_dump"):
        monkeypatch.setattr(device_mod, "_check_adb", lambda: True)

        def fake_adb(*args, serial=None, timeout=120):  # noqa: ARG001
            cmd = ["adb"] + (["-s", serial] if serial else []) + list(args)
            calls["argv"] = cmd
            if "dump" in args or "cat" in args:
                xml = '<?xml version="1.0"?><hierarchy rotation="0"></hierarchy>'
                return SimpleNamespace(returncode=0, stdout=xml, stderr="")
            return SimpleNamespace(returncode=0, stdout="Success", stderr="")

        monkeypatch.setattr(device_mod, "_adb", fake_adb)
    elif tool == "adb_logcat_start":
        monkeypatch.setattr(device_mod, "_check_adb", lambda: True)

        def fake_popen(cmd, **kwargs):
            calls["argv"] = cmd
            return SimpleNamespace(stdout=io.StringIO(""), stderr=io.StringIO(""), pid=4242)

        monkeypatch.setattr(device_mod.subprocess, "Popen", fake_popen)
    elif tool == "scrcpy_start":
        monkeypatch.setattr(shutil, "which", lambda name: f"/fake/{name}")

        def fake_scrcpy_popen(cmd, **kwargs):
            calls["argv"] = cmd
            return SimpleNamespace(pid=4242)

        monkeypatch.setattr(device_mod.subprocess, "Popen", fake_scrcpy_popen)
    elif tool == "scrcpy_screenshot":
        monkeypatch.setattr(device_mod, "_check_adb", lambda: True)

        def fake_run(cmd, **kwargs):
            calls["argv"] = cmd
            return SimpleNamespace(returncode=0, stdout=b"\x89PNG-fake", stderr=b"")

        monkeypatch.setattr(device_mod.subprocess, "run", fake_run)
    elif tool == "native_disasm":
        monkeypatch.setattr(native_mod, "_check", lambda name: True)

        def fake_r2(cmd, **kwargs):
            calls["argv"] = cmd
            return SimpleNamespace(returncode=0, stdout="disasm", stderr="")

        monkeypatch.setattr(native_mod.subprocess, "run", fake_r2)
    elif tool == "mitm_start":
        monkeypatch.setattr(network_mod, "_check_tool", lambda name: True)
        monkeypatch.setattr(network_mod.time, "sleep", lambda seconds: None)

        def fake_mitm_popen(cmd, **kwargs):
            calls["argv"] = cmd
            return SimpleNamespace(pid=4242)

        monkeypatch.setattr(network_mod.subprocess, "Popen", fake_mitm_popen)
    elif tool == "apk_decompile":
        monkeypatch.setattr(static_mod, "_check_tool", lambda name: True)

        def fake_apktool(cmd, **kwargs):
            calls["argv"] = cmd
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        monkeypatch.setattr(static_mod.subprocess, "run", fake_apktool)
    else:
        raise AssertionError(f"no fake recipe for {tool}")


@pytest.fixture
def so_file(tmp_path):
    path = tmp_path / "libtest.so"
    path.write_bytes(b"\x7fELF" + b"\x00" * 64)
    return path


def _call(tool: str, args: dict, monkeypatch, so_file) -> tuple[dict, list]:
    calls: dict = {}
    _prepare(tool, monkeypatch, calls)
    resolved = {key: str(value).replace("{SO}", str(so_file)) for key, value in args.items()}
    result = getattr(_CLASSES[tool](), tool)(resolved)
    return result, calls.get("argv", [])


def _matches(argv: list, fragment) -> bool:
    if isinstance(fragment, str):
        return any(fragment in element for element in argv)
    n = len(fragment)
    return any(list(argv[i:i + n]) == list(fragment) for i in range(len(argv) - n + 1))


# ── the passthrough matrix ────────────────────────────────────────────────

@pytest.mark.parametrize(
    "tool,arg,value,fragment",
    CASES,
    ids=[f"{tool}-{arg}" for tool, arg, _value, _fragment in CASES],
)
def test_argument_reaches_cli_argv(monkeypatch, so_file, tool, arg, value, fragment):
    result, argv = _call(tool, {**BASE[tool], arg: value}, monkeypatch, so_file)
    assert result.get("status") == "ok", result
    assert _matches(argv, fragment), argv


@pytest.mark.parametrize(
    "tool,arg,value,fragment",
    CASES,
    ids=[f"{tool}-{arg}" for tool, arg, _value, _fragment in CASES],
)
def test_omitted_argument_emits_no_cli_fragment(monkeypatch, so_file, tool, arg, value, fragment):
    result, argv = _call(tool, BASE[tool], monkeypatch, so_file)
    assert result.get("status") == "ok", result
    assert not _matches(argv, fragment), argv


def test_adb_shell_command_is_split_not_shelled(monkeypatch):
    """The command is shlex-split into argv elements and never shell-evaluated."""
    calls: dict = {}
    _prepare("adb_shell", monkeypatch, calls)
    handler = device_mod.DeviceHandler()
    result = handler.adb_shell({"command": 'pm grant "com.example app" android.permission.X'})
    assert result["status"] == "ok", result
    assert calls["argv"][1:4] == ["shell", "pm", "grant"]
    assert "com.example app" in calls["argv"]
    assert "; rm -rf /" not in calls["argv"]

    result = handler.adb_shell({"command": "echo a; b"})
    assert result["status"] == "ok", result
    assert "a;" in calls["argv"]  # the operator survives as data, not as syntax


# ── guards ────────────────────────────────────────────────────────────────

def test_every_covered_property_is_tested_or_exempt():
    covered = {(tool, arg) for tool, arg, *_ in CASES}
    missing = []
    for schema in TOOL_SCHEMAS:
        tool = schema["name"]
        if tool not in BASE:
            continue
        for prop in schema["inputSchema"].get("properties", {}):
            if prop not in PROP_EXEMPT and (tool, prop) not in covered:
                missing.append((tool, prop))
    assert not missing, f"untested argv-tool properties: {missing}"


def test_every_subprocess_tool_is_classified():
    """Any tool whose handler shells out must be covered or exempted here.

    The set is computed from the AST (handler call graph → subprocess), so a
    new tool that builds a CLI argv fails this guard until it is classified.
    Dex-side tools are classified by test_dex_passthrough; this file only
    stale-checks its own entries.
    """
    computed = _argv_tools()
    ours = set(BASE) | set(EXEMPT_ARGV)
    dex_side = set(dex_passthrough.BASE) | set(dex_passthrough.OUT_OF_SCOPE)
    unclassified = computed - ours - dex_side
    assert not unclassified, {"unclassified": sorted(unclassified)}
    stale = ours - computed
    assert not stale, {"stale": sorted(stale)}
