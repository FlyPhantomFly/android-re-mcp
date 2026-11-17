"""Hermetic tests for the E-PY-15 token-conservation caps.

The strategy is android-unidbg-mcp's: cap heavy list outputs, keep the
honest total, and end with an actionable narrowing hint — one tool call
must never flood the assistant's context window. Every handler wired to
handlers/caps.py is exercised here with fake queues and fake subprocess
output — no adb, no frida, no ripgrep.
"""

import json

import pytest

from android_re_mcp.handlers.caps import DEFAULT_MAX_OUTPUT_LINES, cap_items, output_cap


@pytest.fixture
def default_cap(monkeypatch):
    monkeypatch.delenv("ANDROID_RE_MCP_MAX_OUTPUT_LINES", raising=False)


# ── caps module ───────────────────────────────────────────────────────────

def test_output_cap_default_and_env_overrides(monkeypatch):
    monkeypatch.delenv("ANDROID_RE_MCP_MAX_OUTPUT_LINES", raising=False)
    assert output_cap() == DEFAULT_MAX_OUTPUT_LINES == 200
    monkeypatch.setenv("ANDROID_RE_MCP_MAX_OUTPUT_LINES", "50")
    assert output_cap() == 50
    monkeypatch.setenv("ANDROID_RE_MCP_MAX_OUTPUT_LINES", "0")
    assert output_cap() == 0  # 0 disables capping
    monkeypatch.setenv("ANDROID_RE_MCP_MAX_OUTPUT_LINES", "-5")
    assert output_cap() == 0  # negative clamps to disabled
    monkeypatch.setenv("ANDROID_RE_MCP_MAX_OUTPUT_LINES", "junk")
    assert output_cap() == 200  # junk falls back to the default


def test_cap_items_under_cap_keeps_exact_shape():
    shown, info = cap_items(["a", "b"], "narrow it")
    assert shown == ["a", "b"]
    assert info == {"total": 2, "shown": 2, "truncated": False}


def test_cap_items_truncates_with_counts_and_hint(monkeypatch):
    monkeypatch.setenv("ANDROID_RE_MCP_MAX_OUTPUT_LINES", "3")
    items = [f"line{i}" for i in range(5)]
    shown, info = cap_items(items, "use the filter")
    assert len(shown) == 3
    assert info["total"] == 5
    assert info["shown"] == 3
    assert info["truncated"] is True
    assert "2 more omitted" in info["hint"]
    assert "use the filter" in info["hint"]


def test_cap_items_zero_cap_disables_truncation(monkeypatch):
    monkeypatch.setenv("ANDROID_RE_MCP_MAX_OUTPUT_LINES", "0")
    items = list(range(300))
    shown, info = cap_items(items, "hint")
    assert shown is items
    assert info["truncated"] is False


# ── frida_read_output ─────────────────────────────────────────────────────

from android_re_mcp.handlers.dynamic import DynamicHandler  # noqa: E402


def _fill_frida(h: DynamicHandler, n: int) -> None:
    for i in range(n):
        h._output_queue.put(f"m{i}")


def test_frida_read_output_caps_and_keeps_remainder_buffered(default_cap):
    h = DynamicHandler()
    _fill_frida(h, 250)
    out = h.frida_read_output({})["output"]
    assert out["count"] == 200
    assert len(out["messages"]) == 200
    assert out["truncated"] is True
    assert out["buffered"] == 50
    assert "frida_read_output" in out["hint"]

    second = h.frida_read_output({})["output"]
    assert second["count"] == 50  # the held-back lines survive for this call
    assert "truncated" not in second

    third = h.frida_read_output({})["output"]
    assert third["count"] == 0
    assert "truncated" not in third


def test_frida_detach_drops_held_back_lines(default_cap):
    h = DynamicHandler()
    _fill_frida(h, 210)
    h.frida_read_output({})
    assert h._pending_output  # 10 lines held back
    h._frida_session = object()  # pretend attached
    assert h.frida_detach({})["output"]["detached"] is True
    assert h._pending_output == []  # they die with the session
    assert h.frida_read_output({})["output"]["count"] == 0


def test_frida_read_output_zero_cap_drains_everything(monkeypatch):
    monkeypatch.setenv("ANDROID_RE_MCP_MAX_OUTPUT_LINES", "0")
    h = DynamicHandler()
    _fill_frida(h, 250)
    out = h.frida_read_output({})["output"]
    assert out["count"] == 250
    assert "truncated" not in out
    assert h._pending_output == []


# ── adb_logcat_read / adb_logcat_stop ─────────────────────────────────────

from android_re_mcp.handlers.device import DeviceHandler  # noqa: E402


def _fill_logcat(h: DeviceHandler, n: int) -> None:
    for i in range(n):
        h._logcat_queue.put(f"L{i}")


def test_logcat_read_clamps_oversized_requests(default_cap):
    h = DeviceHandler()
    _fill_logcat(h, 300)
    out = h.adb_logcat_read({"lines": 300})["output"]
    assert out["count"] == 200
    assert out["truncated"] is True
    assert out["buffered"] == 100
    assert "adb_logcat_start filter" in out["hint"]


def test_logcat_read_under_cap_unchanged_shape(default_cap):
    h = DeviceHandler()
    _fill_logcat(h, 50)
    out = h.adb_logcat_read({"lines": 100})["output"]
    assert out == {"lines": [f"L{i}" for i in range(50)], "count": 50}


def test_logcat_stop_caps_final_buffer_and_counts_dropped(default_cap):
    h = DeviceHandler()
    _fill_logcat(h, 260)
    out = h.adb_logcat_stop({})["output"]
    assert out["logcat_stopped"] is True
    assert len(out["remaining_lines"]) == 200
    assert out["remaining_count"] == 260
    assert out["dropped"] == 60
    assert out["truncated"] is True
    assert "adb_logcat_read" in out["hint"]


def test_logcat_stop_under_cap_unchanged_shape(default_cap):
    h = DeviceHandler()
    _fill_logcat(h, 10)
    out = h.adb_logcat_stop({})["output"]
    assert out == {"logcat_stopped": True, "remaining_lines": [f"L{i}" for i in range(10)]}


# ── search_strings ────────────────────────────────────────────────────────

from android_re_mcp.handlers import static as static_mod  # noqa: E402
from android_re_mcp.handlers.static import StaticHandler  # noqa: E402


def _rg_output(matches: list[dict]) -> str:
    lines = []
    for m in matches:
        lines.append(json.dumps({
            "type": "match",
            "data": {
                "path": {"text": m["file"]},
                "line_number": m["line"],
                "lines": {"text": m["text"] + "\n"},
            },
        }))
    return "\n".join(lines)


def test_search_strings_caps_matches_and_keeps_total(monkeypatch, default_cap):
    matches = [{"file": f"f{i}.smali", "line": i, "text": "needle"} for i in range(230)]

    class FakeProc:
        returncode = 0
        stdout = _rg_output(matches)
        stderr = ""

    monkeypatch.setattr(static_mod, "_check_tool", lambda _name: True)
    monkeypatch.setattr(static_mod.subprocess, "run", lambda *a, **k: FakeProc())
    out = StaticHandler().search_strings({"path": "/decomp", "pattern": "needle"})["output"]
    assert out["total"] == 230
    assert len(out["matches"]) == 200
    assert out["shown"] == 200
    assert out["truncated"] is True
    assert "narrow the pattern" in out["hint"]


def test_search_strings_under_cap_unchanged_shape(monkeypatch, default_cap):
    matches = [{"file": "a.smali", "line": 1, "text": "needle"}]

    class FakeProc:
        returncode = 0
        stdout = _rg_output(matches)
        stderr = ""

    monkeypatch.setattr(static_mod, "_check_tool", lambda _name: True)
    monkeypatch.setattr(static_mod.subprocess, "run", lambda *a, **k: FakeProc())
    out = StaticHandler().search_strings({"path": "/decomp", "pattern": "needle"})["output"]
    assert out == {"matches": matches, "total": 1}


# ── native_strings ────────────────────────────────────────────────────────

from android_re_mcp.handlers.native import NativeHandler  # noqa: E402


def test_native_strings_caps_per_lib_and_names_knobs(tmp_path, monkeypatch, default_cap):
    so = tmp_path / "libtest.so"
    so.write_bytes(b"\x7fELF")
    h = NativeHandler()
    monkeypatch.setattr(h, "_extract_strings", lambda _p, _n: [f"s{i}" for i in range(300)])
    entry = h.native_strings({"so_path": str(so), "interesting_only": False})["output"]["results"]["libtest.so"]
    assert entry["total_strings"] == 300
    assert entry["shown"] == 200
    assert len(entry["strings"]) == 200
    assert entry["truncated"] is True
    assert "min_len" in entry["hint"]
    assert "search_strings" in entry["hint"]


def test_native_strings_under_cap_unchanged_shape(tmp_path, monkeypatch, default_cap):
    so = tmp_path / "libtest.so"
    so.write_bytes(b"\x7fELF")
    h = NativeHandler()
    monkeypatch.setattr(h, "_extract_strings", lambda _p, _n: ["short", "strings"])
    entry = h.native_strings({"so_path": str(so), "interesting_only": False})["output"]["results"]["libtest.so"]
    assert entry == {"total_strings": 2, "shown": 2, "strings": ["short", "strings"]}
