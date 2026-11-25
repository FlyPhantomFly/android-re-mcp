"""Jar-free argv passthrough tests for the dex_* MCP tools.

The ``fake_run`` fixture (conftest.py) replaces ``DexHandler._run`` and records
the argv the handler builds. Each case sets one schema argument and asserts
the matching CLI flag; the reverse case asserts an omitted argument emits no
flag. The coverage guard fails when a covered tool grows an untested property.
"""

from __future__ import annotations

import pytest

from android_re_mcp.handlers.dex import DexHandler
from android_re_mcp.server import TOOL_SCHEMAS

SMALI = ".class public Lpoc/A;\n.super Ljava/lang/Object;\n"

# Minimal valid arguments per tool, so each case varies exactly one thing.
BASE = {
    "dex_info": {"dex_path": "/x/a.dex"},
    "dex_convert": {"in_path": "/x/a.dex", "target_version": "035"},
    "dex_patch": {
        "dex_path": "/x/a.dex",
        "output_path": "/x/out.dex",
        "ops": [{"op": "flip-flags", "class": "a.B", "set": ["STATIC"]}],
    },
    "dex_assemble": {"smali_text": SMALI, "output_path": "/x/out.dex"},
    "dex_split": {"dex_path": "/x/a.dex", "output_dir": "/x/out"},
    "dex_merge": {"dex_paths": ["/x/a.dex", "/x/b.dex"], "output_path": "/x/out.dex"},
    "dex_validate": {"dex_path": "/x/a.dex"},
}

# (tool, argument, value, argv fragment that must appear)
CASES = [
    ("dex_info", "scan", True, ["--scan"]),
    ("dex_convert", "api", 14, ["--api", "14"]),
    ("dex_convert", "era", "dalvik", ["--era", "dalvik"]),
    ("dex_convert", "allow_ambiguous", True, ["--allow-ambiguous-odex"]),
    ("dex_patch", "api", 5, ["--api", "5"]),
    ("dex_patch", "era", "art", ["--era", "art"]),
    ("dex_patch", "allow_ambiguous", True, ["--allow-ambiguous-odex"]),
    ("dex_assemble", "api", 5, ["--api", "5"]),
    ("dex_assemble", "era", "dalvik", ["--era", "dalvik"]),
    ("dex_split", "era", "art", ["--era", "art"]),
    ("dex_split", "allow_ambiguous", True, ["--allow-ambiguous-odex"]),
    ("dex_merge", "era", "dalvik", ["--era", "dalvik"]),
    ("dex_merge", "allow_ambiguous", True, ["--allow-ambiguous-odex"]),
    ("dex_merge", "allow_cdex", True, ["--allow-cdex"]),
    ("dex_validate", "era", "art", ["--era", "art"]),
]

# Properties that are paths/content/positional/non-flag switches, covered by
# the jar-gated round-trip tests or by validation tests instead of argv here.
EXEMPT = {
    "dex_path",
    "in_path",
    "apk_path",
    "output_path",
    "output_dir",
    "dex_paths",
    "ops",
    "smali_text",
    "path",
    "target_version",
    "allow_unloadable",
    "classes",
    "limit",
    "max_issues",
}

# CLI-facing dex tools not covered by CASES, with the reason they are out of
# scope for this argv contract (and where their behavior is covered instead).
OUT_OF_SCOPE = {
    "dex_extract": "positional input plus --out; covered by test_dex_tools.py",
    "dex_read_class_outline": "argv sibling: test_dex_read_class_outline_builds_outline_argv; jar behavior in the gated test",
    "dex_read_pseudocode": "jadx subprocess, not DexHandler._run argv",
    "dex_swap": "pure-Python zip rewrite, no CLI argv",
}


def _call(tool: str, args: dict) -> dict:
    return getattr(DexHandler(), tool)(args)


def _contains(argv: list[str], fragment: list[str]) -> bool:
    n = len(fragment)
    return any(argv[i:i + n] == fragment for i in range(len(argv) - n + 1))


@pytest.mark.parametrize(
    "tool,arg,value,fragment",
    CASES,
    ids=[f"{tool}-{arg}" for tool, arg, _value, _fragment in CASES],
)
def test_argument_reaches_argv(fake_run, tool, arg, value, fragment):
    _call(tool, {**BASE[tool], arg: value})
    assert fake_run["tool"] == tool
    assert _contains(fake_run["cli_args"], fragment), fake_run["cli_args"]


@pytest.mark.parametrize(
    "tool,arg,value,fragment",
    CASES,
    ids=[f"{tool}-{arg}" for tool, arg, _value, _fragment in CASES],
)
def test_omitted_argument_emits_no_flag(fake_run, tool, arg, value, fragment):
    _call(tool, BASE[tool])
    assert fake_run["tool"] == tool
    assert fragment[0] not in fake_run["cli_args"], fake_run["cli_args"]


def test_every_covered_schema_property_is_tested_or_exempt():
    covered = {(tool, arg) for tool, arg, *_ in CASES}
    missing = []
    for schema in TOOL_SCHEMAS:
        tool = schema["name"]
        if tool not in BASE:
            continue
        for prop in schema["inputSchema"].get("properties", {}):
            if prop not in EXEMPT and (tool, prop) not in covered:
                missing.append((tool, prop))
    assert not missing, f"untested schema properties: {missing}"


def test_every_dex_tool_is_classified():
    dex_tools = {schema["name"] for schema in TOOL_SCHEMAS if schema["name"].startswith("dex_")}
    classified = set(BASE) | set(OUT_OF_SCOPE)
    assert dex_tools == classified, {
        "unclassified": sorted(dex_tools - classified),
        "stale": sorted(classified - dex_tools),
    }


def test_dex_convert_undocumented_dex_path_alias_is_gone(fake_run):
    """`dex_path` was never in dex_convert's schema; the handler must not read it.

    Callers that sent only `dex_path` used to be silently accepted via a
    legacy fallback from the first integration cut. Now the positional input
    is empty and the CLI refuses it honestly.
    """
    _call("dex_convert", {"dex_path": "/x/a.dex"})
    argv = fake_run["cli_args"]
    assert "/x/a.dex" not in argv, argv
    assert argv[1] == "", argv
    assert fake_run["tool"] == "dex_convert"


def test_dex_read_class_outline_builds_outline_argv(fake_run):
    """Jar-free sibling of test_dex_read_class_outline_real: the argv contract.

    The outline handler searches dex_path targets directly and passes
    class_name as --class; the gated test proves the jar's behavior, this
    proves the plumbing without the jar.
    """
    result = _call("dex_read_class_outline",
                   {"dex_path": "/x/a.dex", "class_name": "com.example.Foo"})
    assert result["status"] == "ok", result
    argv = fake_run["cli_args"]
    assert _contains(argv, ["outline", "/x/a.dex", "--class", "com.example.Foo"]), argv
