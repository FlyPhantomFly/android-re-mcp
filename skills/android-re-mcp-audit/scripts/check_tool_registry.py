#!/usr/bin/env python3
"""AST checks for android-re-mcp registry and wiring drift.

Checks:
  * TOOL_SCHEMAS vs _dispatch (both directions, duplicates)
  * dispatcher values named dex.* exist on handlers.dex.DexHandler
  * check_tools used_by lists name real tools
  * guard OUTPUT_SUFFIXES keys name real tools

Read-only. Exit code 1 when issues are found.

Usage:
    python check_tool_registry.py --repo /path/to/android-re-mcp
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path


def find_repo(start: Path) -> Path | None:
    current = start.resolve()
    for candidate in (current, *current.parents):
        if (candidate / "python" / "pyproject.toml").is_file() and (
            candidate / "python" / "src" / "android_re_mcp"
        ).is_dir():
            return candidate
    return None


def assignment_value(tree: ast.AST, name: str) -> ast.AST | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    return node.value
        elif isinstance(node, ast.AnnAssign):
            target = node.target
            if isinstance(target, ast.Name) and target.id == name:
                return node.value
    return None


def const_str(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def schema_names(server_tree: ast.AST) -> list[str]:
    value = assignment_value(server_tree, "TOOL_SCHEMAS")
    names: list[str] = []
    if not isinstance(value, ast.List):
        return names
    for item in value.elts:
        if not isinstance(item, ast.Dict):
            continue
        for key, val in zip(item.keys, item.values):
            if const_str(key) == "name":
                name = const_str(val)
                if name:
                    names.append(name)
                break
    return names


def dispatch_entries(server_tree: ast.AST) -> dict[str, str]:
    value = assignment_value(server_tree, "_dispatch")
    entries: dict[str, str] = {}
    if not isinstance(value, ast.Dict):
        return entries
    for key, val in zip(value.keys, value.values):
        name = const_str(key)
        if not name:
            continue
        if isinstance(val, ast.Attribute) and isinstance(val.value, ast.Name):
            entries[name] = f"{val.value.id}.{val.attr}"
        elif isinstance(val, ast.Lambda):
            entries[name] = "<lambda>"
        else:
            entries[name] = f"<{type(val).__name__}>"
    return entries


def _calls_self(node: ast.AST, attrs: set[str]) -> bool:
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        func = child.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr in attrs
            and isinstance(func.value, ast.Name)
            and func.value.id == "self"
        ):
            return True
    return False


def dex_handler_methods(repo: Path) -> tuple[set[str], set[str]]:
    """Return (all DexHandler methods, methods that need the jar)."""
    path = repo / "python" / "src" / "android_re_mcp" / "handlers" / "dex.py"
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "DexHandler":
            methods = {
                n.name for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            jar_methods = {
                n.name
                for n in node.body
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                and not n.name.startswith("_")
                and _calls_self(n, {"_require", "_run"})
            }
            return methods, jar_methods
    return set(), set()


def used_by_references(check_tools_path: Path) -> dict[str, list[str]]:
    """function name -> flattened used_by tool names for literal lists."""
    try:
        tree = ast.parse(check_tools_path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return {}
    found: dict[str, list[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func_name = None
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        if not func_name or not func_name.startswith("_check_"):
            continue
        for kw in node.keywords:
            if kw.arg != "used_by" or not isinstance(kw.value, ast.List):
                continue
            names = [s for s in (const_str(elt) for elt in kw.value.elts) if s]
            if names:
                found.setdefault(func_name, []).extend(names)
    return found


def java_jar_used_by(check_tools_path: Path) -> dict[str, list[str]]:
    """display name -> used_by tools for _check_java_jar(...) calls."""
    try:
        tree = ast.parse(check_tools_path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return {}
    found: dict[str, list[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else (
            func.id if isinstance(func, ast.Name) else None
        )
        if name != "_check_java_jar" or not node.args:
            continue
        display = const_str(node.args[0])
        if not display:
            continue
        for kw in node.keywords:
            if kw.arg != "used_by" or not isinstance(kw.value, ast.List):
                continue
            names = [s for s in (const_str(elt) for elt in kw.value.elts) if s]
            if names:
                found[display] = names
    return found


def guard_suffix_tools(guard_path: Path) -> list[str]:
    try:
        tree = ast.parse(guard_path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return []
    value = assignment_value(tree, "OUTPUT_SUFFIXES")
    if not isinstance(value, ast.Dict):
        return []
    return [s for s in (const_str(k) for k in value.keys) if s]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".", help="Repository root or any path inside it")
    parser.add_argument("--out", help="Write the JSON report here as well")
    args = parser.parse_args()

    repo = find_repo(Path(args.repo))
    if repo is None:
        print(json.dumps({"ok": False, "error": "not an android-re-mcp repo"}))
        return 2

    src = repo / "python" / "src" / "android_re_mcp"
    server_path = src / "server.py"
    check_tools_path = src / "setup" / "check_tools.py"
    guard_path = src / "guard.py"

    try:
        server_tree = ast.parse(server_path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError) as exc:
        print(json.dumps({"ok": False, "error": f"cannot parse {server_path}: {exc}"}))
        return 2

    schemas = schema_names(server_tree)
    dispatch = dispatch_entries(server_tree)
    dex_methods, dex_jar_methods = dex_handler_methods(repo)
    used_by = used_by_references(check_tools_path)
    jar_used_by = java_jar_used_by(check_tools_path)
    suffix_tools = guard_suffix_tools(guard_path)

    issues: list[dict] = []

    schema_set = set(schemas)
    dispatch_set = set(dispatch)

    for name in sorted(schema_set - dispatch_set):
        issues.append(
            {"check": "schema-without-dispatch", "tool": name, "severity": "high",
             "detail": "TOOL_SCHEMAS names a tool with no _dispatch entry"}
        )
    for name in sorted(dispatch_set - schema_set):
        issues.append(
            {"check": "dispatch-without-schema", "tool": name, "severity": "high",
             "detail": "_dispatch names a tool with no TOOL_SCHEMAS entry"}
        )

    for name in sorted({n for n in schemas if schemas.count(n) > 1}):
        issues.append(
            {"check": "duplicate-schema", "tool": name, "severity": "medium",
             "detail": f"TOOL_SCHEMAS contains '{name}' more than once"}
        )

    for tool, target in sorted(dispatch.items()):
        if target.startswith("dex."):
            method = target.split(".", 1)[1]
            if method not in dex_methods:
                issues.append(
                    {"check": "missing-dex-method", "tool": tool, "severity": "high",
                     "detail": f"_dispatch points at dex.{method}, absent from DexHandler"}
                )

    for func, tools in sorted(used_by.items()):
        for name in tools:
            if name not in schema_set:
                issues.append(
                    {"check": "unknown-used-by", "tool": name, "severity": "medium",
                     "detail": f"{func} used_by references a tool absent from TOOL_SCHEMAS"}
                )

    # Every DexHandler method that calls self._require/self._run needs the jar.
    # The check_tools entry must name all of them, and nothing that does not.
    declared = set(jar_used_by.get("dexfile-cli", []))
    for name in sorted(dex_jar_methods - declared):
        issues.append(
            {"check": "incomplete-used-by", "tool": name, "severity": "medium",
             "detail": "DexHandler method needs dexfile-cli but check_tools used_by omits it"}
        )
    for name in sorted(declared - dex_jar_methods):
        if name in dex_methods:
            issues.append(
                {"check": "overstated-used-by", "tool": name, "severity": "low",
                 "detail": "check_tools used_by names a DexHandler method that does not call the jar"}
            )

    for name in sorted(set(suffix_tools) - schema_set):
        issues.append(
            {"check": "unknown-suffix-tool", "tool": name, "severity": "medium",
             "detail": "OUTPUT_SUFFIXES names a tool absent from TOOL_SCHEMAS"}
        )

    report = {
        "ok": not issues,
        "repo": str(repo),
        "counts": {
            "schemas": len(schemas),
            "dispatch": len(dispatch),
            "dex_handler_methods": len(dex_methods),
            "dex_jar_methods": len(dex_jar_methods),
            "used_by_functions": len(used_by),
            "suffix_tools": len(suffix_tools),
            "issues": len(issues),
        },
        "issues": issues,
        "dex_dispatch": {k: v for k, v in dispatch.items() if v.startswith("dex.")},
    }

    text = json.dumps(report, indent=2)
    print(text)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    return 0 if not issues else 1


if __name__ == "__main__":
    sys.exit(main())
