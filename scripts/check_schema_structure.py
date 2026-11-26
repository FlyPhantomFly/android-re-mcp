#!/usr/bin/env python3
"""Structural + handler-passthrough check of android-re-mcp's TOOL_SCHEMAS.

This is the committed guard for the failure class found in commit 49fa0a5:
properties inserted beside ``properties`` instead of inside it, and schema
arguments a handler never reads. It needs neither the MCP SDK nor the
dexfile-cli jar — it parses ``server.py`` and the handler methods with ``ast``.

Checks
------
Structural (exit 1):
  * ``inputSchema`` has a key outside the allowed top-level set
  * a ``required`` entry is not in ``properties``
  * a schema/property node has no type, enum, $ref or combinator
  * an array declares no ``items``
  * a tool name is duplicated

Drift (review; exit 1 only with ``--strict-drift``):
  * a schema property the same-named handler never reads
  * a handler ``args.get(...)``/``args[...]`` key absent from the schema

Keys read through a shared helper are attributed to the caller: a function
whose first (or ``self``-then-first) parameter is ``args`` and that is called
with the caller's ``args`` (``_load_so(args, tool)`` in handlers/sosec.py)
counts as reading the helper's keys. The remaining drift report is therefore
real: an advertised-but-ignored property, or an undocumented handler key.

Usage:
    python scripts/check_schema_structure.py --repo .
    python scripts/check_schema_structure.py --repo . --json
    python scripts/check_schema_structure.py --repo . --strict-drift
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path
from typing import Any

ALLOWED_TOP = {
    "type",
    "properties",
    "required",
    "additionalProperties",
    "description",
    "oneOf",
    "anyOf",
    "allOf",
    "$defs",
    "$ref",
}

_COMBINATORS = ("oneOf", "anyOf", "allOf")
JSON_TYPES = {"object", "array", "string", "number", "integer", "boolean", "null"}


def find_repo(start: Path) -> Path:
    """Find the repository root from a path inside it."""
    current = start.resolve()
    for candidate in (current, *current.parents):
        if (candidate / "python" / "pyproject.toml").is_file() and (
            candidate / "python" / "src" / "android_re_mcp"
        ).is_dir():
            return candidate
    raise SystemExit(f"not an android-re-mcp checkout: {start}")


def assignment_value(tree: ast.AST, name: str) -> ast.AST | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    return node.value
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == name
        ):
            return node.value
    return None


def load_schemas_source(source: str) -> list[dict[str, Any]]:
    """Parse TOOL_SCHEMAS out of server.py source without importing the server."""
    tree = ast.parse(source)
    value = assignment_value(tree, "TOOL_SCHEMAS")
    if value is None:
        raise ValueError("TOOL_SCHEMAS not found")
    schemas = ast.literal_eval(value)
    if not isinstance(schemas, list):
        raise TypeError("TOOL_SCHEMAS is not a list")
    return schemas


def load_schemas(server: Path) -> list[dict[str, Any]]:
    return load_schemas_source(server.read_text(encoding="utf-8"))


def _handler_functions(handlers_dir: Path) -> list[ast.FunctionDef]:
    functions: list[ast.FunctionDef] = []
    for path in sorted(handlers_dir.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                functions.append(node)
    return functions


def _direct_args_keys(fn: ast.FunctionDef) -> set[str]:
    """Literal ``args`` keys this function reads itself."""
    keys: set[str] = set()
    for node in ast.walk(fn):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "args"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            keys.add(node.args[0].value)
        elif (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Name)
            and node.value.id == "args"
            and isinstance(node.slice, ast.Constant)
            and isinstance(node.slice.value, str)
        ):
            keys.add(node.slice.value)
    return keys


def _takes_args_param(fn: ast.FunctionDef) -> bool:
    """True when the function's first (or self, then first) parameter is ``args``."""
    names = [param.arg for param in fn.args.args]
    return "args" in names[:2]


def _helper_call_targets(fn: ast.FunctionDef, helpers: set[str]) -> set[str]:
    """Names of args-consuming helpers this function calls with its ``args``."""
    targets: set[str] = set()
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute):
            name = func.attr
        else:
            continue
        if name not in helpers:
            continue
        passes_args = (
            node.args
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == "args"
        ) or any(
            keyword.arg == "args"
            and isinstance(keyword.value, ast.Name)
            and keyword.value.id == "args"
            for keyword in node.keywords
        )
        if passes_args:
            targets.add(name)
    return targets


def handler_keys(handlers_dir: Path) -> dict[str, set[str]]:
    """Map a handler method name to the literal ``args`` keys it reads.

    Keys read through a shared helper count as read: when a function whose
    first (or ``self``-then-first) parameter is ``args`` is called with the
    caller's ``args`` (``_load_so(args, tool)``), the helper's keys are
    unioned into the caller's. This is iterated to a fixed point so chains
    of helpers resolve too. Name collisions across classes merge, which is
    the same approximation the previous version used.
    """
    functions = _handler_functions(handlers_dir)
    keys: dict[str, set[str]] = {}
    helpers = {fn.name for fn in functions if _takes_args_param(fn)}
    calls: dict[str, set[str]] = {}
    for fn in functions:
        keys.setdefault(fn.name, set()).update(_direct_args_keys(fn))
        calls.setdefault(fn.name, set()).update(_helper_call_targets(fn, helpers))

    for _ in range(10):  # fixed point; handler graphs are tiny
        changed = False
        for name, targets in calls.items():
            gained: set[str] = set()
            for target in targets:
                gained |= keys.get(target, set())
            if not gained <= keys[name]:
                keys[name] |= gained
                changed = True
        if not changed:
            break
    return keys


def handler_flag_literals(handlers_dir: Path) -> dict[str, set[str]]:
    """Map a handler method name to the ``--flag`` literals it builds."""
    out: dict[str, set[str]] = {}
    for path in sorted(handlers_dir.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for cls in (n for n in tree.body if isinstance(n, ast.ClassDef)):
            for fn in (n for n in cls.body if isinstance(n, ast.FunctionDef)):
                flags = out.setdefault(fn.name, set())
                for node in ast.walk(fn):
                    if (
                        isinstance(node, ast.Constant)
                        and isinstance(node.value, str)
                        and node.value.startswith("--")
                        and len(node.value) > 2
                    ):
                        flags.add(node.value)
    return out


def _walk_schema(
    node: Any,
    path: str,
    tool: str,
    structural: list[dict[str, str]],
) -> None:
    """Validate a schema node and recurse into properties/items/combinators."""
    if not isinstance(node, dict):
        structural.append({"tool": tool, "message": f"{path}: schema node is not an object"})
        return

    has_shape = any(k in node for k in ("type", "enum", "$ref", *_COMBINATORS))
    if path and not has_shape and "properties" not in node:
        structural.append(
            {"tool": tool, "message": f"{path}: no type, enum, $ref or combinator"}
        )

    # K8: a declared type must be a real JSON-schema type (string or list form).
    declared = node.get("type")
    if declared is not None:
        types = declared if isinstance(declared, list) else [declared]
        for value in types:
            if not isinstance(value, str) or value not in JSON_TYPES:
                structural.append(
                    {"tool": tool, "message": f"{path}: invalid schema type: {value!r}"}
                )

    # K3: `properties` only makes sense on an object node. A node without an
    # explicit type but with `properties` is an implicit object (allowed).
    if "properties" in node and declared not in (None, "object"):
        structural.append(
            {"tool": tool,
             "message": f"{path}: properties on non-object type: {declared!r}"}
        )

    if node.get("type") == "array" and "items" not in node:
        structural.append({"tool": tool, "message": f"{path}: array without items"})

    if isinstance(node.get("required"), list):
        props = node.get("properties", {})
        if not isinstance(props, dict):
            structural.append({"tool": tool, "message": f"{path}: properties is not an object"})
        else:
            for req in node["required"]:
                if req not in props:
                    structural.append(
                        {"tool": tool, "message": f"{path}: required not in properties: {req}"}
                    )

    props = node.get("properties")
    if isinstance(props, dict):
        for key, value in props.items():
            _walk_schema(value, f"{path}.{key}" if path else key, tool, structural)

    if "items" in node:
        _walk_schema(node["items"], f"{path}[]", tool, structural)

    for combinator in _COMBINATORS:
        branches = node.get(combinator)
        if isinstance(branches, list):
            for index, branch in enumerate(branches):
                _walk_schema(branch, f"{path}.{combinator}[{index}]", tool, structural)


def audit(repo: Path) -> dict[str, Any]:
    """Return the full structural and drift report for a checkout."""
    src = repo / "python" / "src" / "android_re_mcp"
    schemas = load_schemas(src / "server.py")
    handlers = handler_keys(src / "handlers")
    flags = handler_flag_literals(src / "handlers")

    structural: list[dict[str, str]] = []
    drift: list[dict[str, Any]] = []
    seen: set[str] = set()

    for schema in schemas:
        name = schema.get("name", "<unnamed>")
        if name in seen:
            structural.append({"tool": name, "message": "duplicate tool name"})
        seen.add(name)

        input_schema = schema.get("inputSchema")
        if not isinstance(input_schema, dict):
            structural.append({"tool": name, "message": "inputSchema is not an object"})
            continue

        for key in sorted(set(input_schema) - ALLOWED_TOP):
            structural.append({"tool": name, "message": f"stray inputSchema key: {key}"})

        _walk_schema(input_schema, "", name, structural)

        props = input_schema.get("properties", {})
        if not isinstance(props, dict):
            continue
        read = handlers.get(name)
        if read is not None:
            unread = sorted(set(props) - read)
            undoc = sorted(read - set(props))
            if unread or undoc:
                drift.append(
                    {
                        "tool": name,
                        "schema_not_read": unread,
                        "read_not_in_schema": undoc,
                    }
                )

    return {
        "schemas": len(schemas),
        "structural": structural,
        "drift": drift,
        "handler_flags": {k: sorted(v) for k, v in sorted(flags.items()) if v},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".", help="repository root (default: .)")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument(
        "--strict-drift",
        action="store_true",
        help="exit 1 when handler/schema drift is reported (review items included)",
    )
    args = parser.parse_args(argv)
    repo = find_repo(Path(args.repo))
    report = audit(repo)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(
            f"schemas: {report['schemas']}  "
            f"structural: {len(report['structural'])}  drift: {len(report['drift'])}"
        )
        for item in report["structural"]:
            print(f"FAIL {item['tool']}: {item['message']}")
        for item in report["drift"]:
            print(
                f"REVIEW {item['tool']}: "
                f"schema-not-read={item['schema_not_read']} "
                f"read-not-in-schema={item['read_not_in_schema']}"
            )

    if report["structural"]:
        return 1
    if args.strict_drift and report["drift"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
