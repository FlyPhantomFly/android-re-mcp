"""Guard discovery for path-shaped properties nested in object arguments.

Top-level path arguments are covered by guard.PATH_KEYS / PATH_LIST_KEYS.
This test walks every schema (objects and arrays-of-objects) and fails when a
nested property looks like a host path but is absent from
guard.NESTED_PATH_KEYS, so a new nested read cannot ship unguarded.
"""
from __future__ import annotations

import re

from android_re_mcp import guard
from android_re_mcp.server import TOOL_SCHEMAS

PATH_NAME = re.compile(r"(_path|_dir|_file)$|^(file|from_file|to_file|src|dest|output)$", re.I)
PATH_DESC = re.compile(r"\b(path|file|directory|folder)\b", re.I)

# Nested values that are intentionally not host paths (none today). Add a
# tool/key here only with a comment explaining why it is safe.
NON_HOST_NESTED: set[tuple[str, str]] = set()


def _is_pathish(name: str, spec: object) -> bool:
    description = spec.get("description", "") if isinstance(spec, dict) else ""
    return bool(PATH_NAME.search(name) or PATH_DESC.search(description))


def _walk(node: object, tool: str, trail: tuple[str, ...], depth: int):
    if not isinstance(node, dict):
        return
    props = node.get("properties")
    if isinstance(props, dict):
        for name, spec in props.items():
            here = (*trail, name)
            top_level = depth == 0
            known_top = name in guard.PATH_KEYS or name in guard.PATH_LIST_KEYS
            if not top_level and _is_pathish(name, spec) and (tool, name) not in NON_HOST_NESTED:
                yield tool, name, here
            yield from _walk(spec, tool, here, depth + 1)
    items = node.get("items")
    if isinstance(items, dict):
        yield from _walk(items, tool, trail, depth)


def _nested_candidates():
    for schema in TOOL_SCHEMAS:
        yield from _walk(schema["inputSchema"], schema["name"], (), 0)


def test_every_nested_path_property_is_guarded():
    missing = []
    for tool, name, trail in _nested_candidates():
        parent = trail[-2] if len(trail) >= 2 else ""
        allowed = guard.NESTED_PATH_KEYS.get(tool, {}).get(parent, ())
        if name not in allowed:
            missing.append({"tool": tool, "path": ".".join(trail), "parent": parent})
    assert not missing, f"nested path properties without a guard: {missing}"


def test_nested_guard_entries_exist_in_the_schema():
    candidates = {(tool, name, trail[-2] if len(trail) >= 2 else "")
                  for tool, name, trail in _nested_candidates()}
    stale = []
    for tool, parents in guard.NESTED_PATH_KEYS.items():
        for parent, names in parents.items():
            for name in names:
                if (tool, name, parent) not in candidates:
                    stale.append(f"{tool}.{parent}[].{name}")
    assert not stale, f"NESTED_PATH_KEYS entries not present in the schema: {stale}"
