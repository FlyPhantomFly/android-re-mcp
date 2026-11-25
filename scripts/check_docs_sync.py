#!/usr/bin/env python3
"""Read-only README/CHANGELOG versus TOOL_SCHEMAS sync check.

Hard failures (exit 1):
  * a tool has no README table row
  * a table row has a different cell count than its header
  * a schema property is not mentioned in the tool's README row
    (release-window properties plus the era/ambiguity controls by default;
    every property with ``--all-properties``)
  * the [Unreleased] changelog block does not name a property added since
    the last tag

Review items (exit 0 unless --strict-review):
  * an "optional" clause runs into the preceding text ("counts optional")
  * a row claims "verbatim" without mentioning era/ambiguity
  * a schema description names a --flag the handler never builds

Run from the repository root:
    python scripts/check_docs_sync.py --repo .
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

# Paths, content, positional values, and non-flag switches are covered by
# their tests rather than by name in the prose row.
EXEMPT = {
    "dex_path",
    "in_path",
    "apk_path",
    "so_path",
    "output_path",
    "output_dir",
    "output_apk",
    "dex_paths",
    "ops",
    "smali_text",
    "path",
    "entry_name",
    "target_version",
    "allow_unloadable",
    "classes",
    "limit",
    "max_issues",
    "method",
    "cache_dir",
    "offset_lines",
    "max_lines",
    # remaining path-shaped arguments (host, device-side or content) that
    # the round-trip tests cover instead of the prose row
    "zip_path",
    "remote",
    "local",
    "remote_path",
    "capture_path",
    "smali_dir",
    "bundle_path",
    "keystore_path",
    "rules_dir",
    "gadget_path",
}

FLAG_RE = re.compile(r"--[a-zA-Z0-9][a-zA-Z0-9-]*")
# flags printed by install/setup prose, not built by handlers
IGNORED_FLAGS = {"--setup"}
# Always check the controls this skill was created for, even if they predate
# the current release window.
ALWAYS_CHECK = {"api", "era", "allow_ambiguous", "scan", "allow_cdex", "allow_unloadable"}
JOINED_OPTIONAL_RE = re.compile(r"[a-z0-9)`]\s+optional\b", re.IGNORECASE)
SEPARATOR_RE = re.compile(r":?-{3,}:?")


def find_repo(start: Path) -> Path:
    current = start.resolve()
    for candidate in (current, *current.parents):
        if (candidate / "python" / "pyproject.toml").is_file() and (
            candidate / "python" / "src" / "android_re_mcp"
        ).is_dir():
            return candidate
    raise SystemExit(f"not an android-re-mcp checkout: {start}")


def _schema_helpers(repo: Path):
    sys.path.insert(0, str(repo / "scripts"))
    from check_schema_structure import (
        handler_flag_literals,
        load_schemas,
        load_schemas_source,
    )

    return load_schemas, load_schemas_source, handler_flag_literals


def split_cells(line: str) -> list[str] | None:
    line = line.strip()
    if not line.startswith("|") or not line.endswith("|"):
        return None
    parts = re.split(r"(?<!\\)\|", line)
    if len(parts) < 3:
        return None
    return [part.strip() for part in parts[1:-1]]


def readme_rows(readme: Path) -> tuple[dict[str, tuple[int, str, list[str]]], list[dict]]:
    """Return tool -> (line, row text, cells), plus malformed-row findings."""
    rows: dict[str, tuple[int, str, list[str]]] = {}
    malformed: list[dict] = []
    header: list[str] | None = None
    lines = readme.read_text(encoding="utf-8").splitlines()

    for index, line in enumerate(lines):
        cells = split_cells(line)
        if cells is None:
            header = None
            continue
        if all(SEPARATOR_RE.fullmatch(cell) for cell in cells):
            continue
        if header is None:
            header = cells
            continue
        if len(cells) != len(header):
            malformed.append(
                {
                    "line": index + 1,
                    "message": f"row has {len(cells)} cells, header has {len(header)}",
                    "row": line.strip(),
                }
            )
        names = re.findall(r"`([a-z][a-z0-9_]*)`", cells[0])
        for name in names:
            rows[name] = (index + 1, line.strip(), cells)
    return rows, malformed


def changelog_block(changelog: Path) -> str | None:
    text = changelog.read_text(encoding="utf-8")
    match = re.search(
        r"^## \[Unreleased\][^\n]*\n(.*?)(?=^## \[|\Z)",
        text,
        re.MULTILINE | re.DOTALL,
    )
    return match.group(1) if match else None


def added_properties(repo: Path, current: list[dict], load_schemas_source) -> tuple[dict[str, list[str]], str | None]:
    try:
        tag = subprocess.run(
            ["git", "-C", str(repo), "describe", "--tags", "--abbrev=0"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        source = subprocess.run(
            ["git", "-C", str(repo), "show", f"{tag}:python/src/android_re_mcp/server.py"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        return {}, f"cannot compare with the last tag: {exc}"

    old = {schema["name"]: schema for schema in load_schemas_source(source)}
    added: dict[str, list[str]] = {}
    for schema in current:
        name = schema["name"]
        old_props = set(old.get(name, {}).get("inputSchema", {}).get("properties", {}))
        new_props = set(schema["inputSchema"].get("properties", {}))
        delta = sorted(new_props - old_props)
        if delta:
            added[name] = delta
    return added, tag


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict-review", action="store_true",
                        help="exit 1 for review items too")
    parser.add_argument("--all-properties", action="store_true",
                        help="check every schema property, not just the release window")
    args = parser.parse_args(argv)
    repo = find_repo(Path(args.repo))
    load_schemas, load_schemas_source, handler_flags = _schema_helpers(repo)

    schemas = load_schemas(repo / "python/src/android_re_mcp/server.py")
    rows, malformed = readme_rows(repo / "README.md")
    flags = handler_flags(repo / "python/src/android_re_mcp/handlers")
    failures: list[dict] = [{"line": item["line"], "message": item["message"],
                             "row": item["row"]} for item in malformed]
    reviews: list[dict] = []

    added, tag_or_error = added_properties(repo, schemas, load_schemas_source)

    for schema in schemas:
        name = schema["name"]
        row = rows.get(name)
        if row is None:
            failures.append({"tool": name, "message": "no README table row"})
            continue
        lineno, row_text, _cells = row
        props = schema["inputSchema"].get("properties", {})
        if args.all_properties:
            wanted = set(props)
        else:
            wanted = set(added.get(name, ())) | (ALWAYS_CHECK & set(props))
        for prop in wanted:
            if prop in EXEMPT:
                continue
            if not re.search(rf"(?<![a-z0-9_]){re.escape(prop)}(?![a-z0-9_])", row_text):
                failures.append(
                    {
                        "tool": name,
                        "line": lineno,
                        "message": f"README row does not mention `{prop}`",
                    }
                )
        match = JOINED_OPTIONAL_RE.search(row_text)
        if match:
            # "is optional", "are optional" are legitimate; a clause-bearing
            # word or a closing paren before it is the defect we want.
            before = row_text[:match.start()].rstrip()
            last_word = re.search(r"([a-z]+)$", before)
            if not (last_word and last_word.group(1) in {"is", "are", "be", "remains"}):
                reviews.append(
                    {
                        "tool": name,
                        "line": lineno,
                        "message": "'optional' is not separated from the preceding clause",
                    }
                )
        if "verbatim" in row_text.lower() and not (
            "ambiguous" in row_text.lower() or "era" in row_text.lower()
        ):
            reviews.append(
                {
                    "tool": name,
                    "line": lineno,
                    "message": "verbatim claim does not mention era/ambiguity",
                }
            )
        for flag in FLAG_RE.findall(schema.get("description", "")):
            if flag in IGNORED_FLAGS:
                continue
            if flag not in flags.get(name, set()):
                reviews.append(
                    {
                        "tool": name,
                        "line": lineno,
                        "message": f"description names {flag}, handler does not build it",
                    }
                )

    block = changelog_block(repo / "CHANGELOG.md")
    if added:
        if block is None:
            failures.append({"message": "no [Unreleased] changelog block for schema changes"})
        else:
            for tool, props in sorted(added.items()):
                for prop in props:
                    if not re.search(rf"(?<![a-z0-9_]){re.escape(prop)}(?![a-z0-9_])", block):
                        failures.append(
                            {
                                "tool": tool,
                                "message": f"[Unreleased] changelog does not name `{prop}`",
                            }
                        )

    report = {
        "schemas": len(schemas),
        "failures": failures,
        "reviews": reviews,
        "schema_additions_since": tag_or_error if isinstance(tag_or_error, str) else None,
    }
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(
            f"schemas: {len(schemas)}  failures: {len(failures)}  "
            f"review: {len(reviews)}  compared-to: {tag_or_error}"
        )
        for item in failures:
            where = item.get("tool") or f"README:{item.get('line', '?')}"
            if item.get("line") and item.get("tool"):
                where = f"{item['tool']} (README:{item['line']})"
            print(f"FAIL {where}: {item['message']}")
        for item in reviews:
            print(f"REVIEW {item['tool']}: README:{item['line']} {item['message']}")
    if failures:
        return 1
    if args.strict_review and reviews:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
