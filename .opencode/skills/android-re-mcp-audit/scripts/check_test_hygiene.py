#!/usr/bin/env python3
"""Find test-hygiene hazards that hide unrelated coverage.

Checks:
  * module-level pytest.importorskip(...) — suppresses every test in the file
  * module-level pytestmark = pytest.mark.skipif(...) — same effect

Reports how many test functions each module-level skip suppresses. Read-only;
exit code 1 when hazards are found.

Usage:
    python check_test_hygiene.py --repo /path/to/android-re-mcp
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


def call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute):
            return func.attr
        if isinstance(func, ast.Name):
            return func.id
    return None


def module_level_importorskip(tree: ast.Module) -> list[dict]:
    hits: list[dict] = []
    for node in tree.body:
        value = None
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.Expr)):
            value = node.value
        if value is None:
            continue
        if call_name(value) != "importorskip":
            continue
        module = ""
        if isinstance(value, ast.Call) and value.args:
            arg = value.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                module = arg.value
        hits.append({"line": node.lineno, "module": module})
    return hits


def module_level_skipif(tree: ast.Module) -> list[dict]:
    hits: list[dict] = []
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if "pytestmark" not in targets:
            continue
        if call_name(node.value) in ("skipif", "skip"):
            hits.append({"line": node.lineno})
        elif isinstance(node.value, (ast.List, ast.Tuple)):
            for elt in node.value.elts:
                if call_name(elt) in ("skipif", "skip"):
                    hits.append({"line": node.lineno})
                    break
    return hits


def test_count(tree: ast.Module) -> int:
    return sum(
        1
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    )


# Missing core modules make the whole suite unrunnable, so a file-level skip
# for them is not a coverage hazard worth reporting.
_CORE_MODULES = {"mcp", "pytest"}


def classify(path: Path, module: str, count: int) -> tuple[str, str]:
    """Return (bucket, severity) for a module-level skip."""
    if module.lower() in _CORE_MODULES:
        return "ignored", "info"
    if module and module.lower() in path.stem.lower():
        # A file dedicated to one dependency (e.g. test_androguard_tools.py)
        # may legitimately skip as a unit; keep it visible but not actionable.
        return "review", "info"
    return "issue", ("medium" if count >= 10 else "low")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".", help="Repository root or any path inside it")
    parser.add_argument("--out", help="Write the JSON report here as well")
    args = parser.parse_args()

    repo = find_repo(Path(args.repo))
    if repo is None:
        print(json.dumps({"ok": False, "error": "not an android-re-mcp repo"}))
        return 2

    tests_dir = repo / "python" / "tests"
    files = sorted(tests_dir.glob("test_*.py"))
    issues: list[dict] = []
    review: list[dict] = []
    scanned = 0

    def record(check: str, rel: str, line: int, module: str, count: int, detail: str) -> None:
        bucket, severity = classify(Path(rel), module, count)
        if bucket == "ignored":
            return
        entry = {
            "check": check,
            "file": rel,
            "line": line,
            "module": module,
            "test_functions_suppressed": count,
            "severity": severity,
            "detail": detail,
        }
        (review if bucket == "review" else issues).append(entry)

    for path in files:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            continue
        scanned += 1
        count = test_count(tree)
        rel = str(path.relative_to(repo))
        for hit in module_level_importorskip(tree):
            record(
                "module-level-importorskip", rel, hit["line"], hit["module"], count,
                "when that dependency is absent, module-level importorskip skips "
                "every test in this file, including tests that do not need it",
            )
        for hit in module_level_skipif(tree):
            record(
                "module-level-skipif", rel, hit["line"], "", count,
                "when its condition holds, module-level pytestmark skips every test in this file",
            )

    report = {
        "ok": not issues,
        "repo": str(repo),
        "counts": {"files_scanned": scanned, "issues": len(issues), "review": len(review)},
        "issues": issues,
        "review": review,
    }
    text = json.dumps(report, indent=2)
    print(text)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    return 0 if not issues else 1


if __name__ == "__main__":
    sys.exit(main())
