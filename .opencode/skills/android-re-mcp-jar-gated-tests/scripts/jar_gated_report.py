#!/usr/bin/env python3
"""Inventory jar-gated tests and report skips with and without the jar.

The rule this supports: a behavior that is skipped without dexfile-cli.jar
needs a jar-free sibling that asserts the handler's argv (see
``python/tests/test_dex_passthrough.py``). A green suite without naming the
skip count is not evidence that the gated behavior ran.

Usage:
    python .opencode/skills/android-re-mcp-jar-gated-tests/scripts/jar_gated_report.py --repo .
    python .opencode/skills/android-re-mcp-jar-gated-tests/scripts/jar_gated_report.py --repo . --run
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

SKIP_RE = re.compile(r"(\d+) passed(?:, (\d+) skipped)?")
SKIPPED_LINE_RE = re.compile(r"^SKIPPED\s+\[(\d+)\]\s+(.+?):(\d+):\s*(.*)$")


def find_repo(start: Path) -> Path:
    current = start.resolve()
    for candidate in (current, *current.parents):
        if (candidate / "python" / "pyproject.toml").is_file() and (
            candidate / "python" / "src" / "android_re_mcp"
        ).is_dir():
            return candidate
    raise SystemExit(f"not an android-re-mcp checkout: {start}")


def _decorator_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _decorator_name(node.func)
    return ""


def _skip_aliases(tree: ast.AST) -> dict[str, str]:
    """Resolve module-level marker aliases such as ROUNDTRIP/DEX_OUTLINE."""
    aliases: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        value = node.value
        if value is None:
            continue
        names = [_decorator_name(n) for n in ast.walk(value)]
        if not any(name in {"skipif", "skip"} for name in names):
            continue
        source = ast.unparse(value)
        for target in targets:
            if isinstance(target, ast.Name):
                aliases[target.id] = source
    return aliases


def inventory(repo: Path) -> dict:
    gated = []
    module_skips = []
    for path in sorted((repo / "python" / "tests").glob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        aliases = _skip_aliases(tree)
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "pytestmark" for t in node.targets
            ):
                names = [_decorator_name(n) for n in ast.walk(node.value)]
                if "skipif" in names or "skip" in names:
                    module_skips.append(str(path.relative_to(repo)))
        for fn in (n for n in tree.body if isinstance(n, ast.FunctionDef)):
            marks = []
            sources = []
            for decorator in fn.decorator_list:
                name = _decorator_name(decorator)
                if name in {"skipif", "skip"}:
                    marks.append(name)
                    sources.append(ast.unparse(decorator))
                elif name in aliases:
                    marks.append(name)
                    sources.append(aliases[name])
            if marks:
                gated.append(
                    {
                        "file": str(path.relative_to(repo)),
                        "line": fn.lineno,
                        "test": fn.name,
                        "markers": marks,
                        "sources": sources,
                    }
                )
    def is_jar(item: dict) -> bool:
        text = " ".join(item.get("sources", []))
        return any(
            token in text or token in item["test"]
            for token in ("dexfile-cli.jar", "ROUNDTRIP", "DEX_OUTLINE")
        )
    return {
        "gated": gated,
        "gated_count": len(gated),
        "jar_gated_count": sum(is_jar(item) for item in gated),
        "roundtrip_count": sum("ROUNDTRIP" in item["markers"] for item in gated),
        "module_skips": module_skips,
        "passthrough_file": (
            "python/tests/test_dex_passthrough.py"
            if (repo / "python" / "tests" / "test_dex_passthrough.py").is_file()
            else None
        ),
    }


def weak_assertion_candidates(repo: Path) -> list[dict]:
    out = []
    for path in sorted((repo / "python" / "tests").glob("test_*.py")):
        lines = path.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            if "assert" not in line or "status" not in line or "==" not in line:
                continue
            if '"error"' not in line and "'error'" not in line:
                continue
            window = "\n".join(lines[max(0, index - 5):index + 2]).lower()
            if "proceed" in window or "allow_ambiguous" in window:
                following = "\n".join(lines[index + 1:index + 5]).lower()
                # A nearby kind/message assertion makes the status check
                # specific rather than a pass-either-way assertion.
                if any(token in following for token in ("kind", " in ", "not in")):
                    continue
                out.append({"file": str(path.relative_to(repo)), "line": index + 1,
                            "text": line.strip()})
    return out


def pytest_env(repo: Path, home: Path | None = None) -> dict:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo / "python" / "src")
    if home is not None:
        env["HOME"] = str(home)
        env["ANDROID_RE_MCP_TOOLS_DIR"] = str(home / "tools")
        (home / "tools").mkdir(parents=True, exist_ok=True)
        env.pop("ANDROID_RE_MCP_ALLOWED_DIRS", None)
    return env


def run_pytest(repo: Path, home: Path | None = None) -> dict:
    cmd = [sys.executable, "-m", "pytest", "-q", "-rs"]
    try:
        proc = subprocess.run(
            cmd, check=False, cwd=repo / "python", env=pytest_env(repo, home),
            capture_output=True, text=True, timeout=900,
        )
    except subprocess.TimeoutExpired:
        return {"error": "pytest timed out after 900s"}
    text = proc.stdout
    match = SKIP_RE.search(text)
    skips = [line.strip() for line in text.splitlines() if line.startswith("SKIPPED [")]
    return {
        "returncode": proc.returncode,
        "passed": int(match.group(1)) if match else None,
        "skipped": int(match.group(2) or 0) if match else None,
        "skip_lines": skips,
        "summary": "\n".join(text.splitlines()[-5:]),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".")
    parser.add_argument("--run", action="store_true",
                        help="also run pytest with the jar and with an empty HOME")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    repo = find_repo(Path(args.repo))
    report = inventory(repo)
    report["weak_assertion_candidates"] = weak_assertion_candidates(repo)
    if args.run:
        report["with_jar"] = run_pytest(repo)
        with tempfile.TemporaryDirectory(prefix="android-re-nojar-") as temp:
            report["without_jar"] = run_pytest(repo, Path(temp))

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"gated tests: {report['gated_count']}  "
              f"jar-gated: {report['jar_gated_count']}  "
              f"ROUNDTRIP: {report['roundtrip_count']}  "
              f"module-level skips: {len(report['module_skips'])}")
        for item in report["gated"]:
            print(f"  {item['file']}:{item['line']} {item['test']} {item['markers']}")
        if report["module_skips"]:
            print("module-level skip files:", ", ".join(report["module_skips"]))
        if report["weak_assertion_candidates"]:
            print("weak-assertion candidates:")
            for item in report["weak_assertion_candidates"]:
                print(f"  {item['file']}:{item['line']} {item['text']}")
        if args.run:
            for label in ("with_jar", "without_jar"):
                result = report[label]
                print(f"{label}: passed={result.get('passed')} "
                      f"skipped={result.get('skipped')} rc={result.get('returncode')}")
                for skip in result.get("skip_lines", []):
                    print(f"  {label} {skip}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
