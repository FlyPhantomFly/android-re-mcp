#!/usr/bin/env python3
"""Read-only release consistency check for android-re-mcp.

Checks:
  * pyproject version vs top CHANGELOG version
  * README tool counts vs live TOOL_SCHEMAS count
  * README dexfile-cli version vs the pin URL
  * installer success message version vs the pin URL
  * installed jar SHA-256 vs the pin SHA-256
  * CHANGELOG "suite now N passed + M skipped" vs pytest collection here

Outputs JSON. Exit 1 when there are actionable issues; review items do not
fail the run.

Usage:
    python release_check.py --repo /path/to/android-re-mcp
    python release_check.py --repo . --out /tmp/release.json
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import subprocess
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


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def sha256_file(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


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


def schema_count(server_path: Path) -> int | None:
    try:
        tree = ast.parse(read(server_path))
    except SyntaxError:
        return None
    value = assignment_value(tree, "TOOL_SCHEMAS")
    if not isinstance(value, ast.List):
        return None
    return len(value.elts)


def pin_info(install_path: Path) -> dict:
    text = read(install_path)
    match = re.search(
        r'"dexfile-cli\.jar"\s*:\s*\(\s*"(?P<url>[^"]+)"\s*,\s*"(?P<sha>[0-9a-fA-F]{64})"',
        text,
    )
    if not match:
        return {"found": False}
    url = match.group("url")
    message = re.search(r'"dexfile-cli ([\d.]+) installed', text)
    return {
        "found": True,
        "url": url,
        "sha256": match.group("sha").lower(),
        "version": (re.search(r"/v([^/]+)/", url) or [None, None])[1],
        "installer_message_version": message.group(1) if message else None,
    }


def collect_tests(repo: Path) -> dict:
    """Return collected test counts and a static count of hidden test functions."""
    python_dir = repo / "python"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(python_dir / "src") + (
        os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else ""
    )
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "--collect-only", "-q"],
            check=False, cwd=python_dir, env=env, capture_output=True, text=True, timeout=180,
        )
        output = (proc.stdout or "") + (proc.stderr or "")
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"error": str(exc)}

    collected_match = re.findall(r"collected (\d+) items", output)
    if not collected_match:
        collected_match = re.findall(r"(\d+) tests? collected", output)
    skipped_match = re.findall(r"collected \d+ items / (\d+) skipped", output)
    collected = int(collected_match[-1]) if collected_match else None
    skipped_at_collection = int(skipped_match[-1]) if skipped_match else 0

    defined = 0
    hidden = 0
    for path in sorted((python_dir / "tests").glob("test_*.py")):
        try:
            tree = ast.parse(read(path))
        except SyntaxError:
            continue
        tests = [
            n for n in tree.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name.startswith("test_")
        ]
        defined += len(tests)
        for node in tree.body:
            value = None
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.Expr)):
                value = getattr(node, "value", None)
            call = value.func if isinstance(value, ast.Call) else None
            name = None
            if isinstance(call, ast.Attribute):
                name = call.attr
            elif isinstance(call, ast.Name):
                name = call.id
            if name != "importorskip" or not isinstance(value, ast.Call) or not value.args:
                continue
            arg = value.args[0]
            module = arg.value if isinstance(arg, ast.Constant) else ""
            if module not in ("mcp", "pytest"):
                hidden += len(tests)
                break
    return {
        "collected": collected,
        "skipped_at_collection": skipped_at_collection,
        "total_collected": (collected or 0) + skipped_at_collection if collected is not None else None,
        "test_functions_defined": defined,
        "test_functions_hidden_by_module_skip": hidden,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".", help="Repository root or any path inside it")
    parser.add_argument("--out", help="Write the JSON report here as well")
    args = parser.parse_args()

    repo = find_repo(Path(args.repo))
    if repo is None:
        print(json.dumps({"ok": False, "error": "not an android-re-mcp repo"}))
        return 2

    pyproject = repo / "python" / "pyproject.toml"
    changelog = repo / "CHANGELOG.md"
    readme = repo / "README.md"
    server_path = repo / "python" / "src" / "android_re_mcp" / "server.py"
    install_path = repo / "python" / "src" / "android_re_mcp" / "setup" / "install_tool.py"

    py_version_match = re.search(r'^version\s*=\s*"([^"]+)"', read(pyproject), re.MULTILINE)
    ch_version_match = re.search(r"^## \[([^\]]+)\]", read(changelog), re.MULTILINE)
    py_version = py_version_match.group(1) if py_version_match else None
    ch_version = ch_version_match.group(1) if ch_version_match else None

    readme_text = read(readme)
    readme_tool_counts = [int(n) for n in re.findall(r"\b(\d+)\s+tools\b", readme_text)]
    readme_versions = re.findall(r"dexfile-cli[^\n]{0,80}?(\d+\.\d+\.\d+)", readme_text)

    live_schemas = schema_count(server_path)
    pin = pin_info(install_path)
    tools_dir_env = os.environ.get("ANDROID_RE_MCP_TOOLS_DIR")
    tools_dir = Path(tools_dir_env).expanduser() if tools_dir_env else Path.home() / "tools"
    jar = tools_dir / "dexfile-cli.jar"
    actual_sha = sha256_file(jar) if pin.get("found") else None

    suite_match = re.search(r"(?i)suite (?:now )?(\d+) passed \+ (\d+) skipped", read(changelog))
    suite_claim = None
    if suite_match:
        suite_claim = {
            "passed": int(suite_match.group(1)),
            "skipped": int(suite_match.group(2)),
            "total": int(suite_match.group(1)) + int(suite_match.group(2)),
        }
    collection = collect_tests(repo)

    issues: list[dict] = []
    review: list[dict] = []

    def issue(check: str, severity: str, detail: str) -> None:
        issues.append({"check": check, "severity": severity, "detail": detail})

    if py_version != ch_version:
        issue("version-mismatch", "high",
              f"pyproject version={py_version!r} but top CHANGELOG entry={ch_version!r}")

    if live_schemas is None:
        issue("schema-unreadable", "medium", "cannot parse TOOL_SCHEMAS from server.py")
    elif live_schemas not in readme_tool_counts:
        issue("tool-count-mismatch", "medium",
              f"TOOL_SCHEMAS has {live_schemas} tools; README mentions {readme_tool_counts}")

    if not pin.get("found"):
        issue("pin-unreadable", "medium", "cannot parse the dexfile-cli pin from install_tool.py")
    else:
        if pin["version"] and pin["version"] not in readme_versions:
            issue("readme-pin-mismatch", "medium",
                  f"README dexfile-cli versions={readme_versions}, pin={pin['version']}")
        if pin["installer_message_version"] != pin["version"]:
            issue("installer-message-mismatch", "low",
                  f"installer message says {pin['installer_message_version']!r}, pin is {pin['version']!r}")
        if actual_sha is None:
            issue("jar-missing", "high", f"jar not found at {jar}")
        elif actual_sha != pin["sha256"]:
            issue("jar-sha-mismatch", "high",
                  f"installed jar sha256={actual_sha}, pin sha256={pin['sha256']}")

    if suite_claim and collection.get("total_collected") is not None:
        total = collection["total_collected"]
        hidden = collection["test_functions_hidden_by_module_skip"]
        if abs(suite_claim["total"] - total) > 20:
            review.append({
                "check": "suite-count-review",
                "detail": f"CHANGELOG claims {suite_claim['total']} tests; this environment collects "
                          f"{total}, with {hidden} more test functions suppressed by module-level skips. "
                          "Missing extras can explain the gap; verify in a full environment before changing the claim.",
            })

    report = {
        "ok": not issues,
        "repo": str(repo),
        "checks": {
            "pyproject_version": py_version,
            "changelog_top_version": ch_version,
            "readme_tool_counts": readme_tool_counts,
            "live_schema_count": live_schemas,
            "readme_dexfile_versions": readme_versions,
            "pin": pin,
            "jar": str(jar),
            "jar_sha256": actual_sha,
            "suite_claim": suite_claim,
            "collection": collection,
        },
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
