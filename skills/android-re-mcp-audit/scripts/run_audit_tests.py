#!/usr/bin/env python3
"""Run the audit test groups with the repo's src layout handled correctly.

Groups:
  dex         tests/test_dex_tools.py
  check_tools tests/test_check_tools_honesty.py
  guard       tests/test_guard.py
  full        entire suite (only with --full)

Usage:
    python run_audit_tests.py --repo . 
    python run_audit_tests.py --repo . --groups dex,guard
    python run_audit_tests.py --repo . --full --out /tmp/tests.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path


def find_repo(start: Path) -> Path | None:
    current = start.resolve()
    for candidate in (current, *current.parents):
        if (candidate / "python" / "pyproject.toml").is_file() and (
            candidate / "python" / "src" / "android_re_mcp"
        ).is_dir():
            return candidate
    return None


def parse_pytest_output(text: str) -> dict:
    counts = {"passed": 0, "failed": 0, "skipped": 0, "errors": 0}
    for key in ("passed", "failed", "skipped"):
        hits = re.findall(rf"(\d+) {key}\b", text)
        if hits:
            counts[key] = int(hits[-1])
    hits = re.findall(r"(\d+) errors?\b", text)
    if hits:
        counts["errors"] = int(hits[-1])

    failed = []
    errors = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("FAILED "):
            failed.append(line[len("FAILED "):].split(" - ", 1)[0].strip())
        elif line.startswith("ERROR "):
            errors.append(line[len("ERROR "):].split(" - ", 1)[0].strip())
    return {"counts": counts, "failed": failed, "errors": errors}


def run_group(repo: Path, name: str, targets: list[str], timeout: int) -> dict:
    python_dir = repo / "python"
    src = python_dir / "src"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(src) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    env.setdefault("NO_COLOR", "1")

    cmd = [sys.executable, "-m", "pytest", "-q", "-rf", "--tb=short", *targets]
    started = time.time()
    try:
        proc = subprocess.run(
            cmd, cwd=python_dir, env=env, capture_output=True, text=True, timeout=timeout
        )
        output = (proc.stdout or "") + (("\n" + proc.stderr) if proc.stderr else "")
        returncode = proc.returncode
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or "") + "\nTIMEOUT"
        if isinstance(output, bytes):
            output = output.decode("utf-8", "replace")
        returncode = None
    duration = round(time.time() - started, 2)
    parsed = parse_pytest_output(output)
    return {
        "group": name,
        "command": cmd,
        "cwd": str(python_dir),
        "returncode": returncode,
        "duration_seconds": duration,
        **parsed,
        "output_tail": output[-4000:],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".", help="Repository root or any path inside it")
    parser.add_argument(
        "--groups",
        default="dex,check_tools,guard",
        help="Comma-separated groups: dex,check_tools,guard",
    )
    parser.add_argument("--full", action="store_true", help="Also run the entire suite")
    parser.add_argument("--out", help="Write the JSON report here as well")
    parser.add_argument("--timeout", type=int, default=900, help="Per-group timeout in seconds")
    args = parser.parse_args()

    repo = find_repo(Path(args.repo))
    if repo is None:
        print(json.dumps({"ok": False, "error": "not an android-re-mcp repo"}))
        return 2

    targets = {
        "dex": ["tests/test_dex_tools.py"],
        "check_tools": ["tests/test_check_tools_honesty.py"],
        "guard": ["tests/test_guard.py"],
    }
    selected = [g.strip() for g in args.groups.split(",") if g.strip()]
    unknown = [g for g in selected if g not in targets]
    if unknown:
        print(json.dumps({"ok": False, "error": f"unknown groups: {unknown}"}))
        return 2

    results = [run_group(repo, g, targets[g], args.timeout) for g in selected]
    if args.full:
        results.append(run_group(repo, "full", [], args.timeout))

    ok = all(r["returncode"] == 0 for r in results)
    report = {
        "ok": ok,
        "repo": str(repo),
        "groups": results,
        "summary": {
            r["group"]: {
                **r["counts"],
                "returncode": r["returncode"],
                "duration_seconds": r["duration_seconds"],
            }
            for r in results
        },
    }

    text = json.dumps(report, indent=2)
    print(text)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
