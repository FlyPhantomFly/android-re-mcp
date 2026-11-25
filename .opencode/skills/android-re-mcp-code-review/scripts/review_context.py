#!/usr/bin/env python3
"""Collect git and diff context for an android-re-mcp code review.

Read-only. Prints JSON, optionally writes it with --out.

Usage:
    python review_context.py --repo /path/to/android-re-mcp
"""

from __future__ import annotations

import argparse
import json
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


def git(repo: Path, *args: str, timeout: float = 30) -> str:
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), *args],
            check=False, capture_output=True, text=True, timeout=timeout,
        )
        return (proc.stdout or proc.stderr or "").strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"ERROR: {exc}"


def lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.strip()]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".", help="Repository root or any path inside it")
    parser.add_argument("--out", help="Write the JSON report here as well")
    args = parser.parse_args()

    repo = find_repo(Path(args.repo))
    if repo is None:
        print(json.dumps({"ok": False, "error": "not an android-re-mcp repo"}))
        return 2

    status = lines(git(repo, "status", "--porcelain"))
    staged = lines(git(repo, "diff", "--cached", "--name-status"))
    unstaged = lines(git(repo, "diff", "--name-status"))
    untracked = lines(git(repo, "ls-files", "--others", "--exclude-standard"))
    recent = lines(git(repo, "log", "-5", "--oneline"))
    diffstat = lines(git(repo, "diff", "--stat"))
    cachedstat = lines(git(repo, "diff", "--cached", "--stat"))

    report = {
        "ok": True,
        "repo": str(repo),
        "branch": git(repo, "rev-parse", "--abbrev-ref", "HEAD"),
        "head": git(repo, "rev-parse", "--short", "HEAD"),
        "status": status,
        "staged_changes": staged,
        "unstaged_changes": unstaged,
        "untracked_files": untracked,
        "recent_commits": recent,
        "unstaged_diffstat": diffstat,
        "staged_diffstat": cachedstat,
        "summary": {
            "dirty": bool(status),
            "changed_files": len({line.split("\t")[-1] for line in staged + unstaged if "\t" in line}),
            "untracked": len(untracked),
        },
    }
    text = json.dumps(report, indent=2)
    print(text)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
