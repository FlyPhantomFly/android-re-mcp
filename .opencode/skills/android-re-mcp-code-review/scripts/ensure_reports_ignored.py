#!/usr/bin/env python3
"""Ensure the local reports/ directory exists and is ignored by git.

Usage:
    python ensure_reports_ignored.py --repo .
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".", help="Repository root or any path inside it")
    args = parser.parse_args()

    repo = find_repo(Path(args.repo))
    if repo is None:
        print(json.dumps({"ok": False, "error": "not an android-re-mcp repo"}))
        return 2

    reports = repo / "reports"
    reports.mkdir(parents=True, exist_ok=True)

    gitignore = repo / ".gitignore"
    try:
        lines = gitignore.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        print(json.dumps({"ok": False, "error": f"cannot read .gitignore: {exc}"}))
        return 2

    if "reports/" in lines:
        added = False
        line_no = lines.index("reports/") + 1
    else:
        insert_at = None
        for idx, line in enumerate(lines):
            if line.strip().lower() == "# logs":
                insert_at = idx + 1
                break
        if insert_at is None:
            lines.extend(["", "# Reports (local only)"])
            insert_at = len(lines)
        lines.insert(insert_at, "reports/")
        gitignore.write_text("\n".join(lines) + "\n", encoding="utf-8")
        added = True
        line_no = insert_at + 1

    try:
        check = subprocess.run(
            ["git", "-C", str(repo), "check-ignore", "-v", "reports/SUMMARY-example.md"],
            check=False, capture_output=True, text=True, timeout=30,
        )
        ignored = (check.stdout or check.stderr or "").strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        ignored = f"check-ignore failed: {exc}"

    print(json.dumps({
        "ok": True,
        "reports_dir": str(reports),
        "added": added,
        "line": line_no,
        "ignored": ignored,
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
