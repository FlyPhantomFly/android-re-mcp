#!/usr/bin/env python3
"""Add an audit log filename to .gitignore without duplicating it.

Usage:
    python register_audit_log.py --repo . audit-Nov.18.log
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


def check_ignore(repo: Path, name: str) -> str:
    try:
        proc = subprocess.run(
            ["git", "check-ignore", "-v", name],
            check=False, cwd=repo, capture_output=True, text=True, timeout=30,
        )
        return (proc.stdout or proc.stderr or "").strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"check-ignore failed: {exc}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".", help="Repository root or any path inside it")
    parser.add_argument("log_path", help="Log filename, relative to the repo (e.g. audit-Nov.18.log)")
    args = parser.parse_args()

    repo = find_repo(Path(args.repo))
    if repo is None:
        print(json.dumps({"ok": False, "error": "not an android-re-mcp repo"}))
        return 2

    raw = Path(args.log_path)
    if raw.is_absolute():
        try:
            name = raw.resolve().relative_to(repo)
        except ValueError:
            print(json.dumps({"ok": False, "error": "log path is outside the repo"}))
            return 2
    else:
        name = raw
    if name.parent != Path("."):
        print(json.dumps({"ok": False, "error": "log must sit at the repo root"}))
        return 2
    name_str = str(name)

    gitignore = repo / ".gitignore"
    try:
        lines = gitignore.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        print(json.dumps({"ok": False, "error": f"cannot read .gitignore: {exc}"}))
        return 2

    if name_str in lines:
        print(json.dumps({
            "ok": True,
            "added": False,
            "reason": "already present",
            "line": lines.index(name_str) + 1,
            "log_exists": (repo / name_str).is_file(),
            "ignored": check_ignore(repo, name_str),
        }, indent=2))
        return 0

    insert_at = None
    for idx, line in enumerate(lines):
        if line.strip().lower() == "# logs":
            insert_at = idx + 1
            break
    if insert_at is None:
        lines.extend(["", "# Audit logs"])
        insert_at = len(lines)
    lines.insert(insert_at, name_str)

    gitignore.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({
        "ok": True,
        "added": True,
        "line": insert_at + 1,
        "log_exists": (repo / name_str).is_file(),
        "ignored": check_ignore(repo, name_str),
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
