#!/usr/bin/env python3
"""Collect environment and dexfile-cli evidence for an android-re-mcp audit.

Read-only: runs git/java/python probes and the live check_tools function, but
never writes into the repository.

Usage:
    python preflight.py --repo /path/to/android-re-mcp
    python preflight.py --repo . --out /tmp/preflight.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
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


def run(
    cmd: list[str], cwd: Path | None = None, timeout: float = 30, env: dict | None = None
) -> dict:
    try:
        proc = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env
        )
        return {
            "command": cmd,
            "returncode": proc.returncode,
            "stdout": (proc.stdout or "").strip()[:4000],
            "stderr": (proc.stderr or "").strip()[:4000],
        }
    except FileNotFoundError:
        return {"command": cmd, "returncode": None, "error": "not found"}
    except subprocess.TimeoutExpired:
        return {"command": cmd, "returncode": None, "error": "timeout"}
    except OSError as exc:
        return {"command": cmd, "returncode": None, "error": str(exc)}


def sha256_file(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def expected_pin(repo: Path) -> dict:
    """Parse the dexfile-cli pin out of setup/install_tool.py without importing it."""
    path = repo / "python" / "src" / "android_re_mcp" / "setup" / "install_tool.py"
    result: dict = {"path": str(path), "found": False}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        result["error"] = str(exc)
        return result
    block = re.search(
        r'"dexfile-cli\.jar"\s*:\s*\(\s*"(?P<url>[^"]+)"\s*,\s*"(?P<sha>[0-9a-fA-F]{64})"',
        text,
    )
    if not block:
        return result
    message = re.search(r'"dexfile-cli ([\d.]+) installed', text)
    result.update(
        {
            "found": True,
            "url": block.group("url"),
            "sha256": block.group("sha").lower(),
            "version": (re.search(r"/v([^/]+)/", block.group("url")) or [None, None])[1],
            "install_message_version": message.group(1) if message else None,
        }
    )
    return result


def live_check_tools(repo: Path) -> dict:
    """Run the real check_all_tools() in a child interpreter and return the dex entry."""
    src = repo / "python" / "src"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(src) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    code = (
        "import json\n"
        "from android_re_mcp.setup.check_tools import check_all_tools\n"
        "res = check_all_tools()\n"
        "tools = res.get('tools', {})\n"
        "out = {k: v for k, v in tools.items() if 'dex' in k.lower()}\n"
        "print(json.dumps({'summary': res.get('summary'), 'dex': out}, default=str))\n"
    )
    proc = run([sys.executable, "-c", code], cwd=repo, timeout=180, env=env)
    if proc.get("returncode") != 0:
        return {"ok": False, "error": proc.get("error") or proc.get("stderr") or proc.get("stdout")}
    try:
        parsed = json.loads(proc.get("stdout") or "{}")
        return {"ok": True, **parsed}
    except json.JSONDecodeError as exc:
        return {"ok": False, "error": f"invalid JSON from check_tools: {exc}"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".", help="Repository root or any path inside it")
    parser.add_argument("--out", help="Write the JSON report here as well")
    args = parser.parse_args()

    repo = find_repo(Path(args.repo))
    if repo is None:
        print(json.dumps({"ok": False, "error": "not an android-re-mcp repo"}))
        return 2

    tools_segment = os.environ.get("ANDROID_RE_MCP_TOOLS_DIR")
    tools_dir = Path(tools_segment).expanduser() if tools_segment else Path.home() / "tools"
    jar = tools_dir / "dexfile-cli.jar"

    pin = expected_pin(repo)
    actual_sha = sha256_file(jar) if jar.is_file() else None
    check = live_check_tools(repo)
    try:
        ct_text = (repo / "python" / "src" / "android_re_mcp" / "setup" / "check_tools.py").read_text(
            encoding="utf-8"
        )
    except OSError:
        ct_text = ""
    try:
        dex_text = (repo / "python" / "src" / "android_re_mcp" / "handlers" / "dex.py").read_text(
            encoding="utf-8"
        )
    except OSError:
        dex_text = ""

    report = {
        "ok": True,
        "repo": str(repo),
        "tree": {
            "branch": run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=repo),
            "head": run(["git", "rev-parse", "--short", "HEAD"], cwd=repo),
            "status": run(["git", "status", "--porcelain"], cwd=repo),
        },
        "runtime": {
            "python": sys.version,
            "executable": sys.executable,
            "java": run(["java", "-version"]),
            "pytest": run([sys.executable, "-m", "pytest", "--version"]),
        },
        "dexfile_cli": {
            "tools_dir": str(tools_dir),
            "jar": str(jar),
            "jar_exists": jar.is_file(),
            "jar_sha256": actual_sha,
            "expected_pin": pin,
            "sha_matches": bool(actual_sha and pin.get("sha256") == actual_sha),
            "install_message_matches_pin": pin.get("install_message_version") == pin.get("version"),
            "hints": {
                "generic_jar_hint_says_jdk11": "JDK 11+" in ct_text,
                "dex_handler_says_java17": "java 17+" in dex_text.lower(),
            },
            "java_on_path": shutil.which("java"),
            "check_tools": check,
        },
    }

    text = json.dumps(report, indent=2)
    print(text)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
