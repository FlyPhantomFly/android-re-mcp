#!/usr/bin/env python3
"""Collect reproducible evidence for a claim about android-re-mcp work.

This is the evidence collector behind the claim-verification skill. It does
not decide whether a claim is true; it gathers the state, counts, named tests,
commit existence and weak-assertion candidates that the reviewer needs, and
saves the result as a JSON artifact.

Usage:
    python .opencode/skills/android-re-mcp-claim-verification/scripts/claim_context.py \
        --repo . --claim-file reports/claim.md \
        --artifact reports/artifacts/claim-context.json --run-tests
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
from pathlib import Path

HEX_RE = re.compile(r"\b[0-9a-f]{7,40}\b")
COVERAGE_RE = re.compile(r"\b(locks?|covers?|proved?|proves?|verified|live proof)\b", re.IGNORECASE)
COUNT_RE = re.compile(r"\b\d+\s+(?:passed|skipped|schemas?|tools?|tests?)\b", re.IGNORECASE)
TEST_KEYWORD_RE = re.compile(r"era|ambig|passthrough|schema", re.IGNORECASE)


def find_repo(start: Path) -> Path | None:
    current = start.resolve()
    for candidate in (current, *current.parents):
        if (candidate / "python" / "pyproject.toml").is_file() and (
            candidate / "python" / "src" / "android_re_mcp"
        ).is_dir():
            return candidate
    return None


def run(cmd: list[str], cwd: Path | None = None, env: dict | None = None,
        timeout: int = 900) -> dict:
    try:
        proc = subprocess.run(
            cmd, check=False, cwd=cwd, env=env, capture_output=True, text=True,
            timeout=timeout,
        )
        return {
            "cmd": cmd,
            "cwd": str(cwd) if cwd else None,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr[-4000:],
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"cmd": cmd, "cwd": str(cwd) if cwd else None, "error": str(exc)}


def git(repo: Path, *args: str) -> dict:
    return run(["git", "-C", str(repo), *args])


def collect_claim(claim: str) -> dict:
    hashes = sorted({h for h in HEX_RE.findall(claim) if len(h) >= 7})
    coverage = [line.strip() for line in claim.splitlines() if COVERAGE_RE.search(line)]
    counts = [line.strip() for line in claim.splitlines() if COUNT_RE.search(line)]
    return {"commit_hashes": hashes, "coverage_statements": coverage, "count_statements": counts}


def commit_evidence(repo: Path, hashes: list[str]) -> list[dict]:
    out = []
    for commit in hashes:
        kind = git(repo, "cat-file", "-t", commit)
        item = {"hash": commit, "exists": kind.get("returncode") == 0}
        if item["exists"]:
            stat = git(repo, "show", "--stat", "--oneline", commit)
            item["stat"] = stat.get("stdout", "").strip()
        out.append(item)
    return out


def schema_evidence(repo: Path) -> dict:
    result = run(
        [sys.executable, str(repo / "scripts" / "check_schema_structure.py"),
         "--repo", str(repo), "--json"],
        timeout=120,
    )
    if result.get("returncode") != 0:
        return {"error": result.get("stdout") or result.get("stderr") or result.get("error")}
    try:
        return json.loads(result["stdout"])
    except json.JSONDecodeError as exc:
        return {"error": f"schema checker emitted non-JSON: {exc}"}


def pytest_env(repo: Path) -> dict:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo / "python" / "src")
    return env


def collect_tests(repo: Path, run_tests: bool) -> dict:
    env = pytest_env(repo)
    collected = run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        cwd=repo / "python", env=env, timeout=300,
    )
    test_ids = [
        line.strip()
        for line in collected.get("stdout", "").splitlines()
        if "::" in line and not line.startswith("=")
    ]
    collected_match = re.search(r"(\d+) tests? collected", collected.get("stdout", ""))
    out = {
        "collect": {
            "returncode": collected.get("returncode"),
            "tests": int(collected_match.group(1)) if collected_match else len(test_ids),
            "summary_tail": "\n".join(collected.get("stdout", "").splitlines()[-3:]),
        },
        "named_tests": [test for test in test_ids if TEST_KEYWORD_RE.search(test)],
    }
    if run_tests:
        executed = run(
            [sys.executable, "-m", "pytest", "-q"],
            cwd=repo / "python", env=env, timeout=900,
        )
        tail = "\n".join(executed.get("stdout", "").splitlines()[-8:])
        out["run"] = {
            "returncode": executed.get("returncode"),
            "summary_tail": tail,
        }
    return out


def weak_assertion_candidates(repo: Path) -> list[dict]:
    """Flag assert ... == "error" near a proceeds/allow_ambiguous comment."""
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".")
    parser.add_argument("--claim-file", help="file containing the claim to inspect")
    parser.add_argument("--claim", help="claim text (alternative to --claim-file)")
    parser.add_argument("--artifact", help="output JSON path")
    parser.add_argument("--run-tests", action="store_true",
                        help="also run the full pytest suite and capture the summary")
    args = parser.parse_args(argv)
    repo = find_repo(Path(args.repo))
    if repo is None:
        raise SystemExit(f"not an android-re-mcp checkout: {args.repo}")
    if args.claim_file:
        claim = Path(args.claim_file).read_text(encoding="utf-8")
        claim_source = str(Path(args.claim_file).resolve())
    elif args.claim:
        claim = args.claim
        claim_source = "<inline>"
    else:
        claim = ""
        claim_source = None

    head = git(repo, "rev-parse", "HEAD").get("stdout", "").strip()
    status = git(repo, "status", "--short").get("stdout", "").strip()
    upstream = git(repo, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")
    upstream_name = upstream.get("stdout", "").strip() or None
    upstream_head = None
    if upstream_name:
        upstream_head = git(repo, "rev-parse", upstream_name).get("stdout", "").strip()

    evidence = {
        "generated_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "repo": str(repo),
        "claim_source": claim_source,
        "claim": collect_claim(claim),
        "git": {
            "head": head,
            "status_short": status,
            "clean": not status,
            "upstream": upstream_name,
            "upstream_head": upstream_head,
            "pushed": bool(upstream_head and head == upstream_head),
        },
        "commits": commit_evidence(repo, collect_claim(claim)["commit_hashes"]),
        "schemas": schema_evidence(repo),
        "tests": collect_tests(repo, args.run_tests),
        "weak_assertion_candidates": weak_assertion_candidates(repo),
    }

    artifact = Path(args.artifact) if args.artifact else (
        repo / "reports" / "artifacts" /
        f"claim-context-{dt.date.today().isoformat()}.json"
    )
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(json.dumps(evidence, indent=2), encoding="utf-8")

    print(f"artifact: {artifact}")
    print(f"HEAD: {head[:12]}  clean: {evidence['git']['clean']}  "
          f"pushed: {evidence['git']['pushed']}")
    print(f"schemas: {evidence['schemas'].get('schemas', '?')}  "
          f"structural: {len(evidence['schemas'].get('structural', []))}  "
          f"drift: {len(evidence['schemas'].get('drift', []))}")
    print(f"tests collected: {evidence['tests']['collect']['tests']}")
    if "run" in evidence["tests"]:
        print("test summary:", evidence["tests"]["run"]["summary_tail"].splitlines()[-1]
              if evidence["tests"]["run"]["summary_tail"] else "<none>")
    if evidence["claim"]["coverage_statements"]:
        print(f"coverage statements: {len(evidence['claim']['coverage_statements'])}")
    if evidence["weak_assertion_candidates"]:
        print(f"weak-assertion candidates: {len(evidence['weak_assertion_candidates'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
