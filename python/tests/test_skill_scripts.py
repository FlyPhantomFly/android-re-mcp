"""The skill scripts must stay self-contained, so find_repo is copied into
each of them instead of imported (review F7). Drift between the copies is
the failure mode this guards: one script silently walking a different tree.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SKILL_SCRIPTS = REPO_ROOT / ".opencode" / "skills"
SCRIPTS = {
    "jar_gated_report.py": SKILL_SCRIPTS / "android-re-mcp-jar-gated-tests" / "scripts" / "jar_gated_report.py",
    "claim_context.py": SKILL_SCRIPTS / "android-re-mcp-claim-verification" / "scripts" / "claim_context.py",
}


def _find_repo_copies() -> dict[Path, str]:
    """Every skill script's find_repo, normalized via ast.unparse."""
    copies: dict[Path, str] = {}
    for path in sorted(SKILL_SCRIPTS.glob("*/scripts/*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name == "find_repo":
                copies[path] = ast.unparse(node)
                break
    return copies


def test_every_find_repo_copy_is_semantically_identical():
    copies = _find_repo_copies()
    # The test is meaningless with fewer than two copies, and the migration
    # put one into every script that locates the repository.
    assert len(copies) >= 2, sorted(copies)
    reference = next(iter(copies.values()))
    drift = {str(path): source for path, source in copies.items() if source != reference}
    assert not drift, f"find_repo copies drifted from {next(iter(copies))}: {drift}"


def test_the_shared_find_repo_actually_finds_this_repo(tmp_path):
    """One representative copy behaves: finds the repo from inside it, None elsewhere."""
    copies = _find_repo_copies()
    reference_path = next(iter(copies))
    namespace: dict = {}
    exec(compile(ast.parse(next(iter(copies.values()))), str(reference_path), "exec"), namespace)  # noqa: S102
    assert namespace["find_repo"](REPO_ROOT) == REPO_ROOT.resolve()
    assert namespace["find_repo"](tmp_path) is None


def test_scripts_refuse_a_non_repo_with_the_documented_error(tmp_path):
    """8574dc0 moved find_repo's SystemExit into the call sites.

    Both scripts must still fail with the same clear message and non-zero
    exit as before the change: SystemExit(str) exits 1 and prints the
    message to stderr.
    """
    non_repo = tmp_path / "nowhere"
    non_repo.mkdir()
    for name, path in SCRIPTS.items():
        proc = subprocess.run(
            [sys.executable, str(path), "--repo", str(non_repo)],
            capture_output=True, text=True, timeout=120,
        )
        assert proc.returncode == 1, (name, proc.returncode, proc.stderr[-400:])
        assert "not an android-re-mcp checkout" in proc.stderr, (name, proc.stderr[-400:])
        assert str(non_repo) in proc.stderr, name


def test_scripts_still_work_from_the_repository_root(tmp_path):
    """Positive controls: --repo <this repo> runs cleanly (exit 0)."""
    proc = subprocess.run(
        [sys.executable, str(SCRIPTS["jar_gated_report.py"]), "--repo", str(REPO_ROOT)],
        capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, proc.stderr[-400:]
    assert "jar-gated: 12" in proc.stdout

    artifact = tmp_path / "artifact.json"
    proc = subprocess.run(
        [sys.executable, str(SCRIPTS["claim_context.py"]), "--repo", str(REPO_ROOT),
         "--claim", "the suite passes", "--artifact", str(artifact)],
        capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, proc.stderr[-400:]
    assert artifact.is_file()
