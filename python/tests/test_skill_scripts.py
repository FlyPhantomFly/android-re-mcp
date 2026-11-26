"""The skill scripts must stay self-contained, so find_repo is copied into
each of them instead of imported (review F7). Drift between the copies is
the failure mode this guards: one script silently walking a different tree.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SKILL_SCRIPTS = REPO_ROOT / ".opencode" / "skills"


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
