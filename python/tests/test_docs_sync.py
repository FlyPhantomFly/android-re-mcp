"""Tests for the docs-sync release-tag selection."""
from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKER = REPO_ROOT / "scripts" / "check_docs_sync.py"
SCHEMA_CHECKER = REPO_ROOT / "scripts" / "check_schema_structure.py"

OLD = """
TOOL_SCHEMAS = [
    {"name": "demo", "inputSchema": {"type": "object", "properties": {
        "path": {"type": "string"}}}},
]
"""

NEW = """
TOOL_SCHEMAS = [
    {"name": "demo", "inputSchema": {"type": "object", "properties": {
        "path": {"type": "string"}, "newarg": {"type": "string"}}}},
]
"""


def _checker():
    spec = importlib.util.spec_from_file_location("check_docs_sync", CHECKER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _schemas():
    spec = importlib.util.spec_from_file_location("check_schema_structure", SCHEMA_CHECKER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    server = repo / "python" / "src" / "android_re_mcp" / "server.py"
    server.parent.mkdir(parents=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "review@example.invalid")
    _git(repo, "config", "user.name", "Review")
    server.write_text(OLD)
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "old")
    _git(repo, "tag", "v1.0.0")
    server.write_text(NEW)
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "new")
    _git(repo, "tag", "review-baseline")  # non-release tag at HEAD
    return repo


def test_added_properties_uses_the_release_tag_not_a_local_tag(tmp_path):
    checker = _checker()
    repo = _repo(tmp_path)
    current = _schemas().load_schemas_source(NEW)
    added, tag = checker.added_properties(repo, current, _schemas().load_schemas_source)
    assert tag == "v1.0.0", tag
    assert added == {"demo": ["newarg"]}, added


def test_no_release_tag_is_reported_cleanly(tmp_path):
    checker = _checker()
    repo = tmp_path / "repo"
    server = repo / "python" / "src" / "android_re_mcp" / "server.py"
    server.parent.mkdir(parents=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "review@example.invalid")
    _git(repo, "config", "user.name", "Review")
    server.write_text(OLD)
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "old")
    _git(repo, "tag", "not-a-release")
    current = _schemas().load_schemas_source(OLD)
    added, tag_or_error = checker.added_properties(repo, current, _schemas().load_schemas_source)
    assert added == {}
    assert tag_or_error is not None and "cannot compare" in tag_or_error
