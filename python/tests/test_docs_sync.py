"""Tests for the docs-sync release-tag selection."""
from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

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


def test_joined_optional_review_accepts_is_optional():
    checker = _checker()
    assert not checker.joined_optional_is_defect("`method_name` is optional, `use_regex` opt-in")
    assert not checker.joined_optional_is_defect("the path is optional")
    assert checker.joined_optional_is_defect("counts optional entries")
    assert checker.joined_optional_is_defect("`method_name` optional")


def test_ratchet_rejects_new_failures_and_allows_listed_ones():
    checker = _checker()
    failures = [{"tool": "demo", "message": "README row does not mention `newarg`"}]
    assert checker.ratchet_unexpected(failures, set()) == failures
    assert checker.ratchet_unexpected(failures, {"demo:newarg"}) == []


def test_no_release_tag_is_reported_cleanly(tmp_path, monkeypatch):
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
    # Explicitly the LOCAL mode: the warning stays a warning outside CI.
    monkeypatch.delenv("CI", raising=False)
    added, tag_or_error = checker.added_properties(repo, current, _schemas().load_schemas_source)
    assert added == {}
    assert tag_or_error is not None and "cannot compare" in tag_or_error


def test_freshness_check_scans_the_newest_release_block(tmp_path):
    """(a) pending release: entries live in the new versioned block."""
    checker = _checker()
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(
        "## [Unreleased]\n"
        "\n"
        "## [1.1.0] - 2026-11-25\n"
        "\n"
        "### Changed\n"
        "- `demo` gains `newarg` (the release commit moved the entries here).\n",
        encoding="utf-8",
    )
    blocks = checker.changelog_blocks(changelog, "v1.0.0")
    assert len(blocks) == 2
    assert "newarg" in "\n".join(blocks), blocks


def test_freshness_check_stops_scanning_once_tag_equals_heading(tmp_path):
    """(b) tag == newest heading: only [Unreleased] is scanned — the released
    block's mention of a name must not mask a brand-new property."""
    checker = _checker()
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(
        "## [Unreleased]\n"
        "\n"
        "## [1.1.0] - 2026-11-25\n"
        "\n"
        "### Changed\n"
        "- `demo` gains `newarg` (this release is already tagged).\n",
        encoding="utf-8",
    )
    blocks = checker.changelog_blocks(changelog, "v1.1.0")
    assert len(blocks) == 1
    assert "newarg" not in "\n".join(blocks), blocks


def test_freshness_check_scans_unreleased_names(tmp_path):
    """(c) a property named in [Unreleased] is found regardless of the tag."""
    checker = _checker()
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(
        "## [Unreleased]\n"
        "\n"
        "### Changed\n"
        "- `demo` gains `newarg` (pending, named in Unreleased).\n"
        "\n"
        "## [1.1.0] - 2026-11-25\n",
        encoding="utf-8",
    )
    blocks = checker.changelog_blocks(changelog, "v1.1.0")
    assert any("newarg" in block for block in blocks), blocks


def test_tag_failure_is_a_hard_error_on_ci(tmp_path, monkeypatch):
    """F2 residual: a tag-less CI checkout must not skip the check silently."""
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
    monkeypatch.setenv("CI", "true")
    with pytest.raises(SystemExit) as excinfo:
        checker.added_properties(repo, current, _schemas().load_schemas_source)
    message = str(excinfo.value)
    assert "::error::" in message and "cannot compare" in message
