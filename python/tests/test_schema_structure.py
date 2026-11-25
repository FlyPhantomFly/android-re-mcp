"""Jar-free checks for the committed schema-structure validator.

The validator lives at ``scripts/check_schema_structure.py`` (tracked, so CI
can run it without the local ``skills/`` workspace). These tests exercise both
the real catalog and small synthetic catalogs, so a regression in the checker
itself is visible even when today's schemas happen to be clean.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

from android_re_mcp.server import TOOL_SCHEMAS

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKER = REPO_ROOT / "scripts" / "check_schema_structure.py"


def _checker():
    spec = importlib.util.spec_from_file_location("check_schema_structure", CHECKER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _synthetic_checkout(tmp_path: Path, schemas_source: str, handler_source: str) -> Path:
    root = tmp_path / "checkout"
    pkg = root / "python" / "src" / "android_re_mcp"
    (pkg / "handlers").mkdir(parents=True)
    (root / "python" / "pyproject.toml").write_text("[project]\nname='synthetic'\n")
    (pkg / "server.py").write_text(schemas_source)
    (pkg / "handlers" / "demo.py").write_text(handler_source)
    return root


def test_audit_loads_every_runtime_schema():
    report = _checker().audit(REPO_ROOT)
    assert report["schemas"] == len(TOOL_SCHEMAS)


def test_real_catalog_has_no_structural_problems():
    report = _checker().audit(REPO_ROOT)
    assert not report["structural"], report["structural"]


def test_checker_catches_strays_required_and_arrays(tmp_path):
    schemas = """
TOOL_SCHEMAS = [
    {
        "name": "demo",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "items": {"type": "array"},
            },
            "required": ["path", "missing"],
            "era": {"type": "string"},
        },
    },
]
"""
    root = _synthetic_checkout(tmp_path, schemas, "class H:\n    def demo(self, args):\n        return args.get('path')\n")
    report = _checker().audit(root)
    messages = [item["message"] for item in report["structural"]]
    assert any("stray inputSchema key: era" in message for message in messages)
    assert any("required not in properties: missing" in message for message in messages)
    assert any("array without items" in message for message in messages)


def test_checker_reports_handler_keys_absent_from_schema(tmp_path):
    schemas = """
TOOL_SCHEMAS = [
    {"name": "demo", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
]
"""
    handler = """
class H:
    def demo(self, args):
        return args.get("path") or args.get("extra")
"""
    root = _synthetic_checkout(tmp_path, schemas, handler)
    report = _checker().audit(root)
    assert report["drift"] == [
        {"tool": "demo", "schema_not_read": [], "read_not_in_schema": ["extra"]}
    ]
