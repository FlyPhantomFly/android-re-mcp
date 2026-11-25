"""Tests for the CI jar-skip detector (scripts/check_jar_skips.py)."""
from __future__ import annotations

import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKER = REPO_ROOT / "scripts" / "check_jar_skips.py"


def _checker():
    spec = importlib.util.spec_from_file_location("check_jar_skips", CHECKER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "pytest.xml"
    path.write_text("<testsuites><testsuite>" + body + "</testsuite></testsuites>")
    return path


def test_jar_gated_skip_fires(tmp_path):
    report = _write(
        tmp_path,
        '<testcase classname="tests.test_dex_tools" name="test_roundtrip">'
        '<skipped message="dexfile-cli.jar / java not available">'
        "dexfile-cli.jar / java not available</skipped></testcase>",
    )
    assert _checker().main(["check_jar_skips.py", str(report)]) == 1


def test_unrelated_skip_stays_silent(tmp_path):
    report = _write(
        tmp_path,
        '<testcase classname="tests.test_quark_scan" name="test_scan">'
        '<skipped message="quark-engine not installed">quark-engine not installed'
        "</skipped></testcase>",
    )
    assert _checker().main(["check_jar_skips.py", str(report)]) == 0


def test_passing_output_with_the_string_stays_silent(tmp_path):
    report = _write(
        tmp_path,
        '<testcase classname="tests.test_demo" name="test_ok">'
        "<system-out>a log line mentions dexfile-cli.jar</system-out></testcase>",
    )
    assert _checker().main(["check_jar_skips.py", str(report)]) == 0


def test_missing_report_is_an_error(tmp_path):
    assert _checker().main(["check_jar_skips.py", str(tmp_path / "absent.xml")]) == 2
