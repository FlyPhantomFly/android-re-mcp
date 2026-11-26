"""Identity-based jar-gate enforcement, tested without any jar.

Covers both layers added for review finding F1: the JUnit identity check in
``scripts/check_jar_skips.py --require-run`` (a reworded skip reason cannot
defeat it) and the ``ANDROID_RE_MCP_REQUIRE_JAR`` collection gate in
conftest.py (via the importable ``jar_gate`` helper).
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKER = REPO_ROOT / "scripts" / "check_jar_skips.py"


def _checker():
    spec = importlib.util.spec_from_file_location("check_jar_skips", CHECKER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _item(nodeid: str, reason: str | None):
    marks = []
    if reason is not None:
        marks.append(SimpleNamespace(name="skipif", args=(True,), kwargs={"reason": reason}))
    return SimpleNamespace(nodeid=nodeid, iter_markers=lambda name=None: iter(
        mark for mark in marks if name in (None, mark.name)))


def _write_junit(path: Path, cases: list[tuple[str, str, str | None]]) -> None:
    lines = ["<testsuites><testsuite>"]
    for classname, name, reason in cases:
        if reason is None:
            lines.append(
                f'<testcase classname="{classname}" name="{name}"><system-out/></testcase>'
            )
        else:
            lines.append(
                f'<testcase classname="{classname}" name="{name}">'
                f'<skipped message="{reason}" type="pytest.skip"/></testcase>'
            )
    lines.append("</testsuite></testsuites>")
    path.write_text("\n".join(lines), encoding="utf-8")


# ── jar_gate.gated_skips (the conftest gate's logic) ──────────────────────

def test_gated_skips_matches_the_dexfile_reason():
    from jar_gate import gated_skips

    items = [
        _item("tests/test_dex_tools.py::test_dex_validate_clean_dex",
              "dexfile-cli.jar / java not available"),
        _item("tests/test_quark_scan.py::test_x", "quark-engine not installed"),
    ]
    assert gated_skips(items) == ["tests/test_dex_tools.py::test_dex_validate_clean_dex"]


def test_gated_skips_ignores_reworded_and_empty_reasons():
    from jar_gate import gated_skips

    items = [
        _item("a::b", "vendored jar missing"),  # reworded: no dexfile-cli.jar needle
        _item("c::d", None),
    ]
    assert gated_skips(items) == []


def test_gated_skips_accepts_kwargs_and_positional_reasons():
    from jar_gate import gated_skips

    positional = SimpleNamespace(
        nodeid="tests/x.py::test_pos",
        iter_markers=lambda name=None: iter([
            SimpleNamespace(name="skipif", args=(True, "dexfile-cli.jar / java missing"), kwargs={}),
        ]),
    )
    assert gated_skips([positional]) == ["tests/x.py::test_pos"]


# ── check_jar_skips: the reason scan is wording-based (documented) ────────

def test_reason_scan_flags_dexfile_skips_and_files_reworded_ones_as_unrelated(tmp_path):
    checker = _checker()
    xml = tmp_path / "junit.xml"
    _write_junit(xml, [
        ("tests.test_dex_tools", "test_dex_validate_clean_dex",
         "dexfile-cli.jar / java not available"),
        ("tests.test_dex_tools", "test_roundtrip_swap_into_apk", "vendored jar missing"),
    ])
    jar, other = checker.jar_skips(str(xml))
    assert len(jar) == 1 and "test_dex_validate_clean_dex" in jar[0]
    assert len(other) == 1 and "test_roundtrip_swap_into_apk" in other[0]


# ── check_jar_skips --require-run: identity, not wording ─────────────────

def _required_file(tmp_path: Path, needles: list[str]) -> Path:
    path = tmp_path / "required.txt"
    path.write_text("# comment\n\n" + "\n".join(needles) + "\n", encoding="utf-8")
    return path


def test_require_run_passes_when_every_required_node_executed(tmp_path):
    checker = _checker()
    xml = tmp_path / "junit.xml"
    _write_junit(xml, [
        ("tests.test_dex_tools", "test_dex_validate_clean_dex", None),
        ("tests.test_mt_adopt", "test_dex_read_class_outline_real", None),
    ])
    required = _required_file(tmp_path, ["test_dex_tools::test_dex_validate_clean_dex",
                                         "test_mt_adopt::test_dex_read_class_outline_real"])
    assert checker.main(["--require-run", str(required), str(xml)]) == 0


def test_require_run_flags_a_skipped_node_whose_reason_was_reworded(tmp_path):
    """The core F1 regression: wording defeated the scan; identity cannot."""
    checker = _checker()
    xml = tmp_path / "junit.xml"
    _write_junit(xml, [
        ("tests.test_dex_tools", "test_dex_validate_clean_dex", "vendored jar missing"),
        ("tests.test_mt_adopt", "test_dex_read_class_outline_real", None),
    ])
    required = _required_file(tmp_path, ["test_dex_tools::test_dex_validate_clean_dex",
                                         "test_mt_adopt::test_dex_read_class_outline_real"])
    assert checker.main(["--require-run", str(required), str(xml)]) == 1


def test_require_run_flags_a_node_that_never_ran(tmp_path):
    checker = _checker()
    xml = tmp_path / "junit.xml"
    _write_junit(xml, [("tests.test_mt_adopt", "test_dex_read_class_outline_real", None)])
    required = _required_file(tmp_path, ["test_dex_tools::test_dex_validate_clean_dex",
                                         "test_mt_adopt::test_dex_read_class_outline_real"])
    assert checker.main(["--require-run", str(required), str(xml)]) == 1


def test_require_run_rejects_an_empty_needle_list(tmp_path):
    checker = _checker()
    xml = tmp_path / "junit.xml"
    _write_junit(xml, [("tests.test_dex_tools", "test_dex_validate_clean_dex", None)])
    required = tmp_path / "required.txt"
    required.write_text("# only comments\n", encoding="utf-8")
    assert checker.main(["--require-run", str(required), str(xml)]) == 2


def test_require_run_with_the_shipped_list_rejects_an_all_skipped_report(tmp_path):
    """The exact CI failure mode: jar absent, every gated test skipped."""
    checker = _checker()
    xml = tmp_path / "junit.xml"
    shipped = checker.load_required(str(REPO_ROOT / "scripts" / "jar_gated_required.txt"))
    _write_junit(xml, [
        ("tests.test_dex_tools", needle.split("::", 1)[1], "dexfile-cli.jar / java not available")
        for needle in shipped
    ])
    assert checker.main(["--require-run",
                         str(REPO_ROOT / "scripts" / "jar_gated_required.txt"),
                         str(xml)]) == 1


def test_main_returns_2_for_an_unreadable_report(tmp_path):
    checker = _checker()
    assert checker.main([str(tmp_path / "missing.xml")]) == 2
