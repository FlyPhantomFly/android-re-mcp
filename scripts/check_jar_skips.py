#!/usr/bin/env python3
"""Fail when a pytest JUnit report contains a jar-gated skip, or when a
required jar-gated test never ran.

A plain ``grep dexfile-cli.jar`` over the pytest output also matches captured
output and failures, and it cannot tell which test skipped. This reads the
JUnit XML and only inspects ``<skipped>`` reasons.

With ``--require-run FILE`` the check becomes identity-based, not
wording-based: every node named in FILE (``module::test`` substrings, one
per line, '#' comments allowed) must appear in the report as an executed
(non-skipped) testcase. A skip reason can be reworded to defeat the reason
scan; a test that did not run cannot.

Usage:
    pytest ... --junitxml=pytest.xml
    python scripts/check_jar_skips.py pytest.xml
    python scripts/check_jar_skips.py --require-run scripts/jar_gated_required.txt pytest.xml

Exit codes: 0 = ok; 1 = a jar-gated skip, or a required node missing/skipped;
2 = usage or unreadable input.
"""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def jar_skips(path: str) -> tuple[list[str], list[str]]:
    """Return (jar-gated skip lines, unrelated skip lines)."""
    root = ET.parse(path).getroot()
    jar: list[str] = []
    other: list[str] = []
    for case in root.iter("testcase"):
        skipped = case.find("skipped")
        if skipped is None:
            continue
        reason = (skipped.get("message") or skipped.text or "").strip()
        where = f"{case.get('classname', '')}::{case.get('name', '')}"
        line = f"{where}: {reason}"
        if "dexfile-cli" in reason.lower():
            jar.append(line)
        else:
            other.append(line)
    return jar, other


def load_required(path: str) -> list[str]:
    needles: list[str] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            needles.append(line)
    if not needles:
        raise ValueError(f"no required nodes listed in {path}")
    return needles


def require_run(path: str, needles: list[str]) -> tuple[list[str], list[str]]:
    """Return (never_ran, ran_but_skipped) for the required node names.

    Matching is exact, not substring: a needle `module::test` matches a case
    whose classname's last dotted part is `module` and whose name is `test`
    or a parametrized `test[...]`. Substring matching would let a renamed
    required test hide behind another test whose name starts with it.
    """
    nodes: dict[str, list[ET.Element]] = {}
    root = ET.parse(path).getroot()
    for case in root.iter("testcase"):
        node = f"{case.get('classname', '')}::{case.get('name', '')}"
        nodes.setdefault(node, []).append(case)
    missing: list[str] = []
    skipped: list[str] = []
    for needle in needles:
        module, _, test = needle.partition("::")
        matches = [
            case
            for node, cases in nodes.items()
            if node.rsplit("::", 1)[0].rsplit(".", 1)[-1] == module.split(".")[-1]
            and (node.rsplit("::", 1)[1] == test or node.rsplit("::", 1)[1].startswith(test + "["))
            for case in cases
        ]
        if not matches:
            missing.append(needle)
        elif any(case.find("skipped") is not None for case in matches):
            skipped.append(needle)
    return missing, skipped


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", help="pytest JUnit XML path")
    parser.add_argument(
        "--require-run", metavar="FILE",
        help="file of module::test needles that must appear executed (not skipped)",
    )
    args = parser.parse_args(argv)

    try:
        jar, other = jar_skips(args.report)
    except (OSError, ET.ParseError) as exc:
        print(f"::error::cannot read JUnit report {args.report}: {exc}")
        return 2

    for line in other:
        print(f"unrelated skip: {line}")
    for line in jar:
        print(f"::error::jar-gated test skipped: {line}")

    required_count = 0
    if args.require_run:
        try:
            needles = load_required(args.require_run)
            missing, skipped = require_run(args.report, needles)
        except (OSError, ET.ParseError, ValueError) as exc:
            print(f"::error::require-run check failed: {exc}")
            return 2
        for needle in skipped:
            print(f"::error::required jar-gated test was skipped: {needle}")
        for needle in missing:
            print(f"::error::required jar-gated test never ran: {needle}")
        required_count = len(needles)
        if missing or skipped:
            return 1

    if jar:
        return 1
    print(
        f"ok: no jar-gated skips ({len(other)} unrelated skips;"
        f" {required_count} required jar-gated nodes executed)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
