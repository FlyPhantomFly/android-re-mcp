#!/usr/bin/env python3
"""Fail when a pytest JUnit report contains a dexfile-cli-gated skip.

A plain ``grep dexfile-cli.jar`` over the pytest output also matches captured
output and failures, and it cannot tell which test skipped. This reads the
JUnit XML instead and only inspects ``<skipped>`` reasons.

Usage:
    pytest ... --junitxml=pytest.xml
    python scripts/check_jar_skips.py pytest.xml

Exit codes: 0 = no jar-gated skip, 1 = at least one, 2 = unreadable report.
"""
from __future__ import annotations

import sys
import xml.etree.ElementTree as ET


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


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv if argv is None else argv
    if len(argv) != 2:
        print("usage: check_jar_skips.py <pytest-junit.xml>", file=sys.stderr)
        return 2
    try:
        jar, other = jar_skips(argv[1])
    except (OSError, ET.ParseError) as exc:
        print(f"::error::cannot read JUnit report {argv[1]}: {exc}")
        return 2
    for line in other:
        print(f"unrelated skip: {line}")
    for line in jar:
        print(f"::error::jar-gated test skipped: {line}")
    if jar:
        return 1
    print(f"ok: no dexfile-cli-gated skips ({len(other)} unrelated skips)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
