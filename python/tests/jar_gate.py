"""Shared helpers for the ``ANDROID_RE_MCP_REQUIRE_JAR`` gate.

Kept in an importable module (not conftest-only) so the logic is
unit-testable without a jar, a device, or a pytester subprocess.
"""

from __future__ import annotations

import pytest

NEEDLE = "dexfile-cli.jar"


def _skipif_reasons(mark) -> list[str]:
    """The skip reasons attached to one ``skipif`` marker."""
    reasons: list[str] = []
    if mark.args and len(mark.args) > 1:
        reasons.append(str(mark.args[1]))
    if mark.kwargs.get("reason"):
        reasons.append(str(mark.kwargs["reason"]))
    return reasons


def _marker_condition(mark) -> bool:
    """The marker's condition, already evaluated at module import time.

    ``pytest.mark.skipif(not JAR_AVAILABLE, reason=...)`` stores the bool in
    ``args[0]`` (or ``kwargs['condition']``); a falsy condition means the
    test would NOT skip.
    """
    if mark.args:
        return bool(mark.args[0])
    return bool(mark.kwargs.get("condition", False))


def gated_skips(items) -> list[str]:
    """Nodeids carrying the ``jar_gated`` marker whose skipif condition holds.

    Selection is by marker identity, not by reason text — a reworded skip
    reason cannot remove a test from the gate.
    """
    out: list[str] = []
    for item in items:
        if not any(item.iter_markers(name="jar_gated")):
            continue
        for mark in item.iter_markers(name="skipif"):
            if _marker_condition(mark):
                out.append(item.nodeid)
                break
    return out


def jar_gated(available, reason):
    """Decorator factory: mark a test as jar-gated and skip it when absent.

    The ``jar_gated`` marker is the identity — the skip reason is free text
    that CI enforcement never reads.
    """
    def decorate(fn):
        fn = pytest.mark.skipif(not available, reason=reason)(fn)
        fn = pytest.mark.jar_gated(fn)
        return fn
    return decorate
