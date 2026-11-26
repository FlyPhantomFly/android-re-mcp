"""Shared helpers for the ``ANDROID_RE_MCP_REQUIRE_JAR`` gate.

Kept in an importable module (not conftest-only) so the logic is
unit-testable without a jar, a device, or a pytester subprocess.
"""

from __future__ import annotations

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
    """Nodeids whose skipif condition holds AND whose reason names the jar.

    Checking the condition matters: the skipif booleans are evaluated at
    module import, so with the jar installed the reason text is still there
    but the test would run — it must not be counted as a would-skip.
    """
    out: list[str] = []
    for item in items:
        for mark in item.iter_markers(name="skipif"):
            if not _marker_condition(mark):
                continue
            if any(NEEDLE in reason for reason in _skipif_reasons(mark)):
                out.append(item.nodeid)
                break
    return out
