"""
handlers/caps.py — token conservation caps for heavy tool outputs (E-PY-15).

The android-unidbg-mcp strategy: a heavy list output is capped, and the
result carries the honest total, a truncation marker and an actionable
narrowing hint — so one tool call can never flood the assistant's context
window (the pattern unidbg-mcp ships as MAX_EXPORT_LINES: "N more symbols
omitted. Use filter parameter to search.").

The cap is server-wide and read per call, so it can be retuned without a
restart: ``ANDROID_RE_MCP_MAX_OUTPUT_LINES`` (default 200; ``0`` disables
capping and restores the pre-E-PY-15 behavior exactly).

Truncation is always structured, never a mid-JSON cut: the capped list
plus count fields, and every finding-class output (secrets) is capped
with its counts intact rather than silently shortened.
"""

from __future__ import annotations

import os
from typing import Any

DEFAULT_MAX_OUTPUT_LINES = 200

_ENV = "ANDROID_RE_MCP_MAX_OUTPUT_LINES"


def output_cap() -> int:
    """Server-wide item cap for heavy outputs; ``0`` disables capping."""
    raw = os.environ.get(_ENV, "")
    try:
        cap = int(raw)
    except ValueError:
        cap = DEFAULT_MAX_OUTPUT_LINES
    return max(0, cap)


def cap_items(items: list[Any], hint: str) -> tuple[list[Any], dict[str, Any]]:
    """Cap ``items`` unidbg-mcp style.

    Returns ``(shown, info)``. A result under the cap keeps its exact
    previous shape (``total``/``shown``/``truncated: False`` only); a
    truncated result adds ``truncated: True`` and the narrowing ``hint``
    ("N more omitted. <hint>").
    """
    total = len(items)
    cap = output_cap()
    if cap <= 0 or total <= cap:
        return items, {"total": total, "shown": total, "truncated": False}
    return items[:cap], {
        "total": total,
        "shown": cap,
        "truncated": True,
        "hint": f"{total - cap} more omitted. {hint}",
    }
