"""
handlers/apkscan.py — shared zero-dependency APK byte scanning.

The machinery behind the ports of the npm server's ``strings(1)``-based
scans (``patterns.ts``'s ``scanText``/``renderResults`` plus the zip
guards of ``shared/zip.ts``): printable-string extraction (what
``strings -a -n 8`` yields), capped zip opening/entry reads
(``ANDROID_RE_MCP_MAX_FILE_MB`` / ``ANDROID_RE_MCP_MAX_ENTRY_MB``,
``0`` disables), and a pattern scanner that — like npm's ``scanText``
— records only patterns with at least one match (an empty entry would
make a diff report "no changes").

Pattern *tables* live with the tools that use them (``apkdiff._SECRET_
PATTERNS``, ``googleservices._GOOGLE_PATTERNS``); everything
source-agnostic lives here.
"""

from __future__ import annotations

import os
import re
import zipfile
from pathlib import Path

_MB = 1024 * 1024

FILE_CAP_ENV = "ANDROID_RE_MCP_MAX_FILE_MB"
DEFAULT_FILE_CAP_MB = 2048

ENTRY_CAP_ENV = "ANDROID_RE_MCP_MAX_ENTRY_MB"
DEFAULT_ENTRY_CAP_MB = 256

DEFAULT_TEXT_EXTS = (".json", ".xml", ".txt", ".properties", ".yaml", ".yml", ".plist")
DEX_ENTRY_RX = re.compile(r"^classes\d*\.dex$")


class PayloadTooLarge(ValueError):
    """Raised when an input or entry exceeds the configured size caps."""


def _env_max_mb(name: str, fallback: int) -> int:
    """Integer MB from env; ``0`` disables; anything else falls back."""
    raw = os.environ.get(name, "")
    try:
        parsed = int(raw)
    except ValueError:
        return fallback
    return parsed if parsed >= 0 else fallback


def _open_zip(path: str) -> zipfile.ZipFile:
    """Open an APK under ANDROID_RE_MCP_MAX_FILE_MB (0 disables)."""
    cap = _env_max_mb(FILE_CAP_ENV, DEFAULT_FILE_CAP_MB)
    if cap:
        size = Path(path).stat().st_size
        if size > cap * _MB:
            raise PayloadTooLarge(
                f"input file is {size / _MB:.1f} MB, above the {cap} MB cap "
                f"(raise {FILE_CAP_ENV}, or set it to 0 to disable the cap)"
            )
    try:
        return zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        raise zipfile.BadZipFile(f"cannot open {path} as a zip archive: {exc}") from exc


def _read_entry(zf: zipfile.ZipFile, info: zipfile.ZipInfo, cap_mb: int) -> bytes | None:
    """One entry under *cap_mb* MB (0 disables); None = skip."""
    if entry_over_cap(info, cap_mb):
        return None
    try:
        return zf.read(info)
    except Exception:  # noqa: BLE001 — corrupt entry: skip, don't fail the scan
        return None


def entry_cap_mb() -> int:
    """The per-entry cap in MB (ANDROID_RE_MCP_MAX_ENTRY_MB; 0 disables)."""
    return _env_max_mb(ENTRY_CAP_ENV, DEFAULT_ENTRY_CAP_MB)


def entry_over_cap(info: zipfile.ZipInfo, cap_mb: int) -> bool:
    """True when the entry exceeds *cap_mb* MB (0 disables the cap)."""
    return bool(cap_mb) and (info.file_size > cap_mb * _MB or info.compress_size > cap_mb * _MB)


def _printable_strings(data: bytes, min_len: int = 8) -> str:
    """The printable-ASCII runs of *data* (what ``strings -a -n 8`` yields)."""
    rx = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    return "\n".join(m.group(0).decode("ascii", "ignore") for m in rx.finditer(data))


def scan_text(
    text: str,
    patterns: list[tuple[str, re.Pattern[str], str]],
) -> dict[str, dict]:
    """One text over one ``(name, regex, risk)`` pattern set.

    Like the npm ``scanText``: matches are deduplicated per pattern and
    only patterns with at least one match are recorded.
    """
    results: dict[str, dict] = {}
    for name, rx, risk in patterns:
        matches: list[str] = []
        seen: set[str] = set()
        for match in rx.finditer(text):
            value = (match.group(1) if match.lastindex else match.group(0)).strip()
            if value and value not in seen:
                seen.add(value)
                matches.append(value)
        if matches:
            results[name] = {"risk": risk, "matches": matches}
    return results


def scan_zip(
    zf: zipfile.ZipFile,
    patterns: list[tuple[str, re.Pattern[str], str]],
    entry_cap: int,
    notes: list[str],
    *,
    dex: bool = True,
    arsc: bool = True,
    text_assets: bool = True,
) -> dict[str, dict]:
    """Scan an APK's zip sources for *patterns*, merging results across sources.

    Sources: ``classes*.dex`` + ``resources.arsc`` as printable strings
    (the npm ``collectRawApkSecrets`` behaviour) and, optionally,
    in-zip text assets under ``assets/``. Deduplication spans sources;
    over-cap entries are skipped with a note.
    """
    merged: dict[str, dict] = {}

    def absorb(part: dict[str, dict]) -> None:
        for name, entry in part.items():
            got = merged.get(name)
            if got is None:
                merged[name] = entry
                continue
            known = set(got["matches"])
            for value in entry["matches"]:
                if value not in known:
                    known.add(value)
                    got["matches"].append(value)

    for info in zf.infolist():
        name = info.filename
        if (dex and DEX_ENTRY_RX.match(name)) or (arsc and name == "resources.arsc"):
            data = _read_entry(zf, info, entry_cap)
            if data is None:
                notes.append(f"skipped: '{name}' above the per-entry cap")
                continue
            absorb(scan_text(_printable_strings(data), patterns))
        elif text_assets and name.startswith("assets/") and name.endswith(DEFAULT_TEXT_EXTS):
            data = _read_entry(zf, info, entry_cap)
            if data is None:
                notes.append(f"skipped: '{name}' above the per-entry cap")
                continue
            absorb(scan_text(data.decode("utf-8", "ignore"), patterns))
    return merged
