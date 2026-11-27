"""
handlers/native.py — Native library analysis handler.

Gaps covered:
  #1  native_strings    — strings/readelf on .so files
      native_exports    — enumerate exported symbols
      native_disasm     — radare2 batch disassembly of a function
  #8  il2cpp_dump       — run Il2CppDumper on a Unity APK
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_TIMEOUT = 120
_TIMEOUT_LONG = 300
from android_re_mcp.handlers.apkscan import _read_entry, entry_cap_mb
from android_re_mcp.handlers.caps import cap_items
from android_re_mcp.paths import scratch_dir, tools_dir

_TOOLS_DIR = tools_dir()


def _check(name: str) -> bool:
    return shutil.which(name) is not None


def _missing(tool: str, hint: str = "") -> dict:
    return {
        "status": "missing_tool",
        "tool": tool,
        "error": f"'{tool}' not found. Run android-re-mcp --setup, or install '{tool}' yourself.",
        "hint": hint,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_native_libs(apk_path: str, abi: str = "arm64-v8a") -> list[Path]:
    """Extract .so files for the requested ABI from an APK into a temp dir."""
    extracted: list[Path] = []
    try:
        with zipfile.ZipFile(apk_path) as zf:
            cap = entry_cap_mb()
            for name in zf.namelist():
                if f"lib/{abi}/" in name and name.endswith(".so"):
                    data = _read_entry(zf, zf.getinfo(name), cap)
                    if data is None:
                        continue
                    tmp = scratch_dir("native_libs") / Path(name).name
                    tmp.parent.mkdir(parents=True, exist_ok=True)
                    tmp.write_bytes(data)
                    extracted.append(tmp)
    except Exception as exc:  # noqa: BLE001
        logger.warning("APK extraction failed: %s", exc)
    return extracted


def _filter_interesting_strings(strings: list[str]) -> list[str]:
    """Heuristically filter strings that look like keys, URLs, or class names."""
    interesting = []
    for s in strings:
        if len(s) < 4:
            continue
        # URLs and endpoints
        if s.startswith(("http://", "https://", "ws://")) or "://" in s:
            interesting.append(s)
        # Looks like a path or package name
        elif "/" in s and len(s) > 8:
            interesting.append(s)
        # Hex-looking strings (possible keys)
        elif re.match(r"^[0-9a-fA-F]{16,}$", s):
            interesting.append(s)
        # Long words with mixed case (possible class names / symbols)
        elif len(s) > 20 and any(c.isupper() for c in s):
            interesting.append(s)
    return interesting


# ---------------------------------------------------------------------------
# APK-level native inventory (E-PY-14 — port of the npm android_native_libraries)
# ---------------------------------------------------------------------------
#
# Two identification layers, as in npm:
#   1. a known-library table (packers, RASP/anti-tamper, frameworks, SDKs,
#      runtimes) matched on the basename;
#   2. raw ELF header inspection — class/machine, section-header presence
#      and section-name list. Packers and protectors routinely strip or
#      merge sections, so shnum = 0 on an unpacked-looking .so is a
#      protection signal in its own right.
#
# Zero new dependencies: the ELF parser is struct-free int.from_bytes over
# the entry bytes, and the inventory reads the APK through the shared
# :mod:`apkscan` caps.

# Publicly documented Android native libraries (basename match), ported
# verbatim from the npm KNOWN_ANDROID_LIBS table (patterns, labels, kinds
# and per-entry case-insensitivity all preserved).
_KNOWN_ANDROID_LIBS: list[tuple[re.Pattern[str], str, str]] = [
    # ── Packers / protectors (dex-shelling, VMP) ──────────────────────────
    (re.compile(r"^libjiagu", re.I), "Qihoo 360 Jiagu (加固)", "packer"),
    (re.compile(r"^libDexHelper", re.I), "SecNeo", "packer"),
    (re.compile(r"^libexecmain|^libexecs?\."), "Ijiami (爱加密)", "packer"),
    (re.compile(r"^libchaosvmp"), "Naga (娜迦) VMP", "packer"),
    (re.compile(r"^libddiexec"), "Naga (娜迦)", "packer"),
    (re.compile(r"^libnesec"), "Naga (娜迦)", "packer"),
    (re.compile(r"^libshell"), "Tencent Legu (乐固)", "packer"),
    (re.compile(r"^libtup|^libtos\."), "Tencent Legu (乐固)", "packer"),
    (re.compile(r"^libSecShell", re.I), "Bangcle (梆梆安全)", "packer"),
    (re.compile(r"^libDexProtector", re.I), "DexProtector", "packer"),
    (re.compile(r"^libmobisec", re.I), "Alibaba Mobisec", "packer"),
    (re.compile(r"^libkwscmm|^libkwssgmain|^libkwslinker"), "KiwiSec (几维安全)", "packer"),
    # ── RASP / anti-tamper / anti-cheat ──────────────────────────────────
    (re.compile(r"^libAppGuard", re.I), "AppGuard (INKA Entworks)", "rasp"),
    (re.compile(r"^libsgmain|^libsgsecuritybody"), "Alibaba SecurityGuard (聚安全)", "rasp"),
    (re.compile(r"^libtprt", re.I), "Tencent TP (TenProtect)", "rasp"),
    (re.compile(r"^libnqshield", re.I), "NetQin (网秦)", "rasp"),
    # ── Frameworks / engines ─────────────────────────────────────────────
    (re.compile(r"^libflutter"), "Flutter engine", "framework"),
    (re.compile(r"^libreactnativejni"), "React Native", "framework"),
    (re.compile(r"^libunity"), "Unity engine", "framework"),
    (re.compile(r"^libil2cpp"), "Unity IL2CPP", "framework"),
    (re.compile(r"^libxamarin", re.I), "Xamarin", "framework"),
    (re.compile(r"^libmono"), "Mono runtime (Xamarin)", "framework"),
    (re.compile(r"^libgodot"), "Godot engine", "framework"),
    (re.compile(r"^libQt5"), "Qt", "framework"),
    # ── SDKs ─────────────────────────────────────────────────────────────
    (re.compile(r"^libBugly", re.I), "Tencent Bugly (crash reporting)", "sdk"),
    (re.compile(r"^libjpush", re.I), "JPush (极光推送)", "sdk"),
    (re.compile(r"^libgetuiext", re.I), "GeTui (个推)", "sdk"),
    (re.compile(r"^libumeng", re.I), "Umeng (友盟)", "sdk"),
    # ── Runtimes (benign, useful context) ────────────────────────────────
    (re.compile(r"^libc\+\+_shared"), "NDK libc++ runtime", "runtime"),
    (re.compile(r"^libhoudini"), "Intel ARM translation layer", "runtime"),
    (re.compile(r"^libRSSupport|^librsjni"), "RenderScript support", "runtime"),
]

_ELF_MACHINES = {3: "x86", 8: "MIPS", 40: "ARM", 62: "x86-64", 183: "ARM64", 243: "RISC-V"}
_ELF_MAGIC = b"\x7fELF"
_LIB_ENTRY_RX = re.compile(r"^lib/([^/]+)/([^/]+\.so)$")
_SECTIONS_CAP = 20


def match_known_lib(basename: str) -> dict | None:
    """The first known-library row whose pattern matches *basename*."""
    for rx, label, kind in _KNOWN_ANDROID_LIBS:
        if rx.search(basename):
            return {"label": label, "kind": kind}
    return None


def inspect_elf(data: bytes) -> dict:
    """Parse the interesting parts of an ELF header (+ section names).

    Never raises — a non-ELF blob reports ``ok: false``; a truncated
    header does too (the npm original could throw past its magic check,
    the port degrades instead).
    """

    def fail(detail: str) -> dict:
        return {"ok": False, "detail": detail, "machine": None, "shnum": None,
                "sections": None, "note": None}

    if len(data) < 0x34 or data[:4] != _ELF_MAGIC:
        return fail("not an ELF (missing \\x7fELF magic)")
    ei_class, ei_data = data[4], data[5]
    is64 = ei_class == 2
    if not is64 and ei_class != 1:
        return fail(f"ELF with unknown EI_CLASS {ei_class}")
    if ei_data != 1:
        return fail("big-endian ELF is not an Android ABI")

    # Fixed header fields end at 0x40 (ELF64) / 0x34 (ELF32); the npm
    # original could throw past its length check — the port degrades.
    header_len = 0x40 if is64 else 0x34
    if len(data) < header_len:
        return fail(f"truncated ELF header ({len(data)} < {header_len} bytes)")

    try:
        e_type = int.from_bytes(data[0x10:0x12], "little")
        e_machine = int.from_bytes(data[0x12:0x14], "little")
        machine = _ELF_MACHINES.get(e_machine, f"machine {e_machine}")
        type_str = {2: "EXEC", 3: "DYN (shared object)"}.get(e_type, f"type {e_type}")

        # Section-header table location differs between ELF32 and ELF64.
        width = 8 if is64 else 4
        shoff_off, shentsize_off, shnum_off, shstrndx_off = (
            (0x28, 0x3A, 0x3C, 0x3E) if is64 else (0x20, 0x2E, 0x30, 0x32)
        )
        shoff = int.from_bytes(data[shoff_off:shoff_off + width], "little")
        shentsize = int.from_bytes(data[shentsize_off:shentsize_off + 2], "little")
        shnum = int.from_bytes(data[shnum_off:shnum_off + 2], "little")
        shstrndx = int.from_bytes(data[shstrndx_off:shstrndx_off + 2], "little")

        sections: list[str] | None = None
        note: str | None = None

        if shoff == 0 or shnum == 0:
            note = "no section-header table (stripped or packed — common for packer/RASP payloads)"
        elif shstrndx in (0, 0xFFFF):
            note = "section headers present but no section-name table"
        elif shoff + shnum * shentsize <= len(data):
            str_hdr = shoff + shstrndx * shentsize
            str_off_field, str_size_field = (0x18, 0x20) if is64 else (0x10, 0x14)
            str_off = int.from_bytes(data[str_hdr + str_off_field:str_hdr + str_off_field + width], "little")
            str_size = int.from_bytes(data[str_hdr + str_size_field:str_hdr + str_size_field + width], "little")
            if str_off + str_size <= len(data):
                strtab = data[str_off:str_off + str_size]
                sections = []
                for i in range(shnum):
                    base = shoff + i * shentsize
                    sh_type = int.from_bytes(data[base + 4:base + 8], "little")
                    if sh_type == 0:
                        continue  # SHT_NULL carries no real name
                    name_off = int.from_bytes(data[base:base + 4], "little")
                    end = strtab.find(b"\x00", name_off)
                    name = "" if end == -1 else strtab[name_off:end].decode("latin-1")
                    if name:
                        sections.append(name)
        else:
            note = f"section-header table declares {shnum} entries beyond the file end (malformed or packed)"
    except IndexError:
        return fail("truncated ELF header")

    return {
        "ok": True,
        "detail": f"ELF {'64' if is64 else '32'}-bit {machine}, {type_str}",
        "machine": machine,
        "shnum": shnum,
        "sections": sections,
        "note": note,
    }


def apk_native_inventory(apk_path: str) -> dict:
    """Per-ABI ELF inventory of an APK (the npm tool's whole output).

    Every ``lib/<abi>/*.so`` entry is identified against
    ``_KNOWN_ANDROID_LIBS`` and ELF-inspected; packer/RASP matches and
    suspicious ELF layouts surface as ``protection_signals``. Opens the
    APK through the shared size caps; never raises — a bad APK reports
    ``{"error": ...}`` so callers can degrade gracefully.
    """
    from android_re_mcp.handlers import apkscan  # local: keep native.py import-light

    try:
        zf = apkscan._open_zip(apk_path)
    except (apkscan.PayloadTooLarge, zipfile.BadZipFile, OSError) as exc:
        return {"error": str(exc)}

    notes: list[str] = []
    by_abi: dict[str, list[dict]] = {}
    entry_cap = apkscan._env_max_mb(apkscan.ENTRY_CAP_ENV, apkscan.DEFAULT_ENTRY_CAP_MB)
    try:
        for info in zf.infolist():
            match = _LIB_ENTRY_RX.match(info.filename)
            if not match:
                continue
            abi, basename = match.group(1), match.group(2)
            lib: dict = {
                "entry": info.filename,
                "basename": basename,
                "size": info.file_size,
                "identified": match_known_lib(basename),
            }
            data = apkscan._read_entry(zf, info, entry_cap)
            if data is None:
                lib["elf"] = None
                lib["note"] = f"skipped: above the {entry_cap} MB per-entry cap"
                notes.append(f"skipped: '{info.filename}' above the per-entry cap")
            else:
                elf = inspect_elf(data)
                lib["elf"] = elf
                if elf.get("sections") and len(elf["sections"]) > _SECTIONS_CAP:
                    elf["sections_extra"] = len(elf["sections"]) - _SECTIONS_CAP
                    elf["sections"] = elf["sections"][:_SECTIONS_CAP]
                if elf.get("note"):
                    notes.append(f"{basename}: {elf['note']}")
            by_abi.setdefault(abi, []).append(lib)
    finally:
        zf.close()

    signals: list[str] = []
    for abi in sorted(by_abi):
        for lib in by_abi[abi]:
            known, elf = lib.get("identified"), lib.get("elf")
            if known and known["kind"] in ("packer", "rasp"):
                note = elf.get("note") if elf else None
                signals.append(
                    f"{lib['basename']}: {known['label']} ({known['kind']})"
                    + (f" — {note}" if note else "")
                )
            elif not known and elf is not None and elf.get("note"):
                signals.append(
                    f"{lib['basename']}: unrecognised library with a suspicious "
                    f"ELF layout — {elf['note']}"
                )

    counts = {"packer": 0, "rasp": 0, "framework": 0, "sdk": 0, "runtime": 0}
    identified = 0
    total = 0
    for libs in by_abi.values():
        for lib in libs:
            total += 1
            known = lib.get("identified")
            if known:
                identified += 1
                counts[known["kind"]] += 1

    return {
        "by_abi": {abi: by_abi[abi] for abi in sorted(by_abi)},
        "no_native_code": total == 0,
        **({"note": "No lib/<abi>/*.so entries — the APK ships no native code."} if total == 0 else {}),
        "protection_signals": signals,
        "summary": {"total": total, "abis": len(by_abi), "identified": identified, **counts},
        "notes": notes[:5],
    }


class NativeHandler:
    """Native library analysis handler."""

    # =========================================================================
    # Gap #1 — native_strings
    # =========================================================================

    def native_strings(self, args: dict) -> dict:
        """Extract printable strings from a .so file or all .so files in an APK.

        Uses `strings` binary if available, falls back to pure-Python
        extraction for Windows compatibility.
        """
        so_path = args.get("so_path", "")
        apk_path = args.get("apk_path", "")
        abi = args.get("abi", "arm64-v8a")
        min_len = int(args.get("min_len", 8))
        interesting_only = bool(args.get("interesting_only", True))

        so_files: list[Path] = []

        if so_path and Path(so_path).exists():
            so_files = [Path(so_path)]
        elif apk_path:
            so_files = _extract_native_libs(apk_path, abi)
        else:
            return {"status": "error", "tool": "native_strings",
                    "error": "Provide so_path or apk_path"}

        all_results: dict[str, dict] = {}
        # E-PY-15: cap each lib's string list (ANDROID_RE_MCP_MAX_OUTPUT_LINES,
        # default 200) — total_strings stays honest and the hint names the
        # narrowing knobs, so a big .so can't flood the model context.
        for so in so_files:
            strings_list = self._extract_strings(so, min_len)
            filtered = _filter_interesting_strings(strings_list) if interesting_only else strings_list
            shown, info = cap_items(
                filtered,
                "raise min_len, set interesting_only=false to widen, or run search_strings over the extracted .so",
            )
            entry: dict = {
                "total_strings": len(strings_list),
                "shown": len(shown),
                "strings": shown,
            }
            if info["truncated"]:
                entry["truncated"] = True
                entry["hint"] = info["hint"]
            all_results[so.name] = entry

        return {
            "status": "ok",
            "tool": "native_strings",
            "output": {
                "libs_analyzed": len(so_files),
                "interesting_only": interesting_only,
                "results": all_results,
            },
        }

    def _extract_strings(self, so_path: Path, min_len: int) -> list[str]:
        """Run `strings` binary or fall back to pure-Python extraction."""
        if _check("strings"):
            try:
                proc = subprocess.run(
                    ["strings", f"-n{min_len}", str(so_path)],
                    capture_output=True, text=True, timeout=_TIMEOUT,
                )
                return [s.strip() for s in proc.stdout.splitlines() if s.strip()]
            except Exception:  # noqa: BLE001
                pass

        # Pure-Python fallback (covers Windows where `strings` isn't on PATH)
        data = so_path.read_bytes()
        printable = set(range(0x20, 0x7F)) | {0x09, 0x0A}
        current: list[int] = []
        found: list[str] = []
        for byte in data:
            if byte in printable:
                current.append(byte)
            else:
                if len(current) >= min_len:
                    found.append(bytes(current).decode("ascii", errors="ignore"))
                current = []
        if len(current) >= min_len:
            found.append(bytes(current).decode("ascii", errors="ignore"))
        return found

    # =========================================================================
    # Gap #1 — native_exports
    # =========================================================================

    def native_exports(self, args: dict) -> dict:
        """List exported symbols from a .so using readelf or nm.

        Falls back to pure ELF parsing for Windows compatibility.
        """
        so_path = args.get("so_path", "")
        apk_path = args.get("apk_path", "")
        abi = args.get("abi", "arm64-v8a")

        so_files: list[Path] = []
        if so_path and Path(so_path).exists():
            so_files = [Path(so_path)]
        elif apk_path:
            so_files = _extract_native_libs(apk_path, abi)
        else:
            return {"status": "error", "tool": "native_exports",
                    "error": "Provide so_path or apk_path"}

        all_results: dict[str, list[dict]] = {}

        for so in so_files:
            exports = self._get_exports(so)
            all_results[so.name] = exports

        total = sum(len(v) for v in all_results.values())
        return {
            "status": "ok",
            "tool": "native_exports",
            "output": {
                "libs_analyzed": len(so_files),
                "total_exports": total,
                "exports": all_results,
            },
        }

    def _get_exports(self, so_path: Path) -> list[dict]:
        """Return exports via readelf → nm → pure ELF fallback."""
        # Try readelf first
        if _check("readelf"):
            try:
                proc = subprocess.run(
                    ["readelf", "--dyn-syms", "--wide", str(so_path)],
                    capture_output=True, text=True, timeout=_TIMEOUT,
                )
                return self._parse_readelf(proc.stdout)
            except Exception:  # noqa: BLE001
                pass

        # Try nm
        if _check("nm"):
            try:
                proc = subprocess.run(
                    ["nm", "--dynamic", "--defined-only", str(so_path)],
                    capture_output=True, text=True, timeout=_TIMEOUT,
                )
                return self._parse_nm(proc.stdout)
            except Exception:  # noqa: BLE001
                pass

        # Pure ELF fallback
        return self._parse_elf_exports(so_path)

    def _parse_readelf(self, output: str) -> list[dict]:
        exports = []
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 8 and parts[4] in ("FUNC", "OBJECT"):
                exports.append({
                    "name": parts[7],
                    "type": parts[4],
                    "size": parts[2],
                    "bind": parts[5],
                })
        return exports

    def _parse_nm(self, output: str) -> list[dict]:
        exports = []
        for line in output.splitlines():
            parts = line.strip().split(None, 2)
            if len(parts) == 3:
                exports.append({"address": parts[0], "type": parts[1], "name": parts[2]})
        return exports

    def _parse_elf_exports(self, so_path: Path) -> list[dict]:
        """Minimal ELF dynamic symbol table parser (pure Python, ARM64/x86_64)."""
        try:
            data = so_path.read_bytes()
        except Exception:  # noqa: BLE001
            return []

        if len(data) < 64 or data[:4] != b"\x7fELF":
            return []

        import struct

        is_64 = data[4] == 2  # EI_CLASS
        le = data[5] == 1     # EI_DATA little-endian

        endian = "<" if le else ">"

        if is_64:
            e_shoff, = struct.unpack_from(endian + "Q", data, 40)
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + "HHH", data, 58)
            sh_fmt = endian + "IIQQQQIIQQ"
            sym_fmt = endian + "IBBHQQ"
            sym_size = 24
        else:
            e_shoff, = struct.unpack_from(endian + "I", data, 32)
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + "HHH", data, 48)
            sh_fmt = endian + "IIIIIIIIII"
            sym_fmt = endian + "IIIBBH"
            sym_size = 16

        exports: list[dict] = []

        try:
            sections = []
            for i in range(e_shnum):
                off = e_shoff + i * e_shentsize
                sh = struct.unpack_from(sh_fmt, data, off)
                sections.append(sh)

            strtab_data = b""
            dynsym_section = None

            for sh in sections:
                SHT_DYNSYM = 11
                SHT_STRTAB = 3
                if sh[1] == SHT_DYNSYM:
                    dynsym_section = sh
                elif sh[1] == SHT_STRTAB and strtab_data == b"":
                    strtab_off, strtab_sz = (sh[4], sh[5]) if is_64 else (sh[4], sh[5])
                    strtab_data = data[strtab_off: strtab_off + strtab_sz]

            if dynsym_section:
                ds_off = dynsym_section[4] if is_64 else dynsym_section[4]
                ds_sz = dynsym_section[5] if is_64 else dynsym_section[5]
                count = ds_sz // sym_size
                for i in range(count):
                    sym = struct.unpack_from(sym_fmt, data, ds_off + i * sym_size)
                    name_off = sym[0]
                    if strtab_data and name_off < len(strtab_data):
                        end = strtab_data.index(b"\x00", name_off)
                        name = strtab_data[name_off:end].decode("utf-8", errors="ignore")
                        if name:
                            exports.append({"name": name, "type": "ELF_SYM"})
        except Exception:  # noqa: BLE001
            pass

        return exports

    # =========================================================================
    # Gap #1 — native_disasm
    # =========================================================================

    def native_disasm(self, args: dict) -> dict:
        """Disassemble a function or offset in a .so using radare2 (r2).

        Requires radare2 (`r2`) on PATH.
        """
        if not _check("r2"):
            return _missing("r2", "sudo apt install radare2  OR  brew install radare2")

        so_path = args.get("so_path", "")
        target = args.get("target", "")        # symbol name or 0x<hex> offset
        n_instructions = max(1, min(int(args.get("n_instructions", 32)), 2000))
        mode = args.get("mode", "asm")         # asm | graph | pseudocode

        if not so_path or not Path(so_path).exists():
            return {"status": "error", "tool": "native_disasm",
                    "error": f"so_path '{so_path}' not found"}

        # radare2 treats ';' and '!' as command syntax, so only plain symbols and offsets get through.
        # '@' is allowed only as a Ghidra-style '@plt' suffix: radare2 uses '@'/'@@'
        # as its own operators, and a 'foo@@bar' target would run an iterator.
        if not re.fullmatch(r"(0x[0-9a-fA-F]{1,16}|[A-Za-z0-9_.]{1,196}(?:@plt)?)", target):
            return {"status": "error", "tool": "native_disasm",
                    "error": "target must be a symbol name, an 0x offset, or a symbol with an @plt suffix"}
        seek = f"sym.{target}" if not target.startswith("0x") else target

        if mode == "graph":
            r2_cmds = f"aaa; agf @ {seek}"
        elif mode == "pseudocode":
            r2_cmds = f"aaa; pdg @ {seek}"
        else:
            r2_cmds = f"aaa; pd {n_instructions} @ {seek}; pif @ {seek}"

        try:
            proc = subprocess.run(
                ["r2", "-q", "-c", r2_cmds, str(so_path)],
                capture_output=True, text=True, timeout=_TIMEOUT_LONG,
            )
            if proc.returncode != 0 and not proc.stdout:
                return {"status": "error", "tool": "native_disasm",
                        "error": proc.stderr or "r2 returned no output"}

            return {
                "status": "ok",
                "tool": "native_disasm",
                "output": {
                    "so_path": so_path,
                    "target": target,
                    "mode": mode,
                    "disassembly": proc.stdout,
                },
            }
        except subprocess.TimeoutExpired:
            return {"status": "error", "tool": "native_disasm",
                    "error": "r2 timed out after 300s"}
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "native_disasm", "error": str(exc)}

    # =========================================================================
    # Gap #8 — il2cpp_dump
    # =========================================================================

    def il2cpp_dump(self, args: dict) -> dict:
        """Run Il2CppDumper on a Unity IL2CPP APK.

        Extracts `global-metadata.dat` and `libil2cpp.so` from the APK,
        then runs Il2CppDumper to recover a `dump.cs` symbol file.

        Requires `dotnet` runtime + Il2CppDumper from https://github.com/Perfare/Il2CppDumper
        """
        apk_path = args.get("apk_path", "")
        abi = args.get("abi", "arm64-v8a")
        output_dir = args.get("output_dir", "")

        if not apk_path or not Path(apk_path).exists():
            return {"status": "error", "tool": "il2cpp_dump",
                    "error": f"apk_path '{apk_path}' not found"}

        # Find Il2CppDumper
        dumper_paths = [
            _TOOLS_DIR / "il2cppdumper" / "Il2CppDumper",
            _TOOLS_DIR / "il2cppdumper" / "Il2CppDumper.exe",
            Path("/opt/il2cppdumper/Il2CppDumper"),
        ]
        dumper_bin: Optional[Path] = None
        for p in dumper_paths:
            if p.exists():
                dumper_bin = p
                break
        if dumper_bin is None and _check("Il2CppDumper"):
            dumper_bin = Path(shutil.which("Il2CppDumper"))  # type: ignore[arg-type]

        if dumper_bin is None:
            return {
                "status": "missing_tool",
                "tool": "il2cpp_dump",
                "error": "Il2CppDumper not found",
                "hint": (
                    "Download from https://github.com/Perfare/Il2CppDumper/releases\n"
                    f"Extract to {_TOOLS_DIR}/il2cppdumper/"
                ),
            }

        out_dir = Path(output_dir) if output_dir else Path(apk_path).parent / "il2cpp_out"
        out_dir.mkdir(parents=True, exist_ok=True)

        # Extract required files from APK
        metadata_path = out_dir / "global-metadata.dat"
        il2cpp_so_path = out_dir / f"libil2cpp_{abi}.so"

        try:
            with zipfile.ZipFile(apk_path) as zf:
                names = zf.namelist()

                meta_name = next(
                    (n for n in names if "global-metadata.dat" in n), None
                )
                if meta_name:
                    data = _read_entry(zf, zf.getinfo(meta_name), entry_cap_mb())
                    if data is not None:
                        metadata_path.write_bytes(data)

                il2cpp_name = next(
                    (n for n in names if f"lib/{abi}/libil2cpp.so" in n), None
                )
                if il2cpp_name:
                    data = _read_entry(zf, zf.getinfo(il2cpp_name), entry_cap_mb())
                    if data is not None:
                        il2cpp_so_path.write_bytes(data)

        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "il2cpp_dump",
                    "error": f"APK extraction failed: {exc}"}

        if not metadata_path.exists():
            return {"status": "error", "tool": "il2cpp_dump",
                    "error": "global-metadata.dat not found in APK. Is this a Unity IL2CPP app?"}
        if not il2cpp_so_path.exists():
            return {"status": "error", "tool": "il2cpp_dump",
                    "error": f"libil2cpp.so for abi={abi} not found in APK."}

        # Run Il2CppDumper
        try:
            cmd = [str(dumper_bin), str(il2cpp_so_path), str(metadata_path), str(out_dir)]
            if not _check("Il2CppDumper") and str(dumper_bin).endswith(".exe"):
                cmd = ["dotnet", str(dumper_bin)] + cmd[1:]

            proc = subprocess.run(
                cmd,
                capture_output=True, text=True,
                cwd=str(out_dir),
                timeout=_TIMEOUT_LONG,
            )

            dump_cs = out_dir / "dump.cs"
            script_json = out_dir / "script.json"

            return {
                "status": "ok" if dump_cs.exists() else "error",
                "tool": "il2cpp_dump",
                "output": {
                    "output_dir": str(out_dir),
                    "dump_cs": str(dump_cs) if dump_cs.exists() else None,
                    "script_json": str(script_json) if script_json.exists() else None,
                    "raw": proc.stdout[-2000:] if proc.stdout else proc.stderr[-2000:],
                    "note": (
                        "dump.cs contains class/method names. "
                        "Use with Ghidra Il2CppDumper script for full analysis."
                    ),
                },
            }
        except subprocess.TimeoutExpired:
            return {"status": "error", "tool": "il2cpp_dump",
                    "error": "Il2CppDumper timed out after 300s"}
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "il2cpp_dump", "error": str(exc)}
