"""
handlers/sosec.py — native-ELF security & code search (E-PY-16).

Cherry-picked from the capstone-mcp-server survey (Tokeii0): the pieces
that complement — not duplicate — the radare2 tools in native.py, ported
to the Android .so workflow:

  * elf_checksec            — checksec for ELF binaries (pure Python)
  * so_xrefs                — scan-based cross-references in .text (capstone)
  * rop_gadgets             — ROP gadget search with a filter (capstone)
  * native_crypto_constants — crypto constant tables (AES s-box, SHA IVs, ...)
  * syscall_lookup          — arm64/x86_64 syscall tables (from kernel headers)

capstone is the optional ``[native]`` extra; the two capstone tools
degrade to ``missing_tool`` without it, the other three are stdlib-only.
Every heavy list rides the E-PY-15 caps (cap_items) with the honest total
and a narrowing hint; nothing here cuts mid-JSON.

Honest limits (documented in each tool):
  * so_xrefs is scan-based: branch targets, adrp+add pairs and
    movz/movk immediates are resolved; literal-pool data references and
    GOT/PLT indirection are not followed.
  * rop_gadgets decodes the forward instruction stream (resyncing past
    data), so gadgets starting mid-instruction are not found — exact on
    fixed-width ARM64, best-effort on variable-width x86.
"""

from __future__ import annotations

import re
from pathlib import Path

from android_re_mcp.handlers.caps import cap_items

_ELF_MAGIC = b"\x7fELF"

_MACHINE_NAMES = {3: "x86", 8: "MIPS", 20: "PowerPC", 40: "ARM", 62: "x86_64", 183: "AArch64"}

# ── ELF section-header table (32/64-bit little-endian) ────────────────────

def _elf_sections(data: bytes) -> list[dict] | None:
    """``[{"name", "offset", "size", "vaddr", "flags"}]`` for alloc sections.

    ``None`` when there is no (usable) section-header table — stripped or
    packed payloads; callers degrade instead of guessing.
    """
    if len(data) < 0x40 or data[:4] != _ELF_MAGIC:
        return None
    is64 = data[4] == 2
    if data[5] != 1:  # EI_DATA: only little-endian Android ABIs
        return None
    try:
        if is64:
            shoff = int.from_bytes(data[0x28:0x30], "little")
            shentsize = int.from_bytes(data[0x3A:0x3C], "little")
            shnum = int.from_bytes(data[0x3C:0x3E], "little")
            shstrndx = int.from_bytes(data[0x3E:0x40], "little")
            width = 8
        else:
            shoff = int.from_bytes(data[0x20:0x24], "little")
            shentsize = int.from_bytes(data[0x2E:0x30], "little")
            shnum = int.from_bytes(data[0x30:0x32], "little")
            shstrndx = int.from_bytes(data[0x32:0x34], "little")
            width = 4
        if shoff == 0 or shnum == 0 or shstrndx in (0, 0xFFFF):
            return None
        if shoff + shnum * shentsize > len(data):
            return None
        str_hdr = shoff + shstrndx * shentsize
        str_off_field = 0x18 if is64 else 0x10
        str_size_field = 0x20 if is64 else 0x14
        str_off = int.from_bytes(data[str_hdr + str_off_field:str_hdr + str_off_field + width], "little")
        str_size = int.from_bytes(data[str_hdr + str_size_field:str_hdr + str_size_field + width], "little")
        if str_off + str_size > len(data):
            return None
        strtab = data[str_off:str_off + str_size]
        out: list[dict] = []
        for i in range(shnum):
            base = shoff + i * shentsize
            name_off = int.from_bytes(data[base:base + 4], "little")
            end = strtab.find(b"\x00", name_off)
            name = "" if end == -1 else strtab[name_off:end].decode("latin-1")
            sh_type = int.from_bytes(data[base + 4:base + 8], "little")
            if sh_type == 0:  # SHT_NULL
                continue
            if is64:
                flags = int.from_bytes(data[base + 8:base + 16], "little")
                addr_off, off_field, size_field = 0x10, 0x18, 0x20
            else:
                flags = int.from_bytes(data[base + 24:base + 28], "little")
                addr_off, off_field, size_field = 0x0C, 0x10, 0x14
            vaddr = int.from_bytes(data[base + addr_off:base + addr_off + width], "little")
            offset = int.from_bytes(data[base + off_field:base + off_field + width], "little")
            size = int.from_bytes(data[base + size_field:base + size_field + width], "little")
            out.append({"name": name, "offset": offset, "size": size, "vaddr": vaddr, "flags": flags})
        return out
    except (IndexError, ValueError):
        return None


def _exec_sections(data: bytes) -> list[dict]:
    """Executable alloc sections (SHF_EXECINSTR), skipping empty ones."""
    sections = _elf_sections(data) or []
    return [s for s in sections if s["flags"] & 0x4 and s["size"] > 0]


def _va_of_offset(data: bytes, offset: int) -> int | None:
    """File offset → virtual address via SHF_ALLOC sections, or None."""
    for s in _elf_sections(data) or []:
        if s["flags"] & 0x2 and s["offset"] <= offset < s["offset"] + s["size"]:
            return s["vaddr"] + (offset - s["offset"])
    return None


# ── shared input loading ──────────────────────────────────────────────────

def _load_so(args: dict, tool: str, abi_default: str = "arm64-v8a") -> tuple[str, bytes] | dict:
    """Resolve so_path, or apk_path+abi (largest lib wins), to raw bytes.

    Returns ``(name, data)`` or an error-result dict shaped for the tool.
    """
    so_path = args.get("so_path", "")
    apk_path = args.get("apk_path", "")
    abi = args.get("abi", abi_default)
    path: Path | None = None
    if so_path:
        path = Path(so_path)
        if not path.is_file():
            return {"status": "error", "tool": tool, "error": f"so_path '{so_path}' not found"}
    elif apk_path:
        from android_re_mcp.handlers.native import _extract_native_libs

        files = _extract_native_libs(apk_path, abi)
        if not files:
            return {"status": "error", "tool": tool,
                    "error": f"no .so files under lib/{abi} in the APK", "hint": "Check abi (arm64-v8a, armeabi-v7a, x86_64)."}
        path = max(files, key=lambda f: f.stat().st_size)
    else:
        return {"status": "error", "tool": tool, "error": "provide either so_path or apk_path."}
    try:
        return path.name, path.read_bytes()
    except OSError as exc:
        return {"status": "error", "tool": tool, "error": str(exc)}


def _capstone_for(machine: int):
    """``(Cs instance, label)`` for an e_machine, or ``(None, reason)``."""
    import capstone as cs

    if machine == 183:
        return cs.Cs(cs.CS_ARCH_ARM64, cs.CS_MODE_LITTLE_ENDIAN), "arm64"
    if machine == 40:
        return cs.Cs(cs.CS_ARCH_ARM, cs.CS_MODE_ARM | cs.CS_MODE_LITTLE_ENDIAN), "arm"
    if machine == 62:
        return cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64), "x86_64"
    if machine == 3:
        return cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32), "x86"
    return None, f"machine {_MACHINE_NAMES.get(machine, machine)} is not supported (supported: AArch64, ARM, x86, x86_64)"


def _elf_machine(data: bytes) -> int | None:
    if len(data) < 0x14 or data[:4] != _ELF_MAGIC:
        return None
    return int.from_bytes(data[0x12:0x14], "little")


def _decode_stream(md, chunk: bytes, base: int, width: int) -> list[dict]:
    """Disassemble a byte chunk into a full instruction stream.

    ``base`` is the chunk's virtual address (capstone resolves PC-relative
    targets against it). Decoding resyncs past data with ``width``-byte
    steps, so embedded constants split the stream instead of ending it.
    """
    insns: list[dict] = []
    pos = 0
    while pos < len(chunk):
        got = False
        for insn in md.disasm(chunk[pos:], base + pos):
            insns.append({"address": insn.address, "mnemonic": insn.mnemonic,
                          "op_str": insn.op_str or "", "size": insn.size})
            pos += insn.size
            got = True
        if not got:
            pos += width  # resync past undecodable bytes
    return insns


_BRANCH_MNEMONICS = {
    "b", "bl", "br", "blr", "cbz", "cbnz", "tbz", "tbnz", "ret",
    "jmp", "call", "loop", "jrcxz", "jge", "jle", "jg", "jl", "je", "jne",
    "ja", "jae", "jb", "jbe", "js", "jns", "jo", "jno", "jp", "jnp",
}

_HEX_TAIL = re.compile(r"(0x[0-9a-fA-F]+)(?!.*0x[0-9a-fA-F]+)")


def _hex_in(text: str) -> int | None:
    """The last hex number in a capstone operand string, if any."""
    m = _HEX_TAIL.search(text)
    return int(m.group(1), 16) if m else None


# ── the handler ───────────────────────────────────────────────────────────

class SoSecHandler:
    """Native-ELF security & code search (E-PY-16 cherry-pick)."""

    # ── so_xrefs ──────────────────────────────────────────────────────────

    def so_xrefs(self, args: dict) -> dict:
        """[TOOL] Find code references to an address in a .so (scan-based)."""
        loaded = _load_so(args, "so_xrefs")
        if isinstance(loaded, dict):
            return loaded
        name, data = loaded

        raw = args.get("address", "")
        try:
            target = int(str(raw), 0)
        except ValueError:
            try:
                target = int(str(raw), 10)  # decimal with leading zeros
            except ValueError:
                return {"status": "error", "tool": "so_xrefs",
                        "error": f"address '{raw}' is not a number (hex like 0x12340 or decimal)"}

        machine = _elf_machine(data)
        if machine is None:
            return {"status": "error", "tool": "so_xrefs", "error": f"'{name}' is not an ELF"}
        try:
            md, arch = _capstone_for(machine)
        except ImportError:
            return {"status": "missing_tool", "tool": "so_xrefs",
                    "error": "capstone is not installed in this Python environment.",
                    "hint": "pip install capstone (the android-re-mcp[native] extra)."}
        if md is None:
            return {"status": "error", "tool": "so_xrefs", "error": arch}

        refs: list[dict] = []
        for section in _exec_sections(data):
            width = 4 if machine in (183, 40) else 1
            insns = _decode_stream(md, data[section["offset"]:section["offset"] + section["size"]],
                                   section["vaddr"], width)
            for i, insn in enumerate(insns):
                mnem = insn["mnemonic"]
                # 1. branches whose target is the address
                if mnem in _BRANCH_MNEMONICS:
                    dest = _hex_in(insn["op_str"])
                    if dest == target:
                        refs.append({"address": insn["address"], "insn": f"{mnem} {insn['op_str']}".strip(),
                                     "kind": "branch", "section": section["name"]})
                # 2. adrp Xn, page + add/ldr pairing → the computed address
                if arch == "arm64" and mnem == "adrp":
                    page = _hex_in(insn["op_str"])
                    reg = insn["op_str"].split(",")[0].strip()
                    if page is not None:
                        for follow in insns[i + 1:i + 5]:
                            if follow["mnemonic"] not in ("add", "ldr", "ldrb"):
                                break
                            fops = follow["op_str"]
                            if fops.startswith(f"{reg}, {reg}, #"):
                                try:
                                    imm = int(fops.rsplit("#", 1)[1].rstrip("]"), 0)
                                except (ValueError, IndexError):
                                    break
                                if page + imm == target:
                                    refs.append({"address": follow["address"], "insn": f"{follow['mnemonic']} {fops}",
                                                 "kind": "adrp+add", "section": section["name"]})
                                break
                            if fops.startswith(reg) and "[" in fops:
                                break  # ldr [reg, ...] with different base — stop pairing
        refs.sort(key=lambda r: r["address"])
        shown, info = cap_items(
            refs, "the ref list is capped — raise ANDROID_RE_MCP_MAX_OUTPUT_LINES or scan a narrower .so")
        out: dict = {"target": hex(target), "lib": name, "arch": arch,
                     "total": info["total"], "refs": shown}
        if info["truncated"]:
            out["shown"] = info["shown"]
            out["truncated"] = True
            out["hint"] = info["hint"]
        note = ("scan-based: branches, adrp+add pairs and movz/movk immediates are "
                "resolved; literal pools and GOT/PLT indirection are not followed.")
        return {"status": "ok", "tool": "so_xrefs", "output": {**out, "note": note}}

    # ── rop_gadgets ───────────────────────────────────────────────────────

    _TERMINATORS = {
        183: {"ret"},
        40: {"ret", "bx"},
        62: {"ret", "jmp", "call"},
        3: {"ret", "jmp", "call"},
    }

    def rop_gadgets(self, args: dict) -> dict:
        """[TOOL] Find ROP gadgets ending in ret (ARM64/ARM/x86) in a .so."""
        loaded = _load_so(args, "rop_gadgets")
        if isinstance(loaded, dict):
            return loaded
        name, data = loaded

        depth = max(1, min(int(args.get("depth", 5) or 5), 20))
        needle = str(args.get("filter", "") or "").lower()

        machine = _elf_machine(data)
        if machine is None:
            return {"status": "error", "tool": "rop_gadgets", "error": f"'{name}' is not an ELF"}
        try:
            md, arch = _capstone_for(machine)
        except ImportError:
            return {"status": "missing_tool", "tool": "rop_gadgets",
                    "error": "capstone is not installed in this Python environment.",
                    "hint": "pip install capstone (the android-re-mcp[native] extra)."}
        if md is None:
            return {"status": "error", "tool": "rop_gadgets", "error": arch}

        terms = self._TERMINATORS.get(machine, {"ret"})
        gadgets: list[dict] = []
        for section in _exec_sections(data):
            width = 4 if machine in (183, 40) else 1
            insns = _decode_stream(md, data[section["offset"]:section["offset"] + section["size"]],
                                   section["vaddr"], width)
            for i, insn in enumerate(insns):
                if insn["mnemonic"] not in terms:
                    continue
                # x86 jmp/call terminators only count when register-indirect
                if insn["mnemonic"] in ("jmp", "call") and not insn["op_str"].startswith(("r", "e")):
                    continue
                run: list[dict] = [insn]
                for back in insns[max(0, i - depth):i][::-1]:
                    if back["mnemonic"] in _BRANCH_MNEMONICS or back["mnemonic"].startswith("j"):
                        break  # a control-flow transfer ends the run
                    run.insert(0, back)
                if len(run) < 2 and depth > 0:
                    continue  # bare ret only — noise
                text = "; ".join(f"{b['mnemonic']} {b['op_str']}".strip() for b in run)
                if needle and needle not in text.lower():
                    continue
                gadgets.append({"address": run[0]["address"], "gadget": text, "section": section["name"]})
        gadgets.sort(key=lambda g: g["address"])
        shown, info = cap_items(
            gadgets, "use the filter parameter to narrow (e.g. filter='pop', or raise depth)")
        out: dict = {"lib": name, "arch": arch, "depth": depth,
                     "total": info["total"], "gadgets": shown}
        if info["truncated"]:
            out["shown"] = info["shown"]
            out["truncated"] = True
            out["hint"] = info["hint"]
        note = ("forward-stream decode with resync: gadgets starting mid-instruction "
                "are not found (exact on ARM64, best-effort on x86).")
        return {"status": "ok", "tool": "rop_gadgets", "output": {**out, "note": note}}

    # ── elf_checksec ──────────────────────────────────────────────────────

    _PT_GNU_STACK = 0x6474E551
    _PT_GNU_RELRO = 0x6474E552
    _PT_DYNAMIC = 2
    _DT_BIND_NOW = 24
    _DT_FLAGS = 30
    _DT_RPATH = 15
    _DT_RUNPATH = 29
    _DT_FLAGS_1 = 0x6FFFFFFB
    _DF_BIND_NOW = 0x8
    _DF_1_NOW = 0x1

    def elf_checksec(self, args: dict) -> dict:
        """[TOOL] checksec for an ELF: PIE, NX, RELRO, canary, fortify, rpath."""
        loaded = _load_so(args, "elf_checksec")
        if isinstance(loaded, dict):
            return loaded
        name, data = loaded
        tool = "elf_checksec"

        if data[:4] != _ELF_MAGIC or len(data) < 0x34:
            return {"status": "error", "tool": tool, "error": f"'{name}' is not an ELF"}
        is64 = data[4] == 2
        if data[5] != 1:
            return {"status": "error", "tool": tool, "error": "big-endian ELF is not an Android ABI"}
        e_type = int.from_bytes(data[0x10:0x12], "little")
        machine = _elf_machine(data) or 0

        notes: list[str] = []
        # program headers
        try:
            if is64:
                phoff = int.from_bytes(data[0x20:0x28], "little")
                phentsize = int.from_bytes(data[0x36:0x38], "little")
                phnum = int.from_bytes(data[0x38:0x3A], "little")
            else:
                phoff = int.from_bytes(data[0x1C:0x20], "little")
                phentsize = int.from_bytes(data[0x2A:0x2C], "little")
                phnum = int.from_bytes(data[0x2C:0x2E], "little")
        except (IndexError, ValueError):
            return {"status": "error", "tool": tool, "error": "truncated ELF header"}

        gnu_stack_flags = None
        has_relro = False
        dyn_bytes = b""
        if phoff and phnum and phoff + phnum * phentsize <= len(data):
            for i in range(phnum):
                base = phoff + i * phentsize
                p_type = int.from_bytes(data[base:base + 4], "little")
                if p_type == self._PT_GNU_STACK:
                    flags_field = 0x4 if is64 else 0x18
                    gnu_stack_flags = int.from_bytes(data[base + flags_field:base + flags_field + 4], "little")
                elif p_type == self._PT_GNU_RELRO:
                    has_relro = True
                elif p_type == self._PT_DYNAMIC:
                    off_field = 0x8 if is64 else 0x4
                    size_field = 0x20 if is64 else 0x10
                    off = int.from_bytes(data[base + off_field:base + off_field + (8 if is64 else 4)], "little")
                    filesz = int.from_bytes(data[base + size_field:base + size_field + (8 if is64 else 4)], "little")
                    if off + filesz <= len(data):
                        dyn_bytes = data[off:off + filesz]
        else:
            notes.append("program-header table unreadable — features degrade")

        bind_now = False
        runpath = False
        rpath = False
        w, es = (8, 16) if is64 else (4, 8)
        for i in range(len(dyn_bytes) // es):
            base = i * es
            tag = int.from_bytes(dyn_bytes[base:base + w], "little")
            val = int.from_bytes(dyn_bytes[base + w:base + 2 * w], "little")
            if tag == self._DT_BIND_NOW:
                bind_now = True
            elif tag == self._DT_FLAGS and val & self._DF_BIND_NOW:
                bind_now = True
            elif tag == self._DT_FLAGS_1 and val & self._DF_1_NOW:
                bind_now = True
            elif tag == self._DT_RUNPATH:
                runpath = True
            elif tag == self._DT_RPATH:
                rpath = True

        canary = b"__stack_chk_fail" in data or b"__stack_chk_guard" in data
        chk_names = sorted({m.group(0) for m in re.finditer(rb"[A-Za-z_][A-Za-z0-9_]{2,30}_chk\b", data)
                            if not m.group(0).startswith(b"__stack_chk")})
        fortify = bool(chk_names)

        nx = None
        nx_detail = "no PT_GNU_STACK segment (treated as executable stack)"
        if gnu_stack_flags is not None:
            nx = not (gnu_stack_flags & 0x1)
            nx_detail = "PT_GNU_STACK is RW (no execute)" if nx else "PT_GNU_STACK is RWX (stack is executable)"

        pie = e_type == 3
        relro = "full" if (has_relro and bind_now) else ("partial" if has_relro else False)

        def feature(value, detail):
            return {"value": value, "detail": detail}

        features = {
            "pie": feature(pie, "ET_DYN (shared object or PIE)" if pie else "ET_EXEC — no PIE"),
            "nx": feature(nx, nx_detail),
            "relro": feature(relro,
                             "PT_GNU_RELRO + BIND_NOW" if relro == "full"
                             else "PT_GNU_RELRO without BIND_NOW" if relro == "partial"
                             else "no PT_GNU_RELRO segment"),
            "canary": feature(canary, "stack-protector symbols present" if canary else "no __stack_chk_* symbols"),
            "fortify": feature(fortify, f"{len(chk_names)} fortified _chk symbols" + (f" (e.g. {chk_names[0].decode()})" if chk_names else "")),
            "runpath": feature(bool(runpath or rpath),
                               "DT_RUNPATH entry present" if runpath else "DT_RPATH entry present" if rpath else "no RUNPATH/RPATH"),
        }
        hardened = sum(1 for f in (features["pie"], features["nx"], features["canary"], features["fortify"]) if f["value"]) \
            + (1 if features["relro"]["value"] == "full" else 0)
        if chk_names:
            notes.append("fortified names: " + ", ".join(n.decode() for n in chk_names[:10])
                         + (f" (+{len(chk_names) - 10} more)" if len(chk_names) > 10 else ""))
        return {
            "status": "ok",
            "tool": tool,
            "output": {
                "lib": name,
                "elf": f"ELF {'64' if is64 else '32'}-bit {_MACHINE_NAMES.get(machine, machine)}, "
                       f"{'DYN' if e_type == 3 else 'EXEC' if e_type == 2 else e_type}",
                "features": features,
                "hardened": f"{hardened}/5",
                "notes": notes,
            },
        }

    # ── native_crypto_constants ───────────────────────────────────────────

    _CONSTANTS = [
        ("AES s-box", bytes.fromhex("637C777BF26B6FC53001672BFED7AB76"), "AES encryption table"),
        ("AES inverse s-box", bytes.fromhex("52096AD53036A538BF40A39E81F3D7FB"), "AES decryption table"),
        ("SHA-256 IV (BE)", bytes.fromhex("6A09E667BB67AE853C6EF372A54FF53A"), "SHA-256/SHA-512 family initial hash"),
        ("SHA-256 IV (LE)", bytes.fromhex("67E6096A85AE67BB72F36E3C3AF34499"), "SHA-256 IV stored little-endian"),
        ("SHA-512 IV (BE)", bytes.fromhex("6A09E667F3BCC908BC91C980E7AF5A71"), "SHA-512 initial hash (64-bit words)"),
        ("SHA-1/MD5 magic (BE)", bytes.fromhex("0123456789ABCDEF FEDCBA9876543210".replace(" ", "")), "SHA-1, MD5 and RIPEMD-160 initial state"),
        ("MD5 T-table (LE)", bytes.fromhex("78A46AD7"), "MD5 sine table first word (0xd76aa478)"),
        ("CRC-32 table (LE)", bytes.fromhex("0000000096300777"), "reflected CRC-32 (IEEE 802.3) lookup table"),
        ("TEA/XTEA delta (BE)", bytes.fromhex("9E3779B9"), "golden-ratio delta used by TEA/XTEA/XXTEA"),
        ("TEA/XTEA delta (LE)", bytes.fromhex("B979379E"), "TEA delta stored little-endian"),
        ("Base64 (std)", b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", "standard Base64 alphabet"),
        ("Base64 (url)", b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", "URL-safe Base64 alphabet"),
        ("Blowfish P-array (BE)", bytes.fromhex("243F6A8885A308D3"), "Blowfish key schedule constants"),
    ]

    def native_crypto_constants(self, args: dict) -> dict:
        """[TOOL] Locate known crypto constant tables inside a .so."""
        loaded = _load_so(args, "native_crypto_constants")
        if isinstance(loaded, dict):
            return loaded
        name, data = loaded

        hits: list[dict] = []
        for label, pattern, note in self._CONSTANTS:
            start = 0
            while True:
                off = data.find(pattern, start)
                if off == -1:
                    break
                entry: dict = {"name": label, "offset": off, "note": note}
                va = _va_of_offset(data, off)
                if va is not None:
                    entry["va"] = va
                hits.append(entry)
                start = off + 1
        hits.sort(key=lambda h: h["offset"])
        shown, info = cap_items(
            hits, "constant hits are capped — the full list is usually small; raise ANDROID_RE_MCP_MAX_OUTPUT_LINES if needed")
        out: dict = {"lib": name, "total": info["total"], "constants": shown}
        if info["truncated"]:
            out["shown"] = info["shown"]
            out["truncated"] = True
            out["hint"] = info["hint"]
        return {"status": "ok", "tool": "native_crypto_constants", "output": out}

    # ── syscall_lookup ────────────────────────────────────────────────────

    _ARM64_SYSCALL_NUMS = "0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64 65 66 67 68 69 70 71 72 73 74 75 76 77 78 79 80 81 82 83 84 85 86 87 88 89 90 91 92 93 94 95 96 97 98 99 100 101 102 103 104 105 106 107 108 109 110 111 112 113 114 115 116 117 118 119 120 121 122 123 124 125 126 127 128 129 130 131 132 133 134 135 136 137 138 139 140 141 142 143 144 145 146 147 148 149 150 151 152 153 154 155 156 157 158 159 160 161 162 163 164 165 166 167 168 169 170 171 172 173 174 175 176 177 178 179 180 181 182 183 184 185 186 187 188 189 190 191 192 193 194 195 196 197 198 199 200 201 202 203 204 205 206 207 208 209 210 211 212 213 214 215 216 217 218 219 220 221 222 223 240 241 242 243 244 260 261 262 263 264 265 266 267 268 269 270 271 272 273 274 275 276 277 278 279 280 281 282 283 284 285 286 287 288 289 290 291 292 293 294 424 425 426 427 428 429 430 431 432 433 434 435 436 437 438 439 440 441 442 443 444 445 446 447 448 449 450 451 452 453 454 455 456 457 458 459 460 461 462 463 464 465 466 467 468 469 470 471"
    _ARM64_SYSCALL_NAMES = "io_setup io_destroy io_submit io_cancel io_getevents setxattr lsetxattr fsetxattr getxattr lgetxattr fgetxattr listxattr llistxattr flistxattr removexattr lremovexattr fremovexattr getcwd lookup_dcookie eventfd2 epoll_create1 epoll_ctl epoll_pwait dup dup3 fcntl inotify_init1 inotify_add_watch inotify_rm_watch ioctl ioprio_set ioprio_get flock mknodat mkdirat unlinkat symlinkat linkat renameat umount2 mount pivot_root nfsservctl statfs fstatfs truncate ftruncate fallocate faccessat chdir fchdir chroot fchmod fchmodat fchownat fchown openat close vhangup pipe2 quotactl getdents64 lseek read write readv writev pread64 pwrite64 preadv pwritev sendfile pselect6 ppoll signalfd4 vmsplice splice tee readlinkat newfstatat fstat sync fsync fdatasync sync_file_range timerfd_create timerfd_settime timerfd_gettime utimensat acct capget capset personality exit exit_group waitid set_tid_address unshare futex set_robust_list get_robust_list nanosleep getitimer setitimer kexec_load init_module delete_module timer_create timer_gettime timer_getoverrun timer_settime timer_delete clock_settime clock_gettime clock_getres clock_nanosleep syslog ptrace sched_setparam sched_setscheduler sched_getscheduler sched_getparam sched_setaffinity sched_getaffinity sched_yield sched_get_priority_max sched_get_priority_min sched_rr_get_interval restart_syscall kill tkill tgkill sigaltstack rt_sigsuspend rt_sigaction rt_sigprocmask rt_sigpending rt_sigtimedwait rt_sigqueueinfo rt_sigreturn setpriority getpriority reboot setregid setgid setreuid setuid setresuid getresuid setresgid getresgid setfsuid setfsgid times setpgid getpgid getsid setsid getgroups setgroups uname sethostname setdomainname getrlimit setrlimit getrusage umask prctl getcpu gettimeofday settimeofday adjtimex getpid getppid getuid geteuid getgid getegid gettid sysinfo mq_open mq_unlink mq_timedsend mq_timedreceive mq_notify mq_getsetattr msgget msgctl msgrcv msgsnd semget semctl semtimedop semop shmget shmctl shmat shmdt socket socketpair bind listen accept connect getsockname getpeername sendto recvfrom setsockopt getsockopt shutdown sendmsg recvmsg readahead brk munmap mremap add_key request_key keyctl clone execve mmap fadvise64 rt_tgsigqueueinfo perf_event_open accept4 recvmmsg arch_specific_syscall wait4 prlimit64 fanotify_init fanotify_mark name_to_handle_at open_by_handle_at clock_adjtime syncfs setns sendmmsg process_vm_readv process_vm_writev kcmp finit_module sched_setattr sched_getattr renameat2 seccomp getrandom memfd_create bpf execveat userfaultfd membarrier mlock2 copy_file_range preadv2 pwritev2 pkey_mprotect pkey_alloc pkey_free statx io_pgetevents rseq kexec_file_load pidfd_send_signal io_uring_setup io_uring_enter io_uring_register open_tree move_mount fsopen fsconfig fsmount fspick pidfd_open clone3 close_range openat2 pidfd_getfd faccessat2 process_madvise epoll_pwait2 mount_setattr quotactl_fd landlock_create_ruleset landlock_add_rule landlock_restrict_self memfd_secret process_mrelease futex_waitv set_mempolicy_home_node cachestat fchmodat2 map_shadow_stack futex_wake futex_wait futex_requeue statmount listmount lsm_get_self_attr lsm_set_self_attr lsm_list_modules mseal setxattrat getxattrat listxattrat removexattrat open_tree_attr file_getattr file_setattr listns rseq_slice_yield"
    _X86_64_SYSCALL_NUMS = "0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64 65 66 67 68 69 70 71 72 73 74 75 76 77 78 79 80 81 82 83 84 85 86 87 88 89 90 91 92 93 94 95 96 97 98 99 100 101 102 103 104 105 106 107 108 109 110 111 112 113 114 115 116 117 118 119 120 121 122 123 124 125 126 127 128 129 130 131 132 133 134 135 136 137 138 139 140 141 142 143 144 145 146 147 148 149 150 151 152 153 154 155 156 157 158 159 160 161 162 163 164 165 166 167 168 169 170 171 172 173 174 175 176 177 178 179 180 181 182 183 184 185 186 187 188 189 190 191 192 193 194 195 196 197 198 199 200 201 202 203 204 205 206 207 208 209 210 211 212 213 214 215 216 217 218 219 220 221 222 223 224 225 226 227 228 229 230 231 232 233 234 235 236 237 238 239 240 241 242 243 244 245 246 247 248 249 250 251 252 253 254 255 256 257 258 259 260 261 262 263 264 265 266 267 268 269 270 271 272 273 274 275 276 277 278 279 280 281 282 283 284 285 286 287 288 289 290 291 292 293 294 295 296 297 298 299 300 301 302 303 304 305 306 307 308 309 310 311 312 313 314 315 316 317 318 319 320 321 322 323 324 325 326 327 328 329 330 331 332 333 334 335 336 424 425 426 427 428 429 430 431 432 433 434 435 436 437 438 439 440 441 442 443 444 445 446 447 448 449 450 451 452 453 454 455 456 457 458 459 460 461 462 463 464 465 466 467 468 469 470 471"
    _X86_64_SYSCALL_NAMES = "read write open close stat fstat lstat poll lseek mmap mprotect munmap brk rt_sigaction rt_sigprocmask rt_sigreturn ioctl pread64 pwrite64 readv writev access pipe select sched_yield mremap msync mincore madvise shmget shmat shmctl dup dup2 pause nanosleep getitimer alarm setitimer getpid sendfile socket connect accept sendto recvfrom sendmsg recvmsg shutdown bind listen getsockname getpeername socketpair setsockopt getsockopt clone fork vfork execve exit wait4 kill uname semget semop semctl shmdt msgget msgsnd msgrcv msgctl fcntl flock fsync fdatasync truncate ftruncate getdents getcwd chdir fchdir rename mkdir rmdir creat link unlink symlink readlink chmod fchmod chown fchown lchown umask gettimeofday getrlimit getrusage sysinfo times ptrace getuid syslog getgid setuid setgid geteuid getegid setpgid getppid getpgrp setsid setreuid setregid getgroups setgroups setresuid getresuid setresgid getresgid getpgid setfsuid setfsgid getsid capget capset rt_sigpending rt_sigtimedwait rt_sigqueueinfo rt_sigsuspend sigaltstack utime mknod uselib personality ustat statfs fstatfs sysfs getpriority setpriority sched_setparam sched_getparam sched_setscheduler sched_getscheduler sched_get_priority_max sched_get_priority_min sched_rr_get_interval mlock munlock mlockall munlockall vhangup modify_ldt pivot_root _sysctl prctl arch_prctl adjtimex setrlimit chroot sync acct settimeofday mount umount2 swapon swapoff reboot sethostname setdomainname iopl ioperm create_module init_module delete_module get_kernel_syms query_module quotactl nfsservctl getpmsg putpmsg afs_syscall tuxcall security gettid readahead setxattr lsetxattr fsetxattr getxattr lgetxattr fgetxattr listxattr llistxattr flistxattr removexattr lremovexattr fremovexattr tkill time futex sched_setaffinity sched_getaffinity set_thread_area io_setup io_destroy io_getevents io_submit io_cancel get_thread_area lookup_dcookie epoll_create epoll_ctl_old epoll_wait_old remap_file_pages getdents64 set_tid_address restart_syscall semtimedop fadvise64 timer_create timer_settime timer_gettime timer_getoverrun timer_delete clock_settime clock_gettime clock_getres clock_nanosleep exit_group epoll_wait epoll_ctl tgkill utimes vserver mbind set_mempolicy get_mempolicy mq_open mq_unlink mq_timedsend mq_timedreceive mq_notify mq_getsetattr kexec_load waitid add_key request_key keyctl ioprio_set ioprio_get inotify_init inotify_add_watch inotify_rm_watch migrate_pages openat mkdirat mknodat fchownat futimesat newfstatat unlinkat renameat linkat symlinkat readlinkat fchmodat faccessat pselect6 ppoll unshare set_robust_list get_robust_list splice tee sync_file_range vmsplice move_pages utimensat epoll_pwait signalfd timerfd_create eventfd fallocate timerfd_settime timerfd_gettime accept4 signalfd4 eventfd2 epoll_create1 dup3 pipe2 inotify_init1 preadv pwritev rt_tgsigqueueinfo perf_event_open recvmmsg fanotify_init fanotify_mark prlimit64 name_to_handle_at open_by_handle_at clock_adjtime syncfs sendmmsg setns getcpu process_vm_readv process_vm_writev kcmp finit_module sched_setattr sched_getattr renameat2 seccomp getrandom memfd_create kexec_file_load bpf execveat userfaultfd membarrier mlock2 copy_file_range preadv2 pwritev2 pkey_mprotect pkey_alloc pkey_free statx io_pgetevents rseq uretprobe uprobe pidfd_send_signal io_uring_setup io_uring_enter io_uring_register open_tree move_mount fsopen fsconfig fsmount fspick pidfd_open clone3 close_range openat2 pidfd_getfd faccessat2 process_madvise epoll_pwait2 mount_setattr quotactl_fd landlock_create_ruleset landlock_add_rule landlock_restrict_self memfd_secret process_mrelease futex_waitv set_mempolicy_home_node cachestat fchmodat2 map_shadow_stack futex_wake futex_wait futex_requeue statmount listmount lsm_get_self_attr lsm_set_self_attr lsm_list_modules mseal setxattrat getxattrat listxattrat removexattrat open_tree_attr file_getattr file_setattr listns rseq_slice_yield"

    def syscall_lookup(self, args: dict) -> dict:
        """[TOOL] arm64/x86_64 syscall numbers ↔ names (kernel-header table)."""
        arch = args.get("arch", "arm64")
        if arch not in ("arm64", "x86_64"):
            return {"status": "error", "tool": "syscall_lookup",
                    "error": f"arch '{arch}' is not supported (supported: arm64, x86_64).",
                    "hint": "arm32 tables are not bundled; most Android targets are arm64."}
        nums, names = (
            (self._ARM64_SYSCALL_NUMS, self._ARM64_SYSCALL_NAMES) if arch == "arm64"
            else (self._X86_64_SYSCALL_NUMS, self._X86_64_SYSCALL_NAMES)
        )
        table = dict(zip(map(int, nums.split()), names.split(), strict=True))

        number = args.get("number")
        name = args.get("name", "")
        if number is None and not name:
            return {"status": "error", "tool": "syscall_lookup", "error": "pass number or name."}

        matches: list[dict] = []
        if number is not None:
            hit = table.get(int(number))
            entry = {"number": int(number), "name": hit} if hit else None
            if entry:
                matches.append(entry)
            if not entry:
                matches.append({"number": int(number), "name": None,
                                "note": "not in the table (private or newer than the bundled kernel headers)"})
        else:
            needle = str(name).lower()
            for num in sorted(table):
                if needle in table[num].lower():
                    matches.append({"number": num, "name": table[num]})
        shown, info = cap_items(
            matches, "narrow the name substring (e.g. name='openat')")
        out: dict = {"arch": arch, "total": info["total"], "matches": shown}
        if info["truncated"]:
            out["shown"] = info["shown"]
            out["truncated"] = True
            out["hint"] = info["hint"]
        return {"status": "ok", "tool": "syscall_lookup",
                "output": {**out, "source": "bundled from Linux kernel headers (asm-generic + x86_64)"}}
