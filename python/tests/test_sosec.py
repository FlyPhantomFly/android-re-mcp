"""Hermetic tests for the E-PY-16 native-ELF cherry-pick (handlers/sosec.py).

The fixtures are synthetic: a minimal ELF64/AArch64 image builder with
hand-encoded AArch64 instructions (BL, ADRP, ADD, MOV, RET, NOP), a
program-header builder for elf_checksec, and byte blobs for the crypto
constant scan. capstone-backed tests are guarded with importorskip; the
pure-Python tools (checksec, crypto constants, syscalls) always run.
"""

import struct
import sys

import pytest

from android_re_mcp.handlers.sosec import SoSecHandler

NOP = bytes.fromhex("1F2003D5")       # nop
RET = bytes.fromhex("C0035FD6")       # ret
MOVR = {  # mov x0, xN
    1: bytes.fromhex("E00301AA"),
    2: bytes.fromhex("E00302AA"),
    3: bytes.fromhex("E00303AA"),
}


def _bl(from_addr: int, to_addr: int) -> bytes:
    """AArch64 BL with the computed imm26 (target = bl_addr + imm*4)."""
    delta = (to_addr - from_addr) >> 2
    return struct.pack("<I", 0x94000000 | (delta & 0x3FFFFFF))


def _adrp(pc: int, page: int, reg: int = 0) -> bytes:
    """AArch64 ADRP Xreg, <page>."""
    imm21 = (page >> 12) - (pc >> 12)
    return struct.pack("<I", 0x90000000 | ((imm21 & 3) << 29) | (((imm21 >> 2) & 0x7FFFF) << 5) | reg)


def _add_imm(rd: int, rn: int, imm: int) -> bytes:
    """AArch64 ADD Xrd, Xrn, #imm (64-bit, no shift)."""
    return struct.pack("<I", 0x91000000 | ((imm & 0xFFF) << 10) | (rn << 5) | rd)


def _elf64(sections: list[tuple[str, bytes, int, int]], machine: int = 183, e_type: int = 3) -> bytes:
    """Minimal ELF64-LE image: (name, content, vaddr, flags) sections.

    Layout: ehdr | contents (8-byte aligned from 0x40) | shstrtab | shdrs.
    """
    ehsize = 0x40
    contents = b""
    layout: list[tuple[str, int, int, int]] = []  # name, offset, size, vaddr
    pos = ehsize
    for name, content, vaddr, _flags in sections:
        pos = (pos + 7) & ~7
        layout.append((name, pos, len(content), vaddr))
        contents += b"\x00" * (pos - ehsize - len(contents)) + content
        pos += len(content)
    strtab = b"\x00" + b"".join(n.encode() + b"\x00" for n, _, _, _ in sections) + b".shstrtab\x00"
    strtab_off = (pos + 7) & ~7
    shoff = (strtab_off + len(strtab) + 7) & ~7

    shstr = {b"\x00": 0}
    for name, _, _, _ in sections:
        shstr[name.encode()] = strtab.index(name.encode())
    shstr[b".shstrtab"] = strtab.index(b".shstrtab")

    ehdr = bytearray(64)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4], ehdr[5], ehdr[6] = 2, 1, 1
    struct.pack_into("<HHI", ehdr, 0x10, e_type, machine, 1)
    struct.pack_into("<Q", ehdr, 0x28, shoff)
    struct.pack_into("<IHHHHHH", ehdr, 0x30, 0, 0x40, 0, 0, 0x40, 2 + len(sections), len(sections) + 1)

    shdrs = bytearray(struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))  # SHT_NULL
    for name, off, size, vaddr in layout:
        shdrs += struct.pack("<IIQQQQIIQQ", shstr[name.encode()], 1, 0x2 | 0x4, vaddr, off, size, 0, 0, 4, 0)
    shdrs += struct.pack("<IIQQQQIIQQ", shstr[b".shstrtab"], 3, 0, 0, strtab_off, len(strtab), 0, 0, 1, 0)

    return (bytes(ehdr) + contents
            + b"\x00" * (strtab_off - ehsize - len(contents)) + strtab
            + b"\x00" * (shoff - strtab_off - len(strtab)) + bytes(shdrs))


def _elf64_phdr(entries: list[tuple[int, int, bytes]], machine: int = 183) -> bytes:
    """Minimal ELF64 with program headers: (p_type, p_flags, content).

    Content blobs land right after the ehdr; the phdr table follows.
    """
    ehsize = 0x40
    contents = b""
    placed: list[tuple[int, int, int, int]] = []  # type, flags, offset, size
    pos = ehsize
    for p_type, p_flags, content in entries:
        pos = (pos + 7) & ~7
        placed.append((p_type, p_flags, pos, len(content)))
        contents += b"\x00" * (pos - ehsize - len(contents)) + content
        pos += len(content)
    phoff = pos
    phnum = len(entries)

    ehdr = bytearray(64)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4], ehdr[5], ehdr[6] = 2, 1, 1
    struct.pack_into("<HHI", ehdr, 0x10, 3, machine, 1)
    struct.pack_into("<Q", ehdr, 0x20, phoff)
    struct.pack_into("<IHHHHHH", ehdr, 0x30, 0, 0x40, 0x38, phnum, 0x40, 0, 0)

    phdrs = b""
    for p_type, p_flags, off, size in placed:
        phdrs += struct.pack("<IIQQQQQQ", p_type, p_flags, off, 0x100000 + off, 0x100000 + off, size, size, 8)
    return bytes(ehdr) + contents + phdrs


# ── so_xrefs ──────────────────────────────────────────────────────────────

capstone = pytest.importorskip("capstone")


def _xrefs(blob: bytes, address: str) -> dict:
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".so", delete=False) as fh:
        fh.write(blob)
        path = fh.name
    return SoSecHandler().so_xrefs({"so_path": path, "address": address})


def test_so_xrefs_finds_branch_and_adrp_add():
    blob = _elf64([(".text", NOP + _bl(0x1004, 0x1040) + _adrp(0x1008, 0x2000) + _add_imm(0, 0, 0x10), 0x1000, 0x6)])
    out = _xrefs(blob, "0x1040")["output"]
    assert out["total"] == 1
    assert out["refs"][0]["kind"] == "branch"
    assert out["refs"][0]["insn"].startswith("bl ")

    out2 = _xrefs(blob, "0x2010")["output"]  # adrp 0x2000 + add #0x10
    assert out2["total"] == 1
    assert out2["refs"][0]["kind"] == "adrp+add"
    assert out2["refs"][0]["insn"].startswith("add ")


def test_so_xrefs_empty_target_reports_zero_honestly():
    blob = _elf64([(".text", NOP * 2, 0x1000, 0x6)])
    out = _xrefs(blob, "0xdeadbeef")["output"]
    assert out["total"] == 0
    assert out["refs"] == []
    assert "literal pools" in out["note"]


# ── rop_gadgets ───────────────────────────────────────────────────────────

def test_rop_gadgets_finds_runs_and_breaks_at_branches():
    code = (
        MOVR[1] + RET                    # 0x1000: gadget "mov x0, x1; ret"
        + MOVR[2] + _bl(0x100C, 0x1000)  # 0x1008/0x100C: branch splits the run
        + MOVR[3] + RET                  # 0x1010: gadget "mov x0, x3; ret"
    )
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".so", delete=False) as fh:
        fh.write(_elf64([(".text", code, 0x1000, 0x6)]))
        path = fh.name
    out = SoSecHandler().rop_gadgets({"so_path": path})["output"]
    texts = [g["gadget"] for g in out["gadgets"]]
    assert "mov x0, x1; ret" in texts
    assert "mov x0, x3; ret" in texts
    assert not any("x2" in t for t in texts)  # the bl broke that run
    assert out["arch"] == "arm64"


def test_rop_gadgets_filter_narrows():
    code = MOVR[1] + RET + MOVR[3] + RET
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".so", delete=False) as fh:
        fh.write(_elf64([(".text", code, 0x1000, 0x6)]))
        path = fh.name
    out = SoSecHandler().rop_gadgets({"so_path": path, "filter": "x1"})["output"]
    assert out["total"] == 1
    assert out["gadgets"][0]["gadget"] == "mov x0, x1; ret"


def test_rop_gadgets_cap_keeps_total_and_hints(monkeypatch):
    code = b"".join(MOVR[1] + RET for _ in range(5))
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".so", delete=False) as fh:
        fh.write(_elf64([(".text", code, 0x1000, 0x6)]))
        path = fh.name
    monkeypatch.setenv("ANDROID_RE_MCP_MAX_OUTPUT_LINES", "2")
    out = SoSecHandler().rop_gadgets({"so_path": path})["output"]
    assert out["total"] == 5
    assert len(out["gadgets"]) == 2
    assert out["truncated"] is True
    assert "filter" in out["hint"]


# ── elf_checksec ──────────────────────────────────────────────────────────

def test_elf_checksec_hardened_elf():
    dynamic = struct.pack("<QQ", 24, 0)                 # DT_BIND_NOW
    dynamic += struct.pack("<QQ", 0x6FFFFFFB, 0x1)      # DT_FLAGS_1 DF_1_NOW
    blob = _elf64_phdr([
        (0x6474E551, 0x6, b""),                          # PT_GNU_STACK RW (no X)
        (0x6474E552, 0x4, b""),                          # PT_GNU_RELRO
        (2, 0x6, dynamic),                               # PT_DYNAMIC
    ]) + b"__stack_chk_fail\x00__memcpy_chk\x00"
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".so", delete=False) as fh:
        fh.write(blob)
        path = fh.name
    out = SoSecHandler().elf_checksec({"so_path": path})["output"]
    f = out["features"]
    assert f["pie"]["value"] is True
    assert f["nx"]["value"] is True
    assert f["relro"]["value"] == "full"
    assert f["canary"]["value"] is True
    assert f["fortify"]["value"] is True
    assert "__memcpy_chk" in out["notes"][0]
    assert out["hardened"] == "5/5"


def test_elf_checksec_flags_rwx_stack_and_rpath():
    dynamic = struct.pack("<QQ", 29, 0)                 # DT_RUNPATH (val = strtab offset, presence only)
    blob = _elf64_phdr([
        (0x6474E551, 0x7, b""),                          # PT_GNU_STACK RWX
        (2, 0x6, dynamic),
    ])
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".so", delete=False) as fh:
        fh.write(blob)
        path = fh.name
    out = SoSecHandler().elf_checksec({"so_path": path})["output"]
    f = out["features"]
    assert f["nx"]["value"] is False
    assert "executable" in f["nx"]["detail"]
    assert f["relro"]["value"] is False
    assert f["runpath"]["value"] is True


def test_elf_checksec_rejects_non_elf(tmp_path):
    bad = tmp_path / "nope.so"
    bad.write_bytes(b"MZ\x00\x00" + b"\x00" * 100)
    result = SoSecHandler().elf_checksec({"so_path": str(bad)})
    assert result["status"] == "error"
    assert "not an ELF" in result["error"]


# ── native_crypto_constants ───────────────────────────────────────────────

def test_crypto_constants_found_with_offsets_and_va():
    aes = bytes.fromhex("637C777BF26B6FC53001672BFED7AB76")
    sha256_le = bytes.fromhex("67E6096A85AE67BB72F36E3C3AF34499")
    b64 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    blob = _elf64([(".rodata", b"\x00" * 16 + aes + b"\xAA" * 3 + sha256_le + b64, 0x4000, 0x2)])
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".so", delete=False) as fh:
        fh.write(blob)
        path = fh.name
    out = SoSecHandler().native_crypto_constants({"so_path": path})["output"]
    by_name = {c["name"]: c for c in out["constants"]}
    assert by_name["AES s-box"]["offset"] == 80  # file offset: section at 64 + 16 in-section
    assert by_name["AES s-box"]["va"] == 0x4010  # vaddr 0x4000 + (file offset 80 - section offset 64)
    assert by_name["SHA-256 IV (LE)"]["offset"] == 80 + 16 + 3
    assert by_name["Base64 (std)"]["name"]
    assert "AES inverse s-box" not in by_name  # not in the blob → absent


def test_crypto_constants_absent_reports_zero():
    blob = _elf64([(".rodata", b"\x00" * 64, 0x4000, 0x2)])
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".so", delete=False) as fh:
        fh.write(blob)
        path = fh.name
    out = SoSecHandler().native_crypto_constants({"so_path": path})["output"]
    assert out["total"] == 0


# ── syscall_lookup ────────────────────────────────────────────────────────

def test_syscall_lookup_number_exact():
    out = SoSecHandler().syscall_lookup({"arch": "arm64", "number": 56})["output"]
    assert out["total"] == 1
    assert out["matches"][0] == {"number": 56, "name": "openat"}
    assert out["source"].startswith("bundled from Linux kernel headers")


def test_syscall_lookup_name_search_and_unknown_number():
    out = SoSecHandler().syscall_lookup({"name": "clone3"})["output"]
    assert {"number": 435, "name": "clone3"} in out["matches"]
    out2 = SoSecHandler().syscall_lookup({"arch": "x86_64", "number": 999999})["output"]
    assert out2["matches"][0]["name"] is None
    assert "not in the table" in out2["matches"][0]["note"]


def test_syscall_lookup_rejects_other_arch():
    result = SoSecHandler().syscall_lookup({"arch": "mips"})
    assert result["status"] == "error"
    assert "not supported" in result["error"]


def test_syscall_lookup_requires_input():
    result = SoSecHandler().syscall_lookup({})
    assert result["status"] == "error"


# ── shared plumbing ───────────────────────────────────────────────────────

def test_capstone_tools_missing_tool_without_capstone(tmp_path, monkeypatch):
    so = tmp_path / "libx.so"
    so.write_bytes(_elf64([(".text", NOP * 2, 0x1000, 0x6)]))
    monkeypatch.setitem(sys.modules, "capstone", None)
    for tool in ("so_xrefs", "rop_gadgets"):
        args = {"so_path": str(so), "address": "0x1000"} if tool == "so_xrefs" else {"so_path": str(so)}
        result = getattr(SoSecHandler(), tool)(args)
        assert result["status"] == "missing_tool", tool
        assert "capstone" in result["error"]


def test_load_requires_input(tmp_path):
    result = SoSecHandler().so_xrefs({"address": "0x1000"})
    assert result["status"] == "error"
    assert "so_path or apk_path" in result["error"]


def test_load_missing_so_path(tmp_path):
    result = SoSecHandler().so_xrefs({"so_path": str(tmp_path / "no.so"), "address": "0x1000"})
    assert result["status"] == "error"
    assert "not found" in result["error"]


def test_unsupported_machine_degrades(tmp_path):
    # x86 (machine 3) is supported; MIPS (8) is not — honest error, not a crash
    blob = bytearray(_elf64([(".text", NOP * 2, 0x1000, 0x6)]))
    struct.pack_into("<H", blob, 0x12, 8)  # e_machine = MIPS
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".so", delete=False) as fh:
        fh.write(bytes(blob))
        path = fh.name
    result = SoSecHandler().so_xrefs({"so_path": path, "address": "0x1000"})
    assert result["status"] == "error"
    assert "not supported" in result["error"]
