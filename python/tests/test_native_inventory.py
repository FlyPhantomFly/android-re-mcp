"""Hermetic tests for the E-PY-14 native-library fold-in.

The npm android_native_libraries machinery (known-lib table, ELF header
inspection, per-ABI inventory) now lives in handlers/native.py and rides
along in rasp_identify. ELF fixtures are crafted by hand — no real .so
files needed.
"""

import zipfile
from pathlib import Path

from android_re_mcp.handlers.native import (
    _KNOWN_ANDROID_LIBS,
    apk_native_inventory,
    inspect_elf,
    match_known_lib,
)

EM_AARCH64 = 183
ET_DYN = 3


def _elf64(section_names: list[str], stripped: bool = False) -> bytes:
    """Craft a minimal 64-bit little-endian ARM64 ELF (DYN) by hand."""
    header = bytearray(0x40)
    header[:4] = b"\x7fELF"
    header[4] = 2  # ELFCLASS64
    header[5] = 1  # little-endian
    header[0x10:0x12] = ET_DYN.to_bytes(2, "little")
    header[0x12:0x14] = EM_AARCH64.to_bytes(2, "little")
    if stripped:
        # shoff (0x28) and shnum (0x3c) stay zero
        return bytes(header)

    shnum = len(section_names) + 2  # NULL + .shstrtab + named sections
    shentsize = 0x40
    shoff = 0x40
    strtab = bytearray(b"\x00.shstrtab\x00")
    name_offsets: dict[str, int] = {}
    for name in section_names:
        name_offsets[name] = len(strtab)
        strtab += name.encode() + b"\x00"
    strtab_off = shoff + shnum * shentsize

    buf = bytearray(strtab_off + len(strtab))
    buf[:0x40] = header
    buf[0x28:0x30] = shoff.to_bytes(8, "little")
    buf[0x3A:0x3C] = shentsize.to_bytes(2, "little")
    buf[0x3C:0x3E] = shnum.to_bytes(2, "little")
    buf[0x3E:0x40] = (1).to_bytes(2, "little")  # shstrndx = 1 (.shstrtab)

    def shdr(index: int, name_off: int, sh_type: int, off: int = 0, size: int = 0) -> None:
        base = shoff + index * shentsize
        buf[base:base + 4] = name_off.to_bytes(4, "little")
        buf[base + 4:base + 8] = sh_type.to_bytes(4, "little")
        buf[base + 0x18:base + 0x20] = off.to_bytes(8, "little")
        buf[base + 0x20:base + 0x28] = size.to_bytes(8, "little")

    shdr(0, 0, 0)                              # SHT_NULL
    shdr(1, 1, 3, strtab_off, len(strtab))     # .shstrtab (STRTAB); its name sits at strtab offset 1
    for j, name in enumerate(section_names):
        shdr(2 + j, name_offsets[name], 1)     # PROGBITS
    buf[strtab_off:strtab_off + len(strtab)] = strtab
    return bytes(buf)


def _write_apk(tmp_path: Path, name: str, files: dict[str, bytes]) -> str:
    apk_path = tmp_path / name
    with zipfile.ZipFile(apk_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for fname, data in files.items():
            zf.writestr(fname, data)
    return str(apk_path)


def test_inspect_elf_parses_section_names():
    elf = inspect_elf(_elf64([".text", ".rodata", ".data"]))
    assert elf["ok"] is True
    assert elf["machine"] == "ARM64"
    assert "64-bit ARM64, DYN (shared object)" in elf["detail"]
    assert elf["shnum"] == 5  # NULL + .shstrtab + 3 named
    assert set(elf["sections"]) == {".shstrtab", ".text", ".rodata", ".data"}


def test_inspect_elf_stripped_and_32bit():
    stripped = inspect_elf(_elf64([], stripped=True))
    assert stripped["ok"] is True
    assert stripped["shnum"] == 0
    assert stripped["note"] == (
        "no section-header table (stripped or packed — common for packer/RASP payloads)"
    )

    # 32-bit variant: shoff/shnum/shstrndx at the ELF32 offsets
    buf = bytearray(0x34)
    buf[:4] = b"\x7fELF"
    buf[4] = 1  # ELFCLASS32
    buf[5] = 1
    buf[0x10:0x12] = (3).to_bytes(2, "little")
    buf[0x12:0x14] = (40).to_bytes(2, "little")  # EM_ARM
    elf32 = inspect_elf(bytes(buf))
    assert elf32["ok"] is True
    assert "32-bit ARM" in elf32["detail"]


def test_inspect_elf_degrades_without_throwing():
    assert inspect_elf(b"not an elf at all, just bytes")["ok"] is False
    assert "missing" in inspect_elf(b"\x00\x01\x02\x03")["detail"]

    # valid magic + class but truncated below the fixed header size
    truncated = bytearray(0x34)
    truncated[:4] = b"\x7fELF"
    truncated[4] = 2
    truncated[5] = 1
    out = inspect_elf(bytes(truncated))
    assert out["ok"] is False
    assert "truncated" in out["detail"]

    # big-endian ELF is rejected with the npm wording
    be = bytearray(b"\x7fELF" + bytes(0x40))
    be[4], be[5] = 2, 2
    assert "big-endian" in inspect_elf(bytes(be))["detail"]


def test_known_lib_table_matches_npm():
    """Pattern rows, labels and kinds ported verbatim from the npm table."""
    assert len(_KNOWN_ANDROID_LIBS) == 31
    cases = {
        "libjiagu_x86.so": ("Qihoo 360 Jiagu (加固)", "packer"),
        "libDexHelper.so": ("SecNeo", "packer"),
        "libSecShell-x86.so": ("Bangcle (梆梆安全)", "packer"),
        "libDexProtector.so": ("DexProtector", "packer"),
        "libAppGuard.so": ("AppGuard (INKA Entworks)", "rasp"),
        "libsgmainso-6.4.43.so": ("Alibaba SecurityGuard (聚安全)", "rasp"),
        "libflutter.so": ("Flutter engine", "framework"),
        "libunity.so": ("Unity engine", "framework"),
        "libil2cpp.so": ("Unity IL2CPP", "framework"),
        "libBugly.so": ("Tencent Bugly (crash reporting)", "sdk"),
        "libc++_shared.so": ("NDK libc++ runtime", "runtime"),
        "libhoudini.so": ("Intel ARM translation layer", "runtime"),
    }
    for basename, (label, kind) in cases.items():
        got = match_known_lib(basename)
        assert got == {"label": label, "kind": kind}, basename
    # npm's per-row case-insensitivity is preserved (only where npm set /i)
    assert match_known_lib("LIBJIAGU.so")["label"] == "Qihoo 360 Jiagu (加固)"
    assert match_known_lib("libvplayer.so") is None  # unrecognised


def test_apk_native_inventory_end_to_end(tmp_path):
    good = _elf64([".text", ".rodata"])
    stripped = _elf64([], stripped=True)
    apk = _write_apk(tmp_path, "app.apk", {
        "AndroidManifest.xml": b"stub",
        "classes.dex": b"dex",
        "lib/arm64-v8a/libflutter.so": good,
        "lib/armeabi-v7a/libjiaguv3.so": stripped,
        "lib/x86/libvendor_unknown.so": b"\x7fELF-garbage-not-really",
        "res/layout/main.xml": b"<layout/>",
    })
    inv = apk_native_inventory(apk)
    assert inv["no_native_code"] is False
    assert list(inv["by_abi"]) == ["arm64-v8a", "armeabi-v7a", "x86"]

    flutter = inv["by_abi"]["arm64-v8a"][0]
    assert flutter["identified"] == {"label": "Flutter engine", "kind": "framework"}
    assert flutter["elf"]["machine"] == "ARM64"

    jiagu = inv["by_abi"]["armeabi-v7a"][0]
    assert jiagu["identified"]["kind"] == "packer"
    assert jiagu["elf"]["note"] and "no section-header table" in jiagu["elf"]["note"]

    unknown = inv["by_abi"]["x86"][0]
    assert unknown["identified"] is None
    assert unknown["elf"]["ok"] is False  # truncated garbage → degraded, not thrown

    # packer hit (with the ELF note) and only that one → protection signals
    assert inv["protection_signals"] == [
        "libjiaguv3.so: Qihoo 360 Jiagu (加固) (packer) — "
        "no section-header table (stripped or packed — common for packer/RASP payloads)"
    ]
    s = inv["summary"]
    assert (s["total"], s["abis"], s["identified"]) == (3, 3, 2)
    assert (s["packer"], s["framework"], s["rasp"], s["sdk"], s["runtime"]) == (1, 1, 0, 0, 0)


def test_apk_native_inventory_empty_and_missing(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda *_a, **_k: None)
    apk = _write_apk(tmp_path, "plain.apk", {"AndroidManifest.xml": b"stub", "classes.dex": b"dex"})
    inv = apk_native_inventory(apk)
    assert inv["no_native_code"] is True
    assert inv["note"] == "No lib/<abi>/*.so entries — the APK ships no native code."
    assert inv["protection_signals"] == [] and inv["summary"]["total"] == 0

    bad = apk_native_inventory(str(tmp_path / "missing.apk"))
    assert "error" in bad and "not found" in bad["error"] or "No such file" in bad["error"]


def test_rasp_identify_folds_in_native_inventory(tmp_path, monkeypatch):
    from android_re_mcp.handlers.rasp import RaspHandler

    monkeypatch.setattr("shutil.which", lambda *_a, **_k: None)  # skip the apkid strategy
    apk = _write_apk(tmp_path, "packed.apk", {
        "AndroidManifest.xml": b"stub",
        "lib/arm64-v8a/libjiaguv3.so": _elf64([], stripped=True),
        "lib/arm64-v8a/libflutter.so": _elf64([".text"]),
    })
    out = RaspHandler().rasp_identify({"apk_path": apk})["output"]
    hit = next(d for d in out["detected"] if d["vendor"] == "Qihoo 360 Jiagu (加固)")
    assert hit["confidence"] == "high" and hit["signals"] == ["libjiaguv3.so"]
    assert out["protection_tier"] == "enterprise"
    assert out["primary_rasp"] == "Qihoo 360 Jiagu (加固)"

    native = out["native_libraries"]
    assert native["summary"]["total"] == 2
    assert native["summary"]["packer"] == 1 and native["summary"]["framework"] == 1
    assert len(native["protection_signals"]) == 1


def test_rasp_identify_tolerates_missing_apk(tmp_path, monkeypatch):
    from android_re_mcp.handlers.rasp import RaspHandler

    monkeypatch.setattr("shutil.which", lambda *_a, **_k: None)
    out = RaspHandler().rasp_identify({"apk_path": str(tmp_path / "nope.apk")})["output"]
    assert out["detected"] == [] and out["protection_tier"] == "none"
    assert "error" in out["native_libraries"]


# ── R4-7: native_disasm target keeps radare2 operators out ───────────────

class FakeR2Proc:
    returncode = 0
    stdout = "disasm"
    stderr = ""


def _disasm_target(monkeypatch, target):
    """Run native_disasm with r2 'present' and subprocess captured."""
    from android_re_mcp.handlers import native as native_mod

    captured = {}
    so = native_mod.scratch_dir("r4t7") / "libprobe.so"
    so.parent.mkdir(parents=True, exist_ok=True)
    so.write_bytes(b"\x7fELF fake")

    def fake_run(argv, **kw):
        captured["argv"] = argv
        return FakeR2Proc()

    monkeypatch.setattr(native_mod.shutil, "which", lambda name: "/usr/bin/r2")
    monkeypatch.setattr(native_mod.subprocess, "run", fake_run)
    out = native_mod.NativeHandler().native_disasm(
        {"so_path": str(so), "target": target, "n_instructions": 4})
    return out, captured


def test_disasm_target_refuses_radare2_iterators(monkeypatch):
    for bad in ("foo@@bar", "@@@", "sym@x", "a;b", "x!y"):
        out, _ = _disasm_target(monkeypatch, bad)
        assert out["status"] == "error", f"{bad!r} was not refused"
        assert "target must be" in out["error"]


def test_disasm_target_accepts_plain_symbol_offset_and_plt(monkeypatch):
    for good in ("foo", "_Z3barv", "0x1234", "0xdeadbeef", "foo@plt"):
        out, captured = _disasm_target(monkeypatch, good)
        assert out["status"] == "ok", f"{good!r} was refused: {out.get('error')}"
        assert good in captured["argv"][3]
        assert "@@" not in captured["argv"][3]


def test_disasm_target_rejects_oversized_symbol(monkeypatch):
    out, _ = _disasm_target(monkeypatch, "a" * 197)
    assert out["status"] == "error"
    out, _ = _disasm_target(monkeypatch, "a" * 196 + "@plt")
    assert out["status"] == "ok"
