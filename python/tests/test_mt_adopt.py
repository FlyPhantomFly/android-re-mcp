"""Tests for the MT-MCP adoption batch (mt-mcp-android-re-implementation-plan).

Tier-1 zip/signature/native-map tests are hermetic with synthetic fixtures;
keystone tests skip without the engine; jar-gated dex outline tests skip
without dexfile-cli; androguard resource tests skip without androguard —
matching the plan's dependency expectations.
"""

import hashlib
import os
import shutil
import zipfile
from pathlib import Path

import pytest

from android_re_mcp.handlers import apkops as apkops_mod
from android_re_mcp.handlers.apkops import ApkOpsHandler
from android_re_mcp.handlers.dex import DexHandler

FIXTURE_APK = str(Path(__file__).parent / "fixtures" / "notesdemo.apk")

JAR_OK = (apkops_mod.tools_dir() / "dexfile-cli.jar").is_file()
ROUNDTRIP = pytest.mark.skipif(not JAR_OK, reason="dexfile-cli.jar not available")


# ── apk_read_signature ────────────────────────────────────────────────────

def test_read_signature_on_real_apk():
    result = ApkOpsHandler().apk_read_signature({"apk_path": FIXTURE_APK})
    assert result["status"] == "ok"
    out = result["output"]
    assert out["ok"] is True
    assert "verifies" in out
    if out.get("schemes"):  # apksigner present on PATH
        assert isinstance(out["schemes"], dict)


def test_read_signature_on_unsigned_zip(tmp_path):
    unsigned = tmp_path / "unsigned.zip"
    with zipfile.ZipFile(unsigned, "w") as z:
        z.writestr("AndroidManifest.xml", "<manifest/>")
    result = ApkOpsHandler().apk_read_signature({"apk_path": str(unsigned)})
    out = result["output"]
    assert out["ok"] is True
    assert out.get("verifies") is False or "signers" not in out or not out["signers"]


# ── zip_update ────────────────────────────────────────────────────────────

def _three_entry_zip(tmp_path: Path) -> Path:
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("AndroidManifest.xml", "<manifest/>")
        z.writestr("classes.dex", b"dex\n035\x00payload-here")
        z.writestr("res/values/strings.xml", "<resources/>")
    return apk


def test_zip_update_patch_preserves_other_entries(tmp_path):
    apk = _three_entry_zip(tmp_path)
    before = {n: zipfile.ZipFile(apk).read(n) for n in zipfile.ZipFile(apk).namelist()}
    ops = [{"op": "patch", "entry_path": "classes.dex", "byte_offset": 12,
            "expected_hex": before["classes.dex"][12:20].hex(),
            "replacement_hex": "ffffffff"}]
    result = ApkOpsHandler().zip_update({"apk_path": str(apk), "ops": ops})
    assert result["status"] == "ok"
    after = {n: zipfile.ZipFile(apk).read(n) for n in zipfile.ZipFile(apk).namelist()}
    assert after["classes.dex"][:12] + b"\xff" * 4 + after["classes.dex"][20:] == \
        before["classes.dex"][:12] + b"\xff" * 4 + before["classes.dex"][20:]
    assert after["AndroidManifest.xml"] == before["AndroidManifest.xml"]  # byte-identical
    assert hashlib.sha256(after["res/values/strings.xml"]).hexdigest() == \
        hashlib.sha256(before["res/values/strings.xml"]).hexdigest()  # untouched = identical
    # compression type preserved for untouched entries
    infos = {i.filename: i for i in zipfile.ZipFile(apk).infolist()}
    assert infos["AndroidManifest.xml"].compress_type == \
        zipfile.ZipFile(str(apk)).getinfo("AndroidManifest.xml").compress_type


def test_zip_update_patch_expected_mismatch_aborts(tmp_path):
    apk = _three_entry_zip(tmp_path)
    ops = [{"op": "patch", "entry_path": "classes.dex", "byte_offset": 12,
            "expected_hex": "deadbeef", "replacement_hex": "ffffffff"}]
    result = ApkOpsHandler().zip_update({"apk_path": str(apk), "ops": ops})
    assert result["status"] == "ok"  # the batch reports; the op failed
    assert result["output"]["errors"] and "mismatch" in result["output"]["errors"][0]["error"]
    # untouched entries are byte-identical: the patch was not applied
    assert zipfile.ZipFile(apk).read("classes.dex").startswith(b"dex\n035\x00payload")


def test_zip_update_rename_meta_inf_refused(tmp_path):
    apk = _three_entry_zip(tmp_path)
    ops = [{"op": "rename", "from": "res/values/strings.xml", "to": "META-INF/evil.xml"}]
    result = ApkOpsHandler().zip_update({"apk_path": str(apk), "ops": ops})
    errors = result["output"]["errors"]
    assert errors and "signatures" in errors[0]["error"]


def test_zip_update_add_replace_delete(tmp_path):
    apk = _three_entry_zip(tmp_path)
    new_file = tmp_path / "extra.bin"
    new_file.write_bytes(b"added-bytes")
    ops = [
        {"op": "add", "entry_path": "assets/extra.bin", "from_file": str(new_file)},
        {"op": "replace", "entry_path": "res/values/strings.xml", "content": "<resources x/>"},
        {"op": "delete", "entry_path": "classes.dex"},
    ]
    result = ApkOpsHandler().zip_update({"apk_path": str(apk), "ops": ops})
    assert result["status"] == "ok"
    with zipfile.ZipFile(apk) as z:
        names = z.namelist()
        assert "assets/extra.bin" in names and "classes.dex" not in names
        assert z.read("assets/extra.bin") == b"added-bytes"
        assert z.read("res/values/strings.xml") == b"<resources x/>"


def test_zip_update_expected_sha_guard(tmp_path):
    apk = _three_entry_zip(tmp_path)
    result = ApkOpsHandler().zip_update({
        "apk_path": str(apk),
        "ops": [{"op": "delete", "entry_path": "classes.dex"}],
        "expected_sha256": "0" * 64,
    })
    assert result["status"] == "error" and "mismatch" in result["error"]


# ── zip_test ──────────────────────────────────────────────────────────────

def test_zip_test_counts_and_clean_zip(tmp_path):
    apk = _three_entry_zip(tmp_path)
    out = ApkOpsHandler().zip_test({"zip_path": str(apk)})["output"]
    assert out["ok"] is True and out["entries"] == 3
    assert out["bad"] == [] and out["duplicates"] == []
    assert out["methods"].get("store") == 3  # writestr(str) defaults to STORED


def test_zip_test_flags_duplicates_and_corrupt(tmp_path):
    corrupt = tmp_path / "corrupt.zip"
    with zipfile.ZipFile(corrupt, "w") as z:
        z.writestr("a.txt", "aaaa")
        z.writestr("a.txt", "bbbb")  # duplicate name
        z.writestr("b.txt", "cccc")
    raw = corrupt.read_bytes()
    # corrupt b.txt's compressed data inside the file (flip a byte mid-archive)
    idx = raw.index(b"cccc")
    raw = raw[:idx + 2] + b"XX" + raw[idx + 4:]
    corrupt.write_bytes(raw)
    out = ApkOpsHandler().zip_test({"zip_path": str(corrupt)})["output"]
    assert out["duplicates"] == ["a.txt"]
    assert out["ok"] is False
    assert out["bad"] and "b.txt" in out["bad"][0]["name"]


def test_zip_test_on_real_apk():
    out = ApkOpsHandler().zip_test({"apk_path": FIXTURE_APK})["output"]
    assert out["ok"] is True and out["entries"] >= 3


# ── zip_extract ───────────────────────────────────────────────────────────

def test_zip_extract_extracts_named_entries(tmp_path):
    apk = _three_entry_zip(tmp_path)
    out_dir = tmp_path / "out"
    result = ApkOpsHandler().zip_extract({
        "zip_path": str(apk),
        "entries": ["AndroidManifest.xml", "classes.dex"],
        "output_dir": str(out_dir)})
    out = result["output"]
    assert out["extracted"] == 2
    assert (out_dir / "classes.dex").read_bytes().startswith(b"dex\n035")


def test_zip_extract_refuses_zip_slip(tmp_path):
    evil = tmp_path / "evil.zip"
    with zipfile.ZipFile(evil, "w") as z:
        z.writestr("../../escape.txt", "nope")
    result = ApkOpsHandler().zip_extract({
        "zip_path": str(evil), "entries": ["../../escape.txt"],
        "output_dir": str(tmp_path / "out"), "overwrite": True})
    r = result["output"]["results"][0]
    assert r["ok"] is False and "zip-slip" in r["error"]
    assert not (tmp_path / "escape.txt").exists()


def test_zip_extract_partial_failure_keeps_prior_entries(tmp_path):
    apk = _three_entry_zip(tmp_path)
    out_dir = tmp_path / "out"
    result = ApkOpsHandler().zip_extract({
        "zip_path": str(apk), "entries": ["AndroidManifest.xml", "missing.xml"],
        "output_dir": str(out_dir)})
    out = result["output"]
    assert out["extracted"] == 1 and out["results"][1]["ok"] is False
    assert (out_dir / "AndroidManifest.xml").is_file()  # prior entry kept


# ── native_map_address / native patchers ──────────────────────────────────

def _phdr_so(tmp_path: Path, code: bytes, vaddr: int = 0x1000) -> Path:
    """Minimal ELF64/AArch64 with one PT_LOAD carrying `code` at vaddr."""
    from test_sosec import _elf64_phdr

    blob = _elf64_phdr([(1, 0x5, code)])  # PT_LOAD, R+X
    # patch e_machine to AArch64 (the builder defaults to it)
    return _write(tmp_path, blob)


def _write(tmp_path: Path, blob: bytes) -> Path:
    p = tmp_path / "libtest.so"
    p.write_bytes(blob)
    return p


def test_native_map_address_both_directions(tmp_path):
    # the phdr fixture maps vaddr 0x100040 -> file offset 0x40 (0x100000 + off)
    code = b"\x1f\x20\x03\xd5" * 4
    so = _phdr_so(tmp_path, code)
    from android_re_mcp.handlers.sosec import SoSecHandler
    out = SoSecHandler().native_map_address({"so_path": str(so), "address": "0x100044"})["output"]
    assert out["file_offset"] == "0x44"
    assert out["mapped_in_exec"] is True
    back = SoSecHandler().native_map_address({"so_path": str(so), "address": "0x44",
                                              "address_kind": "file_offset"})["output"]
    assert back["va"] == "0x100044"


def test_native_map_address_unmapped_is_honest(tmp_path):
    code = b"\x1f\x20\x03\xd5" * 2
    so = _phdr_so(tmp_path, code)
    del code
    from android_re_mcp.handlers.sosec import SoSecHandler
    result = SoSecHandler().native_map_address({"so_path": str(so), "address": "0xdead0000"})
    assert result["status"] == "error" and "not mapped" in result["error"]


def test_native_patch_string_shortens_and_zero_pads(tmp_path):
    code = b"\x1f\x20\x03\xd5" + b"hello-original\x00" + b"\x1f\x20\x03\xd5"
    so = _phdr_so(tmp_path, code)
    del code
    from android_re_mcp.handlers.sosec import SoSecHandler
    result = SoSecHandler().native_patch_string({
        "so_path": str(so), "expected_text": "hello-original",
        "replacement_text": "hi", "output_path": str(so)})
    assert result["status"] == "ok"
    data = so.read_bytes()
    assert b"hi\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" in data
    assert b"hello-original" not in data
    site = result["output"]["sites"][0]
    assert site["bytes_written"] == len("hello-original")


def test_native_patch_string_too_long_rejected(tmp_path):
    code = b"\x1f\x20\x03\xd5" + b"short\x00"
    so = _phdr_so(tmp_path, code)
    del code
    from android_re_mcp.handlers.sosec import SoSecHandler
    before = so.read_bytes()
    result = SoSecHandler().native_patch_string({
        "so_path": str(so), "expected_text": "short",
        "replacement_text": "much-longer-replacement"})
    assert result["status"] == "error" and "shorter only" in result["error"]
    assert so.read_bytes() == before  # zero writes on abort


def test_native_patch_string_expected_missing_aborts(tmp_path):
    code = b"\x1f\x20\x03\xd5" + b"short\x00"
    so = _phdr_so(tmp_path, code)
    del code
    from android_re_mcp.handlers.sosec import SoSecHandler
    before = so.read_bytes()
    result = SoSecHandler().native_patch_string({
        "so_path": str(so), "expected_text": "absent-string",
        "replacement_text": "x"})
    assert result["status"] == "error" and "not found" in result["error"]
    assert so.read_bytes() == before


keystone = pytest.importorskip("keystone", reason="keystone-engine not installed")


def test_native_patch_instructions_arm64(tmp_path):
    code = b"\x00\x00\x80\xd2" * 2  # movz x0, #0 twice (4 bytes each)
    so = _phdr_so(tmp_path, code)
    from android_re_mcp.handlers.sosec import SoSecHandler
    result = SoSecHandler().native_patch_instructions({
        "so_path": str(so), "address": "0x100040",
        "expected_hex": code[:4].hex(),
        "replacement_assembly": "mov x0, #1", "output_path": str(so)})
    assert result["status"] == "ok"
    data = so.read_bytes()
    assert data[0x40:0x44] == bytes.fromhex("20 00 80 d2".replace(" ", ""))  # MOVZ X0,#1 = 0xd2800020
    assert data[0x44:0x48] == code[4:8]  # second instruction untouched
    report = result["output"]
    assert report["bytes_written"] == 4 and report["assembled_bytes"] == 4


def test_native_patch_instructions_expected_mismatch(tmp_path):
    code = b"\xd2\x80\x00\x00" * 2
    so = _phdr_so(tmp_path, code)
    del code
    before = so.read_bytes()
    from android_re_mcp.handlers.sosec import SoSecHandler
    result = SoSecHandler().native_patch_instructions({
        "so_path": str(so), "address": "0x100040",
        "expected_hex": "aabbccdd", "replacement_assembly": "mov x0, #1"})
    assert result["status"] == "error" and "mismatch" in result["error"]
    assert so.read_bytes() == before


def test_native_patch_instructions_too_long_rejected(tmp_path):
    code = b"\x1f\x20\x03\xd5"  # one 4-byte NOP
    so = _phdr_so(tmp_path, code)
    del code
    before = so.read_bytes()
    from android_re_mcp.handlers.sosec import SoSecHandler
    result = SoSecHandler().native_patch_instructions({
        "so_path": str(so), "address": "0x100040",
        "expected_hex": "1f2003d5",
        "replacement_assembly": "mov x0, #1\nmov x1, #2\nmov x2, #3"})
    assert result["status"] == "error" and "shorter only" in result["error"]
    assert so.read_bytes() == before


# ── apk_build_check ───────────────────────────────────────────────────────

def test_build_check_clean_dir(tmp_path):
    (tmp_path / "AndroidManifest.xml").write_bytes(b"\x03\x00\x08\x00fake-axml")
    out = ApkOpsHandler().apk_build_check({"smali_dir": str(tmp_path)})["output"]
    assert out["stats"]["manifest_ok"] is True
    assert out["ok"] is True  # no blockers


def test_build_check_flags_bak_and_missing_manifest(tmp_path):
    (tmp_path / "some.dex.bak").write_bytes(b"x")
    out = ApkOpsHandler().apk_build_check({"smali_dir": str(tmp_path)})["output"]
    assert any(b["code"] == "MANIFEST_MISSING" for b in out["blockers"])
    assert any(w["code"] == "PENDING_EDITS" for w in out["warnings"])


# ── resource tools (androguard-gated) ─────────────────────────────────────

pytest.importorskip("androguard", reason="androguard not installed")


REAL_APK = "/home/dragon/Documents/appcloner_368_reffree_NOFCALL_signed.apk"
REAL = pytest.mark.skipif(not Path(REAL_APK).is_file(), reason="real APK not present")


@REAL
def test_resource_table_list_on_real_apk():
    out = ApkOpsHandler().resource_table_list({"apk_path": REAL_APK,
                                               "type_name": "string", "limit": 5})["output"]
    pkg = out["packages"][0]
    assert pkg["name"] == "com.applisto.appcloner"
    strings = next(t for t in pkg["types"] if t["name"] == "string")
    assert strings["entry_count"] >= 5
    assert all(e["id"].startswith("0x") for e in strings["entries"])


@REAL
def test_resource_read_resolves_app_name():
    out = ApkOpsHandler().resource_read({"apk_path": REAL_APK,
                                         "ids": ["string/app_name"]})["output"]
    r = out["results"][0]
    assert r["ok"] is True and r["id"] == "0x7f13010b"
    assert any(v["value"] == "App Cloner" for v in r["variants"])


def test_resource_read_missing_resource_is_honest(tmp_path):
    # notesdemo's arsc parses with zero packages → honest not-found
    out = ApkOpsHandler().resource_read({"apk_path": FIXTURE_APK,
                                         "ids": ["string/app_name"]})["output"]
    assert out["results"][0]["ok"] is False


@REAL
def test_resource_xref_finds_hex_uses(tmp_path):
    # synthetic decompile tree referencing app_name's id
    smali_dir = tmp_path / "dec"
    (smali_dir / "smali/com/example").mkdir(parents=True)
    (smali_dir / "smali/com/example/Foo.smali").write_text(
        ".class public Lcom/example/Foo;\n"
        "const v0, 0x7f13010b\n")
    out = ApkOpsHandler().resource_xref({
        "apk_path": REAL_APK, "resource_id": "string/app_name",
        "smali_dir": str(smali_dir)})["output"]
    assert out["total"] == 1
    assert out["matches"][0]["file"] == "smali/com/example/Foo.smali"
    assert "0x7f13010b" in out["matches"][0]["snippet"]


# ── dex reads (jar/jadx gated) ────────────────────────────────────────────


REAL_TOOLS = os.environ.get("ANDROID_RE_MCP_TOOLS_DIR") or str(Path.home() / "tools")
JAR_OK = (Path(REAL_TOOLS) / "dexfile-cli.jar").is_file()
DEX_OUTLINE = pytest.mark.skipif(not JAR_OK, reason="dexfile-cli.jar not available")


@DEX_OUTLINE
def test_dex_read_class_outline_real(monkeypatch, tmp_path):
    monkeypatch.setenv("ANDROID_RE_MCP_TOOLS_DIR", REAL_TOOLS)
    h = DexHandler()
    # build a dex via the same jar
    smali = tmp_path / "Loader.smali"
    smali.write_text(
        ".class public Lcom/poc/Loader;\n.super Ljava/lang/Object;\n\n"
        ".method public static getMessage()Ljava/lang/String;\n    .locals 1\n\n"
        '    const-string v0, "hi"\n\n    return-object v0\n.end method\n')
    assembled = h.dex_assemble({"path": str(smali), "output_path": str(tmp_path / "l.dex")})
    assert assembled["status"] == "ok"
    out = h.dex_read_class_outline({"dex_path": str(tmp_path / "l.dex"),
                                    "class_name": "com.poc.Loader"})["result"]
    assert out["class"] == "com.poc.Loader"
    assert out["super"] == "java.lang.Object"
    assert out["access_flags"] == "public"
    assert out["methods"][0]["name"] == "getMessage"
    assert out["methods"][0]["registers"] == 1


JADX_OK = shutil.which("jadx") is not None
PSEUDO = pytest.mark.skipif(not JADX_OK, reason="jadx not on PATH")


@PSEUDO
def test_dex_read_pseudocode_on_real_apk():
    h = DexHandler()
    out = h.dex_read_pseudocode({"apk_path": FIXTURE_APK,
                                 "class_name": "com.example.notes.Notes"})["output"]
    assert "class" in out["code"]
    assert "Notes" in out["code"]
    assert out["source"].endswith(".java")


def test_dex_read_pseudocode_method_slice_hit_path(tmp_path):
    # jadx omits default constructors, so the slice is tested on the cache
    # hit path with a handwritten Java file (no jadx run needed)
    h = DexHandler()
    cache = tmp_path / "cache"
    java = cache / "sources" / "com/example/Foo.java"
    java.parent.mkdir(parents=True)
    java.write_text(
        "package com.example;\n\n"
        "public class Foo {\n"
        "    int id;\n\n"
        "    public int getId() {\n"
        "        return id;\n"
        "    }\n\n"
        "    public void risky() {\n"
        "        throw new RuntimeException();\n"
        "    }\n}\n")
    out = h.dex_read_pseudocode({"apk_path": FIXTURE_APK, "class_name": "com.example.Foo",
                                 "method": "getId", "cache_dir": str(cache)})["output"]
    assert out["method"] == "getId"
    assert "return id;" in out["code"]
    assert "risky" not in out["code"]  # the slice excludes other methods
