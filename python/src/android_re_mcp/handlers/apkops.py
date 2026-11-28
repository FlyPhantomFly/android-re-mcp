"""
handlers/apkops.py — APK-entry surgery, signatures, resource tables and
build checks. The MT-MCP adoption batch (see the MT MCP implementation
plan in ~/jadx-emu/protected_apks/test_apks/mt_mcp/): the tools MT's
capture proved missing here, minus everything android-re-mcp already
answered.

Conventions carried over from that plan:
* absolute paths; first in-place write creates a `.bak`
* per-op results — one bad op never fails the batch
* `expected_hex` guards on byte-level patches (stale-offset protection)
* pure stdlib first (zip ops), androguard for ARSC (silenced — its debug
  logging is extremely loud), apksigner/openssl for signatures
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import time
import zipfile
import zlib
from pathlib import Path

from android_re_mcp.handlers.caps import cap_items
from android_re_mcp.handlers.apkscan import (
    ENTRY_CAP_ENV,
    entry_cap_mb,
    entry_over_cap,
    PayloadTooLarge,
    _read_entry,
)
from android_re_mcp.paths import data_dir, tools_dir
_CRC_CHUNK = 1024 * 1024  # streamed CRC check chunk

_TIMEOUT = 600
logger = logging.getLogger(__name__)


class ApkOpsHandler:
    """Stateless APK/zip/resource operations (asyncio.to_thread pool)."""

    # ── apk_read_signature ────────────────────────────────────────────────

    def apk_read_signature(self, args: dict) -> dict:
        """[TOOL] Read signing metadata: schemes, signers, digests, validity."""
        apk_path = args.get("apk_path", "")
        if not Path(apk_path).is_file():
            return {"status": "error", "tool": "apk_read_signature",
                    "error": f"apk_path '{apk_path}' not found"}

        out: dict = {"apk": apk_path, "ok": True}
        apksigner = shutil.which("apksigner")
        if apksigner:
            try:
                proc = subprocess.run(
                    [apksigner, "verify", "--print-certs", "--verbose", apk_path],
                    capture_output=True, text=True, timeout=120,
                )
                out["verifies"] = "DOES NOT VERIFY" not in (proc.stdout + proc.stderr)
                out["schemes"] = self._parse_schemes(proc.stdout)
                signers = self._parse_apksigner_certs(proc.stdout)
                if signers:
                    out["signers"] = signers
                warnings = [l.strip() for l in proc.stdout.splitlines()
                            if l.strip().startswith("WARNING")]
                if warnings:
                    out["warnings"] = warnings[:10]
            except subprocess.TimeoutExpired:
                out["warnings"] = ["apksigner timed out after 120s"]
            except Exception as exc:  # noqa: BLE001
                out["warnings"] = [f"apksigner failed: {exc}"]
        else:
            out["warnings"] = ["apksigner not on PATH — scheme matrix unavailable "
                               "(install Android build-tools for the full picture)"]

        # openssl path for subject/issuer/validity/key details from META-INF certs
        openssl = shutil.which("openssl")
        meta_signers = self._meta_inf_signers(apk_path)
        if openssl and meta_signers:
            try:
                with zipfile.ZipFile(apk_path) as z:
                    details = []
                    cap = entry_cap_mb()
                    for name in meta_signers[:4]:
                        cert_der = _read_entry(z, z.getinfo(name), cap)
                        if cert_der is None:
                            out.setdefault("notes", []).append(
                                f"{name}: skipped, above the entry cap")
                            continue
                        detail = self._openssl_cert_details(openssl, cert_der)
                        detail["file"] = name
                        details.append(detail)
                    out.setdefault("signers", [])
                    for detail in details:
                        if detail not in out["signers"]:
                            out["signers"].append(detail)
            except (OSError, zipfile.BadZipFile, KeyError) as exc:
                out.setdefault("warnings", []).append(f"openssl cert read failed: {exc}")
        elif not meta_signers and not apksigner:
            out["verifies"] = False
            out["note"] = "no v1 META-INF certificate and no apksigner — cannot verify; " \
                          "the APK may be v2/v3-only (install build-tools for that)"
        return {"status": "ok", "tool": "apk_read_signature", "output": out}

    @staticmethod
    def _parse_schemes(stdout: str) -> dict:
        schemes = {}
        patterns = {
            "v1": r"Verified using v1 Scheme \(APK Signature Scheme v1\)\s*:\s*(\w+)",
            "v2": r"Verified using v2 Scheme \(APK Signature Scheme v2\)\s*:\s*(\w+)",
            "v3": r"Verified using v3 Scheme \(APK Signature Scheme v3\)\s*:\s*(\w+)",
            "v3_1": r"Verified using v3\.1 Scheme \(APK Signature Scheme v3\.1\)\s*:\s*(\w+)",
            "v4": r"Verified using v4 Scheme \(APK Signature Scheme v4\)\s*:\s*(\w+)",
            "sourceStamp": r"Verified using SourceStamp\s*:\s*(\w+)",
        }
        for key, pattern in patterns.items():
            m = re.search(pattern, stdout)
            if m:
                schemes[key] = m.group(1).lower() == "true"
        return schemes

    @staticmethod
    def _parse_apksigner_certs(stdout: str) -> list[dict]:
        signers = []
        for block in re.split(r"Signer #\d+ certificate certificate", stdout)[1:]:
            dn = re.search(r"DN:\s*(.+)", block)
            sha256 = re.search(r"SHA-256 digest:\s*([0-9a-f]+)", block)
            sha1 = re.search(r"SHA-1 digest:\s*([0-9a-f]+)", block)
            md5 = re.search(r"MD5 digest:\s*([0-9a-f]+)", block)
            if dn:
                signers.append({"subject_dn": dn.group(1).strip(),
                                "sha256": sha256.group(1) if sha256 else None,
                                "sha1": sha1.group(1) if sha1 else None,
                                "md5": md5.group(1) if md5 else None})
        return signers

    @staticmethod
    def _meta_inf_signers(apk_path: str) -> list[str]:
        try:
            with zipfile.ZipFile(apk_path) as z:
                return sorted(n for n in z.namelist()
                              if n.upper().startswith("META-INF/")
                              and (n.upper().endswith((".RSA", ".DSA", ".EC"))))
        except (OSError, zipfile.BadZipFile):
            return []

    @staticmethod
    def _openssl_cert_details(openssl: str, cert_der: bytes) -> dict:
        try:
            proc = subprocess.run(
                [openssl, "pkcs7", "-inform", "DER", "-print_certs", "-text"],
                input=cert_der, capture_output=True, timeout=30,
            )
            text = proc.stdout.decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            return {"error": f"openssl failed: {exc}"}

        def grab(pattern: str) -> str | None:
            m = re.search(pattern, text)
            return m.group(1).strip() if m else None

        subject = grab(r"Subject:\s*(.+?)(?:\n|$)")
        issuer = grab(r"Issuer:\s*(.+?)(?:\n|$)")
        serial = grab(r"Serial Number:\s*\n?\s*([0-9a-fA-F:]+)")
        not_before = grab(r"Not Before:\s*(.+)")
        not_after = grab(r"Not After\s*:\s*(.+)")
        key_alg = grab(r"Public Key Algorithm:\s*(.+)")
        key_bits = grab(r"(?:Public-Key|Public Key):\s*\((\d+) bit\)")
        sig_alg = grab(r"Signature Algorithm:\s*(.+)")
        # sha256 of the cert itself (not the signature block)
        sha256 = hashlib.sha256(cert_der).hexdigest()
        return {"subject": subject, "issuer": issuer,
                "serial_hex": serial.replace(":", "") if serial else None,
                "not_before": not_before, "not_after": not_after,
                "key_alg": key_alg, "key_bits": int(key_bits) if key_bits else None,
                "sig_alg": sig_alg, "cert_sha256": sha256}

    # ── zip_test ──────────────────────────────────────────────────────────

    def zip_test(self, args: dict) -> dict:
        """[TOOL] Full zip/APK integrity audit: CRC every entry, dupes, methods."""
        zip_path = args.get("zip_path") or args.get("apk_path") or ""
        if not Path(zip_path).is_file():
            return {"status": "error", "tool": "zip_test",
                    "error": f"zip_path '{zip_path}' not found"}
        try:
            raw = Path(zip_path).read_bytes()
            with zipfile.ZipFile(zip_path) as z:
                infos = z.infolist()
                methods: dict[str, int] = {}
                duplicates: list[str] = []
                bad: list[dict] = []
                encrypted: list[str] = []
                compressed = uncompressed = 0
                seen: set[str] = set()
                directories = 0
                for info in infos:
                    if info.filename in seen:
                        duplicates.append(info.filename)
                    seen.add(info.filename)
                    if info.filename.endswith("/"):
                        directories += 1
                    method = {zipfile.ZIP_STORED: "store",
                              zipfile.ZIP_DEFLATED: "deflate",
                              zipfile.ZIP_BZIP2: "bzip2",
                              zipfile.ZIP_LZMA: "lzma"}.get(info.compress_type,
                                                            f"method{info.compress_type}")
                    methods[method] = methods.get(method, 0) + 1
                    compressed += info.compress_size
                    uncompressed += info.file_size
                    if info.flag_bits & 0x1:
                        encrypted.append(info.filename)
                    if not info.filename.endswith("/"):
                        try:
                            # streamed: validates the CRC without holding the entry
                            with z.open(info) as fh:
                                while fh.read(_CRC_CHUNK):
                                    pass
                        except Exception as exc:  # noqa: BLE001
                            bad.append({"name": info.filename, "reason": str(exc)[:200]})
                # trailing bytes after the EOCD record
                eocd = raw.rfind(b"PK\x05\x06")
                trailing = 0
                if eocd != -1 and eocd + 22 <= len(raw):
                    comment_len = int.from_bytes(raw[eocd + 20:eocd + 22], "little")
                    trailing = len(raw) - (eocd + 22 + comment_len)

                out: dict = {
                    "zip": zip_path, "ok": not bad and not duplicates,
                    "entries": len(infos), "directories": directories,
                    "compressed": compressed, "uncompressed": uncompressed,
                    "ratio": round(uncompressed / compressed, 3) if compressed else None,
                    "methods": methods, "duplicates": duplicates,
                    "bad": bad, "trailing_bytes": trailing,
                }
                if encrypted:
                    shown, info_ = cap_items(encrypted, "narrow by reading a specific entry")
                    out["encrypted"] = shown
                    out["encrypted_count"] = info_["total"]
                # APK-specific observations
                if zip_path.lower().endswith(".apk"):
                    store_dex = [n for n in seen
                                 if n.startswith("classes") and n.endswith(".dex")
                                 and methods.get("store")]
                    apk_warnings = []
                    if any(n.upper().startswith("META-INF/") and n in seen
                           for n in store_dex if n.upper().startswith("META-INF/")):
                        pass
                    if store_dex:
                        apk_warnings.append(
                            f"STORE-only dex entries: {', '.join(sorted(store_dex)[:4])} "
                            "(alignment smell — unzip before analyzing if offsets matter)")
                    if apk_warnings:
                        out["apk_notes"] = apk_warnings
                return {"status": "ok", "tool": "zip_test", "output": out}
        except zipfile.BadZipFile as exc:
            return {"status": "error", "tool": "zip_test", "error": f"bad zip: {exc}"}
        except OSError as exc:
            return {"status": "error", "tool": "zip_test", "error": str(exc)}

    # ── zip_extract ───────────────────────────────────────────────────────

    def zip_extract(self, args: dict) -> dict:
        """[TOOL] Extract named zip/APK entries, traversal-safe, byte-faithful."""
        zip_path = args.get("zip_path") or args.get("apk_path") or ""
        entries = args.get("entries") or []
        out_dir = args.get("output_dir") or self._default_dir(zip_path, "_extract")
        overwrite = bool(args.get("overwrite", False))
        if not Path(zip_path).is_file():
            return {"status": "error", "tool": "zip_extract",
                    "error": f"zip_path '{zip_path}' not found"}
        if not entries or not isinstance(entries, list):
            return {"status": "error", "tool": "zip_extract",
                    "error": "entries must be a non-empty JSON array of entry names"}

        results: list[dict] = []
        dest = Path(out_dir)
        cap_mb = entry_cap_mb()
        try:
            with zipfile.ZipFile(zip_path) as z:
                for entry in entries:
                    entry = str(entry)
                    result = {"entry": entry}
                    rel = entry.replace("\\", "/").lstrip("/")
                    target = dest / rel
                    # zip-slip and shape checks before any read
                    if ".." in Path(rel).parts or Path(rel).is_absolute() or ":" in rel.split("/")[0]:
                        result.update({"ok": False, "error": "zip-slip refused"})
                        results.append(result)
                        continue
                    resolved_parent = target.parent.resolve()
                    dest_resolved = dest.resolve()
                    if resolved_parent != dest_resolved and dest_resolved not in resolved_parent.parents:
                        result.update({"ok": False, "error": "path escapes the output folder"})
                        results.append(result)
                        continue
                    try:
                        info = z.getinfo(entry)
                    except KeyError:
                        result.update({"ok": False, "error": "entry not found"})
                        results.append(result)
                        continue
                    if entry_over_cap(info, cap_mb):
                        result.update({"ok": False, "error": (
                            f"entry is {info.file_size / (1024 * 1024):.1f} MB, above the "
                            f"{cap_mb} MB entry cap (raise {ENTRY_CAP_ENV}, or set it to 0 to disable)"
                        )})
                        results.append(result)
                        continue
                    if target.is_file() and not overwrite:
                        result.update({"ok": False, "error": "already exists (overwrite=false)"})
                        results.append(result)
                        continue
                    if target.is_symlink():
                        # a symlink at the final component would be followed by open()
                        result.update({"ok": False, "error": "symlink in the way"})
                        results.append(result)
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    # stream: the entry is never held in memory
                    with z.open(info) as src, open(target, "wb") as fh:
                        shutil.copyfileobj(src, fh)
                    result.update({"ok": True, "path": str(target), "bytes": info.file_size})
                    results.append(result)
        except zipfile.BadZipFile as exc:
            return {"status": "error", "tool": "zip_extract", "error": f"bad zip: {exc}"}
        except OSError as exc:
            return {"status": "error", "tool": "zip_extract", "error": str(exc)}

        ok_count = sum(1 for r in results if r.get("ok"))
        out = {"zip": zip_path, "out_dir": out_dir, "results": results,
               "extracted": ok_count, "total": len(results)}
        if ok_count < len(results):
            out["note"] = f"{len(results) - ok_count} entries failed — per-entry errors above, prior entries kept"
        return {"status": "ok", "tool": "zip_extract", "output": out}

    # ── zip_update ────────────────────────────────────────────────────────

    def zip_update(self, args: dict) -> dict:
        """[TOOL] Add/replace/patch/rename/delete zip entries; others byte-identical."""
        zip_path = args.get("zip_path") or args.get("apk_path") or ""
        ops = args.get("ops")
        out_path = args.get("output_apk")
        expected_sha = args.get("expected_sha256")
        if not Path(zip_path).is_file():
            return {"status": "error", "tool": "zip_update",
                    "error": f"zip_path '{zip_path}' not found"}
        if not isinstance(ops, list) or not ops:
            return {"status": "error", "tool": "zip_update",
                    "error": "ops must be a non-empty JSON array (add|replace|patch|rename|delete)"}

        if expected_sha:
            actual = hashlib.sha256(Path(zip_path).read_bytes()).hexdigest()
            if actual.lower() != expected_sha.lower():
                return {"status": "error", "tool": "zip_update",
                        "error": f"expected_sha256 mismatch: file is {actual}"}

        target = Path(out_path) if out_path else Path(zip_path)
        if out_path is None:
            bak = target.with_name(target.name + ".bak")
            if not bak.exists():
                shutil.copy2(zip_path, bak)

        try:
            src = zipfile.ZipFile(zip_path)
        except (zipfile.BadZipFile, OSError) as exc:
            return {"status": "error", "tool": "zip_update", "error": f"cannot read zip: {exc}"}

        try:
            infos = {info.filename: info for info in src.infolist()}
            # Bytes are held in memory only for entries an op reads or rewrites;
            # untouched entries stream from src to the output at write time (R5-1).
            # final[name] is the op's bytes (None = untouched/renamed, still in src);
            # source_of[name] is the archive entry the name currently maps to.
            final: dict[str, bytes | None] = {}
            source_of: dict[str, str] = {name: name for name in infos}
            order = list(infos.keys())
            results: list[dict] = []
            errors: list[dict] = []
            cap_mb = entry_cap_mb()

            def current_bytes(name: str) -> bytes:
                """An op's input bytes: in memory, or read (capped) from the source."""
                if name in final and final[name] is not None:
                    return final[name]
                info = infos[source_of[name]]
                if entry_over_cap(info, cap_mb):
                    raise PayloadTooLarge(
                        f"entry is {info.file_size / (1024 * 1024):.1f} MB, above the "
                        f"{cap_mb} MB entry cap (raise {ENTRY_CAP_ENV}, or set it to 0 to disable)")
                data = _read_entry(src, info, cap_mb)
                if data is None:
                    raise ValueError(f"cannot read entry '{info.filename}' from the source archive")
                return data

            def _refuse_over_cap_target(name: str) -> None:
                """Ops that rewrite an entry are refused when it is over the cap."""
                info = infos[source_of[name]]
                if entry_over_cap(info, cap_mb):
                    raise PayloadTooLarge(
                        f"entry is {info.file_size / (1024 * 1024):.1f} MB, above the "
                        f"{cap_mb} MB entry cap (raise {ENTRY_CAP_ENV}, or set it to 0 to disable)")

            for op in ops:
                if not isinstance(op, dict):
                    errors.append({"error": "each op must be a JSON object"})
                    continue
                op_type = op.get("op")
                try:
                    if op_type == "add":
                        name = str(op.get("entry_path", ""))
                        data = self._op_payload(op)
                        if data is None:
                            raise ValueError("needs from_file (absolute path) or content")
                        if name in source_of:
                            raise ValueError("entry already exists (use replace)")
                        if name.upper().startswith("META-INF/"):
                            results.append({"op": "add", "entry": name, "warning":
                                            "META-INF entries affect signatures — re-sign with apk_sign"})
                        final[name] = data
                        source_of[name] = name
                        order.append(name)
                        results.append({"op": "add", "entry": name, "ok": True,
                                        "after_size": len(data)})
                    elif op_type == "replace":
                        name = str(op.get("entry_path", ""))
                        data = self._op_payload(op)
                        if data is None:
                            raise ValueError("needs from_file (absolute path) or content")
                        if name not in source_of:
                            raise ValueError("entry not found (use add)")
                        _refuse_over_cap_target(name)
                        # current length without reading: in memory, else the source entry's size
                        before = len(final[name]) if name in final and final[name] is not None \
                            else infos[source_of[name]].file_size
                        final[name] = data
                        results.append({"op": "replace", "entry": name, "ok": True,
                                        "before_size": before, "after_size": len(data),
                                        "changed": before != len(data) or
                                        zlib.crc32(data) & 0xFFFFFFFF != infos[source_of[name]].CRC})
                    elif op_type == "patch":
                        name = str(op.get("entry_path", ""))
                        if name not in source_of:
                            raise ValueError("entry not found")
                        _refuse_over_cap_target(name)
                        r = self._apply_patch_bytes(current_bytes(name), op)
                        if not r.get("ok"):
                            raise ValueError(r.get("error", "patch failed"))
                        final[name] = r["data"]
                        results.append({"op": "patch", "entry": name, "ok": True,
                                        "byte_offset": r["byte_offset"],
                                        "before_size": r["before_size"],
                                        "after_size": r["after_size"]})
                    elif op_type == "rename":
                        src_name, dst_name = str(op.get("from", "")), str(op.get("to", ""))
                        if src_name.upper().startswith("META-INF/") or dst_name.upper().startswith("META-INF/"):
                            raise ValueError("renaming META-INF entries breaks signatures — refused")
                        if src_name not in source_of:
                            raise ValueError("entry not found")
                        if dst_name in source_of:
                            raise ValueError("target entry exists")
                        final[dst_name] = final.pop(src_name, None)
                        source_of[dst_name] = source_of.pop(src_name)
                        order = [dst_name if n == src_name else n for n in order]
                        results.append({"op": "rename", "from": src_name, "to": dst_name, "ok": True})
                    elif op_type == "delete":
                        name = str(op.get("entry_path", ""))
                        if name not in source_of:
                            raise ValueError("entry not found")
                        if name.upper().startswith("META-INF/"):
                            results.append({"op": "delete", "entry": name, "warning":
                                            "deleting META-INF entries breaks signatures — re-sign"})
                        final.pop(name, None)
                        del source_of[name]
                        order.remove(name)
                        results.append({"op": "delete", "entry": name, "ok": True})
                    else:
                        raise ValueError("unknown op (add|replace|patch|rename|delete)")
                except ValueError as exc:
                    errors.append({"op": op_type, "entry": op.get("entry_path") or op.get("from"),
                                   "error": str(exc)})

            tmp = Path(str(target) + ".tmp")
            try:
                with zipfile.ZipFile(tmp, "w") as dst:
                    for name in order:
                        if name in final and final[name] is not None:
                            data = final[name]
                            info = infos.get(name)
                            if (info is not None and source_of.get(name) == name
                                    and zlib.crc32(data) & 0xFFFFFFFF == info.CRC):
                                dst.writestr(info, data)  # unchanged: original ZipInfo (compression kept)
                            else:
                                # changed/new: `writestr(name, …)` — fresh ZipInfo stamped
                                # now, the destination archive's own default compression
                                dst.writestr(name, data)
                        else:
                            src_name = source_of[name]
                            if src_name == name:
                                # untouched: stream source → destination, ZipInfo preserved
                                with src.open(infos[name]) as fsrc, dst.open(infos[name], "w") as fdst:
                                    shutil.copyfileobj(fsrc, fdst)
                            else:
                                # renamed: written as `writestr(name, …)` did — a fresh
                                # ZipInfo stamped now, the destination archive's own
                                # default compression
                                new_info = zipfile.ZipInfo(name, date_time=time.localtime()[:6])
                                new_info.compress_type = dst.compression
                                with src.open(infos[src_name]) as fsrc, dst.open(new_info, "w") as fdst:
                                    shutil.copyfileobj(fsrc, fdst)
                tmp.replace(target)
            except (zipfile.BadZipFile, OSError) as exc:
                return {"status": "error", "tool": "zip_update", "error": str(exc)}
            finally:
                # a partial .tmp never survives a failed write; after a successful
                # replace() the path is gone, so this is a no-op (T18)
                tmp.unlink(missing_ok=True)
        finally:
            src.close()

        out: dict = {"zip": zip_path, "output": str(target),
                     "results": results,
                     "final_sha256": hashlib.sha256(target.read_bytes()).hexdigest()}
        if errors:
            out["errors"] = errors
            out["note"] = "some ops failed — see errors; the rest were applied"
        return {"status": "ok", "tool": "zip_update", "output": out}

    @staticmethod
    def _op_payload(op: dict) -> bytes | None:
        from_file = op.get("from_file")
        if from_file:
            p = Path(from_file)
            if not p.is_file():
                return None
            return p.read_bytes()
        content = op.get("content")
        if content is not None:
            return str(content).encode("utf-8")
        return None


    @staticmethod
    def _apply_patch_bytes(data: bytes, op: dict) -> dict:
        offset = op.get("byte_offset")
        expected_hex = str(op.get("expected_hex", "")).replace(" ", "").lower()
        replacement_hex = str(op.get("replacement_hex", "")).replace(" ", "").lower()
        if offset is None or not replacement_hex:
            return {"ok": False, "error": "patch needs byte_offset and replacement_hex"}
        try:
            offset = int(offset)
            replacement = bytes.fromhex(replacement_hex)
        except ValueError as exc:
            return {"ok": False, "error": f"bad patch values: {exc}"}
        if expected_hex:
            try:
                expected = bytes.fromhex(expected_hex)
            except ValueError as exc:
                return {"ok": False, "error": f"bad expected_hex: {exc}"}
            if len(expected) != len(replacement):
                return {"ok": False, "error": "expected_hex and replacement_hex must be the same length"}
        else:
            expected = replacement  # no guard: length equality still enforced
        end = offset + len(expected)
        if end > len(data):
            return {"ok": False, "error": f"byte_offset beyond entry end ({len(data)} bytes)"}
        actual = data[offset:end]
        if actual != expected:
            return {"ok": False, "error": f"expected_hex mismatch — bytes at 0x{offset:x} are "
                                          f"{actual.hex()}, not {expected.hex()}"}
        return {"ok": True, "data": data[:offset] + replacement + data[end:],
                "byte_offset": offset, "before_size": len(data), "after_size": len(data)}

    # ── apk_build_check ───────────────────────────────────────────────────

    def apk_build_check(self, args: dict) -> dict:
        """[TOOL] Pre-build linting: manifest, resources, dex, pending edits."""
        smali_dir = args.get("smali_dir", "")
        apk_path = args.get("apk_path", "")
        if not smali_dir and not apk_path:
            return {"status": "error", "tool": "apk_build_check",
                    "error": "provide smali_dir (an apktool decompile) or apk_path"}
        blockers: list[dict] = []
        warnings: list[dict] = []
        stats: dict = {"manifest_ok": None, "resources_ok": None, "dex_ok": None,
                       "pending_edits": []}

        base = Path(smali_dir) if smali_dir else Path(apk_path)
        # 1. pending-edit detection: .bak files left by dex_patch/dex_swap/smali_patch
        pending = sorted(str(p) for p in base.rglob("*.bak")) if base.is_dir() else \
            sorted(str(p) for p in base.parent.glob(base.name + "*.bak"))
        stats["pending_edits"] = pending[:10]
        if pending:
            warnings.append({"code": "PENDING_EDITS",
                             "message": f"{len(pending)} .bak backup(s) found — uncommitted edits?",
                             "files": pending[:10]})

        # 2. manifest
        manifest_rel = base / "AndroidManifest.xml"
        manifest_bytes = None
        if smali_dir:
            if manifest_rel.is_file():
                manifest_bytes = manifest_rel.read_bytes()
            else:
                blockers.append({"code": "MANIFEST_MISSING",
                                 "message": "AndroidManifest.xml not in the decompile",
                                 "fix_hint": "re-run apk_decompile"})
        elif apk_path and Path(apk_path).is_file():
            try:
                with zipfile.ZipFile(apk_path) as z:
                    if "AndroidManifest.xml" in z.namelist():
                        data = _read_entry(z, z.getinfo("AndroidManifest.xml"), entry_cap_mb())
                        if data is None:
                            blockers.append({
                                "code": "MANIFEST_OVER_CAP",
                                "message": (f"AndroidManifest.xml is above the "
                                            f"{entry_cap_mb()} MB entry cap; skipped"),
                                "fix_hint": "raise ANDROID_RE_MCP_MAX_ENTRY_MB to check it"})
                        else:
                            manifest_bytes = data
            except zipfile.BadZipFile as exc:
                blockers.append({"code": "APK_NOT_A_ZIP", "message": f"bad zip: {exc}"})
        if manifest_bytes is not None:
            # minimal sanity: binary AXML magic
            stats["manifest_ok"] = manifest_bytes[:4] in (b"\x03\x00\x08\x00", b"\x00\x00\x08\x00")
            if not stats["manifest_ok"]:
                blockers.append({"code": "MANIFEST_UNPARSEABLE",
                                 "message": "AndroidManifest.xml is not binary AXML",
                                 "fix_hint": "check the decompile; manifest_parse can confirm"})

        # 3. resources: aapt2 compile check when a res/ dir exists and aapt2 is available
        res_dir = base / "res"
        aapt2 = self._find_aapt2()
        if smali_dir and res_dir.is_dir():
            if aapt2:
                proc = subprocess.run(
                    [aapt2, "compile", "--dir", str(res_dir), "-o", os.devnull],
                    capture_output=True, text=True, timeout=300)
                stats["resources_ok"] = proc.returncode == 0
                if proc.returncode != 0:
                    blockers.append({"code": "RESOURCES_COMPILE_FAILED",
                                     "message": (proc.stderr or proc.stdout).strip()[:800],
                                     "fix_hint": "fix the res errors above, or rebuild with apktool b"})
            else:
                warnings.append({"code": "AAPT2_MISSING",
                                 "message": "aapt2 not found — resource compile check skipped",
                                 "fix_hint": "install Android build-tools and put aapt2 on PATH"})

        # 4. dex sanity via dexfile-cli (jar present) on the apk or decompile sources
        jar = tools_dir() / "dexfile-cli.jar"
        java = shutil.which("java")
        dex_ok = None
        if jar.is_file() and java:
            dex_files: list[Path] = []
            if smali_dir:
                dex_files = sorted(base.glob("smali_classes*.dex")) + sorted(base.glob("classes*.dex"))
            elif apk_path and Path(apk_path).is_file():
                try:
                    with zipfile.ZipFile(apk_path) as z:
                        scratch = Path(data_dir()) / "build-check"
                        scratch.mkdir(parents=True, exist_ok=True)
                        cap = entry_cap_mb()
                        for name in z.namelist():
                            if name.startswith("classes") and name.endswith(".dex"):
                                data = _read_entry(z, z.getinfo(name), cap)
                                if data is None:
                                    continue
                                p = scratch / Path(name).name
                                p.write_bytes(data)
                                dex_files.append(p)
                except zipfile.BadZipFile:
                    pass
            failures = []
            for dex_file in dex_files[:12]:
                r = self._run_dex_info(jar, java, str(dex_file))
                if r.get("status") != "ok":
                    failures.append({"file": Path(dex_file).name, "error": r.get("error", "")[:200]})
            dex_ok = not failures
            stats["dex_ok"] = dex_ok
            stats["dex_files_checked"] = len(dex_files)
            if failures:
                blockers.append({"code": "DEX_UNREADABLE", "message": json.dumps(failures)[:800],
                                 "fix_hint": "dex_info on each file for the full error"})
        else:
            warnings.append({"code": "DEXFILE_CLI_MISSING",
                             "message": "dexfile-cli.jar/java not available — dex sanity skipped",
                             "fix_hint": "run android-re-mcp --setup"})

        ok = not blockers
        return {"status": "ok", "tool": "apk_build_check",
                "output": {"ok": ok, "blockers": blockers, "warnings": warnings, "stats": stats}}

    @staticmethod
    def _find_aapt2() -> str | None:
        found = shutil.which("aapt2")
        if found:
            return found
        # standard SDK layout: $ANDROID_HOME/build-tools/<ver>/aapt2
        sdk_roots = [os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT"),
                     str(Path.home() / "Android" / "Sdk")]
        for root in sdk_roots:
            if not root:
                continue
            candidates = sorted(Path(root).glob("build-tools/*/aapt2"), reverse=True)
            if candidates:
                return str(candidates[0])
        return None

    @staticmethod
    def _run_dex_info(jar: str, java: str, dex_path: str) -> dict:
        try:
            proc = subprocess.run([java, "-jar", jar, "info", dex_path],
                                  capture_output=True, text=True, timeout=300)
            parsed = json.loads(proc.stdout) if proc.stdout.strip() else {}
            if proc.returncode == 0:
                return {"status": "ok"}
            return {"status": "error", "error": str(parsed.get("error", proc.stderr or ""))}
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "error": str(exc)}

    # ── resource tools (androguard ARSC) ──────────────────────────────────

    @staticmethod
    def _arsc(apk_path: str):
        """Parse resources.arsc via androguard, with its logging silenced."""
        from androguard.core.axml import ARSCParser

        with zipfile.ZipFile(apk_path) as z:
            data = _read_entry(z, z.getinfo("resources.arsc"), entry_cap_mb())
            if data is None:
                raise PayloadTooLarge(
                    f"resources.arsc is above the {entry_cap_mb()} MB entry cap "
                    f"(raise ANDROID_RE_MCP_MAX_ENTRY_MB, or set it to 0 to disable)")
            return ARSCParser(data)

    @staticmethod
    def _quiet_androguard():
        """Context manager that silences androguard's chatter.

        androguard 4.x logs through loguru, not the stdlib logging module —
        stdlib levels never touch it. loguru.disable() by module name is
        the only reliable mute.
        """
        import contextlib

        @contextlib.contextmanager
        def _quiet():
            from loguru import logger as loguru_logger
            loguru_logger.disable("androguard")
            try:
                yield
            finally:
                loguru_logger.enable("androguard")
        return _quiet()

    def resource_table_list(self, args: dict) -> dict:
        """[TOOL] Structured resources.arsc view via aapt2 dump resources."""
        apk_path = args.get("apk_path", "")
        type_name = args.get("type_name")
        package = args.get("package")
        limit = max(1, min(int(args.get("limit", 200) or 200), 2000))
        if not Path(apk_path).is_file():
            return {"status": "error", "tool": "resource_table_list",
                    "error": f"apk_path '{apk_path}' not found"}
        aapt2 = self._find_aapt2()
        if not aapt2:
            return {"status": "error", "tool": "resource_table_list",
                    "error": "aapt2 not found — the table view needs Android build-tools",
                    "hint": "install build-tools and put aapt2 on PATH, or ANDROID_HOME/Android/Sdk "
                            "with build-tools/<ver>/aapt2"}
        try:
            proc = subprocess.run([aapt2, "dump", "resources", apk_path],
                                  capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            return {"status": "error", "tool": "resource_table_list",
                    "error": "aapt2 dump resources timed out after 300s"}
        if proc.returncode != 0:
            return {"status": "error", "tool": "resource_table_list",
                    "error": (proc.stderr or proc.stdout).strip()[:800]}

        packages: list[dict] = []
        cur_pkg: dict | None = None
        cur_type: dict | None = None
        for line in proc.stdout.splitlines():
            pkg_m = re.match(r"\s*Package name=([^ ]+) id=", line)
            if pkg_m:
                cur_pkg = {"name": pkg_m.group(1), "types": []}
                packages.append(cur_pkg)
                continue
            type_m = re.match(r"\s+type (\S+) id=([0-9a-fA-F]+) entryCount=(\d+)", line)
            if type_m and cur_pkg:
                cur_type = {"name": type_m.group(1), "id": f"0x{type_m.group(2)}",
                            "entry_count": int(type_m.group(3)), "entries": [],
                            "truncated": False}
                cur_pkg["types"].append(cur_type)
                continue
            entry_m = re.match(r"\s+resource 0x([0-9a-f]+) (\S+)", line)
            if entry_m and cur_type is not None:
                if type_name and cur_type["name"] != type_name:
                    continue
                cur_type["entry_count_check"] = cur_type["entry_count"]
                if cur_type["entry_count_check"] <= limit or \
                        len(cur_type["entries"]) < limit:
                    cur_type["entries"].append({"id": f"0x{entry_m.group(1)}",
                                                "name": entry_m.group(2)})
        if package:
            packages = [p for p in packages if p["name"] == package]
        for pkg in packages:
            for t in pkg["types"]:
                if len(t["entries"]) < t["entry_count"]:
                    t["truncated"] = True
        return {"status": "ok", "tool": "resource_table_list",
                "output": {"apk": apk_path, "packages": packages}}

    def resource_read(self, args: dict) -> dict:
        """[TOOL] Resolve concrete resource variants (ids or type/name refs)."""
        apk_path = args.get("apk_path", "")
        ids = args.get("ids") or []
        depth = max(0, min(int(args.get("resolve_depth", 1) or 1), 5))
        if not Path(apk_path).is_file():
            return {"status": "error", "tool": "resource_read",
                    "error": f"apk_path '{apk_path}' not found"}
        if not ids or not isinstance(ids, list):
            return {"status": "error", "tool": "resource_read",
                    "error": "ids must be a non-empty list (e.g. ['0x7f13010b', 'string/app_name'])"}
        try:
            with self._quiet_androguard():
                p = self._arsc(apk_path)
                packages = p.get_packages_names()
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "resource_read",
                    "error": f"resources.arsc parse failed: {exc}"}

        package = packages[0] if packages else None

        results = []
        for spec in ids[:20]:
            with self._quiet_androguard():
                rid = self._resolve_rid(p, package, str(spec))
            if rid is None:
                results.append({"query": spec, "ok": False, "error": "resource not found"})
                continue
            variants = []
            try:
                with self._quiet_androguard():
                    for config, value in p.get_resolved_res_configs(rid)[:40]:
                        variants.append({"config": self._config_name(config),
                                         "value": self._coerce_value(value)})
            except Exception as exc:  # noqa: BLE001
                results.append({"query": spec, "ok": False,
                                "id": f"0x{rid:08x}", "error": f"resolve failed: {exc}"})
                continue
            # resolve_depth: follow @type/name chains
            follow = []
            for v in variants[:20]:
                val = v["value"]
                if depth > 0 and isinstance(val, str) and val.startswith("@") and "/" in val:
                    ref = val.lstrip("@").split("/", 1)
                    if len(ref) == 2:
                        inner_rid = p.get_res_id_by_key(package, ref[0], ref[1])
                        if inner_rid:
                            try:
                                inner = [(self._config_name(c2), self._coerce_value(v2))
                                         for c2, v2 in p.get_resolved_res_configs(inner_rid)[:10]]
                                follow.append({"ref": val, "id": f"0x{inner_rid:08x}",
                                               "variants": inner})
                            except Exception:  # noqa: BLE001
                                pass
            results.append({"query": spec, "ok": True, "id": f"0x{rid:08x}",
                            "variants": variants, "references": follow[:depth * 4]})
        return {"status": "ok", "tool": "resource_read", "output": {"apk": apk_path,
                                                                   "results": results}}

    @staticmethod
    def _resolve_rid(p, package: str | None, spec: str) -> int | None:
        spec = spec.strip()
        if spec.lower().startswith("0x"):
            try:
                return int(spec, 16)
            except ValueError:
                return None
        if "/" in spec:
            rtype, key = spec.split("/", 1)
            try:
                return p.get_res_id_by_key(package, rtype, key)
            except Exception:  # noqa: BLE001
                return None
        return None

    @staticmethod
    def _config_name(config) -> str:
        text = str(config)
        m = re.search(r"'([^']*)'", text)
        return m.group(1) if m else text

    @staticmethod
    def _coerce_value(value) -> str:
        if value is None:
            return "null"
        if isinstance(value, bytes):
            return f"<{len(value)} bytes>"
        return str(value)[:400]

    def resource_xref(self, args: dict) -> dict:
        """[TOOL] Find a resource id's uses across a decompiled tree (hex grep)."""
        apk_path = args.get("apk_path", "")
        resource_id = str(args.get("resource_id", "")).strip()
        smali_dir = args.get("smali_dir", "")
        if not resource_id:
            return {"status": "error", "tool": "resource_xref",
                    "error": "resource_id required (e.g. '0x7f13010b' or 'string/app_name')"}
        rid = None
        if resource_id.lower().startswith("0x"):
            try:
                rid = int(resource_id, 16)
            except ValueError:
                return {"status": "error", "tool": "resource_xref",
                        "error": f"bad hex id '{resource_id}'"}
        else:
            if not Path(apk_path).is_file():
                return {"status": "error", "tool": "resource_xref",
                        "error": "name-form resource_id needs apk_path to resolve"}
            try:
                with self._quiet_androguard():
                    p = self._arsc(apk_path)
                    packages = p.get_packages_names()
                    rtype, _, key = resource_id.replace("@", "").partition("/")
                    if not key:
                        return {"status": "error", "tool": "resource_xref",
                                "error": "name form must be 'type/name' (e.g. 'string/app_name')"}
                    rid = p.get_res_id_by_key(packages[0] if packages else None, rtype, key)
            except Exception as exc:  # noqa: BLE001
                return {"status": "error", "tool": "resource_xref",
                        "error": f"arsc resolve failed: {exc}"}
            if not rid:
                return {"status": "error", "tool": "resource_xref",
                        "error": f"resource '{resource_id}' not found"}
        if not smali_dir or not Path(smali_dir).is_dir():
            return {"status": "error", "tool": "resource_xref",
                    "error": "smali_dir (an apktool decompile) is required for the grep — "
                             "run apk_decompile first"}

        hex_full = f"0x{rid:08x}"
        hex_plain = f"{rid:08x}"
        matches = []
        base = Path(smali_dir)
        for path in sorted(base.rglob("*")):
            if path.suffix not in (".smali", ".xml") or not path.is_file():
                continue
            try:
                for lineno, line in enumerate(
                        path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                    if hex_full in line.lower() or hex_plain in line.lower():
                        matches.append({"file": str(path.relative_to(base)), "line": lineno,
                                        "snippet": line.strip()[:240]})
                        if len(matches) >= 500:
                            break
            except OSError:
                continue
            if len(matches) >= 500:
                break
        shown, info = cap_items(matches, "narrow with a more specific resource id")
        out = {"resource_id": hex_full, "smali_dir": smali_dir,
               "total": info["total"], "matches": shown}
        if info["truncated"]:
            out["truncated"] = True
            out["hint"] = info["hint"]
        return {"status": "ok", "tool": "resource_xref", "output": out}

    # ── plumbing ──────────────────────────────────────────────────────────

    @staticmethod
    def _default_dir(input_path: str, suffix: str) -> str:
        stem = Path(input_path).stem or "archive"
        return str(data_dir() / "apkops" / f"{stem}{suffix}")
