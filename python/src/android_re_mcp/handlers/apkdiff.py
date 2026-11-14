"""
handlers/apkdiff.py — build-vs-build APK diff.

Ported from the npm server's ``src/tools/android/apk-diff.ts`` (E-NPM-4)
as PyPI tool E-PY-10, with the same sections but structured JSON output:

  * identity + SDK levels and security flags — from the parsed manifest.
    androguard is already the ``[static]`` extra's dependency, so no new
    extras; when it is missing the manifest section degrades to
    ``manifest_read: false`` exactly like the npm tool degraded without
    aapt/apktool.
  * permission and exported-component deltas (explicit
    ``android:exported="true"``, npm-qualified names).
  * native-library deltas (sha256 per ``lib/<abi>/*.so`` entry).
  * optional secret deltas — zero-dependency: printable-string
    extraction over ``classes*.dex`` / ``resources.arsc`` plus in-zip
    text assets, scanned with the shared secret-pattern set (no
    ``strings(1)`` binary, no apkleaks).
  * an archive-inventory summary (entry counts + size changes).

Size caps mirror the npm zip guard (F-NPM-4): ``ANDROID_RE_MCP_MAX_FILE_MB``
(default 2048) checked before opening, ``ANDROID_RE_MCP_MAX_ENTRY_MB``
(default 256) checked per entry before decompression; ``0`` disables
either cap.
"""

from __future__ import annotations

import hashlib
import os
import re
import zipfile
from pathlib import Path

from android_re_mcp.handlers.static import _load_androguard

_LIST_CAP = 20
_DEFAULT_MAX_FILE_MB = 2048
_DEFAULT_MAX_ENTRY_MB = 256
_MB = 1024 * 1024

_TEXT_ASSET_EXTENSIONS = (".json", ".xml", ".txt", ".properties", ".yaml", ".yml", ".plist")
_LIB_ENTRY = re.compile(r"^lib/([^/]+)/([^/]+\.so)$")
_DEX_ENTRY = re.compile(r"^classes\d*\.dex$")

_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
_COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")


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


# ── the shared secret-pattern set (parity with the npm patterns.ts) ────────

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "HIGH"),
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}"), "CRITICAL"),
    (
        "AWS Secret Access Key",
        re.compile(r"(?:aws.?secret|secret.?access.?key)['\":\s=]+['\"]?([A-Za-z0-9/+]{40})['\"]?", re.I),
        "CRITICAL",
    ),
    ("Stripe Secret Key", re.compile(r"sk_(?:live|test)_[0-9a-zA-Z]{24,}"), "CRITICAL"),
    ("Stripe Publishable Key", re.compile(r"pk_(?:live|test)_[0-9a-zA-Z]{24,}"), "MEDIUM"),
    ("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"), "CRITICAL"),
    (
        "JWT Token",
        re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
        "HIGH",
    ),
    ("PEM Private Key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "CRITICAL"),
    ("SendGrid API Key", re.compile(r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}"), "HIGH"),
    ("Twilio Account SID", re.compile(r"AC[0-9a-fA-F]{32}"), "HIGH"),
    ("Twilio Key SID", re.compile(r"SK[0-9a-fA-F]{32}"), "HIGH"),
    ("Mapbox Token", re.compile(r"pk\.eyJ1[A-Za-z0-9_\-]{60,}"), "MEDIUM"),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"), "HIGH"),
    ("Basic Auth Header", re.compile(r"Basic [A-Za-z0-9+/]{20,}={0,2}"), "HIGH"),
    (
        "Generic Hardcoded Credential",
        re.compile(
            r"(?:password|passwd|secret|api_?key|apikey|access_?token)['\":\s=]+"
            r"['\"]([A-Za-z0-9\-_.!@#$%^&*]{8,})['\"]",
            re.I,
        ),
        "MEDIUM",
    ),
]


def _printable_strings(data: bytes, min_len: int = 8) -> str:
    """The printable-ASCII runs of *data* (what ``strings -a -n 8`` yields)."""
    rx = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    return "\n".join(m.group(0).decode("ascii", "ignore") for m in rx.finditer(data))


def _open_zip(path: str) -> zipfile.ZipFile:
    """Open an APK under ANDROID_RE_MCP_MAX_FILE_MB (0 disables)."""
    cap = _env_max_mb("ANDROID_RE_MCP_MAX_FILE_MB", _DEFAULT_MAX_FILE_MB)
    if cap:
        size = Path(path).stat().st_size
        if size > cap * _MB:
            raise PayloadTooLarge(
                f"input file is {size / _MB:.1f} MB, above the {cap} MB cap "
                f"(raise ANDROID_RE_MCP_MAX_FILE_MB, or set it to 0 to disable the cap)"
            )
    try:
        return zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        raise zipfile.BadZipFile(f"cannot open {path} as a zip archive: {exc}") from exc


def _read_entry(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes | None:
    """One entry under ANDROID_RE_MCP_MAX_ENTRY_MB (0 disables); None = skip."""
    cap = _env_max_mb("ANDROID_RE_MCP_MAX_ENTRY_MB", _DEFAULT_MAX_ENTRY_MB)
    if cap and (info.file_size > cap * _MB or info.compress_size > cap * _MB):
        return None
    try:
        return zf.read(info)
    except Exception:  # noqa: BLE001 — corrupt entry: skip, don't fail the diff
        return None


def _native_libs(zf: zipfile.ZipFile, notes: list[str]) -> dict[str, dict]:
    libs: dict[str, dict] = {}
    for info in zf.infolist():
        match = _LIB_ENTRY.match(info.filename)
        if not match:
            continue
        data = _read_entry(zf, info)
        digest: str | None = None
        if data is None:
            notes.append(f"skipped: '{info.filename}' above the per-entry cap")
        else:
            digest = hashlib.sha256(data).hexdigest()[:16]
        libs[info.filename] = {
            "abi": match.group(1),
            "basename": match.group(2),
            "size": info.file_size,
            "hash": digest,
        }
    return libs


def _collect_apk_strings(zf: zipfile.ZipFile, notes: list[str]) -> dict[str, dict]:
    """Secret-pattern matches over DEX/arsc printable strings and text assets.

    Same sources as the npm ``collectRawApkSecrets`` (strings over
    classes*.dex and resources.arsc + text assets), minus the external
    ``strings`` binary. Matches are deduplicated per pattern, and — like
    the npm ``scanText`` — only patterns with at least one match are
    recorded (an empty entry would make the diff report "no changes").
    """
    results: dict[str, dict] = {}
    seen_by_name: dict[str, set[str]] = {}

    def scan(text: str) -> None:
        for name, rx, risk in _SECRET_PATTERNS:
            seen = seen_by_name.setdefault(name, set())
            found: list[str] = []
            for match in rx.finditer(text):
                value = (match.group(1) if match.lastindex else match.group(0)).strip()
                if value and value not in seen:
                    seen.add(value)
                    found.append(value)
            if not found:
                continue
            entry = results.get(name)
            if entry is None:
                results[name] = {"risk": risk, "matches": found}
            else:
                entry["matches"].extend(found)

    for info in zf.infolist():
        if _DEX_ENTRY.match(info.filename) or info.filename == "resources.arsc":
            data = _read_entry(zf, info)
            if data is None:
                notes.append(f"skipped: '{info.filename}' above the per-entry cap")
                continue
            scan(_printable_strings(data))
        elif info.filename.startswith("assets/") and info.filename.endswith(_TEXT_ASSET_EXTENSIONS):
            data = _read_entry(zf, info)
            if data is None:
                notes.append(f"skipped: '{info.filename}' above the per-entry cap")
                continue
            scan(data.decode("utf-8", "ignore"))
    return results


def _secret_delta(
    old: dict[str, dict], new: dict[str, dict]
) -> tuple[list[dict], list[dict], list[dict]]:
    """Pattern-level differences: (new_only, changed, old_only)."""
    new_only: list[dict] = []
    changed: list[dict] = []
    old_only: list[dict] = []
    for name in sorted(set(old) | set(new)):
        old_entry = old.get(name)
        new_entry = new.get(name)
        if old_entry is None and new_entry is not None:
            new_only.append({
                "pattern": name,
                "risk": new_entry["risk"],
                "matches": new_entry["matches"][:3],
            })
        elif old_entry is not None and new_entry is None:
            old_only.append({
                "pattern": name,
                "risk": old_entry["risk"],
                "matches": old_entry["matches"][:3],
            })
        elif old_entry is not None and new_entry is not None:
            old_set = set(old_entry["matches"])
            new_set = set(new_entry["matches"])
            gained = [m for m in new_entry["matches"] if m not in old_set][:3]
            lost = [m for m in old_entry["matches"] if m not in new_set][:3]
            if gained or lost:
                changed.append({"pattern": name, "risk": new_entry["risk"], "gained": gained, "lost": lost})
    return new_only, changed, old_only


def _truthy(value: object) -> bool:
    return str(value).strip().lower() == "true"


def _manifest_facts(apk_path: str) -> dict | None:
    """Manifest-derived facts for one APK, or ``None`` when unreadable.

    androguard is already a ``[static]`` dependency (manifest_parse uses
    it); the npm tool degraded to a "skipped" manifest section when aapt/
    apktool were absent — the same honest degradation applies here.
    """
    loaded = _load_androguard()
    if loaded is None:
        return None
    APK = loaded[0]
    try:
        apk = APK(apk_path)
        pkg = str(apk.get_package() or "")
        app = apk.get_android_manifest_xml().find("application")
        exported: list[str] = []
        if app is not None:
            for tag in _COMPONENT_TAGS:
                for el in app.findall(tag):
                    if str(el.get(_ANDROID_NS + "exported") or "").strip().lower() != "true":
                        continue
                    raw = el.get(_ANDROID_NS + "name")
                    name = "(anonymous)" if not raw else (pkg + raw if raw.startswith(".") else raw)
                    exported.append(f"{name} ({tag})")
        return {
            "package": pkg or None,
            "version_name": str(apk.get_androidversion_name() or "") or None,
            "version_code": str(apk.get_androidversion_code() or "") or None,
            "min_sdk": str(apk.get_min_sdk_version() or "") or None,
            "target_sdk": str(apk.get_target_sdk_version() or "") or None,
            "debuggable": _truthy(apk.get_attribute_value("application", "debuggable")),
            "allow_backup": _truthy(apk.get_attribute_value("application", "allowBackup")),
            "cleartext": _truthy(apk.get_attribute_value("application", "usesCleartextTraffic")),
            "permissions": sorted(p for p in apk.get_permissions() if p),
            "exported_components": sorted(exported),
        }
    except Exception:  # noqa: BLE001 — any parse failure degrades to "skipped"
        return None


class ApkDiffHandler:
    """Stateless build-vs-build APK diff."""

    def apk_diff(self, args: dict) -> dict:
        """[TOOL] Diff two builds of the same app."""
        old_path = args.get("old_path", "")
        new_path = args.get("new_path", "")
        for key, path in (("old_path", old_path), ("new_path", new_path)):
            if not path or not Path(path).is_file():
                return {"status": "error", "tool": "apk_diff", "error": f"{key} '{path}' not found"}

        try:
            old_zip = _open_zip(old_path)
            new_zip = _open_zip(new_path)
        except (PayloadTooLarge, zipfile.BadZipFile, OSError) as exc:
            return {"status": "error", "tool": "apk_diff", "error": str(exc)}

        notes: list[str] = []
        output: dict = {"old_path": old_path, "new_path": new_path}

        try:
            # ── Manifest-derived facts ──────────────────────────────────
            old_facts = _manifest_facts(old_path)
            new_facts = _manifest_facts(new_path)
            if old_facts is not None and new_facts is not None:
                output["manifest_read"] = True
                identity = []
                for field in ("package", "version_name", "version_code", "min_sdk", "target_sdk"):
                    a, b = old_facts[field], new_facts[field]
                    identity.append({"field": field, "old": a, "new": b, "changed": a != b})
                output["identity"] = identity
                output["flags_changed"] = [
                    {"flag": flag, "old": old_facts[key], "new": new_facts[key]}
                    for flag, key in (
                        ("debuggable", "debuggable"),
                        ("allow_backup", "allow_backup"),
                        ("usesCleartextTraffic", "cleartext"),
                    )
                    if old_facts[key] != new_facts[key]
                ]

                old_perms, new_perms = set(old_facts["permissions"]), set(new_facts["permissions"])
                perm_added = sorted(new_perms - old_perms)
                perm_removed = sorted(old_perms - new_perms)
                output["permissions"] = {
                    "old_count": len(old_perms),
                    "new_count": len(new_perms),
                    "added": perm_added[:_LIST_CAP],
                    "removed": perm_removed[:_LIST_CAP],
                    "added_extra": max(0, len(perm_added) - _LIST_CAP),
                    "removed_extra": max(0, len(perm_removed) - _LIST_CAP),
                }

                old_exp, new_exp = set(old_facts["exported_components"]), set(new_facts["exported_components"])
                exp_added = sorted(new_exp - old_exp)
                exp_removed = sorted(old_exp - new_exp)
                output["exported_components"] = {
                    "old_count": len(old_exp),
                    "new_count": len(new_exp),
                    "added": exp_added[:_LIST_CAP],
                    "removed": exp_removed[:_LIST_CAP],
                    "added_extra": max(0, len(exp_added) - _LIST_CAP),
                    "removed_extra": max(0, len(exp_removed) - _LIST_CAP),
                }
            else:
                output["manifest_read"] = False
                missing_extra = _load_androguard() is None
                output["manifest_error"] = (
                    "androguard is not installed — install the [static] extra: "
                    "pip install 'android-re-mcp[static]'"
                    if missing_extra
                    else
                    f"could not parse the {'old' if old_facts is None else 'new'} "
                    "APK's AndroidManifest.xml (not a valid AXML manifest?)"
                )

            # ── Native libraries ────────────────────────────────────────
            old_libs = _native_libs(old_zip, notes)
            new_libs = _native_libs(new_zip, notes)
            lib_added = sorted(new_libs[n]["abi"] + "/" + new_libs[n]["basename"]
                               for n in new_libs if n not in old_libs)
            lib_changed = sorted(new_libs[n]["abi"] + "/" + new_libs[n]["basename"]
                                 for n in new_libs
                                 if n in old_libs and old_libs[n]["hash"] != new_libs[n]["hash"])
            lib_removed = sorted(old_libs[n]["abi"] + "/" + old_libs[n]["basename"]
                                 for n in old_libs if n not in new_libs)
            output["native_libraries"] = {
                "old_count": len(old_libs),
                "new_count": len(new_libs),
                "added": lib_added[:_LIST_CAP],
                "changed": lib_changed[:_LIST_CAP],
                "removed": lib_removed[:_LIST_CAP],
                "added_extra": max(0, len(lib_added) - _LIST_CAP),
                "changed_extra": max(0, len(lib_changed) - _LIST_CAP),
                "removed_extra": max(0, len(lib_removed) - _LIST_CAP),
                "all_identical": not (lib_added or lib_changed or lib_removed),
            }

            # ── Secrets (optional) ──────────────────────────────────────
            if args.get("skip_secrets"):
                output["secrets"] = {"mode": "skipped"}
            else:
                try:
                    old_secrets = _collect_apk_strings(old_zip, notes)
                    new_secrets = _collect_apk_strings(new_zip, notes)
                    new_only, changed, old_only = _secret_delta(old_secrets, new_secrets)
                    output["secrets"] = {
                        "mode": "scanned",
                        "new_only": new_only,
                        "changed": changed,
                        "old_only": old_only,
                        "no_pattern_differences": not (new_only or changed or old_only),
                    }
                except Exception as exc:  # noqa: BLE001
                    output["secrets"] = {"mode": "failed", "error": str(exc)}

            # ── Archive inventory ───────────────────────────────────────
            old_names = {i.filename for i in old_zip.infolist() if not i.is_dir()}
            new_infos = [i for i in new_zip.infolist() if not i.is_dir()]
            new_names = {i.filename for i in new_infos}
            entry_added = sum(1 for i in new_infos if i.filename not in old_names)
            entry_removed = sum(1 for n in old_names if n not in new_names)
            entry_changed = sum(
                1 for i in new_infos
                if i.filename in old_names
                and old_zip.getinfo(i.filename).file_size != i.file_size
            )
            output["archive"] = {
                "old_entries": len(old_names),
                "new_entries": len(new_names),
                "added": entry_added,
                "removed": entry_removed,
                "changed_size": entry_changed,
            }
            output["archive"]["notes"] = notes[:5]
        finally:
            old_zip.close()
            new_zip.close()

        return {"status": "ok", "tool": "apk_diff", "output": output}
