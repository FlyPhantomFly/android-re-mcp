"""
handlers/googleservices.py — Google/Firebase configuration extraction.

Ported from the npm server's ``src/tools/android/google-services.ts``
as PyPI tool E-PY-12. Three sources, as in npm:

  * ``google-services.json`` — parsed from the APK (exact
    ``assets/google-services.json`` first, else any entry whose name
    ends with ``google-services.json``): project info, per-client
    package/app-id/API-key/OAuth client list.
  * with ``smali_dir`` (an apktool decompile): ``res/values/strings.xml``
    scanned for the ten well-known Google string-resource keys —
    structured ``key = value`` pairs.
  * without ``smali_dir``: ``resources.arsc`` scanned for the five
    Google patterns from the npm ``patterns.ts`` (names + risks kept
    verbatim) — zero-dependency printable-string extraction instead of
    the external ``strings(1)`` binary, through the shared
    :mod:`apkscan` machinery (size caps included).

Every section degrades honestly on its own: unparseable JSON, missing
strings.xml, missing resources.arsc — each reports the real reason
instead of failing the whole tool.
"""

from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path

from android_re_mcp.handlers import apkscan
from android_re_mcp.handlers.apkscan import _env_max_mb, _open_zip, _printable_strings, _read_entry

# Verbatim from the npm patterns.ts GOOGLE_PATTERNS (names + risks).
_GOOGLE_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "HIGH"),
    (
        "Firebase Realtime DB URL",
        re.compile(r"https://[a-z0-9][a-z0-9\-]{1,61}(?:-default-rtdb)?\.firebaseio\.com"),
        "HIGH",
    ),
    ("Firebase Storage Bucket", re.compile(r"[a-z0-9][a-z0-9\-]{3,62}\.appspot\.com"), "MEDIUM"),
    ("GCP Storage URL", re.compile(r"https://storage\.googleapis\.com/[a-z0-9\-._/]{3,}"), "MEDIUM"),
    (
        "Google OAuth Client ID",
        re.compile(r"[0-9]{12}-[a-z0-9]{32}\.apps\.googleusercontent\.com"),
        "MEDIUM",
    ),
]

# Verbatim from the npm GOOGLE_STRING_KEYS (order = output order).
_GOOGLE_STRING_KEYS = (
    "google_app_id",
    "google_api_key",
    "google_crash_reporting_api_key",
    "google_storage_bucket",
    "project_id",
    "gcm_defaultSenderId",
    "default_web_client_id",
    "firebase_database_url",
    "google_maps_key",
    "google_maps_api_key",
)

_GS_JSON_EXACT = "assets/google-services.json"


class GoogleServicesHandler:
    """Stateless Google/Firebase config extraction."""

    def android_google_services(self, args: dict) -> dict:
        """[TOOL] Extract Google/Firebase config from an APK."""
        apk_path = args.get("apk_path", "")
        smali_dir = args.get("smali_dir", "")

        if not apk_path or not Path(apk_path).is_file():
            return {
                "status": "error",
                "tool": "android_google_services",
                "error": f"apk_path '{apk_path}' not found",
            }

        try:
            zf = _open_zip(apk_path)
        except (apkscan.PayloadTooLarge, zipfile.BadZipFile, OSError) as exc:
            return {"status": "error", "tool": "android_google_services", "error": str(exc)}

        output: dict = {"apk_path": apk_path}
        try:
            output["google_services_json"] = self._read_gs_json(zf)
            if smali_dir:
                folder = Path(smali_dir)
                if not folder.is_dir():
                    return {
                        "status": "error",
                        "tool": "android_google_services",
                        "error": f"smali_dir '{smali_dir}' not found",
                    }
                output["string_resources"] = self._strings_xml(folder)
            else:
                output["arsc_scan"] = self._scan_arsc(zf)
        finally:
            zf.close()

        return {"status": "ok", "tool": "android_google_services", "output": output}

    # ── google-services.json ─────────────────────────────────────────────
    def _read_gs_json(self, zf: zipfile.ZipFile) -> dict:
        entry = None
        for info in zf.infolist():
            if info.filename == _GS_JSON_EXACT:
                entry = info
                break  # exact location wins
            if entry is None and info.filename.endswith("google-services.json"):
                entry = info
        if entry is None:
            return {"present": False, "note": "not found in APK assets"}

        cap = _env_max_mb(apkscan.ENTRY_CAP_ENV, apkscan.DEFAULT_ENTRY_CAP_MB)
        data = _read_entry(zf, entry, cap)
        if data is None:
            return {
                "present": True,
                "entry": entry.filename,
                "parse_error": f"entry above the {cap} MB per-entry cap",
            }
        try:
            parsed = json.loads(data.decode("utf-8", "replace"))
        except (ValueError, UnicodeDecodeError):
            return {
                "present": True,
                "entry": entry.filename,
                "parse_error": "could not parse google-services.json",
            }
        return {"present": True, "entry": entry.filename, **self._gs_facts(parsed)}

    @staticmethod
    def _gs_facts(parsed: dict) -> dict:
        proj = parsed.get("project_info") or {}
        project_info = {
            key: proj[key]
            for key in ("project_number", "project_id", "firebase_url", "storage_bucket")
            if proj.get(key)
        }
        clients: list[dict] = []
        for client in parsed.get("client") or []:
            info = client.get("client_info") or {}
            android_info = info.get("android_client_info") or {}
            api_keys = (client.get("services") or {}).get("api_key") or []
            oauth = [
                {"client_id": oc.get("client_id"), "client_type": oc.get("client_type")}
                for oc in (client.get("oauth_client") or [])
                if oc.get("client_id")
            ]
            clients.append({
                "package_name": android_info.get("package_name"),
                "app_id": info.get("mobilesdk_app_id"),
                "api_key": (api_keys[0] or {}).get("current_key") if api_keys else None,
                "oauth_clients": oauth,
            })
        return {
            "project_info": project_info,
            "client_count": len(clients),
            "clients": clients,
        }

    # ── res/values/strings.xml (smali_dir path) ──────────────────────────
    @staticmethod
    def _strings_xml(folder: Path) -> dict:
        source = folder / "res" / "values" / "strings.xml"
        if not source.is_file():
            return {"source": str(source), "error": f"strings.xml not found at: {source}"}
        try:
            xml = source.read_text("utf-8", errors="replace")
        except OSError as exc:
            return {"source": str(source), "error": str(exc)}
        found: list[dict] = []
        for key in _GOOGLE_STRING_KEYS:
            rx = re.compile(r"""name=["']%s["'][^>]*>([^<]+)<""" % re.escape(key), re.I)
            for match in rx.finditer(xml):
                found.append({"key": key, "value": match.group(1).strip()})
        return {
            "source": str(source),
            "keys_checked": len(_GOOGLE_STRING_KEYS),
            "found": found,
            **({"note": "No Google-related string resources found"} if not found else {}),
        }

    # ── resources.arsc scan (no smali_dir path) ──────────────────────────
    @staticmethod
    def _scan_arsc(zf: zipfile.ZipFile) -> dict:
        entry = next((i for i in zf.infolist() if i.filename == "resources.arsc"), None)
        if entry is None:
            return {"present": False, "note": "resources.arsc not found in APK"}
        cap = _env_max_mb(apkscan.ENTRY_CAP_ENV, apkscan.DEFAULT_ENTRY_CAP_MB)
        data = _read_entry(zf, entry, cap)
        if data is None:
            return {
                "present": True,
                "note": f"resources.arsc above the {cap} MB per-entry cap — scan skipped",
            }
        # strings -a -n 8 over the arsc, scanned with the Google patterns
        results = apkscan.scan_text(_printable_strings(data), _GOOGLE_PATTERNS)
        return {
            "present": True,
            "patterns": results,
            **({"note": "No Google patterns found"} if not results else {}),
        }
