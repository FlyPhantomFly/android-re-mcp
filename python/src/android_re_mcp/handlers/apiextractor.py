"""
handlers/apiextractor.py — structured Retrofit/OkHttp endpoint extraction.

Ported from the npm server's ``src/tools/android/api-extractor.ts`` as
PyPI tool E-PY-11. Walks a smali tree (decompiling the APK with apktool
first when only ``apk_path`` is given — the same CLI the Python server
already wraps for ``apk_decompile``) and extracts:

  * Retrofit HTTP annotations: ``.annotation runtime Lretrofit2/http/GET;``
    blocks, with the ``value = "..."`` endpoint path per method;
  * OkHttp3 field declarations (``.field ... Lokhttp3/...``).

Two output modes, like the npm tool: ``txt`` returns the annotations and
fields as structured lists (the npm text blob, JSON-shaped), ``postman``
returns a ready-to-import Postman v2.1 collection with every endpoint
pointed at a ``{{base_url}}`` variable.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path

_TIMEOUT_LONG = 300

_ANNOTATION = re.compile(
    r"\.annotation\s+runtime\s+Lretrofit2/http/([A-Z]+);(.*?)\.end annotation", re.S
)
# npm's pattern demanded a space before "Lokhttp3/" (`.field .*? Lokhttp3/`),
# which real apktool output — `.field name:Lokhttp3/Type;` — never matches;
# the port drops the space so canonical field declarations are found too.
_OKHTTP_FIELD = re.compile(r"\.field .*?Lokhttp3/")
_VALUE = re.compile(r'value = "([^"]+)"')


def _walk_smali(root: Path):
    for path in sorted(root.rglob("*.smali")):
        if path.is_file():
            yield path


class ApiExtractorHandler:
    """Stateless Retrofit/OkHttp endpoint extraction."""

    def android_api_extractor(self, args: dict) -> dict:
        """[TOOL] Extract Retrofit/OkHttp endpoints from smali."""
        apk_path = args.get("apk_path", "")
        smali_dir = args.get("smali_dir", "")
        output_format = args.get("output_format") or "txt"

        if not apk_path and not smali_dir:
            return {
                "status": "error",
                "tool": "android_api_extractor",
                "error": "provide either apk_path or smali_dir.",
            }

        tmpdir: str | None = None
        if not smali_dir:
            tmpdir = tempfile.mkdtemp(prefix="apktool-")
            try:
                proc = subprocess.run(
                    ["apktool", "d", apk_path, "-o", tmpdir, "-f"],
                    capture_output=True,
                    text=True,
                    timeout=_TIMEOUT_LONG,
                )
            except FileNotFoundError:
                import shutil

                shutil.rmtree(tmpdir, ignore_errors=True)
                return {
                    "status": "missing_tool",
                    "tool": "android_api_extractor",
                    "error": "apktool not found on PATH.",
                    "hint": "Run android-re-mcp --setup, or install apktool yourself.",
                }
            except subprocess.TimeoutExpired:
                import shutil

                shutil.rmtree(tmpdir, ignore_errors=True)
                return {
                    "status": "error",
                    "tool": "android_api_extractor",
                    "error": "apktool decompile timed out after 300s",
                }
            except Exception as exc:  # noqa: BLE001
                import shutil

                shutil.rmtree(tmpdir, ignore_errors=True)
                return {"status": "error", "tool": "android_api_extractor", "error": str(exc)}
            if proc.returncode != 0:
                import shutil

                shutil.rmtree(tmpdir, ignore_errors=True)
                return {
                    "status": "error",
                    "tool": "android_api_extractor",
                    "error": f"apktool failed: {(proc.stderr or proc.stdout).strip()[:500]}",
                }
            smali_dir = tmpdir

        folder = Path(smali_dir)
        if not folder.is_dir():
            return {
                "status": "error",
                "tool": "android_api_extractor",
                "error": f"smali_dir '{smali_dir}' not found",
            }

        annotations: list[dict] = []
        okhttp_fields: list[str] = []
        try:
            for path in _walk_smali(folder):
                try:
                    content = path.read_text("utf-8", errors="ignore")
                except OSError:
                    continue
                for match in _ANNOTATION.finditer(content):
                    method = match.group(1)
                    body = match.group(2).strip()
                    value = _VALUE.search(body)
                    endpoint = value.group(1) if value else re.sub(r"\s+", " ", body)
                    annotations.append({"method": method, "endpoint": endpoint})
                for match in _OKHTTP_FIELD.finditer(content):
                    okhttp_fields.append(match.group(0).strip())
        finally:
            if tmpdir is not None:
                import shutil

                shutil.rmtree(tmpdir, ignore_errors=True)

        if output_format == "postman":
            items = [
                {
                    "name": f"{a['method']} {a['endpoint']}",
                    "request": {
                        "method": a["method"],
                        "header": [],
                        "url": {
                            "raw": "{{base_url}}" + a["endpoint"],
                            "host": ["{{base_url}}"],
                            "path": [p for p in a["endpoint"].split("/") if p],
                        },
                    },
                }
                for a in annotations
            ]
            collection = {
                "info": {
                    "name": "Retrofit Analysis — android-re-mcp",
                    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
                },
                "item": items,
            }
            return {
                "status": "ok",
                "tool": "android_api_extractor",
                "output": {
                    "format": "postman",
                    "annotation_count": len(annotations),
                    "postman_collection": collection,
                },
            }

        return {
            "status": "ok",
            "tool": "android_api_extractor",
            "output": {
                "format": "txt",
                "annotation_count": len(annotations),
                "okhttp3_field_count": len(okhttp_fields),
                "annotations": annotations,
                "okhttp3_fields": okhttp_fields,
                "message": (
                    "No Retrofit annotations or OkHttp3 fields found in the smali code."
                    if not annotations and not okhttp_fields
                    else ""
                ),
            },
        }
