"""
handlers/apiextractor.py — structured Retrofit/OkHttp/const-string API extraction.

Ported from the npm server's ``src/tools/android/api-extractor.ts`` as
PyPI tool E-PY-11. Walks a smali tree (decompiling the APK with apktool
first when only ``apk_path`` is given — the same CLI the Python server
already wraps for ``apk_decompile``) and extracts:

  * Retrofit HTTP annotations: ``.annotation runtime Lretrofit2/http/GET;``
    blocks, with the ``value = "..."`` endpoint path per method;
  * const-string URLs: every ``const-string`` literal starting with
    ``http://``/``https://``, deduplicated and grouped by host (the
    E-NPM-5 harvest — answers "what endpoints does this APK call?" even
    when the app builds URLs without Retrofit annotations);
  * OkHttp3 field declarations (``.field ... Lokhttp3/...``) — reported
    as detected fields, not as extracted URLs.

Two output modes, like the npm tool: ``txt`` returns the annotations,
URLs and fields as structured lists (the npm text blob, JSON-shaped),
``postman`` returns a ready-to-import Postman v2.1 collection with every
endpoint pointed at a ``{{base_url}}`` variable.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

_TIMEOUT_LONG = 300

_ANNOTATION = re.compile(
    r"\.annotation\s+runtime\s+Lretrofit2/http/([A-Z]+);(.*?)\.end annotation", re.S
)
# npm's pattern demanded a space before "Lokhttp3/" (`.field .*? Lokhttp3/`),
# which real apktool output — `.field name:Lokhttp3/Type;` — never matches;
# the port drops the space so canonical field declarations are found too.
_OKHTTP_FIELD = re.compile(r"\.field .*?Lokhttp3/")
_VALUE = re.compile(r'value = "([^"]+)"')

# E-NPM-5: harvest every URL literal the dex compiler kept as a string
# constant (``const-string`` and ``const-string/jumbo``). An escaped quote
# ends the literal early — the capture stops there (a trailing backslash is
# stripped); the scheme prefix still matched. Oversized constants (embedded
# JSON blobs and friends) are skipped and counted rather than flooding the
# response, and the host-grouped output is capped at _MAX_CONST_URLS.
_CONST_STRING_URL = re.compile(
    r'const-string(?:/jumbo)?\s+[vp]\d+,\s*"(https?://[^"]+)"'
)
_MAX_URL_LEN = 2048
_MAX_CONST_URLS = 500


def _walk_smali(root: Path):
    for path in sorted(root.rglob("*.smali")):
        if path.is_file():
            yield path


def _collect_const_string_urls(
    content: str, by_host: dict[str, set[str]], stats: dict[str, int]
) -> None:
    """Harvest URL string constants from one smali file (E-NPM-5)."""
    for match in _CONST_STRING_URL.finditer(content):
        url = match.group(1)
        if url.endswith("\\"):  # literal cut at an escaped quote
            url = url[:-1]
        if len(url) > _MAX_URL_LEN:
            stats["oversized_skipped"] += 1
            continue
        try:
            host = urlsplit(url).hostname or ""
        except ValueError:  # malformed IPv6 literal etc.
            host = url.split("//", 1)[-1].split("/", 1)[0] or ""
        if host:
            by_host.setdefault(host, set()).add(url)


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
        urls_by_host: dict[str, set[str]] = {}
        url_stats: dict[str, int] = {"oversized_skipped": 0}
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
                _collect_const_string_urls(content, urls_by_host, url_stats)
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

        # E-NPM-5 output: URL constants deduplicated and host-grouped,
        # capped at _MAX_CONST_URLS across hosts (sorted hosts first, so
        # the cut is deterministic); the honest totals ride along.
        hosts = sorted(urls_by_host)
        total_urls = sum(len(urls_by_host[h]) for h in hosts)
        by_host: dict[str, list[str]] = {}
        budget = _MAX_CONST_URLS
        for host in hosts:
            take = min(len(urls_by_host[host]), budget)
            if take:
                by_host[host] = sorted(urls_by_host[host])[:take]
                budget -= take
        shown_urls = sum(len(v) for v in by_host.values())

        return {
            "status": "ok",
            "tool": "android_api_extractor",
            "output": {
                "format": "txt",
                "annotation_count": len(annotations),
                "okhttp3_field_count": len(okhttp_fields),
                "annotations": annotations,
                "okhttp3_fields": okhttp_fields,
                "const_string_urls": {
                    "total": total_urls,
                    "shown": shown_urls,
                    "truncated": shown_urls < total_urls,
                    "oversized_skipped": url_stats["oversized_skipped"],
                    "by_host": by_host,
                },
                "message": (
                    "No Retrofit annotations, OkHttp3 fields or const-string URLs found in the smali code."
                    if not annotations and not okhttp_fields and not urls_by_host
                    else ""
                ),
            },
        }
