"""Hermetic tests for android_api_extractor (PyPI port of the npm tool, E-PY-11).

The smali fixtures mirror what apktool emits for Retrofit interfaces:
runtime annotation blocks under Lretrofit2/http/ plus OkHttp3 field
declarations. The apktool-decompile path is exercised live (real APK
smoke); these tests point the tool at an existing smali_dir.
"""

from pathlib import Path

from android_re_mcp.handlers.apiextractor import ApiExtractorHandler

RETROFIT_SMALI = """.class public interface Lcom/example/Api;
.super Ljava/lang/Object;
.source "Api.java"

# direct methods
.method public constructor <init>()V
    return-void
.end method

.annotation runtime Lretrofit2/http/GET;
    value = "v1/users/{id}"
.end annotation

.method public abstract getUser(Ljava/lang/String;)Lio/reactivex/Observable;
    .annotation system Lretrofit2/Callback;
    .end annotation
.end method

.annotation runtime Lretrofit2/http/POST;
    value = "v1/users"
.end annotation

.field private static final OKCLIENT:Lokhttp3/OkHttpClient;
.field public client:Lokhttp3/OkHttpClient;
"""


def _smali_tree(tmp_path: Path, content: str = RETROFIT_SMALI) -> str:
    root = tmp_path / "smali"
    (root / "com/example").mkdir(parents=True)
    (root / "com/example/Api.smali").write_text(content)
    (root / "smali_dir_marker.txt").write_text("not smali")
    return str(root)


URLS_SMALI = """.class public Lcom/example/Net;
.super Ljava/lang/Object;

.method public constructor <init>()V
    const-string v0, "https://api.example.com/v1/login"
    const-string v1, "https://api.example.com/v1/users"
    const-string v2, "https://api.example.com/v1/login"
    const-string v3, "http://cdn.example.net/assets/app.png"
    const-string v4, "AES/GCM/NoPadding"
    const-string/jumbo v5, "https://ws.example.org/socket"
    const-string v6, "https://escaped.example.com/path\\"tail"
    return-void
.end method
"""


def _write_smali(tmp_path: Path, name: str, content: str) -> str:
    root = tmp_path / "smali"
    (root / "com/example").mkdir(parents=True, exist_ok=True)
    (root / f"com/example/{name}").write_text(content)
    return str(root)


def test_const_string_urls_harvested_deduped_and_host_grouped(tmp_path):
    root = _write_smali(tmp_path, "Net.smali", URLS_SMALI)
    # duplicate URL in a second file must not be double-counted
    _write_smali(tmp_path, "Net2.smali", 'const-string v0, "https://api.example.com/v1/login"\n')
    result = ApiExtractorHandler().android_api_extractor({"smali_dir": root})
    out = result["output"]
    assert result["status"] == "ok"
    assert out["annotation_count"] == 0
    assert out["okhttp3_field_count"] == 0
    cs = out["const_string_urls"]
    assert cs["total"] == 5  # login/users/cdn/ws/escaped — the dup and AES/GCM are dropped
    assert cs["truncated"] is False
    assert cs["shown"] == cs["total"]
    assert cs["oversized_skipped"] == 0
    hosts = cs["by_host"]
    assert list(hosts) == sorted(hosts)  # host-grouped, sorted
    assert hosts["api.example.com"] == [
        "https://api.example.com/v1/login",
        "https://api.example.com/v1/users",
    ]
    assert hosts["cdn.example.net"] == ["http://cdn.example.net/assets/app.png"]
    assert hosts["ws.example.org"] == ["https://ws.example.org/socket"]  # const-string/jumbo
    assert hosts["escaped.example.com"] == ["https://escaped.example.com/path"]


def test_const_string_urls_cap_truncates_deterministically(tmp_path, monkeypatch):
    from android_re_mcp.handlers import apiextractor as mod

    monkeypatch.setattr(mod, "_MAX_CONST_URLS", 3)
    root = _write_smali(tmp_path, "Net.smali", URLS_SMALI)
    out = ApiExtractorHandler().android_api_extractor({"smali_dir": root})["output"]
    cs = out["const_string_urls"]
    assert cs["total"] == 5
    assert cs["shown"] == 3
    assert cs["truncated"] is True
    # sorted hosts first: api.example.com (2) then cdn.example.net (1) fill the cap
    assert list(cs["by_host"]) == ["api.example.com", "cdn.example.net"]
    assert "escaped.example.com" not in cs["by_host"]


def test_const_string_urls_oversized_constants_are_skipped_and_counted(tmp_path, monkeypatch):
    from android_re_mcp.handlers import apiextractor as mod

    monkeypatch.setattr(mod, "_MAX_URL_LEN", 64)
    smali = (
        '.class public LX;\n'
        'const-string v0, "https://ok.example.com/a"\n'
        f'const-string v1, "https://blob.example.com/{"a" * 200}"\n'
    )
    root = _write_smali(tmp_path, "Net.smali", smali)
    cs = ApiExtractorHandler().android_api_extractor({"smali_dir": root})["output"]["const_string_urls"]
    assert cs["total"] == 1
    assert cs["oversized_skipped"] == 1
    assert "blob.example.com" not in cs["by_host"]


def test_postman_mode_has_no_harvest_section(tmp_path):
    root = _write_smali(tmp_path, "Net.smali", URLS_SMALI)
    out = ApiExtractorHandler().android_api_extractor(
        {"smali_dir": root, "output_format": "postman"}
    )["output"]
    assert "const_string_urls" not in out
    assert out["format"] == "postman"


def test_schema_stops_overclaiming_okhttp():
    from android_re_mcp.server import TOOL_SCHEMAS

    desc = next(
        t["description"] for t in TOOL_SCHEMAS if t["name"] == "android_api_extractor"
    )
    assert "const-string URLs" in desc  # the harvest is advertised
    assert "not URLs" in desc  # OkHttp honesty: fields, not extracted URLs


def test_extracts_annotations_and_okhttp_fields(tmp_path):
    handler = ApiExtractorHandler()
    result = handler.android_api_extractor({"smali_dir": _smali_tree(tmp_path)})
    assert result["status"] == "ok"
    out = result["output"]
    assert out["format"] == "txt"
    assert out["annotation_count"] == 2
    endpoints = {(a["method"], a["endpoint"]) for a in out["annotations"]}
    assert ("GET", "v1/users/{id}") in endpoints
    assert ("POST", "v1/users") in endpoints
    assert out["okhttp3_field_count"] == 2
    assert all("Lokhttp3/" in f for f in out["okhttp3_fields"])
    assert any("OKCLIENT" in f for f in out["okhttp3_fields"])


def test_postman_collection_shape(tmp_path):
    handler = ApiExtractorHandler()
    result = handler.android_api_extractor({
        "smali_dir": _smali_tree(tmp_path), "output_format": "postman",
    })
    out = result["output"]
    assert out["format"] == "postman"
    coll = out["postman_collection"]
    assert coll["info"]["schema"].endswith("/collection/v2.1.0/collection.json")
    assert coll["info"]["name"] == "Retrofit Analysis — android-re-mcp"
    assert len(coll["item"]) == 2
    first = coll["item"][0]
    assert first["request"]["method"] in ("GET", "POST")
    assert first["request"]["url"]["host"] == ["{{base_url}}"]
    assert first["request"]["url"]["raw"].startswith("{{base_url}}")
    assert "users" in first["request"]["url"]["path"]


def test_empty_smali_reports_zero_counts(tmp_path):
    handler = ApiExtractorHandler()
    result = handler.android_api_extractor({"smali_dir": _smali_tree(tmp_path, ".class public Lx;\n")})
    out = result["output"]
    assert out["annotation_count"] == 0
    assert out["okhttp3_field_count"] == 0
    assert "No Retrofit annotations" in out["message"]


def test_requires_an_input():
    handler = ApiExtractorHandler()
    result = handler.android_api_extractor({})
    assert result["status"] == "error"
    assert "apk_path or smali_dir" in result["error"]


def test_missing_smali_dir_is_an_error(tmp_path):
    handler = ApiExtractorHandler()
    result = handler.android_api_extractor({"smali_dir": str(tmp_path / "nope")})
    assert result["status"] == "error"
    assert "not found" in result["error"]


def test_missing_apktool_reports_missing_tool(tmp_path, monkeypatch):
    from android_re_mcp.handlers import apiextractor as mod

    def boom(*_a, **_k):
        raise FileNotFoundError("apktool")

    monkeypatch.setattr(mod.subprocess, "run", boom)
    result = mod.ApiExtractorHandler().android_api_extractor({"apk_path": str(tmp_path / "x.apk")})
    assert result["status"] == "missing_tool"
    assert "apktool not found" in result["error"]
