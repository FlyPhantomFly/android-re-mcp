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
