"""Hermetic tests for android_google_services (PyPI port of the npm tool, E-PY-12).

Covers all three sources: the bundled google-services.json, the
smali_dir strings.xml path, and the resources.arsc Google-pattern scan.
The Google-pattern values here are built by concatenation so repo
scanners don't flag the test file itself.
"""

import json
import zipfile
from pathlib import Path

from android_re_mcp.handlers import googleservices as googleservices_mod
from android_re_mcp.handlers.googleservices import GoogleServicesHandler

FAKE_API_KEY = "AIza" + "x" * 35  # AIza + 35 chars, matches the pattern
FAKE_OAUTH_ID = "123456789012" + "a" * 32 + ".apps.googleusercontent.com"

GS_JSON = {
    "project_info": {
        "project_number": "123456789",
        "project_id": "notes-demo",
        "firebase_url": "https://notes-demo.firebaseio.com",
        "storage_bucket": "notes-demo.appspot.com",
    },
    "client": [
        {
            "client_info": {
                "mobilesdk_app_id": "1:123456789:android:abc123def456",
                "android_client_info": {"package_name": "com.example.notes"},
            },
            "services": {"api_key": [{"current_key": FAKE_API_KEY}]},
            "oauth_client": [{"client_id": FAKE_OAUTH_ID, "client_type": 1}],
        },
    ],
}

ARSC_BLOB = (
    b"\x00\x01\x02binarypadding"
    + FAKE_API_KEY.encode()
    + b"\x00\x00"
    + b"my-test-app.appspot.com\x00"
    + b"https://notes-demo-default-rtdb.firebaseio.com\x00"
)


def _write_apk(tmp_path: Path, name: str, files: dict[str, bytes]) -> str:
    apk_path = tmp_path / name
    with zipfile.ZipFile(apk_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for fname, data in files.items():
            zf.writestr(fname, data)
    return str(apk_path)


def _handler() -> GoogleServicesHandler:
    return GoogleServicesHandler()


def test_parses_bundled_google_services_json(tmp_path):
    apk = _write_apk(tmp_path, "app.apk", {
        "AndroidManifest.xml": b"stub",
        "assets/google-services.json": json.dumps(GS_JSON).encode(),
    })
    result = _handler().android_google_services({"apk_path": apk})
    assert result["status"] == "ok"
    gs = result["output"]["google_services_json"]
    assert gs["present"] is True
    assert gs["entry"] == "assets/google-services.json"
    assert gs["project_info"] == {
        "project_number": "123456789",
        "project_id": "notes-demo",
        "firebase_url": "https://notes-demo.firebaseio.com",
        "storage_bucket": "notes-demo.appspot.com",
    }
    assert gs["client_count"] == 1
    client = gs["clients"][0]
    assert client["package_name"] == "com.example.notes"
    assert client["app_id"] == "1:123456789:android:abc123def456"
    assert client["api_key"] == FAKE_API_KEY
    assert client["oauth_clients"] == [{"client_id": FAKE_OAUTH_ID, "client_type": 1}]


def test_finds_gs_json_at_alternate_location(tmp_path):
    apk = _write_apk(tmp_path, "app.apk", {
        "res/raw/notesdemo-google-services.json": json.dumps(GS_JSON).encode(),
    })
    result = _handler().android_google_services({"apk_path": apk})
    gs = result["output"]["google_services_json"]
    assert gs["present"] is True
    assert gs["entry"].endswith("google-services.json")
    assert gs["project_id" if "project_id" in gs else "project_info"]


def test_gs_json_missing_and_unparseable(tmp_path):
    handler = _handler()
    missing = _write_apk(tmp_path, "a.apk", {"AndroidManifest.xml": b"stub"})
    out = handler.android_google_services({"apk_path": missing})["output"]
    assert out["google_services_json"] == {"present": False, "note": "not found in APK assets"}

    broken = _write_apk(tmp_path, "b.apk", {
        "assets/google-services.json": b"{not json at all",
    })
    out = handler.android_google_services({"apk_path": broken})["output"]
    gs = out["google_services_json"]
    assert gs["present"] is True
    assert "could not parse google-services.json" in gs["parse_error"]


def test_strings_xml_via_smali_dir(tmp_path):
    smali = tmp_path / "decompiled"
    (smali / "res" / "values").mkdir(parents=True)
    (smali / "res" / "values" / "strings.xml").write_text(
        '<resources>\n'
        '  <string name="google_app_id">1:123456789:android:abc</string>\n'
        '  <string name="google_api_key" translatable="false">AIzAplaceholder</string>\n'
        '  <string name="Google_Storage_Bucket">  padded-bucket.appspot.com  </string>\n'
        '  <string name="unrelated_key">nothing here</string>\n'
        '</resources>\n'
    )
    apk = _write_apk(tmp_path, "app.apk", {"AndroidManifest.xml": b"stub"})
    result = _handler().android_google_services({"apk_path": apk, "smali_dir": str(smali)})
    out = result["output"]
    # the arsc scan must NOT run when smali_dir is given (npm returns early)
    assert "arsc_scan" not in out
    res = out["string_resources"]
    assert res["keys_checked"] == 10
    found = {(f["key"], f["value"]) for f in res["found"]}
    assert ("google_app_id", "1:123456789:android:abc") in found
    assert ("google_api_key", "AIzAplaceholder") in found
    # npm's regex is case-insensitive on the name attribute, values trimmed
    assert ("google_storage_bucket", "padded-bucket.appspot.com") in found
    assert all(k != "unrelated_key" for k, _ in found)


def test_strings_xml_missing_and_empty(tmp_path):
    handler = _handler()
    apk = _write_apk(tmp_path, "app.apk", {"AndroidManifest.xml": b"stub"})

    no_dir = handler.android_google_services({"apk_path": apk, "smali_dir": str(tmp_path / "nope")})
    assert no_dir["status"] == "error"
    assert "smali_dir" in no_dir["error"] and "not found" in no_dir["error"]

    empty = tmp_path / "empty-decomp"
    (empty / "res" / "values").mkdir(parents=True)
    (empty / "res" / "values" / "strings.xml").write_text("<resources/>\n")
    out = handler.android_google_services({"apk_path": apk, "smali_dir": str(empty)})["output"]
    res = out["string_resources"]
    assert res["found"] == []
    assert res["note"] == "No Google-related string resources found"

    no_xml = tmp_path / "bare-decomp"
    no_xml.mkdir()
    out = handler.android_google_services({"apk_path": apk, "smali_dir": str(no_xml)})["output"]
    assert "strings.xml not found at" in out["string_resources"]["error"]


def test_arsc_scan_records_google_patterns(tmp_path):
    apk = _write_apk(tmp_path, "app.apk", {
        "AndroidManifest.xml": b"stub",
        "resources.arsc": ARSC_BLOB,
    })
    result = _handler().android_google_services({"apk_path": apk})
    out = result["output"]
    assert "string_resources" not in out  # smali_dir-less path scans the arsc
    scan = out["arsc_scan"]
    assert scan["present"] is True
    patterns = scan["patterns"]
    assert set(patterns) == {"Google API Key", "Firebase Storage Bucket", "Firebase Realtime DB URL"}
    assert patterns["Google API Key"]["risk"] == "HIGH"
    assert patterns["Google API Key"]["matches"] == [FAKE_API_KEY]
    assert patterns["Firebase Storage Bucket"]["matches"] == ["my-test-app.appspot.com"]
    assert patterns["Firebase Realtime DB URL"]["risk"] == "HIGH"


def test_arsc_missing_or_clean(tmp_path):
    handler = _handler()
    absent = _write_apk(tmp_path, "a.apk", {"AndroidManifest.xml": b"stub"})
    out = handler.android_google_services({"apk_path": absent})["output"]
    assert out["arsc_scan"] == {"present": False, "note": "resources.arsc not found in APK"}

    clean = _write_apk(tmp_path, "b.apk", {
        "AndroidManifest.xml": b"stub",
        "resources.arsc": b"\x00\x01nothing googley in here\x00",
    })
    out = handler.android_google_services({"apk_path": clean})["output"]
    scan = out["arsc_scan"]
    assert scan["patterns"] == {}
    assert scan["note"] == "No Google patterns found"


def test_requires_apk_path(tmp_path):
    result = _handler().android_google_services({})
    assert result["status"] == "error"
    assert "apk_path" in result["error"]

    missing = _handler().android_google_services({"apk_path": str(tmp_path / "nope.apk")})
    assert missing["status"] == "error"
    assert "not found" in missing["error"]


def test_google_patterns_match_npm_names_and_risks():
    expected = {
        "Google API Key": "HIGH",
        "Firebase Realtime DB URL": "HIGH",
        "Firebase Storage Bucket": "MEDIUM",
        "GCP Storage URL": "MEDIUM",
        "Google OAuth Client ID": "MEDIUM",
    }
    got = {name: risk for name, _, risk in googleservices_mod._GOOGLE_PATTERNS}
    assert got == expected
