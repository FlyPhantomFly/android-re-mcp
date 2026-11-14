"""Hermetic tests for apk_diff (PyPI port of the npm E-NPM-4 tool, E-PY-10).

The two zips here carry a plain-text stub manifest, which androguard
cannot parse — so the manifest section is expected to report
``manifest_read: false``; everything else (native libs, secrets,
inventory) is fully checked. The manifest path itself is exercised with
injected facts and live via the real-APK smoke.
"""

import zipfile
from pathlib import Path

from mobile_re_mcp.handlers import apkdiff as apkdiff_mod

# Built by concatenation at runtime so repo scanners don't flag the test
# file itself (same pattern as the existing secret-fixture tests).
FAKE_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"  # AKIA + 16 chars, matches the pattern
FAKE_GOOGLE_KEY = "AIza" + "SyA1bC2dE3fG4hI5jK6lM7nO8pQ9rStUvWxyz"  # AIza + 35 chars

STUB_MANIFEST = b"not a real AXML manifest"


def _write_apk(tmp_path: Path, name: str, files: dict[str, bytes]) -> str:
    apk_path = tmp_path / name
    with zipfile.ZipFile(apk_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for fname, data in files.items():
            zf.writestr(fname, data)
    return str(apk_path)


def _old_build(tmp_path: Path) -> str:
    return _write_apk(tmp_path, "old.apk", {
        "AndroidManifest.xml": STUB_MANIFEST,
        "classes.dex": b"old dex",
        "lib/arm64-v8a/libnative.so": b"version-one-bytes",
        "assets/config.json": f'{{"k": "{FAKE_AWS_KEY}"}}'.encode(),
    })


def _new_build(tmp_path: Path) -> str:
    return _write_apk(tmp_path, "new.apk", {
        "AndroidManifest.xml": STUB_MANIFEST,
        "classes.dex": b"new dex bytes are longer",
        "lib/arm64-v8a/libnative.so": b"version-two-bytes!!",
        "lib/armeabi-v7a/libextra.so": b"brand new lib",
        "assets/config.json": f'{{"k": "{FAKE_GOOGLE_KEY}"}}'.encode(),
    })


def test_deltas_native_libs_secrets_inventory(tmp_path):
    result = apkdiff_mod.ApkDiffHandler().apk_diff({
        "old_path": _old_build(tmp_path),
        "new_path": _new_build(tmp_path),
    })
    assert result["status"] == "ok"
    out = result["output"]

    # stub manifest is not AXML → honest degradation, with the reason
    assert out["manifest_read"] is False
    assert "AndroidManifest.xml" in out["manifest_error"]

    nl = out["native_libraries"]
    assert (nl["old_count"], nl["new_count"]) == (1, 2)
    assert "arm64-v8a/libnative.so" in nl["changed"]
    assert "armeabi-v7a/libextra.so" in nl["added"]
    assert nl["all_identical"] is False

    sec = out["secrets"]
    assert sec["mode"] == "scanned"
    assert {e["pattern"] for e in sec["new_only"]} == {"Google API Key"}
    assert {e["pattern"] for e in sec["old_only"]} == {"AWS Access Key ID"}
    assert sec["changed"] == []
    assert sec["new_only"][0]["risk"] == "HIGH"
    assert sec["old_only"][0]["risk"] == "CRITICAL"

    arch = out["archive"]
    assert (arch["old_entries"], arch["new_entries"]) == (4, 5)
    assert (arch["added"], arch["removed"], arch["changed_size"]) == (1, 0, 3)


def test_identical_apks_report_all_identical(tmp_path):
    apk = _write_apk(tmp_path, "same.apk", {
        "AndroidManifest.xml": STUB_MANIFEST,
        "classes.dex": b"dex",
        "lib/arm64-v8a/libstable.so": b"stable",
    })
    handler = apkdiff_mod.ApkDiffHandler()
    result = handler.apk_diff({"old_path": apk, "new_path": apk, "skip_secrets": True})
    out = result["output"]
    assert out["archive"]["added"] == 0
    assert out["archive"]["removed"] == 0
    assert out["archive"]["changed_size"] == 0
    nl = out["native_libraries"]
    assert nl["all_identical"] is True and nl["old_count"] == 1
    assert out["secrets"] == {"mode": "skipped"}


def test_rejects_missing_and_non_zip_input(tmp_path):
    handler = apkdiff_mod.ApkDiffHandler()

    missing = handler.apk_diff({"old_path": "/nonexistent/old.apk", "new_path": "/tmp/x.apk"})
    assert missing["status"] == "error"
    assert "old_path" in missing["error"] and "not found" in missing["error"]

    plain = tmp_path / "plain.apk"
    plain.write_bytes(b"definitely not a zip archive")
    not_zip = handler.apk_diff({"old_path": str(plain), "new_path": str(plain)})
    assert not_zip["status"] == "error"
    assert "zip" in not_zip["error"].lower()


def test_manifest_delta_rendering(tmp_path, monkeypatch):
    """The identity/flags/permission/exported sections over injected facts."""
    old = _write_apk(tmp_path, "m_old.apk", {"AndroidManifest.xml": STUB_MANIFEST, "classes.dex": b"x"})
    new = _write_apk(tmp_path, "m_new.apk", {"AndroidManifest.xml": STUB_MANIFEST, "classes.dex": b"y"})

    facts_old = {
        "package": "com.example.app", "version_name": "1.0", "version_code": "1",
        "min_sdk": "21", "target_sdk": "30",
        "debuggable": False, "allow_backup": True, "cleartext": False,
        "permissions": ["android.permission.INTERNET"],
        "exported_components": ["com.example.app.MainActivity (activity)"],
    }
    facts_new = {
        "package": "com.example.app", "version_name": "1.1", "version_code": "2",
        "min_sdk": "21", "target_sdk": "31",
        "debuggable": True, "allow_backup": True, "cleartext": True,
        "permissions": ["android.permission.CAMERA", "android.permission.INTERNET"],
        "exported_components": ["com.example.app.Svc (service)"],
    }
    monkeypatch.setattr(
        apkdiff_mod, "_manifest_facts", lambda p: facts_old if p == old else facts_new
    )

    result = apkdiff_mod.ApkDiffHandler().apk_diff({"old_path": old, "new_path": new})
    assert result["status"] == "ok"
    out = result["output"]
    assert out["manifest_read"] is True

    by_field = {row["field"]: row for row in out["identity"]}
    assert by_field["package"]["changed"] is False
    assert by_field["version_name"]["changed"] is True
    assert (by_field["version_name"]["old"], by_field["version_name"]["new"]) == ("1.0", "1.1")
    assert (by_field["version_code"]["old"], by_field["version_code"]["new"]) == ("1", "2")
    assert by_field["min_sdk"]["changed"] is False
    assert by_field["target_sdk"]["changed"] is True

    flags = {f["flag"]: f for f in out["flags_changed"]}
    assert set(flags) == {"debuggable", "usesCleartextTraffic"}
    assert flags["debuggable"]["new"] is True

    assert out["permissions"]["added"] == ["android.permission.CAMERA"]
    assert out["permissions"]["removed"] == []
    assert out["exported_components"]["removed"] == ["com.example.app.MainActivity (activity)"]
    assert out["exported_components"]["added"] == ["com.example.app.Svc (service)"]


def test_secret_patterns_have_expected_names_and_risks():
    """The pattern set must keep npm parity: names + risks are the contract."""
    expected = {
        "Google API Key": "HIGH", "AWS Access Key ID": "CRITICAL",
        "AWS Secret Access Key": "CRITICAL", "Stripe Secret Key": "CRITICAL",
        "Stripe Publishable Key": "MEDIUM", "GitHub Token": "CRITICAL",
        "JWT Token": "HIGH", "PEM Private Key": "CRITICAL",
        "SendGrid API Key": "HIGH", "Twilio Account SID": "HIGH",
        "Twilio Key SID": "HIGH", "Mapbox Token": "MEDIUM",
        "Slack Token": "HIGH", "Basic Auth Header": "HIGH",
        "Generic Hardcoded Credential": "MEDIUM",
    }
    got = {name: risk for name, _, risk in apkdiff_mod._SECRET_PATTERNS}
    assert got == expected


def test_entry_cap_skips_oversized_entries(tmp_path, monkeypatch):
    """A declared-oversize lib entry is skipped with a note, not a crash."""
    real = apkdiff_mod._env_max_mb
    monkeypatch.setattr(
        apkdiff_mod, "_env_max_mb",
        lambda name, fallback: 1 if name == "MOBILE_RE_MCP_MAX_ENTRY_MB" else real(name, fallback),
    )  # 1 MB per-entry cap, file cap untouched
    huge = b"x" * (2 * 1024 * 1024)  # 2 MB entry > 1 MB cap
    old = _write_apk(tmp_path, "cap_old.apk", {
        "lib/arm64-v8a/libhuge.so": huge,
        "classes.dex": b"same dex",
    })
    new = _write_apk(tmp_path, "cap_new.apk", {
        "lib/arm64-v8a/libhuge.so": huge,
        "classes.dex": b"same dex",
    })
    result = apkdiff_mod.ApkDiffHandler().apk_diff({
        "old_path": old, "new_path": new, "skip_secrets": True,
    })
    assert result["status"] == "ok"
    nl = result["output"]["native_libraries"]
    # both entries unreadable → hash None on both sides → reported unchanged,
    # and the skip is visible in the archive notes
    assert nl["old_count"] == 1 and nl["all_identical"] is True
    notes = result["output"]["archive"]["notes"]
    assert any("above the per-entry cap" in n for n in notes)
