# android-re-mcp (Python)
The live-device half of [android-re-mcp](https://github.com/FlyPhantomFly/android-re-mcp). It is an MCP server that lets an AI assistant drive adb, Frida, mitmproxy, apktool and jadx against a test phone: decompile an app, hook it, read its traffic, patch it, sign it and install it again.
The npm predecessor (`android-re-mcp`) is retired — its static Android tools moved into this package and its iOS tools were dropped (1.4.0). This package is the sole survivor.

## Install
```bash
pip install "android-re-mcp[all]"
android-re-mcp --setup
```
It needs Python 3.11 or newer. The base install is just the MCP server. The `[all]` extra adds Frida, androguard, apkid, apkleaks, mitmproxy and quark-engine, and you can pick parts instead: `frida`, `static`, `network`, `analysis`. If Frida is already pinned in your environment, install without extras and the server will not touch it.
`--setup` downloads pinned, checksum-verified copies of apktool, jadx, uber-apk-signer, Il2CppDumper and dexfile-cli 0.2.2 into `~/tools`. adb comes from your package manager (`sudo apt install adb`); scrcpy and radare2 too.

## Connect it
Claude Code:
```bash
claude mcp add android-re -- android-re-mcp
```
opencode, in `~/.config/opencode/opencode.json`:
```json
{
  "mcp": {
    "android-re": { "type": "local", "command": ["/path/to/venv/bin/android-re-mcp"], "enabled": true }
  }
}
```
Use the full path to the command if it lives in a virtualenv. Any other client needs only the command, with no arguments.
Start with a check of what is installed. Ask "Run check_tools", and the assistant lists which tools it found and which are missing.

## A first session
Ask in plain language and the assistant picks the tools. Some prompts and what they use:
- "List my devices, then push frida-server to the phone and start it." (`adb_devices`, `frida_server_push`)
- "Decompile /home/me/apks/app.apk and search the strings for token or secret." (`apk_decompile`, `search_strings`)
- "Which protection does com.example.app use, and how do I get past it?" (`rasp_identify`, `rasp_bypass`)
- "Start mitmproxy, open the app on the phone, then show me the requests it made." (`mitm_start`, `mitm_read_flows`)
- "Patch the license check in the smali, rebuild, sign and install it." (`smali_patch`, `apk_rebuild_sign`, `adb_install`)
- "Swap one string in classes.dex without rebuilding the APK, then validate the patched dex." (`dex_extract`, `dex_patch`, `dex_validate`, `dex_swap`, `apk_sign`, `adb_install`)
- "These split dex files need to ship as one — merge them and check the result." (`dex_merge`, `dex_info`)
- "Dump the app's memory and look for the session key." (`frida_memdump`, `frida_find_bytes`)

The server also carries short playbooks as MCP prompts, and it keeps per-app notes (`memory_read`, `memory_write`) so a later session can pick up where the last one stopped.

## What is in it
The server exposes **89 tools** (88 on a default install; `install_tool` is off until you set `ANDROID_RE_MCP_ALLOW_INSTALL=1`). The full table with every name is in the
[repository README](https://github.com/FlyPhantomFly/android-re-mcp/blob/master/README.md#the-tool-set).
The main groups:

| Group | Highlights | Needs |
| --- | --- | --- |
| Static analysis | `apk_decompile`, `apk_analyze_full`, `manifest_parse`, `search_strings`, `quark_scan` | apktool, jadx, ripgrep, androguard, apkid, apkleaks, quark-engine |
| Bytecode deep-dive | `analyze_code`, `dex_read_pseudocode`, `dex_read_class_outline` | androguard, jadx, dexfile-cli |
| Frida | `frida_spawn`, `frida_attach`, `frida_inject`, `frida_run_script`, `frida_memdump`, `objection_run` | Frida, a rooted phone or a gadget |
| Device | `adb_devices`, `adb_shell`, `adb_install`, `adb_pull`, `adb_push`, `adb_logcat_*`, `scrcpy_*`, `hermes_decode` | adb, scrcpy |
| Network | `mitm_start`, `mitm_read_flows`, `mitm_export_har`, `ssl_kill_switch` | mitmproxy |
| Patching and signing | `smali_patch`, `inject_gadget`, `apk_sign`, `apk_rebuild_sign` | apktool, uber-apk-signer, Java |
| DEX surgery | `dex_info`, `dex_convert`, `dex_patch`, `dex_assemble`, `dex_split`, `dex_merge`, `dex_validate`, `dex_swap` | dexfile-cli |
| APK/zip surgery | `apk_read_signature`, `zip_test`, `zip_extract`, `zip_update`, `resource_table_list`, `resource_read`, `apk_build_check` | apksigner, openssl, aapt2 |
| Native and cross-platform | `native_strings`, `native_exports`, `native_disasm`, `so_xrefs`, `native_patch_string`, `il2cpp_dump`, `blutter_extract` | radare2, capstone, Il2CppDumper, Blutter |
| Protections and workflow | `rasp_identify`, `rasp_bypass`, `memory_read`, `memory_write`, `check_tools` | none |

The Frida script library behind `frida_list_scripts` is empty until you add scripts of your own to `~/.local/share/android-re-mcp/frida_scripts`. The bypass scripts in `rasp_bypass` are built in.

## Staying safe
This server can run commands on your phone and your computer, so treat its tools with care.
- Use stdio. `--transport sse` listens on 127.0.0.1 only, and any other `--host` needs `ANDROID_RE_MCP_TOKEN`, which clients send as a bearer token.
- Set `ANDROID_RE_MCP_ALLOWED_DIRS` (folders separated by `:`) to keep file arguments inside your workspace. Paths under `~/.ssh`, `~/.config/gh`, shell rc files and similar are always refused.
- Size caps for the zip/apk tools: `ANDROID_RE_MCP_MAX_FILE_MB` (default 2048) refuses to open a heavier APK, `ANDROID_RE_MCP_MAX_ENTRY_MB` (default 256) refuses to read a heavier zip entry; `0` disables either cap.
- Switch tools off with `ANDROID_RE_MCP_DISABLE_TOOLS=adb_shell,adb_push,adb_pull`, and set the risky ones to ask first in your client.
- `install_tool` is off unless you set `ANDROID_RE_MCP_ALLOW_INSTALL=1`. `--setup` always works because you run it yourself.
- mitmproxy listens on 127.0.0.1. Run `adb reverse tcp:8080 tcp:8080` and point the phone's proxy at 127.0.0.1:8080.
- A sample you analyze can try to steer the assistant through its own strings and symbol names. Use a VM, and do not auto-approve tools that touch the device.

## Files
Notes, captures and scratch files live in `~/.local/share/android-re-mcp` (set `ANDROID_RE_MCP_HOME` to move them). Settings such as your signing keystore go in `~/.config/android-re-mcp/config.toml`. Downloaded tools go in `~/tools`.

## Credits
Derived from `mobile-security-mcp` 0.1.4 on PyPI (MIT), whose authors are not named. See [NOTICE.md](NOTICE.md). MIT licensed.
