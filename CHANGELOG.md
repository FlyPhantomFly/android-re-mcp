# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.5.0] - 2026-11-16

### Added (Python)
- `android_api_extractor` gains the E-NPM-5 const-string harvest (commit `8cd2023`): every `const-string`/`const-string/jumbo` literal starting with `http://`/`https://` is deduplicated (across files) and host-grouped via `urlsplit`, returned as a `const_string_urls` block with `total`/`shown`/`truncated` counts, an `oversized_skipped` counter (constants over 2k chars are skipped and counted, not returned) and `by_host` groups capped deterministically at 500 URLs (sorted hosts first). An escaped quote ends the capture with the trailing backslash stripped. Postman mode is unchanged. This answers "what endpoints does this APK call?" for apps that build URLs without Retrofit annotations.
- Token conservation for heavy outputs (E-PY-15, commit `a44711f`), the android-unidbg-mcp strategy: cap the output, keep the honest total, mark the truncation, end with an actionable narrowing hint. New `handlers/caps.py` exposes the server-wide `ANDROID_RE_MCP_MAX_OUTPUT_LINES` cap (read per call, default 200; `0` restores the uncapped behavior exactly). Wired into the five flood-prone tools: `frida_read_output` (capped drain; excess stays buffered for the next call, reset on new session/detach), `adb_logcat_read` (oversized requests clamped, buffered count reported), `adb_logcat_stop` (final buffer capped, dropped lines counted honestly), `search_strings` (matches capped, total kept), `native_strings` (per-lib cap with the narrowing knobs named). Results under the cap are byte-for-byte identical to before; nothing is cut mid-JSON and secret findings are never silently shortened.
- Native ELF security & code search (E-PY-16, commit `52d697e`), the capstone cherry-pick: five tools in the new `handlers/sosec.py` — `so_xrefs` (scan-based xrefs to an address in a .so: branches, adrp+add pairs, movz/movk immediates), `rop_gadgets` (gadget search with `depth`/`filter`), `elf_checksec` (PIE/NX/RELRO/canary/fortify/RUNPATH, pure Python), `native_crypto_constants` (AES s-box, SHA-256/512 IVs, MD5 T-table, CRC-32, TEA delta, Base64, Blowfish — file offset + VA), `syscall_lookup` (arm64/x86_64 tables bundled from kernel headers). capstone becomes the optional `[native]` extra (added to `[all]` and `[dev]`); the pure-Python three work without it. All list outputs ride the E-PY-15 caps. Catalog grows 62 → 67 tools (+0.9k schema tokens vs the +3.2k the full capstone server would have added).

### Changed (Python)
- **Behavior note for upgraders:** heavy list outputs are capped per call by default (200 lines, `ANDROID_RE_MCP_MAX_OUTPUT_LINES`); set it to `0` for the exact 1.4.0 behavior.
- `android_api_extractor`'s description stops overclaiming: the OkHttp side reports detected client-field declarations, not extracted URLs.
- 38 new hermetic tests (`tests/test_output_caps.py`, `tests/test_sosec.py`, `tests/test_api_extractor.py`); suite now 173 passed + 1 skipped.

### Docs
- README: tool counts (67), the E-PY-15 cap notes on the affected tool rows, and a new "Companion servers" section pairing [smali-lsp](https://github.com/surendrajat/smali-lsp) into the patch loop (its `smali_diagnostics` pre-validate hand edits before `apk_rebuild_sign`).

### Changed (Python, unreleased batch 3)
- `apk_decompile_java` degrades to apktool when jadx is unavailable instead of returning `missing_tool`: the call still succeeds, with `engine: "apktool (jadx unavailable)"`, `fallback: true` and a note that `out_dir` holds smali + resources, not Java source (5 new tests, `tests/test_decompile_fallback.py`). jadx present-but-broken is still an honest error — no silent engine swap on real failures.
- Review-doc hygiene pass (D-2, D-3): `check_tools` dropped the never-invoked probes (`binwalk`, `apk-mitm`, `frida-compile`, `frida-ps`) and the redundant `frida-tools`-module / `mitmproxy`-binary / `mitmproxy`-module probes; the dead legacy `scripts/android-api-extractor/analyze_apk.py` is deleted. CI pins bumped (checkout@v7, setup-python@v7, upload-artifact@v7, download-artifact@v8) — clears the Node-20 deprecation annotations from the publish runs.

### Added (Python, unreleased batch 4)
- DEX surgery via DexFile (E-PY-17): seven `dex_*` tools over the new pinned [`dexfile-cli`](https://github.com/FlyPhantomFly/dexfile-cli) jar (v0.1.0, MIT — redistribution of DexFile/Smali/AndroidMisc) — `dex_info`, `dex_extract`, `dex_convert` (old-ART vdex/cdex → 035; 035 → 041 containers), `dex_patch` (const-string/rename/retarget-invoke/flip-flags/replace-method-body, `.bak` discipline, per-op matched counts), `dex_assemble`, `dex_split` (64K balancing) and `dex_swap` (pure-Python zip swap closing the no-rebuild fast loop: `dex_extract → dex_patch → dex_swap → apk_sign`). The jar is a pinned `--setup` download; `check_tools` gains its probe. Phase-0 spike findings recorded in the review doc (vdex027+ carries no embedded dex; cdex round-trip proven; baksmali reads 041 containers fine). 12 new tests; catalog 67 → 74 tools.

## [1.4.0] - 2026-11-15

### Consolidation (PyPI ← npm)

### BREAKING

- Console command renamed **`mobile-re-mcp-py` → `android-re-mcp`** (npm users:
  `mobile-re-mcp` → `android-re-mcp`). No compatibility alias is provided — MCP
  client configs, shell scripts and `uvx`/`pipx` invocations that reference the
  old command must be updated. The Python import package (`android_re_mcp`) is
  unchanged.


The npm server (`mobile-re-mcp`) is retired: its static Android tools are
ported into the Python package, its iOS tools dropped, and its TypeScript
sources deleted — one package,
one implementation, one publish pipeline. Ports landed before any removal, so
there was never a window where a capability existed nowhere.

### Renamed: `android-re-mcp`

With the npm half retired there is no second implementation to disambiguate,
so the project is rebranded: PyPI project **`android-re-mcp`**, command
**`android-re-mcp`** (was `mobile-re-mcp-py`), import package
**`android_re_mcp`**, server name `android-re-mcp`, env prefix
**`ANDROID_RE_MCP_*`** (was `MOBILE_RE_MCP_*`), data/config folders
`~/.local/share/android-re-mcp` and `~/.config/android-re-mcp`. The retired
npm name `mobile-re-mcp` gets a deprecation notice pointing here. Anyone
upgrading: reinstall under the new name and update the env-var prefix in
client configs.

### Added (Python)
- `apk_diff` — build-vs-build diff ported from the npm tool (E-NPM-4 → E-PY-10): identity/SDK levels, security-flag changes, permission and exported-component deltas, native-library sha256 changes, optional secret deltas and an archive inventory. Zero new dependencies — the manifest section reads through the androguard already shipped by `[static]` (missing extra or an unreadable manifest degrades that section honestly), native libs/secrets/inventory are stdlib-only, the secret scan extracts printable strings from `classes*.dex` / `resources.arsc` / text assets instead of shelling out to `strings(1)`, and the npm size caps carry over (`ANDROID_RE_MCP_MAX_FILE_MB`, `ANDROID_RE_MCP_MAX_ENTRY_MB`). Verified live: identical build reports all-same; two different apps show every delta section; manifest-less fixtures degrade with the real reason.
- `android_api_extractor` — Retrofit/OkHttp endpoint extraction ported from the npm tool (E-NPM-5's subject → E-PY-11): walks a smali tree for `Lretrofit2/http/*` runtime annotation blocks (endpoint = the `value = "..."` entry, whitespace-collapsed body as fallback) and OkHttp3 field declarations, with `output_format` of `txt` (structured lists) or `postman` (a ready-to-import Postman v2.1 collection with every endpoint on a `{{base_url}}` variable). Give it `apk_path` and it decompiles first with the apktool the server already wraps, or point `smali_dir` at an existing decompile to skip that step. One port fix: npm's field pattern required a space before `Lokhttp3/`, which real apktool output (`name:Lokhttp3/Type;`) never matches — the port drops the space so canonical field declarations are found. Verified live: real 21 MB APK decompiled end-to-end through the server (honest zero counts — that app carries no annotations or OkHttp-typed fields), plus a canonical-form smali tree extracting 3 annotations and 2 fields into both formats.
- `android_google_services` — Google/Firebase config extraction ported from the npm tool (E-PY-12): parses a bundled `google-services.json` (exact `assets/` location first, else any entry whose name ends with it) into project info + per-client package/app-id/API-key/OAuth list; with `smali_dir` it scans `res/values/strings.xml` for the ten well-known Google keys as structured `key = value` pairs; without it, `resources.arsc` goes through the five Google patterns from npm's `patterns.ts` (names + risks verbatim) via zero-dependency printable-string extraction instead of `strings(1)`. Each section degrades honestly on its own. The scan machinery (printable strings, size caps, zip-source walk) moved into a shared `handlers/apkscan.py` used by both `apk_diff` and this tool — `apk_diff` behavior unchanged. Verified live on TiviMate: the arsc scan surfaces the app's real Firebase config (API key, `tivimate-233306.firebaseio.com`, appspot bucket); the strings.xml path honestly reports that this app stores none of the ten keys.
- `manifest_parse` extended with `categorize_permissions: true` (E-PY-13, the npm permissions-checker port): adds `permission_categorization` — the dangerous/normal split with a per-permission reason and npm's risk-summary lines (toll fraud, tracking, covert recording, arbitrary APK installs). The `dangerous_permissions` set grows from 12 hand-picked grants to the npm tool's 40-name triage taxonomy verbatim (runtime-dangerous plus install-time/signature grants worth triage), now matched on the short name like npm (bare `READ_SMS` counts, custom namespaces don't). Without the flag the output is unchanged. Verified live: notesdemo categorizes 4 dangerous + 1 normal with reasons and two summary lines; TermuxBoot reports 0 dangerous / 2 normal / empty summary.
- `rasp_identify` extended with the npm `android_native_libraries` tool folded in (E-PY-14, no new tool): every `lib/<abi>/*.so` entry is inventoried per ABI and ELF-inspected — class/machine/type, section-header presence and section names — with the npm known-library table ported verbatim (31 rows: packers, RASP, frameworks, SDKs, runtimes). Packer/RASP basename hits join the tool's `detected` list under their product label, and stripped/packed section tables or unrecognised suspicious ELF layouts surface as `protection_signals`. Zero new dependencies (hand-rolled ELF header parse; the npm original could throw past its length check, the port degrades instead). Verified live: TiviMate's 24 `.so` files across 4 ABIs identify `libdexprotector.so` as DexProtector (packer) everywhere, flipping the tool to protection tier `enterprise`; a no-native-code APK reports the npm wording honestly.


### Removed (npm)
- the iOS half of the npm server: all seven `ios_*` tools
  (`ios_manifest_analyzer`, `ios_permissions_checker`, `ios_entitlements_checker`,
  `ios_binary_strings`, `ios_frameworks_detector`, `ios_google_services`,
  `ios_secrets_scanner`), `src/tools/ios/` with its shared `extract-binary.ts`,
  the `plist`/`@types/plist` dependencies, and every iOS/ipa reference in the
  README, CONTRIBUTING, issue/PR templates and CI workflow. The npm package
  now reads Android APKs only — matching its static Android tools moving into
  the Python package this release (see the phase-2 note in
  docs/code-review-and-extensions.md).
- the npm server itself. With all five static Android tools ported (E-PY-10…14),
  the TypeScript half is deleted: `src/`, `test/`, `package.json` +
  `package-lock.json`, `tsconfig.json`, `test-tools.mjs`, the npm publish
  workflow, the reusable-analyze workflow it backed, the Node CI matrix and
  version-match job, the npm Dependabot ecosystem, and `node_modules`/
  `dist` artifacts. CI is now pytest + ruff on Python 3.11/3.13; the publish
  pipeline is PyPI-only (`publish-pypi.yml`). README documents the retirement
  and points installers at `pip install "android-re-mcp[all]"`; CONTRIBUTING
  is rewritten PyPI-only; the bug-report template lists Python tool names;
  SECURITY's supported-versions table is 1.4.x-only. npm marks the package
  deprecated:
  `npm deprecate mobile-re-mcp "consolidated into the Python package (pip install android-re-mcp)"`.

## [1.3.0] - 2026-11-10

This release is the rebuild pass documented in
[docs/code-review-and-extensions.md](docs/code-review-and-extensions.md): every
`[verified live]` finding fixed with before/after evidence, the npm server
hardened against hostile archives, and five new tools.

### Fixed (Python)
- `manifest_parse`, `analyze_code`, `find_crypto_usage` and `find_urls` work again on the androguard 4.x that `[static]` installs — the exported-components logic is now derived from the parsed manifest (with explicit / intent-filter / pre-17 auto-export markers), the call-graph helpers tolerate every 3.x/4.x record shape, and `apk_analyze_full` reports per-stage status honestly instead of masking failures (F-PY-1).
- `check_tools` reports what the handlers actually need: pip CLIs resolve through the interpreter-sibling fallback (`clitools.find_cli`), the SSH cracker named `medusa` no longer counts as the framework, and every entry says which MCP tools use it (F-PY-2).
- The 8 built-in Frida scripts ship with the package again, each implementing the `recv('config')` protocol, and `frida_find_bytes` works on frida 17 (F-PY-3, plus the QuickJS `process` global fix, D-5).
- Tool handlers no longer block the asyncio loop: stateless handlers run on worker threads, the three stateful classes keep their ordering on a dedicated pool (F-PY-4).
- Script parameters travel as `{'type':'config', …}` after load instead of `str.replace` on magic source lines (F-PY-5).
- Dead weight removed from the dependency list and the checks; housekeeping for `frida_memdump`'s dump directory, the HAR helper's deprecated `utcnow`, and `adb_shell`'s argument-model documentation (F-PY-6, F-PY-7, E-PY-9).
- Rooted-device round: `frida_attach` works by package identifier even when frida only knows the app label (D-6); `frida_memdump` no longer OOM-kills the target by reading multi-GB ranges — a per-range cap (`max_range_mb`, default 32) with the skips reported (D-7); and `MOBILE_RE_MCP_FRIDA_ENDPOINT` routes every `frida_*` tool to a stealth frida-server (renamed binary, non-default port via `adb forward`) that USB discovery can never find (D-8).
- The 7 Java-hooking Frida scripts are rebuilt as `frida-compile` bundles with `frida-java-bridge` compiled in — frida 17 removed the `Java` global from script runtimes, so the raw sources died with `ReferenceError: 'Java' is not defined` on a real device (D-9). `build_bundles.sh` reproduces them from `frida_scripts/src/`.

### Fixed (npm)
- Zip-bomb guard: inputs are capped at 2048 MB and single decompressed entries at 256 MB (`ANDROID_RE_MCP_MAX_FILE_MB` / `ANDROID_RE_MCP_MAX_ENTRY_MB`, `0` disables), checked before decompression on every APK/IPA read (F-NPM-4).
- One shared iOS binary extractor and one shared scan-result merge replace three drifting copies each (F-NPM-3).
- `apk_manifest_analyzer` uses the `aapt2` fallback it could already parse (F-NPM-2).
- The smoke runner is honest about fixtures and coverage, `npm test` runs the hermetic suite, and the small consistency fixes landed: shared `min_length` default, prefix-only framework matching, DexGuard out of the iOS table, Windows ENOENT hint, dead code removal (F-NPM-1, F-NPM-5, E-NPM-7).

### Added
- **`quark_scan`** (PyPI): quark-engine behaviour scoring with keyword/score filters; also a best-effort stage of `apk_analyze_full` (E-PY-3).
- **`frida_status`** (PyPI): frida version, devices, server responsiveness, session state — the "am I attached?" read (E-PY-7).
- **`adb_ui_dump`** (PyPI): the current UI as structured elements via uiautomator (E-PY-8).
- **`android_native_libraries`** (npm): every `lib/<abi>/*.so` with packer/RASP/framework fingerprinting and ELF section inspection (E-NPM-3).
- **`apk_diff`** (npm): two builds side by side — identity, flags, permission/component deltas, native-library sha256 deltas, secret deltas (E-NPM-4).

PyPI server: 58 tools. npm server: 14 tools.

## [1.2.3] - 2026-11-03

### Fixed
- `apk_manifest_analyzer` misread the output of `aapt`, which it prefers when installed. `aapt` prints booleans as `(type 0x12)0xffffffff` and the component names on separate lines, so the old patterns found nothing. An APK with `debuggable`, `allowBackup`, cleartext traffic and exported components could be reported as clean. The manifest is now parsed properly from `aapt`, `aapt2` and `apktool` output, and relative class names are shown in full.
- The same tool now lists components that are exported by default through an intent filter, and returns an error instead of a clean result when it cannot read the manifest.

### Added
- Parser tests in `test/`, run with `node --test "test/*.test.mjs"` after a build, and a CI step for them.

### Changed
- The README example now uses an APK.

## [1.2.2] - 2026-11-03

### Changed
- Restored the banner at the top of the README.
- Recreated the npm trusted publisher, so releases can publish from GitHub Actions again.

## [1.2.1] - 2026-11-02

### Changed
- Rewrote the README, CONTRIBUTING and SECURITY in plainer language. The README now opens with a worked example, has install steps for Claude Code, opencode and Claude Desktop, and lists each tool once with what it needs.
- The Python README now covers setup, a first session and the safety settings.

### Fixed
- npm publish workflow: it now ends green when the version is already on npm, which happens when you publish by hand, and a failed publish prints which trusted publisher settings to check. It no longer passes `--provenance`, because trusted publishing adds provenance itself. You can also run it by hand from the Actions tab to see what npm says about the login, without publishing anything.
- Python server: messages about a missing tool now point to `mobile-re-mcp-py --setup`. They used to mention `install_tool`, which is off unless you enable it.

## [1.2.0] - 2026-11-02

### Added
- Python server in `python/`, published on PyPI as `mobile-re-mcp` (command `mobile-re-mcp-py`). It adds adb, Frida, mitmproxy, apktool/jadx, patching and signing tools. It is derived from `mobile-security-mcp` 0.1.4 (MIT), see `python/NOTICE.md`.
- One release tag now publishes both packages, and CI fails if their versions differ. The npm package has no code changes in this release.

### Security (Python server)
- Every tool call is checked before it runs. File arguments reject a leading `-`, NUL bytes and protected places such as `~/.ssh`, `~/.config/gh` and shell rc files, and they follow `MOBILE_RE_MCP_ALLOWED_DIRS`.
- `native_disasm` no longer lets `;` or `!` reach radare2, which allowed shell commands from a hostile symbol name.
- `search_strings` passes the pattern to ripgrep with `-e` and `--`, so `--pre=...` can no longer run a program.
- SSE listens on 127.0.0.1 only, rejects foreign Host headers, and needs `MOBILE_RE_MCP_TOKEN` for any other address. It used to bind 0.0.0.0 with no authentication.
- mitmproxy listens on 127.0.0.1 only. Use `adb reverse` to reach it from the device.
- Downloads are pinned to a release and checked against a SHA-256. The apktool wrapper script no longer comes from the `master` branch.
- `install_tool` is off unless `MOBILE_RE_MCP_ALLOW_INSTALL=1`. pip installs no longer use `--break-system-packages` and cannot change an installed Frida.
- Scratch files live in a private folder instead of fixed names in `/tmp`, and `frida_server_push` no longer picks up binaries from `/tmp`.
- Target notes are stored under `~/.local/share/mobile-re-mcp` and the package name is validated. It could write into any folder before.

### Changed (Python server)
- Requires `mcp` 1.30 or newer and below 2. SDK 2 removed the handler decorators this server uses, so the port is still to do.
- The heavy tools (frida, androguard, apkid, apkleaks, mitmproxy, quark-engine) are optional extras. `textual`, `rich` and `tomli` are no longer dependencies.
- Settings moved to `~/.config/mobile-re-mcp/config.toml`. Nothing is created or added to `PATH` at import time any more.
- Downloaded tools are apktool 2.12.1, jadx 1.5.6, uber-apk-signer 1.3.0, Il2CppDumper 6.7.46 and scrcpy 5.0.1 (Windows). adb is no longer downloaded because Google only publishes an unversioned build. The smali/baksmali installer is gone because its URLs return 404.

### Fixed (Python server)
- `apk_sign` looked for the signer jar in the current directory while the installer put it in `~/tools/signing`.
- `frida_server_push` ignored a failed `chmod` on the device.
- `frida_list_scripts` listed scripts that are not in the package. It now lists only scripts that exist, and your own go in `~/.local/share/mobile-re-mcp/frida_scripts`.
- The SSE endpoint used a route type that cannot serve the message endpoint.
- mitm helper scripts ran under whatever `python` was on `PATH` and now use the server's interpreter.

## [1.1.2] - 2026-11-02

### Fixed
- Added package-lock.json so npm ci works in CI.
- CI now runs on master.

## [1.1.0] - 2026-11-01

### Security
- No tool builds shell command strings any more. All external programs (`apktool`, `aapt`, `aapt2`, `strings`, `file`, `codesign`, `ldid`, `plutil`) run via `execFileSync` with argument arrays and a timeout, closing a command-injection path through `apk_path` / `smali_folder`.
- Input paths are validated: must be absolute, exist, and resolve (symlinks) to a regular `.apk` / `.ipa` file with ZIP magic bytes, or to a directory for `smali_folder`.
- iOS: `CFBundleExecutable` read from an untrusted `Info.plist` is regex-escaped before matching, and the binary-plist conversion uses a private temp directory instead of a predictable file name.
- New optional `MOBILE_RE_MCP_ALLOWED_DIRS` allow-list for readable locations.
- `secrets-scanner`: smali-folder scan now reads regular files only (no symlink-following).
- `reusable-analyze.yml`: workflow inputs/outputs are passed through `env` instead of being interpolated into shell; random heredoc delimiter for step outputs.

### Changed
- The server reports the version from `package.json` instead of a hard-coded string.
- Renamed project to `mobile-re-mcp` (package, binary, server name, docs) and maintainer/repository owner to `FlyPhantomFly`. The original MIT copyright notice (Serhatcck) is retained in `LICENSE`.
- Migrated to MCP TypeScript SDK v2 (`@modelcontextprotocol/server`, `registerTool`, `serveStdio`); tool schemas are wrapped in `z.object(...)`.
- Dependencies: `zod` 3 -> 4, `adm-zip` -> 0.6 (fixes CVE-2026-39244; ships its own types), `typescript` 5 -> 6, `@types/node` 20 -> 22. Removed `ts-node` and `@types/adm-zip`. `@modelcontextprotocol/sdk` ("latest") replaced by pinned-range `@modelcontextprotocol/server`.
- Requires Node.js 22+. CI and publish workflows use `actions/checkout@v6` and `actions/setup-node@v6`; Dependabot now also tracks GitHub Actions.
- `package-lock.json` removed so it can be regenerated against the new dependency set (`npm install`).

## [1.0.0] - 2025-04-02

### Added

**Android tools**
- `apk_manifest_analyzer` — parses AndroidManifest.xml, flags debuggable/allowBackup/cleartext traffic, exported components, intent filters
- `apk_permissions_checker` — categorizes dangerous vs normal permissions with risk summary
- `android_api_extractor` — decompiles smali bytecode to extract Retrofit HTTP endpoints and OkHttp3 fields; outputs plain text or Postman collection
- `android_google_services` — extracts Firebase/GCP config from `google-services.json` and `resources.arsc` via strings command; supports optional smali_folder for structured output
- `android_secrets_scanner` — scans DEX bytecode + `resources.arsc` + text assets for hardcoded API keys and credentials

**iOS tools**
- `ios_manifest_analyzer` — parses Info.plist, flags ATS misconfigs, URL schemes, background location, queried schemes
- `ios_permissions_checker` — maps all `NS*UsageDescription` keys to HIGH/MEDIUM/LOW risk with explanations
- `ios_entitlements_checker` — extracts entitlements from app binary via codesign/ldid, flags get-task-allow and sandbox bypass, detects simulator builds
- `ios_binary_strings` — extracts URLs, emails, private IPs, and API key patterns from Mach-O binary
- `ios_frameworks_detector` — enumerates bundled .framework and .dylib files, maps ~60 known SDKs across networking, analytics, ads, attribution, crash reporting, fraud detection categories
- `ios_google_services` — parses GoogleService-Info.plist for full Firebase configuration
- `ios_secrets_scanner` — two-layer scan: text resource files (plist/json/strings) + app binary via strings command

**Shared**
- `patterns.ts` — centralized `GOOGLE_PATTERNS` and `SECRET_PATTERNS` registry shared across all scanner tools; `scanText` and `renderResults` utilities
