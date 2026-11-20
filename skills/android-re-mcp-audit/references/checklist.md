# Static review checklist — android-re-mcp

Work top to bottom. Record evidence next to each item: a path with lines, a command, or an explicit "not checked: reason". A checked box without evidence is not an audit result.

## 1. Repository and claims

- [ ] `python/pyproject.toml`: version, `requires-python`, runtime dependency pins, extras (`frida`, `static`, `network`, `analysis`, `native`, `all`, `dev`), console script, ruff/pytest config.
- [ ] `README.md`: installed tool counts match `TOOL_SCHEMAS`; every documented extra maps to a handler that needs it; setup claims (pins, versions) match the installer.
- [ ] `CHANGELOG.md`: newest entry describes the code that exists; no "fixed" claim is contradicted by the current source.
- [ ] `CONTRIBUTING.md` conventions (structured JSON, `missing_tool` honesty, guard on every path, tests/fixtures) are followed by the modules under review.
- [ ] `SECURITY.md` and transport claims match `server.py`/`__main__.py` (SSE loopback, token requirement).
- [ ] Git state is recorded. An audit of a dirty working tree says so.

## 2. Server wiring (`python/src/android_re_mcp/server.py`)

- [ ] Every `TOOL_SCHEMAS` entry has exactly one `_dispatch` target.
- [ ] Every `_dispatch` key has a schema entry.
- [ ] Every handler class referenced in `_dispatch` is instantiated in `create_server()`.
- [ ] Schema-required arguments match what the handler actually consumes (`required`, property names, enums).
- [ ] Descriptions do not overclaim (for example "extract URLs" when the code only detects fields).
- [ ] Stateful handlers (`DynamicHandler`, `NetworkHandler`, `DeviceHandler`) are the only ones flagged `_SERIALIZE`; stateless work goes through `asyncio.to_thread`.
- [ ] `_run_tool` catches handler exceptions, applies `guard.validate` first, and reports unknown tools without crashing.
- [ ] Resources/prompts resolve through `KNOWLEDGE_DIR` and degrade when a file is missing.

## 3. Guard and path safety (`python/src/android_re_mcp/guard.py`, `paths.py`)

- [ ] `PATH_KEYS` covers every host-side path argument in the schemas (especially new dex/apkops/native tools).
- [ ] `WRITE_KEYS` covers every key that writes.
- [ ] `OUTPUT_SUFFIXES` entries name real tools and sensible suffixes.
- [ ] Sensitive-home list still blocks credential and shell-rc locations; symlinks resolve before the check.
- [ ] `ANDROID_RE_MCP_ALLOWED_DIRS`, `ANDROID_RE_MCP_DISABLE_TOOLS`, and `ANDROID_RE_MCP_ALLOW_INSTALL` behave as documented.
- [ ] `data_dir`, `scratch_dir`, `captures_dir` are private (0700 where possible); `tools_dir` honors `ANDROID_RE_MCP_TOOLS_DIR`.
- [ ] `ensure_tools_on_path` appends rather than prepends, so system tools still win.

## 4. Dex handler (`python/src/android_re_mcp/handlers/dex.py`)

- [ ] `_require` returns `missing_tool` for a missing jar or missing `java`, with an actionable hint.
- [ ] `_run` uses an argv list, a timeout, parses JSON stdout, and maps nonzero exits honestly.
- [ ] `_default_target` reads the magic only; unreadable input falls back safely; explicit `target_version` wins.
- [ ] `_validate_ops` covers every supported op, required fields, rename targets, flag names/hex, and non-empty method bodies.
- [ ] `dex_patch` writes the `.bak` once, cleans the temp ops file in `finally`, and skips the `.bak` when `output_path` is given.
- [ ] `dex_swap` matches dex entries only, preserves every other entry's compression, writes the `.apk.bak` once, and cleans up on failure.
- [ ] `dex_read_class_outline` searches every `classes*.dex` in an APK and reports the last real error, not a generic one.
- [ ] `dex_read_pseudocode` reuses its cache, pages correctly, and gives a smali-level hint on jadx failure.

## 5. Setup and tool discovery (`setup/`)

- [ ] Every `_PINNED` URL is https and has a matching SHA-256; downloads verify before `os.replace`.
- [ ] Every installer returns honest `ok` / `error` / `manual_required` and its success message names the version actually installed.
- [ ] `check_tools` probes what the handler executes (`find_cli` for pip CLIs, `_check_java_jar` for jars).
- [ ] Every `used_by` list names real tools, including all jar-dependent handlers.
- [ ] `_check_java_jar` distinguishes missing java from missing jar.
- [ ] `install_tool` stays off unless `ANDROID_RE_MCP_ALLOW_INSTALL=1`.
- [ ] Extras in `pyproject.toml` match what `check_tools` reports as required.

## 6. APK/zip and native surgery (spot-check the release batch)

- [ ] `apkops.py`: zip-slip refused, META-INF rename/delete guarded, `expected_sha256` honored, untouched entries byte-identical, build-check blockers have codes and hints.
- [ ] `sosec.py`: VA/file-offset mapping is correct both ways; patch guards (`expected_text`, `expected_hex`) abort before writes; `.bak` discipline holds.
- [ ] `native.py` / `rasp.py`: known-library fingerprints do not overlap ambiguously; ELF parsing degrades instead of throwing.
- [ ] `apkdiff.py`: manifest failure degrades honestly; section-level errors do not mask a clean result.

## 7. Tests and CI

- [ ] Targeted dex tests (`tests/test_dex_tools.py`) pass; note whether real-jar roundtrips ran or skipped.
- [ ] `tests/test_check_tools_honesty.py` passes; resolution shared between handler and checker.
- [ ] `tests/test_guard.py` passes; injection and protected-path cases still refused.
- [ ] Full suite counts are recorded (`passed`, `skipped`, `failed`). Every failure gets a cause category: code, environment, or test harness.
- [ ] No module-level `pytest.importorskip` or `pytestmark = pytest.mark.skipif` suppresses unrelated tests; run `check_test_hygiene.py` and report the test-function count hidden by each.
- [ ] `.github/workflows/`: CI Python versions, ruff/pytest commands, publish version match, artifact/action versions.
- [ ] Fixtures are hermetic and do not depend on `~/tools` or a device.

## 8. Packaging and code quality

- [ ] `pyproject.toml` wheel/sdist include the handlers, knowledge, and frida scripts the server reads at runtime.
- [ ] Optional imports are guarded so base installs still start and report `missing_tool`.
- [ ] Subprocess use is argv-based, has a timeout, and never interpolates a shell string.
- [ ] Temp files live under the private data dir and are cleaned up on every path.
- [ ] Error payloads stay bounded (no multi-megabyte stderr dumps).
- [ ] Dead code, stale comments, and version strings that no longer match the pin are flagged as Low.

## 9. Findings quality

- [ ] Each finding has an ID, severity, confidence, file:line, evidence command, impact, and recommendation.
- [ ] Findings distinguish "broken now" from "risky later" and "message-only".
- [ ] The log has a limitations section listing what this environment could not prove.
- [ ] The conclusion states what was verified, not what was assumed.
