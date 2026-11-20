# Dexfile-cli audit protocol

The question "does dexfile-cli work?" has several layers. Passing one layer does not prove the next one. Work through them in order and record which layer each piece of evidence covers.

## Layer 1 — artifact and pin

Inspect `python/src/android_re_mcp/setup/install_tool.py`:

- `_PINNED["dexfile-cli.jar"]` has an https URL and a 64-hex SHA-256.
- The URL version (`/v0.1.6/`) matches the pin documented in `CHANGELOG.md` and `README.md`.
- `_download` refuses non-https, hashes the stream, and only then `os.replace`s.
- `_install_dexfile_cli` writes to `tools_dir() / "dexfile-cli.jar"` and its message names the same version as the pin. A stale message is a Low finding.
- `_INSTALLERS` registers the recipe under `"dexfile-cli"`.

Run the preflight helper. It reports the actual jar path, actual SHA-256, expected SHA-256 parsed from the installer, whether they match, and whether the installer's success message version matches the pin. It also flags the generic `JDK 11+` jar hint when the dex handler requires Java 17+.

## Layer 2 — discovery and reporting

Inspect `python/src/android_re_mcp/setup/check_tools.py`:

- `check_all_tools()` calls `_check_java_jar("dexfile-cli", ...)`.
- `_check_java_jar` checks `java` first, then the jar, and returns distinct errors for each.
- The `used_by` list names every tool that cannot work without the jar. Compare against `DexHandler` methods that call `_require` or `_run`; `dex_read_class_outline` is easy to miss because it calls `_require` directly.

Run the live checker (from the repo, with `PYTHONPATH=python/src`):

```bash
python -c "from android_re_mcp.setup.check_tools import check_all_tools; import json; print(json.dumps(check_all_tools()['tools'].get('dexfile-cli'), indent=2))"
```

Expected: `available: true`, `kind: java_jar`, a real path, and an accurate `used_by`.

## Layer 3 — handler plumbing

Inspect `python/src/android_re_mcp/handlers/dex.py`:

- `_require(tool)` returns `missing_tool` for a missing jar and for missing `java`, with hints naming `--setup` / `install_tool`.
- `_run` invokes `[java, "-jar", jar, *args]` as an argv list, with a timeout, and parses JSON stdout.
- Nonzero exits are reported with the parsed `kind` and message; do not let a JVM stack trace masquerade as success.
- `DexHandler` methods exist for every dex tool in the server dispatch: `dex_info`, `dex_extract`, `dex_convert`, `dex_patch`, `dex_assemble`, `dex_split`, `dex_swap`, `dex_read_class_outline`, `dex_read_pseudocode`.
- `dex_swap` is pure Python and must work with no jar.
- `dex_patch` validates ops before running, writes the ops JSON to the private data dir, and deletes it in `finally`.
- In-place `dex_patch` and `dex_swap` create their backup exactly once; `output_path` / `output_apk` skip the backup.

## Layer 4 — server wiring

Inspect `python/src/android_re_mcp/server.py`:

- Every dex tool has a `TOOL_SCHEMAS` entry and an `_dispatch` entry.
- Required arguments in the schema match handler expectations (`dex_path`, `in_path`, `ops`, `class_name`, `apk_path`).
- Descriptions say the jar is required where it is.
- `guard.OUTPUT_SUFFIXES` covers `dex_convert`, `dex_patch`, `dex_assemble`, and `dex_swap` output keys.
- `guard.PATH_KEYS` includes `dex_path` and `in_path`.

Run the registry checker; it reports missing dispatch/schema pairs and dex-handler methods that do not exist.

## Layer 5 — behavior evidence

Run the targeted tests:

```bash
python <skill-dir>/scripts/run_audit_tests.py --repo . --groups dex
```

Or directly:

```bash
cd python && PYTHONPATH=src python -m pytest tests/test_dex_tools.py -v
```

Record:
- pass/fail/skip counts;
- whether `test_roundtrip_assemble_info_patch_convert` and `test_roundtrip_swap_into_apk` actually ran. If they skipped, say that the real jar was not exercised.
- the specific behaviors covered: missing-tool honesty, `.bak` discipline, ops validation, caps, default target selection, compression preservation, pure-Python `dex_swap`, guard path checks.

## Layer 6 — known behavioral claims

Cross-check the CHANGELOG's dexfile-cli bullets against code and tests:

- default convert target: vdex/cdex → 037, flat dex → 035, explicit override wins;
- odex instructions counted and noted;
- dex 041 containers split by `dex_extract`;
- `outline` subcommand supports `dex_read_class_outline`;
- patch/convert report `odex_instructions` when relevant;
- cdex write is deliberately not exposed.

Anything the changelog claims but no code/test supports is a finding (severity depends on how user-visible the claim is).

## What "works as intended" is allowed to mean

It is fair to conclude "the integration works in this environment" only when Layers 1–5 have evidence and the real-jar tests ran. It is not fair to conclude that every subcommand handles every malformed dex. Write the limitations explicitly: which jar version, which java, which tests ran, and what was not exercised.
