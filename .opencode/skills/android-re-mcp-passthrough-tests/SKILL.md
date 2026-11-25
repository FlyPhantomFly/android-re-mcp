---
name: android-re-mcp-passthrough-tests
description: Write and maintain jar-free tests that prove each MCP tool argument reaches the dexfile-cli argv. Use whenever a dex_* tool gains, loses, or renames an argument (api, era, allow_ambiguous, scan, allow_cdex and similar), when a handler is suspected of dropping an advertised argument, or when asked for passthrough or argv tests. Uses the shared fake_run fixture; never needs dexfile-cli.jar.
---

# Android RE MCP Passthrough Tests

The schema can advertise an argument the handler never reads, and a handler
can build a flag the schema never exposes. `python/tests/test_dex_passthrough.py`
closes that gap in milliseconds, with no jar and no device.

## Run it

```bash
repo=$(git rev-parse --show-toplevel)
cd "$repo"
PYTHONPATH="$repo/python/src" python -m pytest python/tests/test_dex_passthrough.py -q
PYTHONPATH="$repo/python/src" python -m pytest python/tests/test_schema_structure.py python/tests/test_dex_passthrough.py -q
```

## How it works

- `python/tests/conftest.py` defines `fake_run`: it patches
  `DexHandler._require` and `_run`, records `tool`, `cli_args` and parsed ops
  JSON, and returns a canned success. The same fixture serves
  `test_dex_tools.py`.
- `BASE` holds minimal valid arguments for each CLI-facing dex tool.
- `CASES` is one row per covered schema property:
  `(tool, argument, value, argv fragment)`.
- `test_argument_reaches_argv` sets the argument and asserts the fragment.
- `test_omitted_argument_emits_no_flag` calls the base arguments and asserts
  the flag is absent, catching both dropped passthrough and accidental
  always-on flags.
- `test_every_covered_schema_property_is_tested_or_exempt` fails when a covered
  tool grows a property with no case.
- `test_every_dex_tool_is_classified` fails when a new `dex_*` tool is neither
  in `BASE` nor in `OUT_OF_SCOPE` with a reason.

Current coverage includes `api` → `--api`, `era` → `--era`,
`allow_ambiguous` → `--allow-ambiguous-odex`, `scan` → `--scan`,
`allow_cdex` → `--allow-cdex`.

## Adding a case

1. Add the schema property and handler passthrough first (see
   `android-re-mcp-catalog-edit`).
2. Add a `CASES` row with a value and the exact fragment the handler builds.
   If the argument only takes effect with a companion (for example `limit`
   needs `classes`), add the companion to the base or extend the case model
   rather than writing a misleading “omitted” assertion.
3. Run the two parametrized tests and the coverage guard.
4. Prove the test can fail: temporarily delete the passthrough line, run the
   suite, confirm exactly that case fails, then restore the line. Report the
   mutation check; a test that passes either way is not coverage.

## Scope

The file covers the CLI-facing dex tools that route through `DexHandler._run`.
`dex_read_pseudocode` drives jadx directly, `dex_swap` is a pure-Python zip
rewrite, and `dex_extract`/`dex_read_class_outline` are covered by their
round-trip tests; `OUT_OF_SCOPE` names each with a reason. When a new dex tool
appears, classify it.

## Caveats

- `dex_convert` reads `in_path` only; the old undocumented `dex_path` fallback
  is gone. Keep it that way.
- A handler may resolve keys through a shared helper; the schema checker
  attributes helper reads to callers by helper name, so the argv test remains
  the stronger proof for the final flag.
- These tests prove the argv contract, not the jar's behavior. Keep the
  jar-gated round-trip tests for that.
