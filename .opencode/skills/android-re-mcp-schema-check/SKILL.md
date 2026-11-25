---
name: android-re-mcp-schema-check
description: Structural and passthrough check of the android-re-mcp tool catalog. Use whenever TOOL_SCHEMAS in server.py or a handler's argument handling changed, or when asked to verify that tool schemas are well-formed, that every advertised argument is actually read by its handler, or that no schema has stray keys outside properties. Read-only; reports findings with tool names. Complements android-re-mcp-audit, which checks schema-to-dispatch pairing.
---

# Android RE MCP Schema Check

This is the committed guard for the failure class in commit `49fa0a5`: three
schemas put `era`/`allow_ambiguous` beside `properties` instead of inside it,
and a `dex_merge` handler advertised arguments it never read. The structural
validator was a throwaway script; it now lives in the repo and runs in CI.

## Run it

From anywhere inside the checkout, with any Python 3.11+ interpreter:

```bash
repo=$(git rev-parse --show-toplevel)
cd "$repo"
python scripts/check_schema_structure.py --repo .
PYTHONPATH="$repo/python/src" python -m pytest python/tests/test_schema_structure.py -q
```

The checker needs neither `dexfile-cli.jar` nor the `mcp` SDK; it parses
`server.py` and the handlers with `ast`.

## What it checks

| Check | Class | Meaning |
| --- | --- | --- |
| Stray `inputSchema` key | Structural, exit 1 | A property sits beside `properties`, so clients never see it |
| `required` not in `properties` | Structural, exit 1 | Clients are told to send an argument the schema does not define |
| Property without type/enum/$ref/combinator | Structural, exit 1 | Under-specified argument |
| Array without `items` | Structural, exit 1 | Clients cannot build a valid value |
| Duplicate tool name | Structural, exit 1 | Ambiguous dispatch |
| Schema property the handler never reads | Drift, review | Advertised but ignored |
| Handler `args.get(...)`/`args[...]` key not in schema | Drift, review | Works only if a caller guesses it |

Drift is review-only by default so the checker can report a catalog that is
still being repaired. The current catalog is clean; `--strict-drift` turns a
non-empty drift list into exit 1, and CI runs it that way.

## Known review items at 2026-11-24

None. The drift list is real findings only:

- `dex_convert`'s `dex_path` fallback was removed (the schema always
  required `in_path`).
- `frida_spawn_hluda` `config` and `frida_memdump` `max_range_mb` gained
  schema properties.
- `native_map_address`/`native_patch_string`/`native_patch_instructions`
  gained the `abi` property they already read through `_load_so`.
- Keys read through args-consuming helpers (`_load_so`) are attributed to
  the caller, so helper resolution no longer produces false positives.

`test_real_catalog_has_no_handler_schema_drift` keeps the drift list at
zero; a new mismatch in either direction fails CI.

## CI

`python/tests/test_schema_structure.py` loads this script, compares the AST
schema count with `TOOL_SCHEMAS`, asserts the real catalog has no structural
problems, and runs synthetic catalogs through the checker so the checker
itself cannot rot. No jar needed.

## Honesty rules

- A review item is not a pass; say which you reviewed and why it is acceptable.
- If the checker cannot run, report that instead of “no findings”.
- Do not call drift “locked” unless a named test exercises it.

## References

- `scripts/check_schema_structure.py` — tracked checker at the repository root.
- `python/tests/test_schema_structure.py` — synthetic and real-catalog tests.
- `android-re-mcp-passthrough-tests` skill — proves the arguments reach argv.
- `android-re-mcp-audit` skill — schema-to-dispatch and wider registry audit.
