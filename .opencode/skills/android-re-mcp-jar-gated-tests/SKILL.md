---
name: android-re-mcp-jar-gated-tests
description: Manage tests that need dexfile-cli.jar, java, or a device. Use when adding or changing a test marked ROUNDTRIP or otherwise skipped without the jar, when a changelog or report quotes a passed/skipped count, or when asked whether jar-dependent behavior is really tested. Ensures each gated behavior has a jar-free sibling, reports skips per marker, and flags weak assertions in gated tests.
---

# Android RE MCP Jar-Gated Tests

`test_dex_tools.py` has a `ROUNDTRIP` marker that skips every jar-dependent
test when `dexfile-cli.jar` or `java` is absent. A green suite on a machine
without the jar therefore says nothing about those paths. This skill keeps
that from becoming a silent hole.

## Rules

1. **Every gated behavior needs a jar-free sibling.** The sibling uses
   `fake_run` and asserts the argv the handler builds; the gated test proves
   the jar's behavior, not the plumbing. See
   `android-re-mcp-passthrough-tests`.
2. **A skip is reported, not hidden.** A quoted test count must name the
   environment and the skip count.
3. **Gated assertions must be able to fail.** An assertion that holds whether
   the feature works or not is not coverage.

## Workflow

### 1. Inventory

```bash
repo=$(git rev-parse --show-toplevel)
python "$repo/.opencode/skills/android-re-mcp-jar-gated-tests/scripts/jar_gated_report.py" --repo "$repo"
```

This lists every test carrying `ROUNDTRIP`/`skipif`/`skip`, module-level skip
hazards, and weak-assertion candidates (`assert ... == "error"` near a
“proceeds”/`allow_ambiguous` comment).

### 2. Run both ways

```bash
repo=$(git rev-parse --show-toplevel)
python "$repo/.opencode/skills/android-re-mcp-jar-gated-tests/scripts/jar_gated_report.py" --repo "$repo" --run
```

`--run` executes pytest with the jar and with an empty temporary HOME
(`ANDROID_RE_MCP_TOOLS_DIR` pointed at an empty directory), and prints passed
and skipped counts for each. The no-jar run is the important one: every
`ROUNDTRIP` test should appear as skipped, never as passed. The with-jar run
should show zero skips for those tests.

Read the suite count from `pytest --collect-only` and the `-rs` summary rather
than trusting a hardcoded number. On the 2026-11-24 review host with the jar
and project extras, the suite collected 338 tests: 334 passed and 4 skipped
(quark-engine absent). Those skips are optional-tool skips, not `ROUNDTRIP`
tests; any quoted number is environment-specific.

### 3. Pair each gated test

For each `ROUNDTRIP` test, find the jar-free test that covers the same handler
path. The new `python/tests/test_dex_passthrough.py` covers the argv surface of the
seven flag-bearing CLI dex tools, so `dex_patch`/`dex_assemble`/`dex_split`/
`dex_merge`/`dex_validate` now have jar-free siblings; `dex_extract` and
`dex_read_class_outline` keep their path arguments in the round-trip tests. If a new gated test has no sibling, list it as a
gap and hand off to the passthrough skill.

### 4. Review the assertions

The 2026-11-24 audit flagged `test_roundtrip_era_pinned_write_api_override`:
an `allowed["status"] == "error"` under the comment “allow_ambiguous proceeds
past the guard” passed whether or not the flag worked. It now asserts the
specific “no API interpretation reads it” error and that the kind is not
`ambiguous_odex`; the actual `allow_ambiguous` path is exercised on the 20bc
fixture below. Use the report script to find any remaining candidates.

### 5. Report

Give a table of markers, test counts, and results with and without the jar,
followed by gaps and weak assertions. Do not present a no-jar run as proof of
jar behavior.

## CI suggestion

Run two jobs:

- without the jar: only jar-free tests run; print the skip count with `-rs`;
- with the jar built/downloaded from the pinned release: require every
  `ROUNDTRIP` test to run; fail if any skips, so a broken download cannot pass
  silently.

## References

- `scripts/jar_gated_report.py` — inventory and two-environment runner.
- `../../../python/tests/test_dex_passthrough.py` — jar-free argv siblings.
- `android-re-mcp-claim-verification` skill — count/coverage claims.
