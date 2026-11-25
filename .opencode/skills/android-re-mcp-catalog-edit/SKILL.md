---
name: android-re-mcp-catalog-edit
description: Safe workflow for editing the android-re-mcp tool catalog. Use whenever the user asks to add, change, or remove a tool argument, add a new tool, or touch TOOL_SCHEMAS in server.py or a handler's args handling, including passthrough of flags such as api, era, allow_ambiguous, or scan to dexfile-cli. Enforces structural edits, a post-edit schema check, a handler-versus-schema key diff, and a test for every new argument. Not for read-only review; use android-re-mcp-audit for that.
---

# Android RE MCP Catalog Edit

A catalog edit touches three things that must stay in step: the schema in
`TOOL_SCHEMAS`, the handler that reads the arguments, and the tests and docs
that describe them. Drift fails silently: a client never sees an argument, or
sends one the handler drops.

## Rules

1. **Never insert by line number or by anchoring on a neighbouring line.**
   `required` sits outside `properties`; an insertion anchored there lands at
   the wrong nesting level. Edit by matching the whole property block, or load
   the structure and rewrite it with a JSON/AST-aware tool.
2. **Add the property to the schema, the handler and a test in the same
   change.** A property with no handler read is advertised and ignored. A
   handler read with no schema property is invisible to clients.
3. **Schema descriptions state behaviour, not intent.** If the handler
   refuses, say it refuses. Put the recovery path first (pin `era` before
   `allow_ambiguous`).
4. **A path/content argument still counts.** If it is positional rather than a
   flag, cover it in a round-trip or handler test and record it as exempt in
   the passthrough coverage set. Do not let “it is just a path” hide a dropped
   argument.

## Workflow

### 1. Snapshot

```bash
repo=$(git rev-parse --show-toplevel)
cd "$repo"
git status --short
python scripts/check_schema_structure.py --repo .
PYTHONPATH="$repo/python/src" python -m pytest python/tests/test_schema_structure.py python/tests/test_dex_passthrough.py -q
```

Record the schema count and the current drift. If the tree is dirty, say so;
the checks describe the working tree.

### 2. Make the edit

Change the schema property block, the handler's `args.get(...)` handling and
the argv it builds. Keep all three in one commit. For a new flag, check the
CLI help/jar accepts the exact spelling before wiring it.

### 3. Run the structural and argv checks

```bash
repo=$(git rev-parse --show-toplevel)
cd "$repo"
python scripts/check_schema_structure.py --repo .
PYTHONPATH="$repo/python/src" python -m pytest python/tests/test_schema_structure.py python/tests/test_dex_passthrough.py -q
```

Every structural failure blocks. Review every drift line; a new
`schema_not_read` or `read_not_in_schema` entry is usually the bug you just
introduced.

### 4. Prove the argument reaches the handler

For each new argument, add a case to `python/tests/test_dex_passthrough.py`:

- set the argument and assert the matching flag/fragment appears in the
  `fake_run` argv;
- omit it and assert the flag is absent;
- add it to `EXEMPT` only if it is a path/content/positional value covered by a
  different test, and say where.

The coverage guard fails when a covered tool grows an untested property. If
the tool is new, add it to `BASE` or to `OUT_OF_SCOPE` with a reason.

### 5. Sync the docs

```bash
repo=$(git rev-parse --show-toplevel)
cd "$repo"
python scripts/check_docs_sync.py --repo .
```

The README row for the tool must name every argument added since the last tag
(plus the era/ambiguity controls), and the `[Unreleased]` changelog block must
name every added schema property. Both are hard failures now. Fix prose only
when asked; otherwise report the gap.

### 6. Report

List what changed in each of the three places, the checker output and the
named tests that cover the change. Do not claim a behaviour is “locked” unless
a named test exercises it.

## Honesty rules

- If the checker cannot run, say so; do not report it as passing.
- A jar-gated test that skipped did not prove anything. Say it skipped.
- Do not push unless the user asks.

## References

- `android-re-mcp-schema-check` skill — structural and handler drift checks.
- `android-re-mcp-passthrough-tests` skill — jar-free argv coverage.
- `android-re-mcp-docs-sync` skill — README/changelog sync.
- `android-re-mcp-claim-verification` skill — verify the final report.
- `android-re-mcp-audit` skill — read-only follow-up if the checks reveal wider drift.
