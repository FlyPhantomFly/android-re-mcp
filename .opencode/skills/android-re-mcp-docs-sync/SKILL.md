---
name: android-re-mcp-docs-sync
description: Check that android-re-mcp README tool rows, schema descriptions, and CHANGELOG entries agree with the actual tool arguments. Use after any schema or handler change, before a release, or when asked whether the README documents every argument, whether table rows are well-formed, or whether the changelog mentions a change. Read-only; reports each gap with file and line. Complements android-re-mcp-release-check, which covers versions and counts.
---

# Android RE MCP Docs Sync

The README and changelog have drifted from the code twice in one session: a
changelog sentence said the MCP surface only gained `dex_convert`'s `api`, and
the README rows said “written verbatim” without the era-ambiguity guard. The
`b9f88fd` rewrite also joined “optional” clauses to the preceding text. This
skill checks the prose against the schemas.

## Run it

```bash
repo=$(git rev-parse --show-toplevel)
cd "$repo"
python scripts/check_docs_sync.py --repo .
python scripts/check_docs_sync.py --repo . --strict-review
python scripts/check_docs_sync.py --repo . --all-properties
python scripts/check_docs_sync.py --repo . --all-properties --ratchet scripts/docs_sync_ratchet.json
```

The checker is tracked at `scripts/check_docs_sync.py` so CI can run it; there
is no separate copy in this skill directory.

- Default: checks arguments added since the last git tag, plus the
  `api`/`era`/`allow_ambiguous`/`scan`/`allow_cdex`/`allow_unloadable`
  controls. This is the release-window audit and stays actionable.
- `--all-properties`: checks every schema property. The README is now
  argument-complete (0 failures at this revision).
- `--ratchet FILE`: combines with `--all-properties`; failures listed in the
  tracked JSON allowlist are reported as `ratchet-allowed`, while any new
  failure fails. The allowlist is empty, so this is the merge gate for new
  arguments.
- `--strict-review`: exit 1 for review items too. Hard failures already exit 1.

## What the script checks

| Check | Class | Rule |
| --- | --- | --- |
| Argument coverage | Fail | The tool's README row names each release-window property (or the property is exempt as a path/content/positional value) |
| Row shape | Fail | A table row has the same cell count as its header |
| Joined phrase | Review | “optional” is not separated from the preceding clause by punctuation |
| Verbatim claim | Review | A row claiming "verbatim" also mentions era/ambiguity |
| Changelog freshness | Fail | Under `[Unreleased]`, every property added since the last tag is named |
| Description drift | Review | A schema description names a `--flag` the handler never builds |

The script cannot tell whether the code or the docs are wrong. For each
finding, open the file and state both.

## Current status (2026-11-25)

The default and `--all-properties` checks are both clean after the README rows
were argument-completed; the ratchet allowlist is empty. Known non-issues:
`dex_info`'s description mentions `--setup` (an install command, filtered),
and `dex_read_pseudocode` mentions jadx's `--single-class` (not a handler
flag).

## Changelog comparison

The script uses `git describe --tags --abbrev=0 --match 'v[0-9]*'
--first-parent` and parses `TOOL_SCHEMAS` at that release tag. Local
non-release tags such as `review-baseline` are ignored. A property added after the tag must appear in the
`## [Unreleased]` block. If there is no tag or no Unreleased section, it
reports that instead of guessing. A shallow clone with no tags cannot run this
comparison; fetch tags (`git fetch --tags --unshallow`) before relying on it.

## Honesty rules

- A review item is not a failure; say whether you accept it or will fix it.
- Do not rename a README row to “fix” a checker false positive; fix the rule.
- This skill does not edit docs unless the user asks. Report first.

## References

- `scripts/check_docs_sync.py` — the tracked checker (repository root).
- `android-re-mcp-schema-check` skill — schema shape and handler drift.
- `android-re-mcp-release-check` skill — version/pin/count consistency.
