---
name: android-re-mcp-claim-verification
description: Verify a written claim about android-re-mcp work, such as a status report, commit message, changelog entry, or a statement that something was fixed, pushed, tested, or proven. Use whenever the user pastes a summary and asks to evaluate, verify, or fact-check it, or asks whether tests really lock a behavior. Extracts each checkable assertion, matches it to a commit, a file line, or a named test, and rates it confirmed, partly confirmed, unverifiable, or contradicted. Read-only.
---

# Android RE MCP Claim Verification

A claim about a repo is not evidence. This skill turns a sentence such as
“the test locks it end to end” into a table of assertions, each tied to a
commit, a file line, a named test, or a reproduced count. The deliverable is a
dated report plus a JSON/live-proof artifact, not a patch.

## Workflow

### 1. Extract the assertions

Split the claim into single statements and tag each:

- **state** — commit hash, clean tree, pushed, release tag;
- **change** — what was fixed and where;
- **count** — schemas, tools, tests passed/skipped;
- **coverage** — “locks”, “covers”, “proves”, “verified”;
- **artifact** — a validator, log, or “output above”.

### 2. Collect evidence

```bash
repo=$(git rev-parse --show-toplevel)
cd "$repo"
python .opencode/skills/android-re-mcp-claim-verification/scripts/claim_context.py \
  --repo . \
  --claim-file reports/<claim>.md \
  --artifact reports/artifacts/<name>-<date>.json \
  --run-tests
```

The collector records the HEAD/upstream state, commit existence and stats, the
schema audit, collected test IDs, the full suite summary when `--run-tests` is
used, coverage statements, and weak-assertion candidates. It never edits code.

Save live-proof output next to it, for example:

```bash
python -m pytest python/tests/test_dex_tools.py -q -k era_pinned \
  > reports/artifacts/era-live-proof-<date>.txt 2>&1
```

`reports/` is intentionally gitignored; the artifact lives in the checkout but
is not committed. Say that explicitly. If the user wants a versioned artifact,
put it under a tracked docs path and update `.gitignore` deliberately.

### 3. Match coverage statements to named tests

For every “locks / covers / proves” sentence, answer:

1. Which tool(s) and argument(s) does the named test actually invoke?
2. Does the assertion distinguish working from broken behavior, or does it
   pass on both outcomes?
3. Is the test gated (jar, device, optional dependency), so it silently skips
   in the environment that matters?
4. Does the claim say “end to end” when the test covers one of several paths?

A test that only asserts `status == "error"` under a comment saying
“allow_ambiguous proceeds” is a weak assertion, not coverage of the flag.

### 4. Rate and report

Use **Confirmed**, **Partly confirmed** (state what is missing),
**Unverifiable** (state what evidence would settle it), and **Contradicted**
(cite the contradiction). Lead with a one-line verdict, then a table of
assertions, ratings and evidence, then gaps and follow-ups.

## Worked example (2026-11-24 report)

The report `reports/android-re-mcp_Audit_Verification_of_the_MCP_era_ambiguity_Claim.md`
was verified as follows:

| Assertion | Rating |
| --- | --- |
| HEAD `a1b48d6`, clean, pushed | Confirmed at the time |
| Strays introduced in `49fa0a5`, fixed in `b9f88fd` | Confirmed from the diffs |
| 89 schemas, 0 structural problems | Confirmed with the committed checker |
| `dex_merge` dropped `era`/`allow_ambiguous` | Confirmed |
| `dex_patch`/`dex_assemble`/`dex_validate` missing flags | Confirmed |
| README/changelog updated | Mostly confirmed; punctuation was wrong |
| `dex_info` `scan` was “missing” | Contradicted in detail — it shipped earlier |
| Structural validator in the repo | Was false; now addressed by `scripts/check_schema_structure.py` |
| Regression tests for the fixes | Was false; now addressed by `test_dex_passthrough.py` |
| “Locks it end to end” | Overstated; the jar test covered convert/info only |
| Live proof in the repo | Was false; artifacts now captured under `reports/artifacts/` |
| 239 passed + 2 skipped at `a1b48d6` | Reproduced; the current tree is 275 passed + 2 skipped after the new checks |

The report was largely accurate. The skill's value is naming the exact parts
that were overstated and showing which gaps have since been closed.

## Honesty rules

- Never rate a count as confirmed unless it was reproduced here. Say why it
  could not be (no pytest, no jar, no network).
- A skipped test is not a pass.
- Credit what is accurate; most claims are mostly right.
- Distinguish overstatement (wording stronger than the evidence) from error
  (the code is wrong).
- Do not fix code or docs unless asked.

## References

- `scripts/claim_context.py` — evidence collector.
- `android-re-mcp-jar-gated-tests` skill — skip accounting.
- `android-re-mcp-schema-check` skill — schema counts and drift.
- `android-re-mcp-code-review` skill — general review workflow.
