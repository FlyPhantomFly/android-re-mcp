---
name: android-re-mcp-code-review
description: Code review for android-re-mcp changes. Use when the user asks for a code review, a review before merge/push, a review of the current diff or latest release, or a dated review summary. Inspects the working tree and recent commits, runs the existing audit and release checks, records findings with file:line and severity, and writes reports/SUMMARY-YYYY-MM-DD.md with the run date in the filename and title. Read-only unless the user explicitly asks for fixes; never pushes.
---

# Android RE MCP Code Review

A review is not a summary of the diff. It is a judgment about whether the change is correct, safe, tested, and consistent with the rest of the repo. The deliverable is a dated report under `reports/`, not a patch — unless the user explicitly asks you to fix what you find.

## Workflow

### 1. Snapshot the change

```bash
repo=$(git rev-parse --show-toplevel)
python "$repo/.opencode/skills/android-re-mcp-code-review/scripts/review_context.py" --repo "$repo"
```

Keep the JSON. It records the branch, HEAD, working-tree status, staged/unstaged/untracked files, diffstat, and recent commits. A review of a dirty tree describes that tree; say so.

### 2. Run the standing checks

Run these with the project venv interpreter that has the declared extras (for example `/path/to/venv/bin/python`). A bare `python` may be the system interpreter without androguard/capstone/keystone, which turns a healthy tree into false skips and `mcp`-version failures.

Use the other skills rather than inventing new probes: run the
`android-re-mcp-audit` skill for preflight, registry, test-hygiene and the full
audit, the `android-re-mcp-schema-check` skill for schema shape/drift, and the
`android-re-mcp-release-check` skill for release metadata.

```bash
repo=$(git rev-parse --show-toplevel)
PYTHONPATH="$repo/python/src" python -m pytest "$repo/python/tests/test_schema_structure.py" "$repo/python/tests/test_dex_passthrough.py" -q
```

If the `android-re` MCP namespace is connected, call `check_tools` and compare the exposed tool count with `TOOL_SCHEMAS` minus `guard.disabled_tools()`.

### 3. Review the change

Read `references/review-checklist.md`. Focus on the changed files first, then on the contracts they touch: the schema/dispatch pair, guard path and suffix rules, `check_tools` `used_by`, tests, and docs. For every finding record:

- `file:line`
- what is wrong and the impact
- the evidence (command output, test, or quoted code)
- severity and confidence
- the smallest correct fix

Do not report style preferences as defects. Do not call a test failure a code bug until you have separated code, environment, and test-harness causes.

### 4. Write the dated report

Use `references/report-template.md`. Name the file with the run date:

```
reports/SUMMARY-YYYY-MM-DD.md
```

The title and metadata must repeat the date. Every future report gets its own dated filename; never overwrite an earlier summary.

Ensure the directory is ignored:

```bash
repo=$(git rev-parse --show-toplevel)
python "$repo/.opencode/skills/android-re-mcp-code-review/scripts/ensure_reports_ignored.py" --repo "$repo"
```

### 5. Fixes (only when asked)

If the user asks you to make the changes:

1. Fix only findings you agree with, and say why for any you decline.
2. Add or update a test for each behavioral fix.
3. Run the targeted tests, then the full suite, then the registry/test-hygiene/release checks again.
4. Update the same dated report with a **Changes made** and **Verification** section.
5. Do not commit or push. Report back with the exact test counts and the remaining risks; the user decides when to push.

## Verdicts

- **APPROVE** — no blocking findings; only informational notes.
- **APPROVE WITH NITS** — Low findings or documentation drift that do not block.
- **REQUEST CHANGES** — a Medium/High correctness, security, or test-coverage finding.
- **BLOCK** — data loss, security bypass, or a release artifact that cannot be trusted.

## Honesty rules

- "Skipped" is not "passed"; report skips separately.
- A green suite in a corrected environment does not erase latent test-hygiene hazards; distinguish active failures from structural risks.
- A finding without a file:line or a command is an opinion, not a review result.
- If the change cannot be exercised (no device, no APK, no network), write that in limitations.
- Never push, tag, or publish as part of a review.

## References

- `references/review-checklist.md` — what to inspect in this repo.
- `references/report-template.md` — dated report skeleton.
- `scripts/review_context.py` — git/diff context collector.
- `scripts/ensure_reports_ignored.py` — adds `reports/` to `.gitignore` without duplication.
  **This writes the tracked `.gitignore`**: running it leaves a diff on a versioned file,
  which is expected — mention it in the report instead of reverting it silently.
- `android-re-mcp-audit` skill — deep audit, dexfile-cli protocol, registry/test-hygiene checks.
- `android-re-mcp-release-check` skill — version/pin/count consistency.
