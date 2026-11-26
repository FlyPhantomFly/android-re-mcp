---
name: android-re-mcp-audit
description: Independent, read-only audit of the android-re-mcp repository. Use whenever the user asks to audit, review, verify, sanity-check, or "check the claims" of android-re-mcp, especially after a batch of changes to dexfile-cli integration, the tool registry, guard, setup, or tests — including the newer dex_validate, dex_merge, and cdex opt-in tools. Also use when the user asks whether dexfile-cli works, wants an audit log produced, or says "review everything" / "make sure there are no mistakes" without naming an audit. Produces a dated audit-Mon.Day.log with evidence-backed findings and adds it to .gitignore; never edits product code.
---

# Android RE MCP Audit

Turn "audit android-re-mcp" into a repeatable, evidence-first review. The deliverable is a dated log another engineer can trust, not a patch. Stay read-only: if the user also wants fixes, finish the audit first and ask before changing source.

## What a good audit output looks like

- A log at the repository root named `audit-<Mon>.<Day>.log` (for example `audit-Nov.18.log`).
- Every finding has a file path and line, the command that exposed it, and a severity plus confidence.
- Pass/fail counts come from real commands, not impressions.
- Code defects, test-harness issues, and missing-environment issues are separated explicitly.
- `.gitignore` contains the log filename, and no product source changed.

## Workflow

### 0. Locate the repo and take a snapshot

Run the preflight helper (it locates the repo, records git state, checks java/jar/pytest, and reads the live `check_tools` entry for dexfile-cli):

```bash
repo=$(git rev-parse --show-toplevel)
python "$repo/.opencode/skills/android-re-mcp-audit/scripts/preflight.py" --repo "$repo"
```

Keep the JSON as evidence. If the repo has uncommitted changes, say so in the log: an audit of a dirty tree describes that tree, not `HEAD`.

### 1. Read the claim surface

Read these before judging the code:

- `README.md` — tool tables, counts, install/setup claims.
- `CHANGELOG.md` — the newest entry and the "Unreleased" section.
- `python/pyproject.toml` — version, extras, dependency pins, test config.
- `CONTRIBUTING.md` / `SECURITY.md` — stated conventions.
- `python/src/android_re_mcp/server.py` — `TOOL_SCHEMAS`, `_dispatch`, resources/prompts.
- `python/tests/` — what the tests claim to cover.

A claim is not a fact until the code or a command supports it. Note the gap when it does not.

### 2. Static review

Use `references/checklist.md`. Read it section by section; skip a section only after noting why it does not apply. Focus first on the modules changed by the release being audited, then on the guard and setup paths because they affect every tool.

### 3. Check the tool registry for drift

```bash
repo=$(git rev-parse --show-toplevel)
python "$repo/.opencode/skills/android-re-mcp-audit/scripts/check_tool_registry.py" --repo "$repo"
python "$repo/scripts/check_schema_structure.py" --repo "$repo"
PYTHONPATH="$repo/python/src" python -m pytest "$repo/python/tests/test_schema_structure.py" "$repo/python/tests/test_dex_passthrough.py" -q
```

This catches schema entries with no dispatch target, plus structural schema
strays and handler/argv drift (the new checks; see `android-re-mcp-schema-check`
and `android-re-mcp-passthrough-tests`)., dispatch targets with no schema, duplicate names, dex-handler methods that do not exist, `used_by` references to unknown tools, and guard suffix rules naming unknown tools. Treat any nonzero exit as a finding, not a nuisance.

Also check test hygiene:

```bash
repo=$(git rev-parse --show-toplevel)
python "$repo/.opencode/skills/android-re-mcp-audit/scripts/check_test_hygiene.py" --repo "$repo"
```

A module-level `pytest.importorskip(...)` or `pytestmark = pytest.mark.skipif(...)` skips every test in the file *when that dependency is absent*, including tests that do not need it. Report the file, the line, and how many test functions it would suppress; that is why a "6 skipped" summary can hide 30 unrun tests. These are structural hazards even on a fully provisioned host where nothing skips today.

### 4. Collect test evidence

Run the fast, audit-specific groups first:

```bash
repo=$(git rev-parse --show-toplevel)
python "$repo/.opencode/skills/android-re-mcp-audit/scripts/run_audit_tests.py" --repo "$repo"
```

Then run the full suite when time allows:

```bash
repo=$(git rev-parse --show-toplevel)
python "$repo/.opencode/skills/android-re-mcp-audit/scripts/run_audit_tests.py" --repo "$repo" --full
```

The helper sets `PYTHONPATH=python/src` and runs pytest from `python/`. Run tests yourself if you need a traceback the summary omits. Never report a skipped test as a pass.

### 4.5 Verify the live MCP surface (when available)

If the `android-re` MCP namespace is connected, call `check_tools` through it and confirm the dexfile-cli entry is available. Compare the exposed tool count with `TOOL_SCHEMAS` minus `guard.disabled_tools()` — at 1.8.0 that is 89 schemas and 88 exposed tools because `install_tool` is off by default. This proves the running server matches the source; a clean pytest run alone does not. If the namespace is not connected, skip this step and say so in the log.

### 5. Dexfile-cli deep dive

Follow `references/dexfile-cli.md`. At minimum, prove:

- the pinned jar exists and its SHA-256 matches the pin (read the pin from code; it moves every few releases — v0.2.2 at the time of this review);
- `java` is present and the jar runs;
- `check_tools` reports the entry and its `used_by` list covers every jar-dependent `DexHandler` method;
- every dex tool schema has a dispatch target and a handler, including `dex_validate` and `dex_merge`;
- the dex tests that use the real jar actually ran rather than skipped;
- `dex_validate` reports unknown references and truncation honestly, `dex_merge` detects class collisions, and cdex output is refused unless the caller opts in with `allow_unloadable=true`;
- `dex_swap` works without the jar, because it is pure Python;
- in-place patch/swap backup discipline and zip compression preservation still hold.

Tool and test counts change across releases (89 tools at 1.8.0). Read them from the code and the live test run; never carry an old number into a new audit.

### 6. Write the log and ignore it

Use `references/audit-log-template.md` as the skeleton. Put the log at the repo root with today's date:

```bash
repo=$(git rev-parse --show-toplevel)
python "$repo/.opencode/skills/android-re-mcp-audit/scripts/register_audit_log.py" --repo "$repo" audit-Nov.18.log
```

Then verify:

```bash
git status --short
git check-ignore -v audit-Nov.18.log
```

Only `.gitignore` should be modified. If the user wants source fixes, propose them separately after the audit is delivered.

## Severity and confidence

| Severity | Meaning |
| --- | --- |
| Critical | Security bypass, data loss, or a tool that silently produces wrong results in normal use. |
| High | A core tool is broken for normal use, or a documented claim is materially false. |
| Medium | An important edge case, misleading output, or a test/CI gap that hides regressions. |
| Low | Messages, docs, observability, or cosmetic inconsistency. |

Label confidence as **confirmed** (a command proves it), **inferred** (code reading only), or **unverified** (needs a device, APK, or dependency not available here).

## Honesty rules

- "Skipped" is not "passed"; count it separately and say why.
- Distinguish environment problems from code defects. For example, a missing `androguard` (`[static]` extra) makes manifest-dependent tests fail, and an `mcp` SDK version mismatch can break `test_server.py`; neither proves a dexfile-cli regression.
- Passing tests prove the tested paths, not every edge case. Put untested areas in a limitations section.
- On failure, include the exact assertion or traceback line, not just "test failed".
- If a claim cannot be checked in this environment, write that down instead of guessing.

## Common traps

- `pytest` from `python/` needs `PYTHONPATH=src`; the bundled helpers set it for you.
- Run the helpers with the interpreter that has the project extras (`/path/to/venv/bin/python`). A bare `python` may be the system interpreter without androguard/capstone/keystone, which turns a healthy tree into a wall of skips and `mcp`-version failures.
- The full suite needs optional extras for some tests (`[static]` for androguard). Missing extras are environment findings.
- `test_server.py` drives a real MCP stdio session; a mismatch between the installed `mcp` package and the test expectations shows up as client/pydantic errors, not a handler crash.
- `check_tools` probes many binaries and is slow; that is normal, not a hang.
- The log date in the existing convention is `Mon.Day` with no zero padding (`Nov.18`), not an ISO timestamp.
- Adding the log to `.gitignore` is allowed; changing product code is not.

## References

- `references/checklist.md` — repo-specific static review checklist.
- `references/dexfile-cli.md` — dexfile-cli audit protocol and expected signals.
- `references/audit-log-template.md` — log skeleton to copy and fill.
- `scripts/preflight.py` — environment, git, jar/SHA, pin-vs-message, hint, and live `check_tools` evidence.
- `scripts/check_tool_registry.py` — AST checks for schema/dispatch/`used_by` drift.
- `scripts/check_test_hygiene.py` — finds module-level skips that hide unrelated coverage.
- `scripts/run_audit_tests.py` — targeted and full pytest runs with JSON summaries.
- `scripts/register_audit_log.py` — adds the log filename to `.gitignore` without duplication.
  **This writes the tracked `.gitignore`**: the audit's only allowed repo change is that
  one line — say so in the log, and expect the `.gitignore` diff to be part of the run.
