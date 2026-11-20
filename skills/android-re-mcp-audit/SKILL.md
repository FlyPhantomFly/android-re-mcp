---
name: android-re-mcp-audit
description: Independent, read-only audit of the android-re-mcp repository. Use whenever the user asks to audit, review, verify, sanity-check, or "check the claims" of android-re-mcp, especially after a batch of changes to dexfile-cli integration, the tool registry, guard, setup, or tests. Also use when the user asks whether dexfile-cli works, wants an audit log produced, or says "review everything" / "make sure there are no mistakes" without naming an audit. Produces a dated audit-Mon.Day.log with evidence-backed findings and adds it to .gitignore; never edits product code.
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
python <skill-dir>/scripts/preflight.py --repo .
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
python <skill-dir>/scripts/check_tool_registry.py --repo .
```

This catches schema entries with no dispatch target, dispatch targets with no schema, duplicate names, dex-handler methods that do not exist, `used_by` references to unknown tools, and guard suffix rules naming unknown tools. Treat any nonzero exit as a finding, not a nuisance.

Also check test hygiene:

```bash
python <skill-dir>/scripts/check_test_hygiene.py --repo .
```

A module-level `pytest.importorskip(...)` or `pytestmark = pytest.mark.skipif(...)` skips every test in the file, including tests that do not need that dependency. Report the file, the line, and how many test functions it suppresses; that is why a "6 skipped" summary can hide 30 unrun tests.

### 4. Collect test evidence

Run the fast, audit-specific groups first:

```bash
python <skill-dir>/scripts/run_audit_tests.py --repo .
```

Then run the full suite when time allows:

```bash
python <skill-dir>/scripts/run_audit_tests.py --repo . --full
```

The helper sets `PYTHONPATH=python/src` and runs pytest from `python/`. Run tests yourself if you need a traceback the summary omits. Never report a skipped test as a pass.

### 5. Dexfile-cli deep dive

Follow `references/dexfile-cli.md`. At minimum, prove:

- the pinned jar exists and its SHA-256 matches the pin;
- `java` is present and the jar runs;
- `check_tools` reports the entry and its `used_by` list is complete;
- every dex tool schema has a dispatch target and a handler;
- the dex tests that use the real jar actually ran rather than skipped;
- `dex_swap` works without the jar, because it is pure Python;
- in-place patch/swap backup discipline and zip compression preservation still hold.

### 6. Write the log and ignore it

Use `references/audit-log-template.md` as the skeleton. Put the log at the repo root with today's date:

```bash
python <skill-dir>/scripts/register_audit_log.py --repo . audit-Nov.18.log
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
