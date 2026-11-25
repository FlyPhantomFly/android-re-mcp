---
name: android-re-mcp-release-check
description: Pre-release consistency check for android-re-mcp. Use whenever the user asks whether the repo is ready to tag or release, wants the version, CHANGELOG, README, and pyproject to agree, asks to verify the dexfile-cli pin matches the installer message and the installed jar, or wants a claimed test count reconciled with the suite that actually collects. Produces a short release-readiness report and never edits product code.
---

# Android RE MCP Release Check

A fast, read-only consistency check before a release. It is narrower than the full audit skill: it checks release metadata and count drift, not handler behavior. If it finds a behavioral concern, hand off to `android-re-mcp-audit`.

## Workflow

### 1. Run the checker

```bash
repo=$(git rev-parse --show-toplevel)
python "$repo/.opencode/skills/android-re-mcp-release-check/scripts/release_check.py" --repo "$repo"
```

It reads versions from `python/pyproject.toml` and the top `CHANGELOG.md` entry, tool counts from `README.md` and `server.py`, the dexfile-cli pin and installer message from `setup/install_tool.py`, and compares the topmost "Suite N passed + M skipped" line (case-insensitive, `now` optional) with what pytest collects here. The Unreleased line wins over historical summaries.

### 2. Inspect every issue

For each issue, open the file and line the checker names. Do not fix code; report what is wrong and what the right value should be. If you need proof beyond metadata (for example, a tool that claims to exist but is not wired), run the registry and preflight helpers from `android-re-mcp-audit`.

### 3. Report

Use the structure in `references/release-report-template.md`. Keep it short: a verdict, a checks table, the issues, and caveats. Do not create a log file unless the user asks; if they do, name it `release-check-<Mon>.<Day>.log` and add it to `.gitignore`.

## Verdicts

- **READY** — no issues; only review items, if any.
- **NEEDS ATTENTION** — one or more Low/Medium issues that should be fixed before tagging.
- **BLOCKED** — the pyproject version and the top CHANGELOG version disagree, or the pinned jar and the installed jar disagree.

## Honesty rules

- A test-count mismatch is a *review item*, not automatically a bug. Missing optional extras and module-level `pytest.importorskip` calls can suppress collection; state exactly what was collected here and why the claim may differ.
- A README that mentions several tool counts is fine as long as one of them matches the live schema count; do not force a single number.
- The installer message must name the version in the pin URL, not a previous release.
- The installed jar's SHA-256 must match the pin, otherwise the release artifact is unverified.
- If a check cannot run (missing pytest, unreadable file), say so rather than guessing.

For schema shape, handler passthrough and per-argument README/changelog drift, run the sibling `android-re-mcp-schema-check` and `android-re-mcp-docs-sync` skills; this checker covers release metadata and counts only.

## References

- `scripts/release_check.py` — the read-only metadata/count checker.
- `references/release-checklist.md` — the manual checklist for items a script cannot prove.
- `references/release-report-template.md` — the short report skeleton.
- `android-re-mcp-audit` skill — the full audit, for behavioral follow-up.
