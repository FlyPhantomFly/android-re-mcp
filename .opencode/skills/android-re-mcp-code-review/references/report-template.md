# Code review report template

Save as `reports/SUMMARY-YYYY-MM-DD.md`. Repeat the date in the title and metadata. Never overwrite a prior summary.

```
# Android RE MCP — Code Review — YYYY-MM-DD

Date: YYYY-MM-DD
Repository: <path>
Branch/HEAD: <branch @ short-sha, clean/dirty>
Scope: <diff, release, focused area>
Verdict: APPROVE | APPROVE WITH NITS | REQUEST CHANGES | BLOCK

## Summary

<3–6 bullets: what was reviewed, what blocks, what is fine.>

## Findings

### F-01 (<severity>, <confidence>): <title>

- Location: `<path:line>`
- Evidence: `<command or quoted code>`
- Impact: <what breaks or misleads>
- Fix: <smallest correct change>
- Status: open | fixed in this pass | declined (reason)

Repeat.

## Tests

- Targeted: `<command>` — <counts>
- Full: `<command>` — <counts>
- Skips: <which and why>
- Environment: <mcp version, extras>

## Changes made (only if authorized)

- `<path>` — <what changed and why>
- New/updated tests: <list>

## Verification

- Full suite: <passed/failed/skipped>
- Registry: <schemas/dispatch, issues>
- Test hygiene: <hazards>
- Release check: <issues/review>
- Live MCP: <checked or unavailable>

## Limitations

- <device/APK/network/dependency gaps>

## Push status

Not committed or pushed. The user decides when to push.

```
