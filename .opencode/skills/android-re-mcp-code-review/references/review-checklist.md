# Code review checklist — android-re-mcp

Review the change, not the whole repo, unless the user asks for a full audit. Use `android-re-mcp-audit` for that.

## 1. Scope and intent

- [ ] The diff does what the commit message/PR claims, and nothing unrelated.
- [ ] New behavior has a test; fixed behavior has a regression test.
- [ ] Docs (README/CHANGELOG) and schema descriptions match the code, not the intent.

## 2. Wiring and contracts

- [ ] Every new tool has a `TOOL_SCHEMAS` entry, an `_dispatch` target, and a real handler method.
- [ ] Required schema arguments match handler access; defaults are not contradicted by handler logic.
- [ ] `check_tools` `used_by` lists every tool that depends on the new binary/jar/module.
- [ ] `guard.PATH_KEYS`, `WRITE_KEYS`, and `OUTPUT_SUFFIXES` cover new paths and output types.
- [ ] Error paths return `ok`/`error`/`missing_tool` honestly; no uncaught exceptions.

## 3. Behavior and edge cases

- [ ] Inputs are validated before side effects (no backup/temp file before a missing-tool check).
- [ ] Subprocess calls use argv lists, timeouts, and bounded output.
- [ ] Temp files are private and cleaned up in `finally`.
- [ ] Multi-file operations detect collisions/duplicates and report the real cause.
- [ ] Caps/truncation preserve honest totals and name the narrowing knob.

## 4. Tests

- [ ] Targeted tests pass; live/gated tests either ran or are explicitly skipped with a reason.
- [ ] Full suite passes in the corrected environment (`mcp>=1.30,<2` plus extras).
- [ ] New failure modes have a test (missing jar, bad input, expected-hash mismatch, collision).
- [ ] No new module-level `pytest.importorskip`/`pytestmark` hides unrelated tests.
- [ ] Skips are counted separately from passes.

## 5. Security and safety

- [ ] Path arguments are absolute, guarded, and cannot escape allowed dirs.
- [ ] Zip operations refuse zip-slip and guard META-INF.
- [ ] Byte patches require an expected value and write a `.bak` exactly once.
- [ ] No shell string interpolation; no secrets in logs or reports.

## 6. Release metadata

- [ ] `pyproject.toml`, top `CHANGELOG.md`, README counts, and the dexfile-cli pin agree.
- [ ] Installed jar SHA-256 matches the pin.
- [ ] The claimed suite count matches a run in the documented environment.
- [ ] `reports/` is ignored; the report filename carries the run date.

## 7. Finding quality

- [ ] Each finding has file:line, evidence, impact, severity, confidence, and a fix.
- [ ] Findings distinguish code defects, environment issues, and test-harness issues.
- [ ] The verdict follows the rubric: APPROVE / APPROVE WITH NITS / REQUEST CHANGES / BLOCK.
