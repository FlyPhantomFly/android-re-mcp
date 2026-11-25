# Audit log template

Copy this skeleton into `audit-<Mon>.<Day>.log` at the repository root. Delete sections that genuinely do not apply and say why, rather than filling them with filler.

```
ANDROID RE MCP — Independent Code Audit (Full)
==============================================
Date: YYYY-MM-DD
Auditor: <name / agent>
Repository: <absolute path or repo name>
Tree: <branch @ short-sha, dirty/clean>
Version (pyproject): <version>
Scope: <modules/release/batch reviewed>

-----------------------------------------------------------------------------
1) EXECUTIVE SUMMARY
-----------------------------------------------------------------------------
<3–7 bullets. Lead with the audited question, then the verdict.
State explicitly whether the primary question (for example dexfile-cli
integration) is verified, partially verified, or blocked.
Include full-suite counts if run.>

-----------------------------------------------------------------------------
2) SCOPE AND METHODOLOGY
-----------------------------------------------------------------------------
In scope:
- <files/modules>
Methods:
- <static review, commands run, tests run, environment checks>
Out of scope / not performed:
- <devices, real APKs, network transports, etc.>

-----------------------------------------------------------------------------
3) ENVIRONMENT AND EVIDENCE
-----------------------------------------------------------------------------
- Python: <version>
- Java: <version>
- tools_dir: <path>
- dexfile-cli.jar: <path> sha256=<actual> expected=<expected> match=<yes/no>
- pytest: <version>
- Optional extras present: <androguard, capstone, ...>
- Git state: <branch @ sha, dirty files>
Commands run:
- <command> → <result summary>

-----------------------------------------------------------------------------
4) ARCHITECTURE AND STATIC REVIEW
-----------------------------------------------------------------------------
Repository layout, server wiring, handler boundaries, guard, paths, setup.
Only claim what was inspected. Reference file:line.

-----------------------------------------------------------------------------
5) DEXFILE-CLI DEEP DIVE
-----------------------------------------------------------------------------
Layer 1 pin/artifact:
Layer 2 discovery/check_tools:
Layer 3 handler plumbing:
Layer 4 server wiring and guard:
Layer 5 behavior evidence:
Layer 6 changelog claims:
Verdict and limitations:

-----------------------------------------------------------------------------
6) TEST RESULTS
-----------------------------------------------------------------------------
Command:
- <command>
Counts: <passed> passed, <skipped> skipped, <failed> failed in <time>
Failures:
- <test id> — <exact failure line> — cause category: code/environment/test harness
Skipped:
- <test id> — reason
Notable passes (especially real-jar roundtrips):
- <test id>

-----------------------------------------------------------------------------
7) FINDINGS
-----------------------------------------------------------------------------
F-01 (<severity>, <confidence>): <one-line title>
  Location: <path:line>
  Evidence: <command or quoted code>
  Impact: <what breaks or misleads>
  Recommendation: <fix or next check>

Repeat for each finding. Use "Info" for neutral observations.

-----------------------------------------------------------------------------
8) RECOMMENDATIONS
-----------------------------------------------------------------------------
R-01 <action tied to a finding>
R-02 ...

-----------------------------------------------------------------------------
9) LIMITATIONS
-----------------------------------------------------------------------------
- <what could not be proven here, and why>
- <tests that skipped>
- <device/network/dependency gaps>

-----------------------------------------------------------------------------
10) CONCLUSION
-----------------------------------------------------------------------------
<What was verified. What remains uncertain. Whether code was modified
(should be "no" for this skill). Artifact path.>

End of audit.
```
