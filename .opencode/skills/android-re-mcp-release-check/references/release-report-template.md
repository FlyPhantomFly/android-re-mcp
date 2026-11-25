# Release check report template

```
Android RE MCP — Release Check
===============================
Date: YYYY-MM-DD
Version: <pyproject version> / CHANGELOG <top version>
Repository: <path @ sha, clean/dirty>

VERDICT: READY | NEEDS ATTENTION | BLOCKED

CHECKS
- Version agreement: <consistent / mismatch>
- Tool count: README <numbers> / server.py <count>
- dexfile-cli pin: <version>, SHA-256 <match/mismatch>, installed jar <path>
- Installer message: <version> (<match/mismatch> with pin)
- Suite count: CHANGELOG claims <N>; collected here <M>; hidden by module skips <K>

ISSUES
- I-01 (<severity>): <title>
  Location: <path:line>
  Evidence: <command or code>
  Correct value: <what it should be>

REVIEW ITEMS
- R-01: <item that is environment-dependent and needs a full environment to confirm>

CAVEATS
- <extras missing, mcp version mismatch, etc.>

No product code was modified.
```
