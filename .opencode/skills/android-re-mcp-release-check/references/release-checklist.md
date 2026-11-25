# Release-check manual checklist

The script catches metadata drift. These items need a human or the full audit skill.

- [ ] The git tag you plan to push matches `python/pyproject.toml` and the top `CHANGELOG.md` entry.
- [ ] `CHANGELOG.md` has an entry for every user-visible change in the release, including new/deleted tools and pin bumps.
- [ ] `README.md` tool tables and counts match `TOOL_SCHEMAS`; new tools have rows with honest "needs" columns.
- [ ] New tools have a schema entry, a dispatch target, a real handler, and (if they write files) guard path/suffix rules.
- [ ] `check_tools` `used_by` lists cover every dependency added by the release; run `check_tool_registry.py` from the audit skill.
- [ ] If the `android-re` MCP server is live, its exposed tool count equals `TOOL_SCHEMAS` minus `guard.disabled_tools()`, and `check_tools` reports the new dependencies as available.
- [ ] The dexfile-cli pin, installer success message, README, and CHANGELOG all name the same version; installed jar SHA-256 matches the pin.
- [ ] `CHANGELOG.md`'s suite count was produced in an environment with the declared extras and a compatible `mcp` version. If not, the entry says so.
- [ ] Run `check_test_hygiene.py` from the audit skill: no new module-level `importorskip` hides unrelated tests.
- [ ] No stale numbers remain from the previous release (old tool counts, old pin versions, old "suite now" lines quoted as current).
- [ ] `--setup` docs still list every downloaded artifact the release needs.
