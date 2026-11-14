# Contributing
Bug reports, new detection patterns and new tools are all welcome. For anything bigger than a small fix, open an issue first so we can agree on the approach.

## Setting up
```bash
git clone https://github.com/FlyPhantomFly/mobile-re-mcp.git
cd mobile-re-mcp
python -m venv .venv && . .venv/bin/activate
pip install -e "python[dev]"
ruff check python && pytest python/tests
```
The Python server needs Python 3.11 or newer. `ruff format python` is the formatter; CI runs ruff check and pytest on 3.11 and 3.13.

## How the Python server is laid out
`python/src/android_re_mcp/server.py` owns the tool list: every tool has a schema entry and a dispatch entry. The work happens in `python/src/android_re_mcp/handlers/` — one module per area (`static.py` for apktool/androguard/apkleaks/quark, `dynamic.py` for Frida, `network.py` for mitmproxy, `device.py` for adb, and so on). Shared helpers live beside them: `paths.py` (scratch/data folders), `guard.py` (path validation), and `apkscan.py` (the zero-dependency APK byte-scanning machinery: size caps, printable strings, the pattern scanner).

## Adding a tool
1. Create or extend a handler module and add a method that takes `args: dict` and returns `{"status": ..., "tool": ..., "output": ...}` (`ok` / `error` / `missing_tool`).
2. Register the method in `server.py`: the `TOOLS` schema list and the dispatch mapping.
3. Add a row to the tools table in `README.md` and a line to `CHANGELOG.md`.

Return structured JSON, degrade honestly (a missing section reports the real reason), and never raise past the handler. If the tool wraps an external program, check it with `shutil.which` and return `missing_tool` with a hint pointing at `android-re-mcp --setup`; build argument arrays, never shell strings; validate every path with the guard (absolute, exists, inside an allowed dir).

If the tool parses the output of another program, add a fixture under `python/tests/fixtures/` taken from the real program and a test beside it. The manifest analyzer once read `aapt` output wrongly and called a bad APK clean, which is why those tests exist.

## Adding a detection pattern
Secret scanning (`apk_scan_secrets`) runs [apkleaks](https://github.com/dwisiswant0/apkleaks) with its own rule set; the zero-dependency scanners carry their pattern tables beside the tool that uses them — `_SECRET_PATTERNS` in `python/src/android_re_mcp/handlers/apkdiff.py` (the `apk_diff` secret deltas) and `_GOOGLE_PATTERNS` in `python/src/android_re_mcp/handlers/googleservices.py`. Add an entry there:
```python
("My Service API Key", re.compile(r"my-service-[A-Za-z0-9]{32}"), "HIGH"),
```
Risk is one of `HIGH`, `MEDIUM` or `LOW`. To teach the native-library identification about a known library (packer, RASP, framework, SDK or runtime), add a row to `_KNOWN_ANDROID_LIBS` in `python/src/android_re_mcp/handlers/native.py` with a pattern, a label and a kind.

## Pull requests
Keep each one to a single change, say what changed and why, and run `ruff check python` and `pytest python/tests` first. If you can, try the change on a real APK, and leave sensitive details out of what you paste. Add a line to `CHANGELOG.md`.

## Releasing
This part is for maintainers. The package is published from GitHub Actions through PyPI trusted publishing (OIDC), so no PyPI token is stored in GitHub. For the first release, add a pending publisher on pypi.org under Your account, Publishing (project `android-re-mcp`, owner `FlyPhantomFly`, repository `mobile-re-mcp`, workflow `publish-pypi.yml`, environment `pypi`). In GitHub, create the `pypi` environment under Settings, Environments, and add yourself as a required reviewer.

For every release:
1. Update `CHANGELOG.md` and set the `version` in `python/pyproject.toml`. Commit and push.
2. Tag it (`git tag vX.Y.Z && git push origin vX.Y.Z`) and create a GitHub Release for the tag.
3. The release starts `publish-pypi.yml`. Approve the deployment when GitHub asks. The workflow refuses to publish if the tag does not match `pyproject.toml`, and building distributions is part of the workflow itself.

## Reporting issues
Use the issue templates for bugs and feature requests. Security problems go through [SECURITY.md](SECURITY.md), not a public issue.
