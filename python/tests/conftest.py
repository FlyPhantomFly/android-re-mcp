import json
import os
from pathlib import Path

import pytest

from android_re_mcp.handlers.dex import DexHandler
from jar_gate import gated_skips


@pytest.fixture(autouse=True)
def isolated_env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_DATA_HOME", str(home / ".local" / "share"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    for var in ("ANDROID_RE_MCP_HOME", "ANDROID_RE_MCP_ALLOWED_DIRS", "ANDROID_RE_MCP_DISABLE_TOOLS",
                "ANDROID_RE_MCP_ALLOW_INSTALL", "ANDROID_RE_MCP_TOOLS_DIR", "ANDROID_RE_MCP_CONFIG",
                "ANDROID_RE_MCP_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    return home


@pytest.fixture
def fake_run(monkeypatch):
    """Fake the CLI runner: success with a canned result, recording argv + ops content.

    Shared by ``test_dex_tools.py`` and ``test_dex_passthrough.py`` so the
    argv contract can be tested without dexfile-cli.jar or Java.
    """
    calls = {}
    # The patch/convert handlers check the jar before side effects; a faked
    # _run alone would still hit the isolated HOME's empty tools dir.
    monkeypatch.setattr(
        DexHandler, "_require", staticmethod(lambda tool: ("/fake/dexfile-cli.jar", "/fake/java"))
    )

    def fake(tool, cli_args):
        calls["tool"] = tool
        calls["cli_args"] = cli_args
        calls["ops_json"] = None
        if "--ops" in cli_args:
            ops_file = cli_args[cli_args.index("--ops") + 1]
            calls["ops_json"] = json.loads(Path(ops_file).read_text())
        return {"status": "ok", "tool": tool, "result": {"out": "fake"}}

    monkeypatch.setattr(DexHandler, "_run", staticmethod(fake))
    return calls


def pytest_collection_modifyitems(config, items):
    """``ANDROID_RE_MCP_REQUIRE_JAR=1`` hard-fails collection when jar-gated
    tests would skip. CI's jar job sets it, so a stale pin or a broken
    download cannot pass silently; normal runs keep the plain skips.
    """
    if os.environ.get("ANDROID_RE_MCP_REQUIRE_JAR") != "1":
        return
    gated = gated_skips(items)
    if gated:
        raise pytest.UsageError(
            "ANDROID_RE_MCP_REQUIRE_JAR=1 but jar-gated tests would skip:\n  "
            + "\n  ".join(gated)
        )
