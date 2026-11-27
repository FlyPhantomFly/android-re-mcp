"""Round-4 config-permission tests (R4-6).

The user config.toml holds [signing] keystore passwords in plaintext;
the server warns at startup when that file is group- or
world-readable. Jar-free: everything here uses files in tmp_path.
"""

from __future__ import annotations

import logging
import os

import pytest

from android_re_mcp.config import config_permission_warning


@pytest.fixture()
def config_path(tmp_path, monkeypatch):
    """A temp user config path, registered via ANDROID_RE_MCP_CONFIG."""
    p = tmp_path / "config.toml"
    monkeypatch.setenv("ANDROID_RE_MCP_CONFIG", str(p))
    return p


def _write(p, body):
    p.write_text(body, encoding="utf-8")


_PASSWORD_BODY = '[signing]\nkeystore_path = "/tmp/ks.jks"\nkeystore_password = "s3cret"\n'


def test_no_warning_when_file_absent(config_path):
    assert config_permission_warning() is None


def test_owner_only_file_is_silent(config_path):
    _write(config_path, _PASSWORD_BODY)
    os.chmod(config_path, 0o600)
    assert config_permission_warning() is None


def test_world_readable_file_with_password_warns(config_path):
    _write(config_path, _PASSWORD_BODY)
    os.chmod(config_path, 0o644)
    msg = config_permission_warning()
    assert msg is not None
    assert "world-readable" in msg
    assert str(config_path) in msg
    assert "chmod 600" in msg
    assert "command-line" in msg  # the argv exposure is stated, not just the file mode


def test_group_readable_file_warns(config_path):
    _write(config_path, _PASSWORD_BODY)
    os.chmod(config_path, 0o640)
    assert config_permission_warning() is not None


def test_readable_file_without_password_is_silent(config_path):
    _write(config_path, '[signing]\nkeystore_path = "/tmp/ks.jks"\n')
    os.chmod(config_path, 0o644)
    assert config_permission_warning() is None


def test_unparseable_readable_file_still_warns(config_path):
    _write(config_path, "this is not = toml = [")
    os.chmod(config_path, 0o644)
    assert config_permission_warning() is not None


def test_key_password_alone_triggers_the_warning(config_path):
    _write(config_path, '[signing]\nkey_password = "s3cret"\n')
    os.chmod(config_path, 0o604)
    assert config_permission_warning() is not None


def test_create_server_logs_the_warning(config_path, caplog):
    from android_re_mcp.server import create_server

    _write(config_path, _PASSWORD_BODY)
    os.chmod(config_path, 0o644)
    with caplog.at_level(logging.WARNING, logger="android_re_mcp.server"):
        create_server()
    assert any("world-readable" in r.message for r in caplog.records)
