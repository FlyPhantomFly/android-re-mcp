"""Settings from the packaged defaults, overridden by the user's config file."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from android_re_mcp.paths import tools_dir, user_config_path

_DEFAULTS = Path(__file__).parent / "config.toml"


def _read(path: Path) -> dict:
    try:
        import tomllib
    except ImportError:  # Python < 3.11 is not supported, kept for safety
        return {}
    try:
        with open(path, "rb") as fh:
            return tomllib.load(fh)
    except (FileNotFoundError, PermissionError, ValueError):
        return {}


def load_config() -> dict[str, dict[str, Any]]:
    merged = _read(_DEFAULTS)
    for section, values in _read(user_config_path()).items():
        if isinstance(values, dict):
            merged.setdefault(section, {}).update(values)
    return merged


def signer_jar() -> Path:
    """Absolute path to uber-apk-signer. Never resolved against the working directory."""
    configured = str(load_config().get("signing", {}).get("jar_path", "") or "")
    if configured and Path(configured).is_absolute():
        return Path(configured)
    return tools_dir() / "signing" / "uber-apk-signer.jar"


_SIGNING_PASSWORD_KEYS = ("keystore_password", "key_password")


def config_permission_warning() -> str | None:
    """Warning text when the user config.toml is group/world-readable (R4-6).

    ``[signing]`` passwords live in plaintext there, so a file other local
    users can read exposes them. ``None`` when the file is absent, is
    readable only by its owner, or parses and holds no password.
    """
    path = user_config_path()
    if not path.is_file():
        return None
    try:
        mode = path.stat().st_mode & 0o777
    except OSError:
        return None
    if not mode & 0o044:  # no read bit for group or others
        return None
    try:
        import tomllib

        signing = tomllib.loads(path.read_text(encoding="utf-8")).get("signing", {})
    except (OSError, ValueError):
        signing = None  # cannot parse: warn anyway, the file may still hold secrets
    if signing is not None and not any(signing.get(k) for k in _SIGNING_PASSWORD_KEYS):
        return None
    return (
        f"{path} is group/world-readable (mode 0{mode:o}) and holds [signing] "
        "keystore passwords other local users can read. Fix: chmod 600 "
        f"{path} — note the passwords still reach uber-apk-signer as command-line "
        "arguments, visible to local users in the process list."
    )
