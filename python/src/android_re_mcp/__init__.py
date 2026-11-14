"""android-re-mcp (Python): dynamic Android analysis MCP server.

Derived from mobile-security-mcp 0.1.4 (MIT). See NOTICE.md in the repository.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("android-re-mcp")
except PackageNotFoundError:  # running from a source checkout
    __version__ = "0+local"
