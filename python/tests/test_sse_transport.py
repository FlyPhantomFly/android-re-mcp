"""Round-4 SSE-transport tests (R4-2 bearer auth, R4-3 allowed hosts).

The bearer check must be a byte-level constant-time comparison that
answers 401 (False) instead of raising for non-UTF-8 or non-ASCII
input, and a wildcard bind must not pin the Host allow-list to an
address no remote client can use. Jar-free: scope dicts and helper
calls only, no live server.
"""

from __future__ import annotations

from android_re_mcp.server import _bearer_ok, _check_auth_header, _sse_transport_settings


def _http_scope(auth_header: bytes) -> dict:
    return {"type": "http", "headers": [(b"authorization", auth_header), (b"host", b"127.0.0.1")]}


# ── R4-2: bearer auth is byte-safe and never raises ──────────────────────

def test_correct_ascii_token_accepted():
    assert _check_auth_header(_http_scope(b"Bearer tok123"), "tok123") is True


def test_wrong_token_refused():
    assert _check_auth_header(_http_scope(b"Bearer wrong"), "tok123") is False


def test_missing_authorization_header_refused():
    assert _check_auth_header({"type": "http", "headers": []}, "tok123") is False


def test_non_utf8_header_refused_not_raised():
    # v1.9.0 raised UnicodeDecodeError here (500 instead of 401)
    assert _check_auth_header(_http_scope(b"Bearer \xff\xfe\xfd"), "tok123") is False


def test_non_ascii_token_accepted_when_header_matches():
    # v1.9.0 raised TypeError even for the CORRECT token (str compare_digest)
    token = "tökøn"
    assert _check_auth_header(_http_scope(f"Bearer {token}".encode("utf-8")), token) is True


def test_non_ascii_token_refused_when_header_differs():
    token = "tökøn"
    assert _check_auth_header(_http_scope("Bearer tokøn".encode("utf-8")), token) is False


def test_non_utf8_single_byte_encoding_refused():
    # the expected value is encoded as UTF-8; a latin-1 (single-byte)
    # encoding of the same token is not accepted — clients must send UTF-8
    assert _bearer_ok(b"Bearer caf\xe9", "caf\xe9") is False


def test_empty_token_disables_auth():
    assert _check_auth_header(_http_scope(b"Bearer anything"), "") is True
    assert _check_auth_header({"type": "http", "headers": []}, "") is True


def test_lifespan_scope_without_headers_is_not_authenticated():
    # v1.9.0 gated on scope["type"] == "http"; the helper keeps that gate
    assert _check_auth_header({"type": "lifespan"}, "tok123") is True
    assert _check_auth_header({"type": "lifespan", "headers": None}, "tok123") is True


def test_bearer_ok_handles_all_manners_of_garbage():
    for garbage in (b"", b"x", b"Bearer", b"Bearer ", b"\x00" * 64, b"Bearer \x80\x81"):
        assert isinstance(_bearer_ok(garbage, "tok"), bool)
    assert _bearer_ok(b"Bearer tok", "tok") is True
    assert _bearer_ok(b"Bearer \x80\x81", "tok") is False


# ── R4-3: the Host allow-list follows the bind address ───────────────────

def test_loopback_bind_keeps_exact_host_list():
    settings = _sse_transport_settings("127.0.0.1", loopback=True)
    assert settings.allowed_hosts == ["127.0.0.1:*", "localhost:*", "[::1]:*"]
    assert settings.enable_dns_rebinding_protection is True
    assert settings.allowed_origins == ["http://127.0.0.1:*", "http://localhost:*"]


def test_specific_non_loopback_bind_pins_its_own_host():
    settings = _sse_transport_settings("192.168.1.5", loopback=False)
    assert settings.allowed_hosts == ["127.0.0.1:*", "localhost:*", "[::1]:*", "192.168.1.5:*"]


def test_wildcard_bind_skips_the_host_check():
    for host in ("0.0.0.0", "::"):
        settings = _sse_transport_settings(host, loopback=False)
        # v1.9.0 pinned f"{host}:*", so a client arriving via the LAN IP got 421;
        # mcp has no any-host wildcard, so the check itself is disabled instead
        assert settings.enable_dns_rebinding_protection is False
        assert settings.allowed_hosts == []
