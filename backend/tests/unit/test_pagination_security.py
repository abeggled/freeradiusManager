"""Keyset-Cursor und Session-Token."""

from __future__ import annotations

import pytest

from app.core.config import Settings
from app.core.errors import AuthenticationError
from app.core.pagination import clamp_limit, decode_cursor, encode_cursor
from app.core.ratelimit import RateLimiter
from app.core.security import create_session_token, principal_from_token
from app.models.mgr import Role


def test_cursor_roundtrip() -> None:
    assert decode_cursor(encode_cursor({"id": 4711})) == {"id": 4711}
    assert decode_cursor(None) is None
    assert decode_cursor("kein-cursor") is None


def test_limit_is_clamped() -> None:
    assert clamp_limit(None) == 50
    assert clamp_limit(0) == 50
    assert clamp_limit(10) == 10
    assert clamp_limit(10_000) == 200


def test_session_token_roundtrip() -> None:
    config = Settings(secret_key="test-secret", db_password="x")
    token, _ = create_session_token(7, "anna", Role.OPERATOR, "de", config=config)
    principal = principal_from_token(token, config=config)
    assert principal.account_id == 7
    assert principal.role is Role.OPERATOR
    assert principal.can_write and not principal.is_admin


def test_token_from_other_secret_is_rejected() -> None:
    token, _ = create_session_token(
        1, "anna", Role.AUDITOR, "de", config=Settings(secret_key="a", db_password="x")
    )
    with pytest.raises(AuthenticationError):
        principal_from_token(token, config=Settings(secret_key="b", db_password="x"))


def test_rate_limiter_blocks_after_limit() -> None:
    limiter = RateLimiter(limit=2, window_seconds=60)
    limiter.check("ip")
    limiter.check("ip")
    with pytest.raises(Exception) as excinfo:
        limiter.check("ip")
    assert "rate_limited" in str(excinfo.value)
    limiter.reset("ip")
    limiter.check("ip")
