"""
Unit tests for app.config.resolve_cookie_secure -- the fix for Safari login
failing over plain HTTP (dev / docker-compose / phone-on-LAN testing).
Pure function, no DB, no FastAPI app needed.
"""
from app.config import resolve_cookie_secure


def test_development_defaults_to_not_secure():
    # This is the actual bug: over plain HTTP, Safari silently refuses to
    # store a Secure cookie, so login looked fine but the session never stuck.
    assert resolve_cookie_secure("development") is False


def test_production_defaults_to_secure():
    assert resolve_cookie_secure("production") is True


def test_environment_is_case_insensitive():
    assert resolve_cookie_secure("PRODUCTION") is True
    assert resolve_cookie_secure("Development") is False


def test_unknown_environment_falls_back_to_not_secure():
    # Anything that isn't explicitly "production" should fail safe toward
    # "cookie actually gets set", not toward "login silently breaks".
    assert resolve_cookie_secure("staging") is False
    assert resolve_cookie_secure("") is False


def test_explicit_override_wins_over_environment():
    assert resolve_cookie_secure("production", override="false") is False
    assert resolve_cookie_secure("development", override="true") is True


def test_override_is_case_insensitive_and_whitespace_tolerant():
    assert resolve_cookie_secure("development", override=" True ") is True
    assert resolve_cookie_secure("production", override=" FALSE ") is False


def test_empty_override_is_ignored_not_treated_as_false():
    assert resolve_cookie_secure("production", override="") is True
    assert resolve_cookie_secure("production", override=None) is True
