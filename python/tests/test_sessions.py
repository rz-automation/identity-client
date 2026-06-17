"""Tests for the framework-neutral SessionPolicy.

These drive the session state machine with NO web framework -- just a
``FakeIdentity`` and plain dicts -- which is exactly how a non-FastAPI binding
(Flask, or another language's port mirroring this logic) would use it. The
FastAPI adapter is covered separately in test_fastapi.py.
"""
from __future__ import annotations

import time

from identity_client import IdentityUnavailable, SessionPolicy
from identity_client.testing import FakeIdentity


def _policy(identity, **kw) -> SessionPolicy:
    return SessionPolicy(identity, **kw)


def _claims(identity):
    # The shape new_session consumes: a verified access token's claims.
    return {"sub": identity.sub, "email": identity.email, "exp": int(time.time()) + 600}


def test_new_session_payload_shape():
    pol = _policy(FakeIdentity())
    data = pol.new_session({"sub": "u-1", "email": "a@b", "exp": 123, "is_admin": True}, "RT")
    assert data["uid"] == "u-1"
    assert data["rt"] == "RT"
    assert data["axp"] == 123
    assert data["adm"] is True
    assert data["iat"] == data["seen"]


def test_evaluate_none_is_unauthed():
    assert _policy(FakeIdentity()).evaluate(None) == (False, None)


def test_evaluate_live_session_passes_without_refresh():
    identity = FakeIdentity()
    pol = _policy(identity)
    data = pol.new_session(_claims(identity), "RT")
    authed, out = pol.evaluate(dict(data))
    assert authed is True
    assert out is not None
    # axp was fresh, so no refresh call was made.
    assert identity.refresh_calls == []


def test_evaluate_refreshes_when_stale():
    identity = FakeIdentity()
    pol = _policy(identity)
    data = pol.new_session(_claims(identity), "RT")
    data["axp"] = int(time.time()) - 1  # already expired -> must refresh
    authed, out = pol.evaluate(data)
    assert authed is True
    assert identity.refresh_calls == ["RT"]


def test_evaluate_fails_closed_when_refresh_raises():
    identity = FakeIdentity()
    identity.refresh_exc = IdentityUnavailable("identity down")
    pol = _policy(identity)
    data = pol.new_session(_claims(identity), "RT")
    data["axp"] = int(time.time()) - 1
    assert pol.evaluate(data) == (False, None)


def test_admin_only_demotion_ends_session_on_refresh():
    identity = FakeIdentity(admin=True)
    identity.refresh_admin = False  # demoted at refresh time
    pol = _policy(identity, admin_only=True)
    data = pol.new_session(_claims(identity), "RT")
    data["axp"] = int(time.time()) - 1
    assert pol.evaluate(data) == (False, None)


def test_out_of_bounds_absolute_lifetime():
    pol = _policy(FakeIdentity(), absolute_lifetime_seconds=100)
    data = {"rt": "RT", "iat": int(time.time()) - 200, "seen": int(time.time()), "axp": int(time.time()) + 600}
    assert pol.evaluate(data) == (False, None)


def test_idle_timeout_opt_out():
    # idle_timeout_seconds=None means only the absolute lifetime bounds it.
    pol = _policy(FakeIdentity(), idle_timeout_seconds=None)
    data = {"rt": "RT", "iat": int(time.time()), "seen": int(time.time()) - 99999, "axp": int(time.time()) + 600}
    authed, _ = pol.evaluate(data)
    assert authed is True
