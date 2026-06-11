"""Tests for the optional FastAPI integration (identity_client.fastapi).

Drives the whole login / refresh / gate chain through a real FastAPI app with a
``FakeIdentity`` (no network, no real provider): login, the user vs admin gate,
fail-closed refresh, the idle/absolute bounds, logout, and the admin-only login
policy.
"""
from __future__ import annotations

import time

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from identity_client.fastapi import (
    IdentitySessions,
    IdentityUser,
    auth_router,
    require_admin,
    require_user,
)
from identity_client.testing import FakeIdentity

_SECRET = b"k" * 32
_GATED_USER = "/protected/user"
_GATED_ADMIN = "/protected/admin"


def _build(identity: FakeIdentity, *, admin_only: bool = False) -> TestClient:
    sessions = IdentitySessions(
        identity,
        secret_key=_SECRET,
        cookie_secure=False,  # TestClient speaks http://
        admin_only=admin_only,
    )
    app = FastAPI()
    app.include_router(auth_router(sessions), prefix="/api/auth")

    user_dep = require_user(sessions)
    admin_dep = require_admin(sessions)

    @app.get(_GATED_USER)
    def user_route(user: IdentityUser = Depends(user_dep)):
        return {"id": user.id, "is_admin": user.is_admin}

    @app.get(_GATED_ADMIN)
    def admin_route(user: IdentityUser = Depends(admin_dep)):
        return {"id": user.id}

    c = TestClient(app)
    c._sessions = sessions  # type: ignore[attr-defined]
    return c


def _seed(client, *, axp=None, iat=None, seen=None, admin=True, rt="RT"):
    now = int(time.time())
    data = {
        "uid": "user-123",
        "email": "u@e",
        "rt": rt,
        "axp": axp if axp is not None else now + 3600,
        "adm": admin,
        "iat": iat if iat is not None else now,
        "seen": seen if seen is not None else now,
    }
    client.cookies.set("identity_session", client._sessions._serializer.dumps(data))


def _login(client) -> None:
    r = client.post("/api/auth/login", json={"credential": "google-id-token"})
    assert r.status_code == 200, r.text


# --- login -------------------------------------------------------------------


def test_login_admits_any_user_and_sets_session():
    identity = FakeIdentity(admin=False)  # a regular, non-admin account
    client = _build(identity)
    _login(client)
    assert identity.sign_in_calls == ["google-id-token"]
    r = client.get(_GATED_USER)
    assert r.status_code == 200
    assert r.json()["is_admin"] is False


def test_login_without_credential_is_400():
    client = _build(FakeIdentity())
    assert client.post("/api/auth/login", json={"credential": ""}).status_code == 400


def test_protected_route_requires_session():
    client = _build(FakeIdentity())
    assert client.get(_GATED_USER).status_code == 401


def test_auth_config_exposes_client_id():
    identity = FakeIdentity()
    client = _build(identity)
    r = client.get("/api/auth/auth-config")
    assert r.status_code == 200
    assert r.json()["google_client_id"] == identity.google_cid


# --- user vs admin gate ------------------------------------------------------


def test_require_admin_denies_non_admin_but_allows_admin():
    # non-admin: user route ok, admin route 403
    nonadmin = _build(FakeIdentity(admin=False))
    _login(nonadmin)
    assert nonadmin.get(_GATED_USER).status_code == 200
    assert nonadmin.get(_GATED_ADMIN).status_code == 403

    # admin: both ok
    admin = _build(FakeIdentity(admin=True))
    _login(admin)
    assert admin.get(_GATED_ADMIN).status_code == 200


# --- admin_only login policy -------------------------------------------------


def test_admin_only_login_refuses_non_admin_and_discards_token():
    identity = FakeIdentity(admin=False)
    client = _build(identity, admin_only=True)
    r = client.post("/api/auth/login", json={"credential": "google-id-token"})
    assert r.status_code == 403
    assert identity.logout_calls == ["RT"]  # just-issued token revoked
    assert client.get(_GATED_USER).status_code == 401  # no session


def test_admin_only_login_admits_admin():
    client = _build(FakeIdentity(admin=True), admin_only=True)
    _login(client)
    assert client.get(_GATED_ADMIN).status_code == 200


# --- refresh: kill-switch + fail-closed --------------------------------------


def test_stale_token_is_refreshed_and_admitted():
    identity = FakeIdentity(admin=True)
    client = _build(identity)
    _seed(client, axp=int(time.time()) - 5)
    assert client.get(_GATED_USER).status_code == 200
    assert identity.refresh_calls == ["RT"]


def test_refresh_failure_fails_closed():
    from identity_client import AuthRejected

    identity = FakeIdentity(admin=True)
    identity.refresh_exc = AuthRejected("disabled")
    client = _build(identity)
    _seed(client, axp=int(time.time()) - 5)
    assert client.get(_GATED_USER).status_code == 401


def test_admin_only_demotion_on_refresh_ends_session():
    identity = FakeIdentity(admin=True)
    identity.refresh_admin = False  # demoted at refresh
    client = _build(identity, admin_only=True)
    _seed(client, axp=int(time.time()) - 5)
    assert client.get(_GATED_USER).status_code == 401


def test_non_admin_only_demotion_keeps_user_but_drops_admin():
    # Without admin_only, a demotion does not end the session; the user stays
    # signed in but admin routes start refusing.
    identity = FakeIdentity(admin=True)
    identity.refresh_admin = False
    client = _build(identity)
    _seed(client, axp=int(time.time()) - 5, admin=True)
    assert client.get(_GATED_USER).status_code == 200
    assert client.get(_GATED_ADMIN).status_code == 403


# --- lifetime bounds ---------------------------------------------------------


def test_idle_timeout_ends_session():
    client = _build(FakeIdentity())
    _seed(client, seen=int(time.time()) - 12 * 3600 - 10)
    assert client.get(_GATED_USER).status_code == 401


def test_absolute_lifetime_ends_session():
    client = _build(FakeIdentity())
    _seed(client, iat=int(time.time()) - 7 * 24 * 3600 - 10)
    assert client.get(_GATED_USER).status_code == 401


# --- logout + session report -------------------------------------------------


def test_logout_revokes_and_reports_unauthed():
    identity = FakeIdentity()
    client = _build(identity)
    _login(client)
    assert client.get("/api/auth/session").json()["authenticated"] is True
    assert client.post("/api/auth/logout").status_code == 200
    assert identity.logout_calls and identity.logout_calls[-1] == "RT"
    assert client.get("/api/auth/session").json()["authenticated"] is False


def test_session_reports_false_on_refresh_failure():
    from identity_client import AuthRejected

    identity = FakeIdentity()
    identity.refresh_exc = AuthRejected("disabled")
    client = _build(identity)
    _seed(client, axp=int(time.time()) - 5)
    assert client.get("/api/auth/session").json()["authenticated"] is False


# --- config guard ------------------------------------------------------------


def test_requires_exactly_one_secret_source():
    with pytest.raises(ValueError):
        IdentitySessions(FakeIdentity())  # neither secret_key nor secret_path
    with pytest.raises(ValueError):
        IdentitySessions(FakeIdentity(), secret_key=_SECRET, secret_path="/tmp/x")


def test_construction_does_no_filesystem_io(tmp_path):
    # A secret_path whose parent dir does not exist yet: constructing the manager
    # must not touch the filesystem (the dir may only be mounted at runtime).
    target = tmp_path / "not-created-yet" / "secret"
    sessions = IdentitySessions(FakeIdentity(), secret_path=target)
    assert not target.parent.exists()  # no I/O at construction
    # The key is loaded/created lazily on first use.
    _ = sessions._serializer
    assert target.exists()
