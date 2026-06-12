"""Tests for the FastAPI delete-account flow + reconciler background task."""
from __future__ import annotations

import asyncio
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from identity_client import DeletionReconciler
from identity_client.fastapi import (
    IdentitySessions,
    auth_router,
    start_deletion_reconciler,
)
from identity_client.testing import FakeIdentity

_SECRET = b"k" * 32


def _build(identity: FakeIdentity, purged: list):
    sessions = IdentitySessions(identity, secret_key=_SECRET, cookie_secure=False)
    app = FastAPI()
    app.include_router(
        auth_router(sessions, on_account_deleted=purged.append),
        prefix="/api/auth",
    )
    c = TestClient(app)
    c._sessions = sessions  # type: ignore[attr-defined]
    return c


def _seed(client, *, uid="user-123", rt="RT"):
    now = int(time.time())
    data = {
        "uid": uid,
        "email": None,
        "rt": rt,
        "axp": now + 3600,
        "adm": True,
        "iat": now,
        "seen": now,
    }
    client.cookies.set("identity_session", client._sessions._serializer.dumps(data))


# --- delete-account routes ---------------------------------------------------


def test_challenge_requires_session():
    identity = FakeIdentity()
    client = _build(identity, [])
    r = client.post("/api/auth/delete-account/challenge")
    assert r.status_code == 401


def test_challenge_returns_nonce_for_session_user():
    identity = FakeIdentity(sub="user-123")
    client = _build(identity, [])
    _seed(client, uid="user-123")
    r = client.post("/api/auth/delete-account/challenge")
    assert r.status_code == 200
    assert r.json()["nonce"] == "N"
    # The challenge was requested for the session's own user id.
    assert identity.challenge_calls == ["user-123"]


def test_delete_account_relays_purges_and_clears_session():
    identity = FakeIdentity(sub="user-123")
    purged: list[str] = []
    client = _build(identity, purged)
    _seed(client, uid="user-123")
    r = client.post("/api/auth/delete-account", json={"credential": "reauth-token"})
    assert r.status_code == 200
    # Relayed the re-auth token for this user.
    assert identity.delete_calls == [("user-123", "reauth-token")]
    # Local purge ran for this user.
    assert purged == ["user-123"]
    # Session cookie cleared.
    assert "identity_session" in r.headers.get("set-cookie", "")


def test_delete_account_missing_credential_400():
    identity = FakeIdentity(sub="user-123")
    client = _build(identity, [])
    _seed(client, uid="user-123")
    r = client.post("/api/auth/delete-account", json={"credential": ""})
    assert r.status_code == 400


def test_delete_account_reauth_rejected_401_no_purge():
    from identity_client import AuthRejected

    identity = FakeIdentity(sub="user-123")
    identity.delete_exc = AuthRejected("nope")
    purged: list[str] = []
    client = _build(identity, purged)
    _seed(client, uid="user-123")
    r = client.post("/api/auth/delete-account", json={"credential": "bad"})
    assert r.status_code == 401
    assert purged == []  # nothing purged on a failed re-auth


def test_routes_absent_without_callback():
    """Without on_account_deleted the delete routes are not mounted."""
    identity = FakeIdentity()
    sessions = IdentitySessions(identity, secret_key=_SECRET, cookie_secure=False)
    app = FastAPI()
    app.include_router(auth_router(sessions), prefix="/api/auth")
    client = TestClient(app)
    client.cookies.set(
        "identity_session",
        sessions._serializer.dumps(
            {
                "uid": "u",
                "email": None,
                "rt": "RT",
                "axp": int(time.time()) + 3600,
                "adm": True,
                "iat": int(time.time()),
                "seen": int(time.time()),
            }
        ),
    )
    r = client.post("/api/auth/delete-account/challenge")
    assert r.status_code == 404  # route not registered


# --- reconciler background task ----------------------------------------------


def test_start_and_stop_reconciler_processes_a_page():
    identity = FakeIdentity()
    identity.deletion_pages = [
        {"deletions": [{"user_id": "u1", "seq": 1, "deleted_at": "t"}], "cursor": 1}
    ]
    purged: list[str] = []
    cursor = {"v": 0}
    rec = DeletionReconciler(
        identity,  # type: ignore[arg-type]
        on_user_deleted=purged.append,
        get_cursor=lambda: cursor["v"],
        set_cursor=lambda s: cursor.__setitem__("v", s),
    )

    async def _drive():
        handle = start_deletion_reconciler(
            rec, wait=0.0, retry_backoff=0.01, idle_sleep=0.01
        )
        # Give the loop a few ticks to drain the scripted page.
        for _ in range(50):
            if purged:
                break
            await asyncio.sleep(0.01)
        await handle.stop()

    asyncio.run(_drive())
    assert purged == ["u1"]
    assert cursor["v"] == 1
