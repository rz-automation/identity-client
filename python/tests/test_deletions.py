"""Tests for the GDPR-deletion client surface.

Covers:
  - DeletionReconciler: seq-order purge, cursor-after-success, high-watermark
    advance on a sparse/empty scoped page, and head-of-line block-and-alert on a
    failing purge.
  - IdentityClient.fetch_deletions / delete_user / request_deletion_challenge HTTP
    wiring (params, long-poll timeout, 401 -> AuthRejected).
"""
from __future__ import annotations

from typing import Any, Optional

import pytest

from identity_client import (
    AuthRejected,
    DeletionReconciler,
    IdentityClient,
    IdentityConfig,
)
from identity_client.testing import FakeIdentity


# --- a tiny recording HTTP stub (GET + POST) ---------------------------------


class _Resp:
    def __init__(self, json_data: Any, status: int = 200) -> None:
        self._json = json_data
        self.status_code = status

    def json(self) -> Any:
        return self._json


class _StubSession:
    """Records GET/POST calls and returns scripted responses."""

    def __init__(self, *, get_resp: Any = None, post_resp: Any = None) -> None:
        self._get_resp = get_resp
        self._post_resp = post_resp
        self.get_calls: list[dict[str, Any]] = []
        self.post_calls: list[dict[str, Any]] = []

    def get(self, url, headers=None, params=None, timeout=None):
        self.get_calls.append(
            {"url": url, "params": params, "timeout": timeout}
        )
        return self._get_resp

    def post(self, url, headers=None, json=None, timeout=None):
        self.post_calls.append({"url": url, "json": json, "timeout": timeout})
        return self._post_resp


def _client(session: _StubSession) -> IdentityClient:
    cfg = IdentityConfig(base_url="http://identity.test", service_credential="7.secret")
    return IdentityClient(cfg, session=session)  # type: ignore[arg-type]


# --- DeletionReconciler ------------------------------------------------------


class _Store:
    """In-memory cursor + purge log for reconciler tests."""

    def __init__(self) -> None:
        self.cursor = 0
        self.purged: list[str] = []
        self.fail_for: set[str] = set()

    def on_user_deleted(self, user_id: str) -> None:
        if user_id in self.fail_for:
            raise RuntimeError(f"purge failed for {user_id}")
        self.purged.append(user_id)

    def get_cursor(self) -> int:
        return self.cursor

    def set_cursor(self, seq: int) -> None:
        self.cursor = seq


def _reconciler(identity: FakeIdentity, store: _Store, on_blocked=None) -> DeletionReconciler:
    return DeletionReconciler(
        identity,  # type: ignore[arg-type]
        on_user_deleted=store.on_user_deleted,
        get_cursor=store.get_cursor,
        set_cursor=store.set_cursor,
        on_blocked=on_blocked,
        limit=100,
    )


def test_reconcile_empty_feed_no_purge():
    identity = FakeIdentity()
    store = _Store()
    n = _reconciler(identity, store).reconcile_page()
    assert n == 0
    assert store.purged == []
    assert store.cursor == 0


def test_reconcile_purges_in_seq_order_and_advances_cursor():
    identity = FakeIdentity()
    identity.deletion_pages = [
        {
            "deletions": [
                {"user_id": "u1", "seq": 1, "deleted_at": "t"},
                {"user_id": "u2", "seq": 2, "deleted_at": "t"},
            ],
            "cursor": 2,
        }
    ]
    store = _Store()
    n = _reconciler(identity, store).reconcile_page()
    assert n == 2
    assert store.purged == ["u1", "u2"]
    assert store.cursor == 2


def test_reconcile_empty_scoped_page_advances_to_watermark():
    """A page with no rows but a higher cursor still advances (no prefix rescan)."""
    identity = FakeIdentity()
    identity.deletion_pages = [{"deletions": [], "cursor": 17}]
    store = _Store()
    _reconciler(identity, store).reconcile_page()
    assert store.cursor == 17


def test_reconcile_blocks_on_failing_purge():
    identity = FakeIdentity()
    identity.deletion_pages = [
        {
            "deletions": [
                {"user_id": "u1", "seq": 1, "deleted_at": "t"},
                {"user_id": "bad", "seq": 2, "deleted_at": "t"},
                {"user_id": "u3", "seq": 3, "deleted_at": "t"},
            ],
            "cursor": 3,
        }
    ]
    store = _Store()
    store.fail_for = {"bad"}
    n = _reconciler(identity, store).reconcile_page()
    # u1 purged (cursor -> 1); blocked at seq 2; u3 never reached.
    assert n == 1
    assert store.purged == ["u1"]
    assert store.cursor == 1


def test_reconcile_block_alerts_on_repeated_failure():
    identity = FakeIdentity()
    page = {
        "deletions": [{"user_id": "bad", "seq": 5, "deleted_at": "t"}],
        "cursor": 5,
    }
    store = _Store()
    store.fail_for = {"bad"}
    alerts: list[tuple[int, int]] = []

    def on_blocked(seq, count, exc):
        alerts.append((seq, count))

    rec = _reconciler(identity, store, on_blocked=on_blocked)
    # First failure: logged, not yet a repeated alert.
    identity.deletion_pages = [dict(page)]
    rec.reconcile_page()
    assert alerts == []
    # Second failure of the same seq: repeated -> alert.
    identity.deletion_pages = [dict(page)]
    rec.reconcile_page()
    assert alerts == [(5, 2)]
    assert store.cursor == 0  # never advanced past the poison seq


def test_reconcile_recovers_after_block_clears():
    identity = FakeIdentity()
    store = _Store()
    store.fail_for = {"bad"}
    page = {"deletions": [{"user_id": "bad", "seq": 1, "deleted_at": "t"}], "cursor": 1}
    rec = _reconciler(identity, store)
    identity.deletion_pages = [dict(page)]
    rec.reconcile_page()
    assert store.cursor == 0
    # The purge starts succeeding; the same seq now goes through.
    store.fail_for = set()
    identity.deletion_pages = [dict(page)]
    rec.reconcile_page()
    assert store.purged == ["bad"]
    assert store.cursor == 1


# --- IdentityClient HTTP wiring ----------------------------------------------


def test_fetch_deletions_sends_params_and_longpoll_timeout():
    session = _StubSession(get_resp=_Resp({"deletions": [], "cursor": 3}))
    client = _client(session)
    out = client.fetch_deletions(3, limit=50, wait=25.0)
    assert out == {"deletions": [], "cursor": 3}
    call = session.get_calls[0]
    assert call["url"].endswith("/api/v1/deletions")
    assert call["params"] == {"since": 3, "limit": 50, "wait": 25.0}
    # Read timeout must exceed the wait so a long-poll is not cut off early.
    assert call["timeout"] > 25.0


def test_fetch_deletions_plain_poll_uses_request_timeout():
    session = _StubSession(get_resp=_Resp({"deletions": [], "cursor": 0}))
    client = _client(session)
    client.fetch_deletions(0)
    call = session.get_calls[0]
    assert "wait" not in call["params"]
    assert call["timeout"] == client.config.request_timeout


def test_fetch_deletions_401_raises_auth_rejected():
    session = _StubSession(get_resp=_Resp(None, status=401))
    client = _client(session)
    with pytest.raises(AuthRejected):
        client.fetch_deletions(0)


def test_delete_user_posts_token_and_path():
    session = _StubSession(post_resp=_Resp({"deleted": True}))
    client = _client(session)
    out = client.delete_user("user-xyz", "reauth-token")
    assert out == {"deleted": True}
    call = session.post_calls[0]
    assert call["url"].endswith("/api/v1/users/user-xyz/delete")
    assert call["json"] == {"google_id_token": "reauth-token"}


def test_delete_user_401_raises_auth_rejected():
    session = _StubSession(post_resp=_Resp(None, status=401))
    client = _client(session)
    with pytest.raises(AuthRejected):
        client.delete_user("user-xyz", "bad")


def test_request_challenge_posts_to_challenge_path():
    session = _StubSession(post_resp=_Resp({"nonce": "N", "expires_at": "x"}))
    client = _client(session)
    out = client.request_deletion_challenge("user-xyz")
    assert out["nonce"] == "N"
    assert session.post_calls[0]["url"].endswith(
        "/api/v1/users/user-xyz/delete-challenge"
    )
