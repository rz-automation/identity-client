"""Test doubles and crypto helpers for services integrating with identity.

Import these in your OWN test suite so you do not have to re-derive a fake
identity client or hand-roll RSA token signing. None of this is needed at
runtime; it depends on ``cryptography`` (already pulled in by ``PyJWT[crypto]``).

  * ``FakeIdentity`` -- a drop-in stand-in for ``IdentityClient`` with no network
    and no real Google. Drive your login / refresh / gate code through admin /
    non-admin and refresh-time demotion, and assert on the recorded calls.
  * ``generate_keypair`` / ``jwk_for`` / ``make_token`` / ``FakeHTTP`` -- mint real
    RS256 tokens and serve a fake JWKS, to test ``AccessTokenVerifier`` wiring or
    a gate that verifies tokens for real.
"""

from __future__ import annotations

import json
import time
from typing import Any, Optional

import jwt
import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm


class FakeIdentity:
    """Stand-in for ``IdentityClient``: no network, no real Google.

    ``sign_in`` mints access token ``'AT'``; ``refresh`` mints ``'AT2'``;
    ``verify`` returns claims derived from the configured flags so a consumer's
    login / refresh / gate code can be exercised through admin / non-admin and
    refresh-time demotion. Set ``sign_in_exc`` / ``refresh_exc`` to drive error
    paths, and ``refresh_admin`` to flip admin state at refresh. Records
    ``sign_in_calls`` / ``refresh_calls`` / ``logout_calls`` for assertions.
    """

    def __init__(self, *, admin: bool = True, sub: str = "user-123",
                 email: str = "user@example.com", aud: str = "1",
                 google_client_id: str = "cid.apps.googleusercontent.com") -> None:
        self.google_cid = google_client_id
        self.admin = admin
        self.sub = sub
        self.email = email
        self.aud = aud
        self.sign_in_exc: Optional[Exception] = None
        self.refresh_exc: Optional[Exception] = None
        self.refresh_admin: Optional[bool] = None   # override admin on refresh if set
        self.access_ttl = 600
        self.logout_calls: list[str] = []
        self.sign_in_calls: list[str] = []
        self.refresh_calls: list[str] = []
        # GDPR-deletion: scripted feed pages + recorded trigger calls.
        self.deletion_pages: list[dict[str, Any]] = []
        self.challenge_calls: list[str] = []
        self.delete_calls: list[tuple[str, str]] = []
        self.challenge_result: dict[str, Any] = {"nonce": "N", "expires_at": "x"}
        self.challenge_exc: Optional[Exception] = None
        self.delete_exc: Optional[Exception] = None

    def _claims(self, *, admin: bool) -> dict[str, Any]:
        c = {"sub": self.sub, "email": self.email, "iss": "identity",
             "aud": self.aud, "exp": int(time.time()) + self.access_ttl}
        if admin:
            c["is_admin"] = True
        return c

    def sign_in(self, google_id_token: str) -> dict[str, Any]:
        self.sign_in_calls.append(google_id_token)
        if self.sign_in_exc is not None:
            raise self.sign_in_exc
        return {"access_token": "AT", "refresh_token": "RT", "expires_at": "x",
                "user": {"id": self.sub, "email": self.email,
                         "is_new": False}}

    def refresh(self, refresh_token: str) -> dict[str, Any]:
        self.refresh_calls.append(refresh_token)
        if self.refresh_exc is not None:
            raise self.refresh_exc
        return {"access_token": "AT2", "expires_at": "x"}

    def logout(self, refresh_token: str) -> None:
        self.logout_calls.append(refresh_token)

    def google_client_id(self) -> Optional[str]:
        return self.google_cid

    def verify(self, access_token: str) -> dict[str, Any]:
        if access_token == "AT2":
            admin = self.refresh_admin if self.refresh_admin is not None else self.admin
            return self._claims(admin=admin)
        return self._claims(admin=self.admin)

    # -- GDPR deletion --

    def request_deletion_challenge(self, user_id: str) -> dict[str, Any]:
        self.challenge_calls.append(user_id)
        if self.challenge_exc is not None:
            raise self.challenge_exc
        return self.challenge_result

    def delete_user(self, user_id: str, google_id_token: str) -> dict[str, Any]:
        self.delete_calls.append((user_id, google_id_token))
        if self.delete_exc is not None:
            raise self.delete_exc
        return {"deleted": True}

    def fetch_deletions(
        self, since: int, *, limit: Optional[int] = None, wait: float = 0.0
    ) -> dict[str, Any]:
        """Pop the next scripted page, or an empty page advancing the cursor.

        Fill ``deletion_pages`` with ``{"deletions": [...], "cursor": n}`` dicts.
        When the queue is empty, returns an empty page with the cursor unchanged.
        """
        if self.deletion_pages:
            return self.deletion_pages.pop(0)
        return {"deletions": [], "cursor": since}


# --- real-crypto helpers (for testing the verifier / a real gate) ------------


def generate_keypair():
    """Return ``(private_key, public_key)`` for an RSA-2048 signer."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key, key.public_key()


def jwk_for(public_key, kid: str) -> dict[str, Any]:
    """Build a JWKS entry (dict) for *public_key* under *kid*."""
    jwk = json.loads(RSAAlgorithm.to_jwk(public_key))
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return jwk


def make_token(private_key, kid: str, *, aud: str = "1", iss: str = "identity",
               exp_delta: int = 600, extra: Optional[dict] = None,
               alg: str = "RS256") -> str:
    """Mint a signed token (defaults: valid, ``aud='1'``, ``iss='identity'``).

    Pass ``extra={'is_admin': True}`` for an admin token, ``exp_delta=-10`` for an
    expired one, ``alg='HS256'`` / ``aud=...`` / ``iss=...`` for adversarial cases.
    """
    now = int(time.time())
    payload = {"sub": "user-1", "iss": iss, "aud": aud, "iat": now,
               "exp": now + exp_delta}
    if extra:
        payload.update(extra)
    return jwt.encode(payload, private_key, algorithm=alg, headers={"kid": kid})


class FakeResp:
    """Minimal stand-in for a ``requests`` response."""

    def __init__(self, json_data: Any = None, status: int = 200) -> None:
        self._json = json_data
        self.status_code = status

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(f"status {self.status_code}")

    def json(self) -> Any:
        if self._json is None:
            raise ValueError("no json body")
        return self._json


class FakeHTTP:
    """Scripted stand-in for ``requests.Session``: GET serves JWKS /
    auth-providers; POST pops from a queue you fill with ``queue_post``."""

    def __init__(self, *, jwks: Any = None, providers: Any = None,
                 get_exc: Optional[Exception] = None) -> None:
        self._jwks = jwks
        self._providers = providers
        self._get_exc = get_exc
        self.get_calls = 0
        self.post_calls: list[tuple] = []
        self._post_queue: list[Any] = []

    def get(self, url, timeout=None):
        self.get_calls += 1
        if self._get_exc is not None:
            raise self._get_exc
        if "auth-providers" in url:
            return FakeResp(self._providers)
        return FakeResp(self._jwks)

    def queue_post(self, resp) -> None:
        self._post_queue.append(resp)

    def post(self, url, headers=None, json=None, timeout=None):
        self.post_calls.append((url, headers, json))
        if not self._post_queue:
            raise AssertionError("unexpected POST")
        resp = self._post_queue.pop(0)
        if isinstance(resp, Exception):
            raise resp
        return resp


__all__ = [
    "FakeIdentity",
    "generate_keypair",
    "jwk_for",
    "make_token",
    "FakeResp",
    "FakeHTTP",
]
