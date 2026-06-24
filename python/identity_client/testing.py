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
                 google_client_id: str = "cid.apps.googleusercontent.com",
                 discord_enabled: bool = False,
                 password_enabled: bool = False,
                 base_url: str = "https://id.example.test") -> None:
        self.google_cid = google_client_id
        self.discord_enabled = discord_enabled
        self.password_enabled = password_enabled
        self.base_url = base_url.rstrip("/")
        self.admin = admin
        self.sub = sub
        self.email = email
        self.aud = aud
        self.sign_in_exc: Optional[Exception] = None
        self.password_exc: Optional[Exception] = None
        self.refresh_exc: Optional[Exception] = None
        self.refresh_admin: Optional[bool] = None   # override admin on refresh if set
        self.access_ttl = 600
        self.logout_calls: list[str] = []
        # Recorded as (provider, credential) tuples to match sign_in's signature.
        self.sign_in_calls: list[tuple[str, str]] = []
        # Recorded as (op, email, password) for password_signup/password_login.
        self.password_calls: list[tuple[str, str, str]] = []
        self.refresh_calls: list[str] = []
        # Account-delete stand-in: records each deleted user id; ``delete_exc``
        # lets a test force a failure (AuthRejected / IdentityUnavailable).
        self.delete_calls: list[str] = []
        self.delete_exc: Optional[Exception] = None
        # Password-reset stand-ins. ``reset_valid`` drives validate's result.
        self.reset_calls: list[tuple[str, str]] = []
        self.reset_valid: bool = True

    def _claims(self, *, admin: bool) -> dict[str, Any]:
        c = {"sub": self.sub, "email": self.email, "iss": "identity",
             "aud": self.aud, "exp": int(time.time()) + self.access_ttl}
        if admin:
            c["is_admin"] = True
        return c

    def sign_in(self, provider: str, credential: str) -> dict[str, Any]:
        self.sign_in_calls.append((provider, credential))
        if self.sign_in_exc is not None:
            raise self.sign_in_exc
        return {"access_token": "AT", "refresh_token": "RT", "expires_at": "x",
                "user": {"id": self.sub, "email": self.email,
                         "is_new": False}}

    def _password_body(self) -> dict[str, Any]:
        return {"access_token": "AT", "refresh_token": "RT", "expires_at": "x",
                "user": {"id": self.sub, "email": self.email,
                         "is_new": True}}

    def password_signup(self, email: str, password: str) -> dict[str, Any]:
        self.password_calls.append(("signup", email, password))
        if self.password_exc is not None:
            raise self.password_exc
        return self._password_body()

    def password_login(self, email: str, password: str) -> dict[str, Any]:
        self.password_calls.append(("login", email, password))
        if self.password_exc is not None:
            raise self.password_exc
        return self._password_body()

    def password_reset_request(self, email: str) -> dict[str, Any]:
        self.reset_calls.append(("request", email))
        if self.password_exc is not None:
            raise self.password_exc
        return {"ok": True}

    def password_reset_validate(self, token: str) -> dict[str, Any]:
        self.reset_calls.append(("validate", token))
        if self.password_exc is not None:
            raise self.password_exc
        return {"valid": self.reset_valid}

    def password_reset_confirm(self, token: str, password: str) -> dict[str, Any]:
        self.reset_calls.append(("confirm", token))
        if self.password_exc is not None:
            raise self.password_exc
        return {"ok": True}

    def refresh(self, refresh_token: str) -> dict[str, Any]:
        self.refresh_calls.append(refresh_token)
        if self.refresh_exc is not None:
            raise self.refresh_exc
        return {"access_token": "AT2", "expires_at": "x"}

    def logout(self, refresh_token: str) -> None:
        self.logout_calls.append(refresh_token)

    def delete_account(self, user_id: str) -> None:
        self.delete_calls.append(user_id)
        if self.delete_exc is not None:
            raise self.delete_exc

    def providers(self) -> list[dict[str, Any]]:
        provs: list[dict[str, Any]] = [{"id": "google", "client_id": self.google_cid}]
        if self.discord_enabled:
            provs.append({"id": "discord"})
        if self.password_enabled:
            provs.append({"id": "password"})
        return provs

    def google_client_id(self) -> Optional[str]:
        return self.google_cid

    def discord_start_url(self) -> Optional[str]:
        if not self.discord_enabled:
            return None
        return f"{self.base_url}/auth/discord/start?service_id={self.aud}"

    def verify(self, access_token: str) -> dict[str, Any]:
        if access_token == "AT2":
            admin = self.refresh_admin if self.refresh_admin is not None else self.admin
            return self._claims(admin=admin)
        return self._claims(admin=self.admin)


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
        self.last_get_headers: Any = None
        self.post_calls: list[tuple] = []
        self._post_queue: list[Any] = []

    def get(self, url, headers=None, timeout=None):
        self.get_calls += 1
        self.last_get_headers = headers
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
