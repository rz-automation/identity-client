"""Identity service client + access-token verifier.

This is the canonical Python integration for the shared ``identity`` auth service:
the one place its three server-to-server calls and its RS256 token verification
live, so consumers depend on it instead of copy-pasting security-critical code.
It lives in the identity repo (``clients/python``) on purpose, next to the
token-signing code it must stay in lockstep with.

Self-contained: depends only on ``requests``, ``PyJWT`` (with the ``cryptography``
backend), and the stdlib. No web framework. Wire it to your own framework's
session layer separately (see the README).

Two responsibilities, kept apart:

  * ``IdentityClient`` -- the server-to-server auth calls (provider sign-in via
    ``/auth/google`` or ``/auth/discord/exchange``, plus ``/auth/refresh`` and
    ``/auth/logout``), authenticated with this service's ``<service-id>.<secret>``
    credential, plus provider discovery (``providers()`` / ``google_client_id()``
    / ``discord_start_url()``).
  * ``AccessTokenVerifier`` -- RS256-pinned JWKS verification of the access JWT.

Security invariants -- do NOT weaken:

  * Verify EVERY access token, fully and unconditionally. Pin
    ``algorithms=["RS256"]``; never read the algorithm from the token header;
    reject ``none`` and every HMAC alg. (identity publishes its RSA *public* key
    at the JWKS endpoint, so an HMAC-accepting verifier could be handed a token
    HMAC-signed with that public key -- the classic alg-confusion forgery.)
  * Check signature, ``exp``, ``iss == "identity"``, and ``aud == this service's
    id``. The ``aud`` check is what stops a token identity minted for another
    service being replayed here.
  * Bound the JWKS cache with a TTL (so a revoked key stops being trusted within
    that window) and rate-limit refetches triggered by an unknown ``kid`` (so a
    stream of random-kid tokens cannot be turned into a fetch-amplification DoS
    against identity).

Both auth-failure exceptions below mean the same thing to a caller: deny. They
are distinguished only so the caller may log/measure them differently.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import jwt
import requests
from jwt.algorithms import RSAAlgorithm


# --- exceptions --------------------------------------------------------------


class IdentityError(Exception):
    """Base: any identity interaction the caller must treat as auth failure."""


class AuthRejected(IdentityError):
    """identity positively rejected the credential or token (HTTP 401, or a
    token that failed verification). The subject is not (or no longer) a valid,
    authorised user."""


class IdentityUnavailable(IdentityError):
    """identity could not be reached or answered with a non-auth error
    (timeout, connection error, 5xx, malformed body). Per the fail-closed rule
    this still denies access, but it is *not* a statement about the user."""


# --- config ------------------------------------------------------------------


@dataclass
class IdentityConfig:
    """Everything a consumer needs to talk to identity.

    ``service_id`` (the expected JWT ``aud``) is derived from the credential:
    identity issues the credential as ``<service-id>.<secret>`` and mints the
    access JWT with ``aud == str(<service-id>)``, so they are the same value.
    """

    base_url: str
    service_credential: str
    issuer: str = "identity"
    request_timeout: float = 5.0
    # JWKS cache controls (see module docstring).
    jwks_cache_ttl: float = 600.0
    jwks_min_refetch_interval: float = 60.0
    service_id: str = field(init=False)

    def __post_init__(self) -> None:
        self.base_url = self.base_url.rstrip("/")
        if "." not in self.service_credential:
            raise ValueError(
                "service_credential must be of the form '<service-id>.<secret>'"
            )
        # The secret is url-safe base64 (no dots), so the first dot splits id
        # from secret cleanly.
        self.service_id = self.service_credential.split(".", 1)[0]
        if not self.service_id:
            raise ValueError("service_credential has an empty service id")

    @property
    def jwks_url(self) -> str:
        return f"{self.base_url}/.well-known/jwks.json"

    @property
    def _auth_header(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.service_credential}"}


# --- access-token verification ----------------------------------------------


class AccessTokenVerifier:
    """RS256-pinned verification of identity access tokens against its JWKS.

    Maintains a small in-process cache of signing keys keyed by ``kid``. A new
    ``kid`` triggers a refetch (rate-limited); the whole cache is refreshed once
    its TTL lapses so revoked keys age out.
    """

    def __init__(self, config: IdentityConfig,
                 session: Optional[requests.Session] = None) -> None:
        self._config = config
        self._session = session or requests.Session()
        self._lock = threading.Lock()
        self._keys: dict[str, Any] = {}      # kid -> RSA public key object
        self._fetched_at: float = 0.0        # when _keys was last populated
        self._last_fetch_attempt: float = 0.0

    # -- public API --

    def verify(self, token: str) -> dict[str, Any]:
        """Verify *token* and return its claims, or raise.

        Raises ``AuthRejected`` for a token that is malformed, expired, has the
        wrong ``iss``/``aud``, a bad signature, or a ``kid`` identity does not
        publish. Raises ``IdentityUnavailable`` only if the JWKS could not be
        fetched when it had to be.
        """
        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError as exc:
            raise AuthRejected(f"malformed token header: {exc}") from exc

        # Pin the algorithm from OUR config, never from the token header.
        if header.get("alg") != "RS256":
            raise AuthRejected(f"unexpected alg {header.get('alg')!r}; only RS256")
        kid = header.get("kid")
        if not kid:
            raise AuthRejected("token header has no kid")

        key = self._signing_key(kid)
        try:
            claims = jwt.decode(
                token,
                key=key,
                algorithms=["RS256"],          # hard pin; rejects none/HMAC
                audience=self._config.service_id,
                issuer=self._config.issuer,
                options={"require": ["exp", "iss", "aud"]},
            )
        except jwt.InvalidTokenError as exc:
            raise AuthRejected(f"token verification failed: {exc}") from exc
        return claims

    # -- key cache --

    def _signing_key(self, kid: str):
        now = time.monotonic()
        with self._lock:
            fresh = (now - self._fetched_at) < self._config.jwks_cache_ttl
            if kid in self._keys and fresh:
                return self._keys[kid]
            # Need a (re)fetch: either an unknown kid or a stale cache. Rate-limit
            # so unknown-kid spam can't amplify into unbounded JWKS fetches.
            if (now - self._last_fetch_attempt) < self._config.jwks_min_refetch_interval:
                if kid in self._keys:
                    return self._keys[kid]            # serve stale rather than refetch
                raise AuthRejected("unknown kid (refetch rate-limited)")
            self._last_fetch_attempt = now
            self._refresh_keys_locked()
            if kid in self._keys:
                return self._keys[kid]
            raise AuthRejected(f"unknown kid {kid!r} after JWKS refresh")

    def _refresh_keys_locked(self) -> None:
        try:
            resp = self._session.get(
                self._config.jwks_url, timeout=self._config.request_timeout
            )
            resp.raise_for_status()
            jwks = resp.json()
        except (requests.RequestException, ValueError) as exc:
            raise IdentityUnavailable(f"could not fetch JWKS: {exc}") from exc

        keys: dict[str, Any] = {}
        for jwk in jwks.get("keys", []):
            if jwk.get("kty") != "RSA" or "kid" not in jwk:
                continue
            try:
                keys[jwk["kid"]] = RSAAlgorithm.from_jwk(json.dumps(jwk))
            except (ValueError, KeyError, TypeError):
                continue                              # skip a malformed entry
        if keys:
            self._keys = keys
            self._fetched_at = time.monotonic()


# --- the three auth calls ----------------------------------------------------


class IdentityClient:
    """Server-to-server calls into identity, plus the bundled verifier.

    A consumer creates one of these at startup and uses it for the whole login /
    refresh / logout lifecycle.
    """

    def __init__(self, config: IdentityConfig,
                 session: Optional[requests.Session] = None,
                 verifier: Optional[AccessTokenVerifier] = None) -> None:
        self.config = config
        self._session = session or requests.Session()
        self.verifier = verifier or AccessTokenVerifier(config, self._session)
        self._providers: Optional[list[dict[str, Any]]] = None
        self._providers_at: float = 0.0
        self._providers_ttl: float = 3600.0

    def providers(self) -> list[dict[str, Any]]:
        """Discover this service's enabled login providers from ``/auth-providers``.

        Returns the provider list identity advertises for this service, e.g.
        ``[{"id": "google", "client_id": ...}, {"id": "discord"}]``. We send this
        service's credential so identity returns *this service's* configuration
        (its Google client id, whether Discord is enabled for it); the endpoint
        stays public, so an unauthenticated call still works and yields identity's
        own defaults. Cached ~1h since it rarely changes. Returns the stale cache
        (or ``[]`` if nothing is cached) when identity is unreachable, so the
        login page degrades to "no buttons" rather than erroring -- correct under
        hard cutover (no identity, no login).
        """
        now = time.monotonic()
        if (
            self._providers is not None
            and (now - self._providers_at) < self._providers_ttl
        ):
            return self._providers
        try:
            resp = self._session.get(
                f"{self.config.base_url}/auth-providers",
                headers=self.config._auth_header,
                timeout=self.config.request_timeout,
            )
            resp.raise_for_status()
            data = resp.json()
        except (requests.RequestException, ValueError):
            return self._providers or []     # serve stale if we have it, else []
        provs = data.get("providers", [])
        if isinstance(provs, list):
            self._providers = provs
            self._providers_at = now
        return self._providers or []

    def google_client_id(self) -> Optional[str]:
        """This service's Google client id (from ``providers()``), or None.

        identity owns the client id (it verifies the Google token's ``aud``
        against its own configured value), so consumers must not hardcode it --
        discovering it here makes the two match by construction. None means either
        Google is not configured for this service or identity is unreachable with
        nothing cached; the Google button then cannot render, which is correct.
        """
        for provider in self.providers():
            if provider.get("id") == "google":
                return provider.get("client_id")
        return None

    def discord_start_url(self) -> Optional[str]:
        """Absolute URL that begins Discord sign-in, or None if it's not enabled.

        The browser navigates here at the top level (not a fetch): identity runs
        the whole Discord OAuth dance server-side and bounces back to this
        service's registered Discord return URL with a single-use exchange code,
        which the backend swaps via ``sign_in("discord", code)``. None when
        Discord is not advertised for this service (or identity is unreachable).
        """
        if not any(p.get("id") == "discord" for p in self.providers()):
            return None
        return (
            f"{self.config.base_url}/auth/discord/start"
            f"?service_id={self.config.service_id}"
        )

    def sign_in(self, provider: str, credential: str) -> dict[str, Any]:
        """Exchange a provider credential for identity tokens.

        - ``provider="google"``: *credential* is the relayed Google ID token
          (POST ``/auth/google``).
        - ``provider="discord"``: *credential* is the single-use exchange code
          from the Discord return redirect (POST ``/auth/discord/exchange``).

        Returns the identity response body
        (``access_token``, ``refresh_token``, ``expires_at``, ``user``). Raises
        ``ValueError`` for an unknown provider.
        """
        if provider == "google":
            return self._post("/auth/google", {"google_id_token": credential})
        if provider == "discord":
            return self._post("/auth/discord/exchange", {"code": credential})
        raise ValueError(f"unknown provider {provider!r}")

    def refresh(self, refresh_token: str) -> dict[str, Any]:
        """Mint a fresh access token (POST /auth/refresh).

        Returns ``{access_token, expires_at}``. Raises ``AuthRejected`` when the
        refresh token is invalidated or the user/service is no longer valid
        (identity answers 401).
        """
        return self._post("/auth/refresh", {"refresh_token": refresh_token})

    def logout(self, refresh_token: str) -> None:
        """Best-effort revoke of *refresh_token* (POST /auth/logout).

        Never raises: logout must always be able to tear the local session down,
        regardless of whether identity is reachable or the token already gone.
        """
        try:
            self._session.post(
                f"{self.config.base_url}/auth/logout",
                headers=self.config._auth_header,
                json={"refresh_token": refresh_token},
                timeout=self.config.request_timeout,
            )
        except requests.RequestException:
            pass

    def verify(self, access_token: str) -> dict[str, Any]:
        """Verify an access token (delegates to the bundled verifier)."""
        return self.verifier.verify(access_token)

    # -- GDPR deletion: trigger + propagation feed --

    def request_deletion_challenge(self, user_id: str) -> dict[str, Any]:
        """Ask identity for a single-use deletion nonce for *user_id*.

        Step one of the two-step "delete my account" trigger. Returns
        ``{nonce, expires_at}`` to pass to the browser re-auth, or
        ``{already_deleted: True}`` if the account is already a tombstone (the
        caller should then skip the re-auth and just tear down locally). Raises
        ``AuthRejected`` / ``IdentityUnavailable`` like the other calls.
        """
        return self._post(f"/api/v1/users/{user_id}/delete-challenge", {})

    def delete_user(self, user_id: str, google_id_token: str) -> dict[str, Any]:
        """Trigger global GDPR erasure of *user_id* (step two of the trigger).

        ``google_id_token`` is the freshly minted re-auth token from the browser,
        carrying the deletion nonce. identity verifies it stricter than sign-in
        (token bound to the user + matching nonce) before erasing. Returns
        ``{deleted: True}``. Raises ``AuthRejected`` if the re-auth fails.
        """
        return self._post(
            f"/api/v1/users/{user_id}/delete", {"google_id_token": google_id_token}
        )

    def fetch_deletions(
        self, since: int, *, limit: Optional[int] = None, wait: float = 0.0
    ) -> dict[str, Any]:
        """Read the scoped deletion feed from cursor *since* (GET /api/v1/deletions).

        Returns ``{deletions: [{user_id, seq, deleted_at}, ...], cursor}``, scoped
        to this service's users. Persist ``cursor`` (even on an empty page) and
        pass it as the next ``since`` so the feed never rescans the prefix.

        With ``wait > 0`` this is a **long-poll**: identity holds the request open
        until a matching deletion lands or ``wait`` elapses, so propagation is
        near-instant. The read timeout is set above ``wait`` so the connection is
        not cut off before identity returns; a wait-bounded re-poll is also the
        periodic floor, so a silently dropped connection still catches up. Raises
        ``IdentityUnavailable`` on a network/5xx error (the cursor is unchanged, so
        nothing is lost) and ``AuthRejected`` on a 401.
        """
        params: dict[str, Any] = {"since": int(since)}
        if limit is not None:
            params["limit"] = int(limit)
        if wait and wait > 0:
            params["wait"] = float(wait)
        # A long-poll must not time out before identity does: give the read a
        # margin over `wait`. A plain poll (wait=0) uses the normal timeout.
        timeout = (
            self.config.request_timeout
            if not wait
            else float(wait) + self.config.request_timeout
        )
        return self._get("/api/v1/deletions", params=params, timeout=timeout)

    # -- internals --

    def _get(
        self, path: str, params: dict[str, Any], timeout: float
    ) -> dict[str, Any]:
        try:
            resp = self._session.get(
                f"{self.config.base_url}{path}",
                headers=self.config._auth_header,
                params=params,
                timeout=timeout,
            )
        except requests.RequestException as exc:
            raise IdentityUnavailable(f"identity {path} unreachable: {exc}") from exc
        return self._parse(resp, path)

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        try:
            resp = self._session.post(
                f"{self.config.base_url}{path}",
                headers=self.config._auth_header,
                json=body,
                timeout=self.config.request_timeout,
            )
        except requests.RequestException as exc:
            raise IdentityUnavailable(f"identity {path} unreachable: {exc}") from exc
        return self._parse(resp, path)

    @staticmethod
    def _parse(resp: Any, path: str) -> dict[str, Any]:
        """Map an identity HTTP response to a body dict or a typed failure.

        401 -> ``AuthRejected``; any other >=400 or a non-JSON body ->
        ``IdentityUnavailable`` (fail closed without asserting anything about the
        subject).
        """
        if resp.status_code == 401:
            raise AuthRejected(f"identity {path} rejected the request (401)")
        if resp.status_code >= 400:
            raise IdentityUnavailable(f"identity {path} returned {resp.status_code}")
        try:
            return resp.json()
        except ValueError as exc:
            raise IdentityUnavailable(
                f"identity {path} returned a non-JSON body"
            ) from exc


def is_admin_claim(claims: dict[str, Any]) -> bool:
    """True iff the verified claims carry ``is_admin`` set to exactly ``True``.

    identity emits ``is_admin`` ONLY when true (it is deliberately absent for
    non-admins, so a token holder cannot tell the admin tier exists). Gate on the
    value, not presence, so a future serialization change to a truthy non-bool
    (a ``1`` or ``"true"``) cannot be mistaken for admin.
    """
    return claims.get("is_admin") is True
