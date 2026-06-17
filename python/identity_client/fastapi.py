"""FastAPI integration for the identity client (optional extra ``[fastapi]``).

The core ``identity_client`` package is framework-agnostic: it verifies access
tokens and makes the three server-to-server auth calls, and nothing more. This
module is the *framework glue* that turns those primitives into a working login
for a FastAPI app, so a consumer does not re-implement (and risk drifting on) the
security-critical session handling.

It provides three things:

* ``IdentitySessions`` -- a signed-cookie session manager. The session lives
  entirely in a signed, ``HttpOnly``, ``Secure`` cookie carrying the identity
  refresh token, the verified access-token expiry, and login/last-seen
  timestamps. Lifetime is bounded by an idle timeout and an absolute cap, both
  enforced from the cookie's own timestamps. When the short-lived access token
  goes stale it refreshes against identity and **fails closed** on any
  uncertainty, so an identity-side disable/delete bites within one refresh cycle.
* ``auth_router`` -- an ``APIRouter`` exposing ``/auth-config`` (enabled
  providers + their public config), ``/login`` (exchange a relayed provider
  credential -- Google ID token or Discord exchange code -- for a session),
  ``/discord/callback`` (the browser-facing Discord return target), ``/logout``
  (revoke + clear), and ``/session`` (report auth state). Mount it under whatever
  prefix you like.
* ``require_user`` / ``require_admin`` -- per-route dependencies. ``require_user``
  admits any signed-in identity account; ``require_admin`` additionally requires
  the ``is_admin`` claim. Both re-issue the (refreshed) cookie on the response.

Minimal wiring::

    from identity_client import IdentityClient, IdentityConfig
    from identity_client.fastapi import IdentitySessions, auth_router, require_user

    client = IdentityClient(IdentityConfig(base_url=..., service_credential=...))
    sessions = IdentitySessions(client, secret_path=...)
    app.include_router(auth_router(sessions), prefix="/api/auth")

    user_required = require_user(sessions)

    @app.get("/api/whoami")
    def whoami(user=Depends(user_required)):
        return {"id": user.id}  # user.id is the identity subject (global user id)

The blocking identity calls are run in a threadpool, so this is safe to use from
an async app without stalling the event loop.
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional, Union

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from .client import (
    AuthRejected,
    IdentityClient,
    IdentityError,
    PasswordRejected,
    is_admin_claim,
)
from .sessions import SessionPolicy

_NO_STORE = {"Cache-Control": "no-store"}

_DAY = 24 * 3600


@dataclass(frozen=True)
class IdentityUser:
    """The authenticated account behind a request.

    ``id`` is the global identity subject (the access token's ``sub``); use it as
    the key for your own per-app profile/data. ``email`` may be ``None``.
    """

    id: str
    email: Optional[str]
    is_admin: bool


def _load_or_create_secret(path: Union[str, Path]) -> bytes:
    """Return a stable 32-byte signing key, persisting it 0600 on first use.

    Written via a temp file + atomic rename so a concurrent reader never sees a
    half-written key. Persisting it (rather than generating per process) keeps
    sessions valid across restarts.
    """
    secret_path = Path(path)
    if secret_path.exists():
        data = secret_path.read_bytes()
        if data:
            return data
    key = secrets.token_bytes(32)
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = secret_path.with_name(secret_path.name + ".tmp")
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(key)
    except Exception:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass
        raise
    os.replace(tmp_path, secret_path)
    return key


class IdentitySessions:
    """Signed-cookie session manager bound to one :class:`IdentityClient`.

    Provide exactly one of ``secret_key`` (raw bytes) or ``secret_path`` (a file
    that is created with a fresh key on first boot and reused thereafter).

    ``admin_only`` tightens the policy for admin consoles: ``/login`` refuses a
    non-admin account, and a refresh that loses the ``is_admin`` claim ends the
    session (demotion kill-switch). With the default ``admin_only=False`` any
    valid identity account may sign in, and you gate admin-only routes with
    ``require_admin`` instead.
    """

    def __init__(
        self,
        client: IdentityClient,
        *,
        secret_key: Optional[bytes] = None,
        secret_path: Optional[Union[str, Path]] = None,
        cookie_name: str = "identity_session",
        cookie_secure: bool = True,
        salt: str = "identity-session",
        idle_timeout_seconds: Optional[int] = 12 * 3600,
        absolute_lifetime_seconds: int = 7 * _DAY,
        refresh_skew_seconds: int = 30,
        admin_only: bool = False,
    ) -> None:
        if (secret_key is None) == (secret_path is None):
            raise ValueError("provide exactly one of secret_key or secret_path")
        self.client = client
        self.cookie_name = cookie_name
        self.cookie_secure = cookie_secure
        self.idle_timeout_seconds = idle_timeout_seconds
        self.absolute_lifetime_seconds = absolute_lifetime_seconds
        self.refresh_skew_seconds = refresh_skew_seconds
        self.admin_only = admin_only
        self._salt = salt
        self._secret_key = secret_key
        self._secret_path = secret_path
        self._serializer_cache: Optional[URLSafeTimedSerializer] = None
        # The framework-neutral decision core; this class is its cookie/HTTP
        # adapter. The refresh / fail-closed / bounds logic lives in SessionPolicy
        # so other bindings (Flask, another language) reuse it instead of
        # reimplementing it -- see identity_client.sessions.
        self._policy = SessionPolicy(
            client,
            idle_timeout_seconds=idle_timeout_seconds,
            absolute_lifetime_seconds=absolute_lifetime_seconds,
            refresh_skew_seconds=refresh_skew_seconds,
            admin_only=admin_only,
        )

    @property
    def _serializer(self) -> URLSafeTimedSerializer:
        """Build the signing serializer on first use.

        Lazy on purpose: constructing the manager does no filesystem I/O, so a
        ``secret_path`` whose directory isn't ready yet (or only mounted at
        runtime) never breaks import. The key is loaded/created the first time a
        cookie is signed or read.
        """
        if self._serializer_cache is None:
            key = (
                self._secret_key
                if self._secret_key is not None
                else _load_or_create_secret(self._secret_path)  # type: ignore[arg-type]
            )
            self._serializer_cache = URLSafeTimedSerializer(key, salt=self._salt)
        return self._serializer_cache

    # -- cookie read/write --

    def new_session(self, claims: dict[str, Any], refresh_token: str) -> dict[str, Any]:
        """Build a fresh session payload from a verified access token's claims."""
        return self._policy.new_session(claims, refresh_token)

    def issue(self, response: Response, data: dict[str, Any]) -> None:
        """Write the signed session payload onto the response cookie."""
        response.set_cookie(
            self.cookie_name,
            self._serializer.dumps(data),
            max_age=self.absolute_lifetime_seconds,
            httponly=True,
            secure=self.cookie_secure,
            samesite="lax",
            path="/",
        )

    def clear(self, response: Response) -> None:
        response.delete_cookie(self.cookie_name, path="/")

    def read(self, request: Request) -> Optional[dict[str, Any]]:
        """Decode the signed cookie, or None if absent/invalid/too old."""
        token = request.cookies.get(self.cookie_name)
        if not token:
            return None
        try:
            data = self._serializer.loads(token, max_age=self.absolute_lifetime_seconds)
        except (BadSignature, SignatureExpired):
            return None
        return data if isinstance(data, dict) else None

    # -- evaluation (the gate) --

    def evaluate(self, request: Request) -> tuple[bool, Optional[dict[str, Any]]]:
        """Decide whether the request carries a live session.

        Decodes the signed cookie and delegates the decision to the
        framework-neutral :class:`~identity_client.sessions.SessionPolicy`.
        Returns ``(authed, data)``: when ``authed`` is True, ``data`` is the
        (possibly refreshed) payload the caller must re-issue so the bumped
        expiry/last-seen persist. Blocking: makes a synchronous identity call
        when refreshing, so async callers run it in a threadpool.
        """
        return self._policy.evaluate(self.read(request))


# --- routes ------------------------------------------------------------------


class _Credential(BaseModel):
    # The provider credential relayed from the browser: a Google ID token for
    # provider="google", or the single-use exchange code for provider="discord".
    credential: str = Field(default="", max_length=4096)
    provider: str = Field(default="google", max_length=32)


class _PasswordCredential(BaseModel):
    # The email+password credential for the password provider, relayed
    # same-origin from the browser to /password/signup or /password/login.
    email: str = Field(default="", max_length=320)
    password: str = Field(default="", max_length=1024)


def _error(status: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": message}, headers=_NO_STORE)


def _append_query(url: str, params: dict[str, str]) -> str:
    """Return *url* with *params* merged into its query string."""
    parts = urlparse(url)
    query = dict(parse_qsl(parts.query))
    query.update(params)
    return urlunparse(parts._replace(query=urlencode(query)))


def auth_router(
    sessions: IdentitySessions,
    *,
    post_login_path: str = "/",
) -> APIRouter:
    """Build the login surface for *sessions*. Mount it under any prefix you like::

        app.include_router(auth_router(sessions), prefix="/api/auth")

    Routes:
      * ``GET  /auth-config`` -- the enabled providers + their public config
        (Google client id, Discord start URL), for a frontend to render buttons.
      * ``POST /login`` -- exchange a relayed provider credential (a Google ID
        token, or a Discord exchange code) for a session.
      * ``GET  /discord/callback`` -- the browser-facing Discord return target.
        Register THIS URL (e.g. ``https://app.example/api/auth/discord/callback``)
        as the service's Discord return URL in identity's admin console. It reads
        the exchange code, establishes the session, and redirects to
        ``post_login_path`` (``?error=...`` on failure).
      * ``POST /logout`` -- revoke + clear. ``GET /session`` -- report auth state.
    """
    router = APIRouter()
    client = sessions.client

    @router.get("/auth-config")
    async def auth_config() -> JSONResponse:
        provs = await run_in_threadpool(client.providers)
        out_providers: list[dict[str, Any]] = []
        for p in provs:
            if p.get("id") == "discord":
                start_url = await run_in_threadpool(client.discord_start_url)
                out_providers.append({"id": "discord", "start_url": start_url})
            elif p.get("id") == "google":
                out_providers.append(
                    {"id": "google", "client_id": p.get("client_id")}
                )
        return JSONResponse(
            content={"providers": out_providers}, headers=_NO_STORE
        )

    def _establish(claims: dict[str, Any], refresh_token: str, out: Response) -> None:
        """Write the session cookie for a verified sign-in onto *out*."""
        sessions.issue(out, sessions.new_session(claims, refresh_token))

    @router.post("/login")
    async def login(body: _Credential) -> JSONResponse:
        if not body.credential:
            return _error(400, "No credential received.")
        try:
            resp = await run_in_threadpool(
                client.sign_in, body.provider, body.credential
            )
            claims = await run_in_threadpool(client.verify, resp["access_token"])
        except (AuthRejected, ValueError):
            return _error(401, "Sign-in was rejected.")
        except (IdentityError, KeyError):
            return _error(503, "Sign-in service is unavailable. Try again shortly.")

        if sessions.admin_only and not is_admin_claim(claims):
            # Valid account, but not an admin. Discard the just-issued refresh
            # token and refuse.
            await run_in_threadpool(client.logout, resp.get("refresh_token", ""))
            return _error(403, "This account is not authorized.")

        if not isinstance(claims.get("exp"), (int, float)) or not claims.get("sub"):
            return _error(503, "Sign-in returned an unexpected response.")

        out = JSONResponse(content={"ok": True}, headers=_NO_STORE)
        _establish(claims, resp["refresh_token"], out)
        return out

    async def _password_session(
        call: Callable[..., dict[str, Any]], *args: Any
    ) -> JSONResponse:
        """Run a password signup/login, verify, and establish the session.

        Maps failures the same way ``/login`` does, plus a ``PasswordRejected``
        path that surfaces identity's precise status + message. Shared by the
        two password routes; the caller supplies the right ``client`` method and
        the (email, password) args.
        """
        try:
            resp = await run_in_threadpool(call, *args)
            claims = await run_in_threadpool(client.verify, resp["access_token"])
        except PasswordRejected as e:
            return _error(e.status, e.message)
        except AuthRejected:
            return _error(401, "Incorrect email or password.")
        except (IdentityError, KeyError):
            return _error(503, "Sign-in service is unavailable. Try again shortly.")

        if sessions.admin_only and not is_admin_claim(claims):
            await run_in_threadpool(client.logout, resp.get("refresh_token", ""))
            return _error(403, "This account is not authorized.")
        if not isinstance(claims.get("exp"), (int, float)) or not claims.get("sub"):
            return _error(503, "Sign-in returned an unexpected response.")

        out = JSONResponse(content={"ok": True}, headers=_NO_STORE)
        _establish(claims, resp["refresh_token"], out)
        return out

    @router.post("/password/signup")
    async def password_signup(body: _PasswordCredential) -> JSONResponse:
        return await _password_session(
            client.password_signup, body.email, body.password
        )

    @router.post("/password/login")
    async def password_login(body: _PasswordCredential) -> JSONResponse:
        return await _password_session(
            client.password_login, body.email, body.password
        )

    @router.get("/discord/callback")
    async def discord_callback(
        code: str = "", error: Optional[str] = None
    ) -> RedirectResponse:
        """Browser-facing Discord return target (register as the service's URL).

        identity bounces the browser here with ``?code=`` after a successful
        Discord login (or ``?error=`` on denial). We swap the code for a session
        and redirect to ``post_login_path``; on any failure we redirect there with
        ``?error=...`` so the SPA can show a message. A redirect (not JSON) because
        this is a top-level navigation, not a fetch.
        """
        def _fail(reason: str) -> RedirectResponse:
            return RedirectResponse(
                _append_query(post_login_path, {"error": reason}),
                status_code=303,
                headers=_NO_STORE,
            )

        if error or not code:
            return _fail("discord")
        try:
            resp = await run_in_threadpool(client.sign_in, "discord", code)
            claims = await run_in_threadpool(client.verify, resp["access_token"])
        except AuthRejected:
            return _fail("rejected")
        except (IdentityError, KeyError):
            return _fail("unavailable")

        if sessions.admin_only and not is_admin_claim(claims):
            await run_in_threadpool(client.logout, resp.get("refresh_token", ""))
            return _fail("forbidden")
        if not isinstance(claims.get("exp"), (int, float)) or not claims.get("sub"):
            return _fail("unexpected")

        out = RedirectResponse(
            post_login_path, status_code=303, headers=_NO_STORE
        )
        _establish(claims, resp["refresh_token"], out)
        return out

    @router.post("/logout")
    async def logout(request: Request) -> JSONResponse:
        data = sessions.read(request)
        if data and data.get("rt"):
            await run_in_threadpool(client.logout, data["rt"])
        out = JSONResponse(content={"ok": True}, headers=_NO_STORE)
        sessions.clear(out)
        return out

    @router.get("/session")
    async def session(request: Request) -> JSONResponse:
        authed, data = await run_in_threadpool(sessions.evaluate, request)
        out = JSONResponse(content={"authenticated": authed}, headers=_NO_STORE)
        if authed and data is not None:
            sessions.issue(out, data)
        else:
            sessions.clear(out)
        return out

    return router


# --- dependencies ------------------------------------------------------------


def require_user(sessions: IdentitySessions) -> Callable[..., IdentityUser]:
    """Dependency factory: admit any signed-in identity account.

    Raises 401 when there is no live session. Re-issues the (refreshed) cookie on
    the response. Returns an :class:`IdentityUser`. Plain ``def`` so FastAPI runs
    it in a threadpool, keeping the blocking refresh off the event loop::

        user_required = require_user(sessions)

        @app.get("/api/thing")
        def thing(user=Depends(user_required)):
            ...
    """

    def dependency(request: Request, response: Response) -> IdentityUser:
        authed, data = sessions.evaluate(request)
        if not authed or data is None:
            raise HTTPException(status_code=401, detail={"error": "Unauthorized."}, headers=_NO_STORE)
        sessions.issue(response, data)
        return IdentityUser(
            id=str(data["uid"]),
            email=data.get("email"),
            is_admin=bool(data.get("adm")),
        )

    return dependency


def require_admin(sessions: IdentitySessions) -> Callable[..., IdentityUser]:
    """Dependency factory: admit only accounts with the ``is_admin`` claim.

    A live but non-admin session yields 403. Otherwise as ``require_user``.
    """
    base = require_user(sessions)

    def dependency(request: Request, response: Response) -> IdentityUser:
        user = base(request, response)
        if not user.is_admin:
            raise HTTPException(status_code=403, detail={"error": "Admin access required."}, headers=_NO_STORE)
        return user

    return dependency


__all__ = [
    "IdentityUser",
    "IdentitySessions",
    "auth_router",
    "require_user",
    "require_admin",
]
