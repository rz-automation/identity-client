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
* ``auth_router`` -- an ``APIRouter`` exposing ``/auth-config`` (Google client-id
  discovery), ``/login`` (exchange a relayed Google credential for a session),
  ``/logout`` (revoke + clear), and ``/session`` (report auth state). Mount it
  under whatever prefix you like.
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
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional, Union

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from .client import AuthRejected, IdentityClient, IdentityError, is_admin_claim

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
        idle_timeout_seconds: int = 12 * 3600,
        absolute_lifetime_seconds: int = 7 * _DAY,
        refresh_skew_seconds: int = 30,
        admin_only: bool = False,
    ) -> None:
        if (secret_key is None) == (secret_path is None):
            raise ValueError("provide exactly one of secret_key or secret_path")
        key = secret_key if secret_key is not None else _load_or_create_secret(secret_path)  # type: ignore[arg-type]
        self.client = client
        self.cookie_name = cookie_name
        self.cookie_secure = cookie_secure
        self.idle_timeout_seconds = idle_timeout_seconds
        self.absolute_lifetime_seconds = absolute_lifetime_seconds
        self.refresh_skew_seconds = refresh_skew_seconds
        self.admin_only = admin_only
        self._serializer = URLSafeTimedSerializer(key, salt=salt)

    # -- cookie read/write --

    def new_session(self, claims: dict[str, Any], refresh_token: str) -> dict[str, Any]:
        """Build a fresh session payload from a verified access token's claims."""
        now = int(time.time())
        return {
            "uid": str(claims.get("sub")),
            "email": claims.get("email"),
            "rt": refresh_token,
            "axp": int(claims["exp"]),  # verified access-token expiry
            "adm": is_admin_claim(claims),
            "iat": now,  # login time (absolute-lifetime anchor)
            "seen": now,  # last request time (idle-timeout anchor)
        }

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

    def _in_bounds(self, data: dict[str, Any]) -> bool:
        if not data.get("rt"):
            return False
        now = int(time.time())
        if now - int(data.get("iat", 0)) >= self.absolute_lifetime_seconds:
            return False
        if now - int(data.get("seen", 0)) >= self.idle_timeout_seconds:
            return False
        return True

    def _try_refresh(self, data: dict[str, Any]) -> bool:
        """Refresh the access token against identity; fail closed.

        Mutates ``data`` (``axp``/``adm``) and returns True only on a verified,
        unexpired token (and, when ``admin_only``, an ``is_admin`` one). Any other
        outcome -- a 401, 5xx, timeout, malformed body, or demotion under
        ``admin_only`` -- returns False so the caller denies the request.
        """
        try:
            resp = self.client.refresh(data["rt"])
            claims = self.client.verify(resp["access_token"])
        except (IdentityError, KeyError):
            return False
        if self.admin_only and not is_admin_claim(claims):
            return False
        exp = claims.get("exp")
        if not isinstance(exp, (int, float)):
            return False
        data["axp"] = int(exp)
        data["adm"] = is_admin_claim(claims)
        return True

    def evaluate(self, request: Request) -> tuple[bool, Optional[dict[str, Any]]]:
        """Decide whether the request carries a live session.

        Returns ``(authed, data)``. When ``authed`` is True, ``data`` is the
        (possibly refreshed) payload the caller must re-issue so the bumped
        expiry/last-seen persist. Blocking: makes a synchronous identity call
        when refreshing, so async callers run it in a threadpool.
        """
        data = self.read(request)
        if data is None or not self._in_bounds(data):
            return (False, None)
        if int(time.time()) >= int(data.get("axp", 0)) - self.refresh_skew_seconds:
            if not self._try_refresh(data):
                return (False, None)
        data["seen"] = int(time.time())
        return (True, data)


# --- routes ------------------------------------------------------------------


class _Credential(BaseModel):
    # The Google ID token the sign-in button hands the SPA, relayed here.
    credential: str = Field(default="", max_length=4096)


def _error(status: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": message}, headers=_NO_STORE)


def auth_router(sessions: IdentitySessions) -> APIRouter:
    """Build the login surface (``/auth-config``, ``/login``, ``/logout``,
    ``/session``) for *sessions*. Mount it under any prefix you like::

        app.include_router(auth_router(sessions), prefix="/api/auth")
    """
    router = APIRouter()
    client = sessions.client

    @router.get("/auth-config")
    async def auth_config() -> JSONResponse:
        cid = await run_in_threadpool(client.google_client_id)
        return JSONResponse(content={"google_client_id": cid}, headers=_NO_STORE)

    @router.post("/login")
    async def login(body: _Credential) -> JSONResponse:
        if not body.credential:
            return _error(400, "No credential received.")
        try:
            resp = await run_in_threadpool(client.sign_in, body.credential)
            claims = await run_in_threadpool(client.verify, resp["access_token"])
        except AuthRejected:
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
        sessions.issue(out, sessions.new_session(claims, resp["refresh_token"]))
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
