"""Framework-neutral session policy: the refresh / fail-closed state machine.

This is the executable spec for a login session built on identity. It owns the
DECISIONS -- is the session in bounds, must the access token be refreshed, does a
refresh fail closed -- over a plain session dict, with zero web-framework and zero
cookie dependency. A binding (``identity_client.fastapi.IdentitySessions``, or a
Flask / Kotlin / other adapter) supplies only the thin plumbing: decode the
request's signed cookie to a dict, call :meth:`evaluate`, and re-encode the
returned dict onto the response. Keeping this layer pure is what lets a second
backend -- another Python framework, or another language -- mirror the logic
instead of reimplementing it from source.

Session dict shape (what a binding signs into its cookie)::

    {
      "uid":   str,         # identity subject (global user id)
      "email": str | None,
      "rt":    str,         # identity refresh token (secret; server-side only)
      "axp":   int,         # verified access-token expiry (unix seconds)
      "adm":   bool,        # is_admin at last verify
      "iat":   int,         # login time (absolute-lifetime anchor)
      "seen":  int,         # last-seen time (idle-timeout anchor)
    }

Security invariants -- do NOT weaken. Every decision fails closed: a refresh that
errors, returns a malformed body, or (under ``admin_only``) loses the ``is_admin``
claim denies the request rather than degrading to a stale-but-allowed session.
The refresh token is the only long-lived secret in the dict; a binding must keep
it server-side (a signed, HttpOnly cookie), never expose it to the browser.
"""
from __future__ import annotations

import time
from typing import Any, Optional

from .client import IdentityClient, IdentityError, is_admin_claim

_DAY = 24 * 3600


class SessionPolicy:
    """The framework-neutral session decisions, bound to one ``IdentityClient``.

    A binding constructs one of these (usually indirectly, via its own session
    manager) and routes every gate decision through :meth:`evaluate`. The policy
    never touches a request, response, or cookie; it operates only on the decoded
    session dict.

    ``admin_only`` tightens the policy for admin consoles: a refresh that loses
    the ``is_admin`` claim ends the session (demotion kill-switch). With the
    default ``admin_only=False`` any valid identity account stays signed in and
    callers gate admin-only routes separately.
    """

    def __init__(
        self,
        client: IdentityClient,
        *,
        idle_timeout_seconds: Optional[int] = 12 * 3600,
        absolute_lifetime_seconds: int = 7 * _DAY,
        refresh_skew_seconds: int = 30,
        admin_only: bool = False,
    ) -> None:
        self.client = client
        self.idle_timeout_seconds = idle_timeout_seconds
        self.absolute_lifetime_seconds = absolute_lifetime_seconds
        self.refresh_skew_seconds = refresh_skew_seconds
        self.admin_only = admin_only

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

    def in_bounds(self, data: dict[str, Any]) -> bool:
        """True iff the session still holds a refresh token and is within both
        the absolute lifetime and (unless opted out) the idle timeout."""
        if not data.get("rt"):
            return False
        now = int(time.time())
        if now - int(data.get("iat", 0)) >= self.absolute_lifetime_seconds:
            return False
        # idle_timeout_seconds=None opts out of the idle check entirely: the
        # session then lives until the absolute lifetime or the refresh token
        # lapses. Suits low-sensitivity consumers; sensitive ones keep the default.
        if self.idle_timeout_seconds is not None:
            if now - int(data.get("seen", 0)) >= self.idle_timeout_seconds:
                return False
        return True

    def try_refresh(self, data: dict[str, Any]) -> bool:
        """Refresh the access token against identity; fail closed.

        Mutates ``data`` (``axp``/``adm``) and returns True only on a verified,
        unexpired token (and, when ``admin_only``, an ``is_admin`` one). Any other
        outcome -- a 401, 5xx, timeout, malformed body, or demotion under
        ``admin_only`` -- returns False so the caller denies the request. This is
        a blocking call (it talks to identity); async callers run it off the loop.
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

    def evaluate(
        self, data: Optional[dict[str, Any]]
    ) -> tuple[bool, Optional[dict[str, Any]]]:
        """Decide whether a decoded session is live, refreshing if stale.

        Pass the dict a binding decoded from its signed cookie (or None if there
        was no valid cookie). Returns ``(authed, data)``: when ``authed`` is True,
        ``data`` is the (possibly refreshed, last-seen-bumped) payload the binding
        must re-encode so the bumped expiry/last-seen persist. Blocking when it
        refreshes.
        """
        if data is None or not self.in_bounds(data):
            return (False, None)
        if int(time.time()) >= int(data.get("axp", 0)) - self.refresh_skew_seconds:
            if not self.try_refresh(data):
                return (False, None)
        data["seen"] = int(time.time())
        return (True, data)


__all__ = ["SessionPolicy"]
