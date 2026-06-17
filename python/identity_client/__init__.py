"""identity-client: Python integration for the shared identity auth service.

Public API:

    from identity_client import (
        IdentityClient, IdentityConfig, AccessTokenVerifier,
        IdentityError, AuthRejected, IdentityUnavailable, is_admin_claim,
        SessionPolicy,
    )

``SessionPolicy`` is the framework-neutral session state machine (refresh /
fail-closed / bounds) for building a login on any backend: a FastAPI app gets it
wrapped by ``identity_client.fastapi.IdentitySessions``, and a Flask / other
binding can drive it directly (decode cookie -> evaluate -> re-encode).

Test helpers live in ``identity_client.testing`` (import them only from tests).

A FastAPI integration (cookie session + login routes + gate dependencies) is
available as an optional extra: install ``identity-client[fastapi]`` then
``from identity_client.fastapi import IdentitySessions, auth_router, require_user``.
It is not imported here so the core stays dependency-light.
"""

from .client import (
    AccessTokenVerifier,
    AuthRejected,
    IdentityClient,
    IdentityConfig,
    IdentityError,
    IdentityUnavailable,
    PasswordRejected,
    is_admin_claim,
)
from .sessions import SessionPolicy

__version__ = "0.8.0"

__all__ = [
    "IdentityClient",
    "IdentityConfig",
    "AccessTokenVerifier",
    "IdentityError",
    "AuthRejected",
    "IdentityUnavailable",
    "PasswordRejected",
    "is_admin_claim",
    "SessionPolicy",
]
