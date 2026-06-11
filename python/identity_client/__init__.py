"""identity-client: Python integration for the shared identity auth service.

Public API:

    from identity_client import (
        IdentityClient, IdentityConfig, AccessTokenVerifier,
        IdentityError, AuthRejected, IdentityUnavailable, is_admin_claim,
    )

Test helpers live in ``identity_client.testing`` (import them only from tests).
"""

from .client import (
    AccessTokenVerifier,
    AuthRejected,
    IdentityClient,
    IdentityConfig,
    IdentityError,
    IdentityUnavailable,
    is_admin_claim,
)

__version__ = "0.1.0"

__all__ = [
    "IdentityClient",
    "IdentityConfig",
    "AccessTokenVerifier",
    "IdentityError",
    "AuthRejected",
    "IdentityUnavailable",
    "is_admin_claim",
]
