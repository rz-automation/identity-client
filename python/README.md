# identity-client (Python)

The canonical Python integration for the shared `identity` auth service: its three
server-to-server calls and the RS256 access-token verifier, in one place so
consumers depend on it instead of copy-pasting security-critical code.

This package contains only client-side logic: HTTP calls to identity and
verification against identity's **public** JWKS key. No secrets live here; the
consumer supplies its own service credential at runtime. The security contract
and threat model are documented inline in `identity_client/client.py`.

## Install

```
identity-client @ git+https://github.com/rz-automation/identity-client.git@v0.1.0#subdirectory=python
```

The repo is public, so no credentials or build secrets are needed. Pin to a tag.

## Use

```python
from identity_client import IdentityClient, IdentityConfig, is_admin_claim

client = IdentityClient(IdentityConfig(
    base_url="https://id.example.com",
    service_credential=SERVICE_CREDENTIAL,   # "<service-id>.<secret>", server-side only
))

# Discover the shared Google client id for your login button (never hardcode it):
cid = client.google_client_id()

# After the browser relays a Google ID token to your backend:
resp = client.sign_in(google_id_token)            # POST /auth/google
claims = client.verify(resp["access_token"])      # RS256 + aud/iss/exp, raises on failure
if not is_admin_claim(claims):                    # gate on the value, not presence
    client.logout(resp.get("refresh_token", ""))
    deny()

# Keep the refresh token in your own signed, HttpOnly, Secure cookie. When the
# access token goes stale, refresh and re-verify; fail closed on anything that is
# not a verified, unexpired, admin token:
try:
    fresh = client.refresh(refresh_token)         # POST /auth/refresh
    claims = client.verify(fresh["access_token"])
except Exception:
    deny()                                        # 401 / outage / malformed all deny
```

`verify` raises `AuthRejected` (identity said no) or `IdentityUnavailable`
(couldn't reach it / bad response). Both mean deny; they differ only so you can
log them apart.

## Testing your integration

`identity_client.testing` ships the doubles so you don't re-derive them:

```python
from identity_client.testing import FakeIdentity, generate_keypair, jwk_for, make_token, FakeHTTP

fake = FakeIdentity()                  # no network, no real Google
fake.refresh_admin = False             # simulate an admin demotion at refresh
# ... inject `fake` where your app expects an IdentityClient ...

# Or test a real verifier against minted tokens + a fake JWKS:
priv, pub = generate_keypair()
http = FakeHTTP(jwks={"keys": [jwk_for(pub, "k1")]})
token = make_token(priv, "k1", extra={"is_admin": True})
```

## What this does NOT do

No web-framework glue. Your login route, session cookie, gate, and CSRF are
yours to write (they are framework-specific). This package is the part you must
never hand-copy: the verify and the three calls.
