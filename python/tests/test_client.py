"""Unit tests for the identity client + access-token verifier.

These are the security core, so they exercise the real RSA/JWS path: a generated
keypair, a JWKS served by a fake HTTP session, and genuine ``jwt.encode`` tokens.
The adversarial cases (alg confusion, ``alg:none``, wrong ``aud``/``iss``,
expired, unknown ``kid``) are the ones that must never regress.
"""

from __future__ import annotations

import time

import jwt
import pytest
import requests

from identity_client import (
    AccessTokenVerifier,
    AuthRejected,
    IdentityClient,
    IdentityConfig,
    IdentityUnavailable,
    PasswordRejected,
    is_admin_claim,
)
from identity_client.testing import (
    FakeHTTP,
    FakeResp,
    generate_keypair,
    jwk_for,
    make_token,
)


CREDENTIAL = "1.supersecretvalue"   # service_id == "1" == expected aud
ISSUER = "identity"


def _config(**kw) -> IdentityConfig:
    base = dict(base_url="https://id.example", service_credential=CREDENTIAL)
    base.update(kw)
    return IdentityConfig(**base)


# --- verifier: happy path ---------------------------------------------------


def test_verify_accepts_valid_token():
    priv, pub = generate_keypair()
    http = FakeHTTP(jwks={"keys": [jwk_for(pub, "k1")]})
    v = AccessTokenVerifier(_config(), session=http)
    claims = v.verify(make_token(priv, "k1", extra={"is_admin": True}))
    assert claims["sub"] == "user-1"
    assert is_admin_claim(claims) is True


def test_jwks_is_cached_across_verifies():
    priv, pub = generate_keypair()
    http = FakeHTTP(jwks={"keys": [jwk_for(pub, "k1")]})
    v = AccessTokenVerifier(_config(), session=http)
    v.verify(make_token(priv, "k1"))
    v.verify(make_token(priv, "k1"))
    assert http.get_calls == 1   # second verify hit the cache, no refetch


# --- verifier: adversarial --------------------------------------------------


def test_rejects_alg_none():
    priv, pub = generate_keypair()
    http = FakeHTTP(jwks={"keys": [jwk_for(pub, "k1")]})
    v = AccessTokenVerifier(_config(), session=http)
    now = int(time.time())
    payload = {"sub": "x", "iss": ISSUER, "aud": "1", "exp": now + 600}
    none_token = jwt.encode(payload, key=None, algorithm="none",
                            headers={"kid": "k1"})
    with pytest.raises(AuthRejected):
        v.verify(none_token)


def test_rejects_hmac_algorithm():
    """Alg-confusion defence: any HS* token is rejected by the RS256 pin."""
    priv, pub = generate_keypair()
    http = FakeHTTP(jwks={"keys": [jwk_for(pub, "k1")]})
    v = AccessTokenVerifier(_config(), session=http)
    now = int(time.time())
    forged = jwt.encode(
        {"sub": "attacker", "iss": ISSUER, "aud": "1", "exp": now + 600,
         "is_admin": True},
        "attacker-chosen-secret", algorithm="HS256", headers={"kid": "k1"},
    )
    with pytest.raises(AuthRejected):
        v.verify(forged)


def test_rejects_expired_token():
    priv, pub = generate_keypair()
    http = FakeHTTP(jwks={"keys": [jwk_for(pub, "k1")]})
    v = AccessTokenVerifier(_config(), session=http)
    with pytest.raises(AuthRejected):
        v.verify(make_token(priv, "k1", exp_delta=-10))


def test_rejects_wrong_audience():
    priv, pub = generate_keypair()
    http = FakeHTTP(jwks={"keys": [jwk_for(pub, "k1")]})
    v = AccessTokenVerifier(_config(), session=http)
    with pytest.raises(AuthRejected):
        v.verify(make_token(priv, "k1", aud="999"))


def test_rejects_wrong_issuer():
    priv, pub = generate_keypair()
    http = FakeHTTP(jwks={"keys": [jwk_for(pub, "k1")]})
    v = AccessTokenVerifier(_config(), session=http)
    with pytest.raises(AuthRejected):
        v.verify(make_token(priv, "k1", iss="evil"))


def test_unknown_kid_refetches_then_rejects():
    priv, pub = generate_keypair()
    http = FakeHTTP(jwks={"keys": [jwk_for(pub, "k1")]})
    v = AccessTokenVerifier(_config(), session=http)
    with pytest.raises(AuthRejected):
        v.verify(make_token(priv, "unknown-kid"))
    assert http.get_calls == 1   # it did try a refetch


def test_unknown_kid_refetch_is_rate_limited():
    priv, pub = generate_keypair()
    http = FakeHTTP(jwks={"keys": [jwk_for(pub, "k1")]})
    v = AccessTokenVerifier(_config(jwks_min_refetch_interval=300), session=http)
    for _ in range(5):
        with pytest.raises(AuthRejected):
            v.verify(make_token(priv, "missing"))
    assert http.get_calls == 1   # only the first unknown-kid triggered a fetch


def test_new_kid_is_picked_up_on_refetch():
    priv1, pub1 = generate_keypair()
    priv2, pub2 = generate_keypair()
    http = FakeHTTP(jwks={"keys": [jwk_for(pub1, "k1")]})
    v = AccessTokenVerifier(_config(jwks_min_refetch_interval=0), session=http)
    v.verify(make_token(priv1, "k1"))            # caches k1
    http._jwks = {"keys": [jwk_for(pub1, "k1"), jwk_for(pub2, "k2")]}
    claims = v.verify(make_token(priv2, "k2"))   # unknown kid -> refetch -> found
    assert claims["sub"] == "user-1"


def test_jwks_unreachable_raises_unavailable():
    http = FakeHTTP(get_exc=requests.ConnectionError("boom"))
    v = AccessTokenVerifier(_config(), session=http)
    priv, _ = generate_keypair()
    with pytest.raises(IdentityUnavailable):
        v.verify(make_token(priv, "k1"))


# --- client: the three calls ------------------------------------------------


def _client(http) -> IdentityClient:
    cfg = _config()
    return IdentityClient(cfg, session=http,
                          verifier=AccessTokenVerifier(cfg, session=http))


def test_sign_in_google_returns_body_on_200():
    http = FakeHTTP()
    http.queue_post(FakeResp({"access_token": "AT", "refresh_token": "RT"}))
    body = _client(http).sign_in("google", "google-token")
    assert body["access_token"] == "AT"
    assert http.post_calls[0][0].endswith("/auth/google")
    assert http.post_calls[0][1]["Authorization"] == f"Bearer {CREDENTIAL}"


def test_sign_in_discord_posts_exchange_code():
    http = FakeHTTP()
    http.queue_post(FakeResp({"access_token": "AT", "refresh_token": "RT"}))
    body = _client(http).sign_in("discord", "exchange-code")
    assert body["access_token"] == "AT"
    assert http.post_calls[0][0].endswith("/auth/discord/exchange")


def test_sign_in_unknown_provider_raises():
    with pytest.raises(ValueError):
        _client(FakeHTTP()).sign_in("myspace", "x")


def test_sign_in_401_raises_auth_rejected():
    http = FakeHTTP()
    http.queue_post(FakeResp(status=401))
    with pytest.raises(AuthRejected):
        _client(http).sign_in("google", "bad")


def test_refresh_5xx_raises_unavailable():
    http = FakeHTTP()
    http.queue_post(FakeResp(status=503))
    with pytest.raises(IdentityUnavailable):
        _client(http).refresh("RT")


def test_refresh_timeout_raises_unavailable():
    http = FakeHTTP()
    http.queue_post(requests.Timeout("slow"))
    with pytest.raises(IdentityUnavailable):
        _client(http).refresh("RT")


def test_logout_never_raises():
    http = FakeHTTP()
    http.queue_post(requests.ConnectionError("down"))
    _client(http).logout("RT")


# --- email+password ---------------------------------------------------------


def test_password_signup_returns_body_on_200():
    http = FakeHTTP()
    http.queue_post(FakeResp({"access_token": "AT", "refresh_token": "RT",
                              "user": {"id": "u", "email": "user@example.com",
                                       "is_new": True}}))
    body = _client(http).password_signup("user@example.com", "pw")
    assert body["access_token"] == "AT"
    assert http.post_calls[0][0].endswith("/auth/password/signup")
    assert http.post_calls[0][2] == {"email": "user@example.com", "password": "pw"}
    assert http.post_calls[0][1]["Authorization"] == f"Bearer {CREDENTIAL}"


def test_password_login_returns_body_on_200():
    http = FakeHTTP()
    http.queue_post(FakeResp({"access_token": "AT", "refresh_token": "RT"}))
    body = _client(http).password_login("user@example.com", "pw")
    assert body["access_token"] == "AT"
    assert http.post_calls[0][0].endswith("/auth/password/login")
    assert http.post_calls[0][2] == {"email": "user@example.com", "password": "pw"}


def test_password_signup_409_raises_password_rejected_with_status():
    http = FakeHTTP()
    http.queue_post(FakeResp({"detail": {"error": "Email already in use."}},
                             status=409))
    with pytest.raises(PasswordRejected) as exc:
        _client(http).password_signup("user@example.com", "pw")
    assert exc.value.status == 409
    assert exc.value.message == "Email already in use."


def test_password_signup_400_weak_password_carries_message():
    http = FakeHTTP()
    http.queue_post(FakeResp({"detail": {"error": "Password too weak."}},
                             status=400))
    with pytest.raises(PasswordRejected) as exc:
        _client(http).password_signup("user@example.com", "x")
    assert exc.value.status == 400
    assert exc.value.message == "Password too weak."


def test_password_login_401_raises_auth_rejected():
    http = FakeHTTP()
    http.queue_post(FakeResp(status=401))
    with pytest.raises(AuthRejected):
        _client(http).password_login("user@example.com", "bad")


def test_password_login_429_raises_password_rejected():
    http = FakeHTTP()
    http.queue_post(FakeResp({"detail": {"error": "Too many attempts."}},
                             status=429))
    with pytest.raises(PasswordRejected) as exc:
        _client(http).password_login("user@example.com", "pw")
    assert exc.value.status == 429


def test_password_5xx_raises_unavailable():
    http = FakeHTTP()
    http.queue_post(FakeResp(status=503))
    with pytest.raises(IdentityUnavailable):
        _client(http).password_login("user@example.com", "pw")


# --- password reset ---------------------------------------------------------


def test_password_reset_request_posts_email_and_returns_body():
    http = FakeHTTP()
    http.queue_post(FakeResp({"ok": True}))
    body = _client(http).password_reset_request("user@example.com")
    assert body == {"ok": True}
    assert http.post_calls[0][0].endswith("/auth/password/reset/request")
    assert http.post_calls[0][2] == {"email": "user@example.com"}


def test_password_reset_request_404_raises_password_rejected():
    http = FakeHTTP()
    http.queue_post(FakeResp({"detail": {"error": "Not enabled."}}, status=404))
    with pytest.raises(PasswordRejected) as exc:
        _client(http).password_reset_request("user@example.com")
    assert exc.value.status == 404


def test_password_reset_validate_returns_validity():
    http = FakeHTTP()
    http.queue_post(FakeResp({"valid": True}))
    body = _client(http).password_reset_validate("tok")
    assert body == {"valid": True}
    assert http.post_calls[0][0].endswith("/auth/password/reset/validate")
    assert http.post_calls[0][2] == {"token": "tok"}


def test_password_reset_confirm_posts_token_and_password():
    http = FakeHTTP()
    http.queue_post(FakeResp({"ok": True}))
    body = _client(http).password_reset_confirm("tok", "a new password")
    assert body == {"ok": True}
    assert http.post_calls[0][0].endswith("/auth/password/reset/confirm")
    assert http.post_calls[0][2] == {"token": "tok", "password": "a new password"}


def test_password_reset_confirm_400_raises_password_rejected():
    http = FakeHTTP()
    http.queue_post(FakeResp({"detail": {"error": "Link no longer valid."}},
                             status=400))
    with pytest.raises(PasswordRejected) as exc:
        _client(http).password_reset_confirm("stale", "a new password")
    assert exc.value.status == 400


# --- google client id discovery ---------------------------------------------


def test_google_client_id_discovered_from_auth_providers():
    http = FakeHTTP(providers={"providers": [{"id": "google", "client_id": "abc.apps"}]})
    assert _client(http).google_client_id() == "abc.apps"


def test_google_client_id_sends_service_credential():
    """Discovery carries the service credential so identity can return this
    service's own client id (per-service Google client, SPEC §9)."""
    http = FakeHTTP(providers={"providers": [{"id": "google", "client_id": "abc.apps"}]})
    _client(http).google_client_id()
    assert http.last_get_headers == {"Authorization": f"Bearer {CREDENTIAL}"}


def test_google_client_id_is_cached():
    http = FakeHTTP(providers={"providers": [{"id": "google", "client_id": "abc.apps"}]})
    c = _client(http)
    c.google_client_id()
    c.google_client_id()
    assert http.get_calls == 1   # second call served from cache


def test_google_client_id_none_when_unreachable():
    http = FakeHTTP(get_exc=requests.ConnectionError("down"))
    assert _client(http).google_client_id() is None


# --- discord discovery ------------------------------------------------------


def test_discord_start_url_built_when_advertised():
    http = FakeHTTP(
        providers={"providers": [{"id": "google", "client_id": "abc"}, {"id": "discord"}]}
    )
    url = _client(http).discord_start_url()
    assert url is not None
    assert url.endswith("/auth/discord/start?service_id=1")


def test_discord_start_url_none_when_not_advertised():
    http = FakeHTTP(providers={"providers": [{"id": "google", "client_id": "abc"}]})
    assert _client(http).discord_start_url() is None


# --- helpers ----------------------------------------------------------------


def test_is_admin_claim_requires_true_value():
    assert is_admin_claim({"is_admin": True}) is True
    assert is_admin_claim({"is_admin": "true"}) is False
    assert is_admin_claim({"is_admin": 1}) is False
    assert is_admin_claim({}) is False


def test_config_rejects_malformed_credential():
    with pytest.raises(ValueError):
        IdentityConfig(base_url="https://x", service_credential="nodot")


def test_config_derives_service_id():
    cfg = _config(service_credential="42.secret")
    assert cfg.service_id == "42"


# --- FakeIdentity (the shipped test double) ---------------------------------


def test_fake_identity_admin_and_demotion():
    from identity_client.testing import FakeIdentity
    fake = FakeIdentity()
    assert is_admin_claim(fake.verify(fake.sign_in("google", "g")["access_token"])) is True
    fake.refresh_admin = False
    assert is_admin_claim(fake.verify("AT2")) is False
    assert fake.sign_in_calls == [("google", "g")]
