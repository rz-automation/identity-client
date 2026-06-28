# identity client contract

The single source of truth every client implements against. A new backend SDK
(another language, e.g. Kotlin) or a non-FastAPI binding should be able to be
written from this document alone, without reading another language's source.

`identity` is the auth service. It owns the providers (Google, Discord), mints
RS256 access tokens, and holds the only long-lived secret material. A **client**
never sees a provider secret: it only calls identity with its own service
credential, verifies tokens against identity's public JWKS, and (for the browser)
sends the user through identity for the OAuth dance.

There are two kinds of client, and they are different things:

- **Backend SDK** (one per language: `python/`, future `kotlin/`, ...). Runs on the
  consumer's server. Makes the server-to-server calls, verifies access tokens,
  and runs the session state machine.
- **Web frontend** (`web/`, exactly one, because browsers run JS regardless of
  backend). Renders the login buttons and runs each provider's browser flow,
  talking only to the consumer's own backend (same-origin), never to identity.

---

## 1. Service credential

identity issues each service a credential `"<service-id>.<secret>"`. The backend
SDK sends it as `Authorization: Bearer <service-id>.<secret>` on every
server-to-server call. The access token's `aud` equals `str(service-id)`, so the
id is both the credential prefix and the expected audience. The secret is
server-side only and never reaches a browser.

---

## 2. Server-to-server endpoints (backend SDK, credentialed)

All require the `Authorization: Bearer` credential. None emit CORS. JSON in/out.
On failure: `401` means reject (bad credential/token); any other `>= 400` or a
non-JSON body means treat as unavailable. Both deny (see §5).

| Method | Path | Request | Response |
|--------|------|---------|----------|
| POST | `/auth/google` | `{ "google_id_token": str }` | `{ access_token, refresh_token, expires_at, user: { id, email, is_new } }` |
| POST | `/auth/discord/exchange` | `{ "code": str }` | same as `/auth/google` |
| POST | `/auth/password/signup` | `{ "email": str, "password": str }` | same as `/auth/google`. Errors: `400` weak password, `409` email taken, `404` password not enabled. |
| POST | `/auth/password/login` | `{ "email": str, "password": str }` | same as `/auth/google`. Errors: `401` generic (wrong/unknown), `429` rate-limited, `404` not enabled. |
| POST | `/auth/refresh` | `{ "refresh_token": str }` | `{ access_token, expires_at }` |
| POST | `/auth/logout` | `{ "refresh_token": str }` | `{ "ok": true }` (best-effort; always succeeds) |
| POST | `/api/v1/users/{id}/delete` | (none) | `{ "ok": true }`. Realm-local GDPR delete, scoped to a user this service serves. Idempotent: `404` (already gone / out of scope) is treated as success by the client (`delete_account` / `deleteAccount`). |
| GET | `/auth-providers` | (credential optional) | `{ "providers": [ { "id": "google", "client_id": str\|null }, { "id": "discord" }, { "id": "password" } ] }` |

`sign_in(provider, credential)` dispatches: `google` -> `/auth/google` with
`{google_id_token: credential}`; `discord` -> `/auth/discord/exchange` with
`{code: credential}`. Both return the same body. Email+password is separate
(two fields, not one relayed token): `password_signup(email, password)` ->
`/auth/password/signup` and `password_login(email, password)` ->
`/auth/password/login`. The actionable 4xx above (`400/404/409/429`) carry
`{ "detail": { "error": str } }`; a client surfaces them with their status
rather than collapsing to "unavailable".

---

## 3. Public endpoints (no credential)

| Method | Path | Notes |
|--------|------|-------|
| GET | `/.well-known/jwks.json` | `{ "keys": [ JWK, ... ] }`. CORS `*`. The verify path's key source. |
| GET | `/auth/discord/start?service_id=<id>` | Browser navigates here (top-level). 302 to discord.com. 404 if Discord is off for the service. |
| GET | `/auth/discord/callback?code=&state=` | identity's own Discord redirect target. Resolves the user and 302s the browser to the service's registered return URL with `?code=<exchange_code>` (or `?error=...`). |

The browser-facing Discord start URL a backend SDK exposes to its frontend is
`<base_url>/auth/discord/start?service_id=<service-id>` (built from config; only
present when `/auth-providers` advertises `discord`).

---

## 4. Access-token verification (the security core — do NOT weaken)

Every access token is verified fully and unconditionally:

- **Algorithm pinned to `RS256`** from the verifier's own config, never read from
  the token header. Reject `none` and every HMAC alg. (identity publishes its RSA
  *public* key; an HMAC-accepting verifier could be handed a token HMAC-signed
  with that public key — the classic alg-confusion forgery.)
- Verify the **signature** against the JWK whose `kid` matches the token header.
- `iss == "identity"`.
- `aud == str(service-id)` (this is what stops a token minted for another service
  being replayed here).
- `exp` present and not in the past.
- Require the `exp`, `iss`, `aud` claims to be present.

Access token claims:
`{ iss: "identity", sub, aud: str(service-id), email?, is_admin?, iat, exp, jti }`.
`is_admin` is emitted **only when true** (absent otherwise) — gate on the value
being exactly `true`, not on presence.

**JWKS cache:** cache keys by `kid`. An unknown `kid` triggers a refetch, but
**rate-limit** refetches (so a stream of random-kid tokens cannot amplify into a
fetch DoS against identity) and bound the whole cache with a **TTL** (so a revoked
key ages out within that window). On an unknown kid while rate-limited, serve a
cached key if present, else reject.

---

## 5. Fail-closed rule

Any uncertainty denies. A `401` denies (the subject is not/no longer valid). An
outage, timeout, `5xx`, or malformed body also denies — it just is not a statement
about the subject. A client should distinguish the two only for logging.

---

## 6. Session contract (backend SDK)

A logged-in session is a single signed, `HttpOnly`, `Secure` cookie the consumer
backend owns. identity sets no cookie. The cookie carries this dict:

```
{
  "uid":   str,        # identity subject (global user id)
  "email": str | null,
  "rt":    str,        # identity refresh token (secret; server-side only)
  "axp":   int,        # verified access-token expiry (unix seconds)
  "adm":   bool,       # is_admin at last verify
  "iat":   int,        # login time (absolute-lifetime anchor)
  "seen":  int         # last-seen time (idle-timeout anchor)
}
```

Gate decision (`SessionPolicy.evaluate` in the Python SDK is the reference):

1. No valid cookie, or out of bounds -> deny. Bounds: `rt` present; `now - iat <
   absolute_lifetime`; and (unless idle is opted out) `now - seen < idle_timeout`.
2. If `now >= axp - refresh_skew`, refresh: call `/auth/refresh`, verify the new
   access token (§4), and **fail closed** on any error (or, in admin-only mode, on
   a lost `is_admin`). Update `axp`/`adm`.
3. Bump `seen` and re-issue the cookie.

`IdentityClient.refresh` coalesces concurrent calls for the same refresh token into
one network call (a short result cache keyed by the token, `refresh_coalesce_seconds`
/ `refreshCoalesceMillis`, default 10s, 0 to disable). A page load fires many
authenticated requests at once and the gate refreshes from each; without coalescing
that multiplies into one `/auth/refresh` per request. Coalescing is a transport
optimisation only -- it never changes the gate's deny/allow decision, and errors are
never cached.

The signing scheme of the cookie is the binding's own choice (each service signs
with its own secret; sessions are never shared across services), so it is **not**
part of this cross-language contract.

---

## 7. Consumer login surface (frontend <-> backend)

The browser talks only to the consumer backend (same-origin), which relays to
identity. A binding (the Python `auth_router` is the reference) exposes:

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/auth-config` | `{ providers: [ { id: "google", client_id }, { id: "discord", start_url }, { id: "password" } ] }` — what buttons to render (each provider present only when enabled). |
| POST | `/login` | `{ provider, credential }` -> establish session, `{ "ok": true }`. Used by Google (the relayed GIS credential). |
| POST | `/password/signup` | `{ email, password }` -> establish session, `{ "ok": true }`. On the actionable 4xx returns that status with `{ "error": str }`. |
| POST | `/password/login` | `{ email, password }` -> establish session, `{ "ok": true }`. `401` is generic ("Incorrect email or password."); `429/404` pass through with `{ "error": str }`. |
| GET | `/discord/callback` | The browser-facing Discord return target. Registered as the service's return URL in identity. Reads `?code`, establishes the session, redirects to the app (`?error=...` on failure). |
| POST | `/logout` | Revoke + clear. |
| GET | `/session` | `{ "authenticated": bool }`. |

---

## 8. Provider flows

**Google** (in-page, no full redirect):
1. Frontend loads Google Identity Services, renders the button using the
   `client_id` from `/auth-config`.
2. On credential, frontend POSTs `{ provider: "google", credential }` to the
   backend `/login`.
3. Backend `sign_in("google", credential)` -> `/auth/google`, verifies the access
   token, establishes the session.

**Discord** (broker; full redirect, secret stays on identity):
1. Frontend navigates the browser to `<base_url>/auth/discord/start?service_id=<id>`.
2. identity 302s to discord.com (scope `identify email`), signed state binds the
   service.
3. discord.com returns to identity's `/auth/discord/callback`. identity exchanges
   the code, **requires a verified email** (`verified == true` and non-empty),
   resolves/creates the user, mints a single-use exchange code, and 302s the
   browser to the service's registered return URL (`/discord/callback`) with
   `?code=<exchange_code>`.
4. Backend `/discord/callback` calls `sign_in("discord", code)` ->
   `/auth/discord/exchange`, verifies, establishes the session, redirects to the app.

The verified-email requirement is mandatory: identity merges a Google and a
Discord login into one account when the email matches, so an unverified email
would be an account-takeover primitive. The merge happens once at first link;
thereafter the stable `(provider, provider_id)` pair keys the account.
