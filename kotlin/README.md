# identity-client (Kotlin / JVM)

The JVM backend SDK for the shared `identity` auth service: the Kotlin sibling of
[`../python`](../python). It implements [`../CONTRACT.md`](../CONTRACT.md): the
server-to-server calls, the RS256 access-token verifier, and the framework-neutral
session state machine. The core is dependency-light (jjwt + kotlinx-serialization;
HTTP via the JDK's own `java.net.http`), so any JVM backend can depend on it
without pulling in a web framework.

Nothing secret lives here. The SDK only calls identity and verifies tokens against
its public JWKS; the service credential is supplied at runtime, and the provider
OAuth secrets never leave identity.

## Install (JitPack)

JitPack builds this subfolder from a repo tag (see [`../jitpack.yml`](../jitpack.yml)).

```kotlin
repositories {
    maven("https://jitpack.io")
}
dependencies {
    implementation("com.github.rz-automation:identity-client:0.9.1")
}
```

> JitPack maps this repo's single build artifact to
> `com.github.rz-automation:identity-client:<tag>` (verified against the published
> tag). The same coordinate is produced by `./gradlew publishToMavenLocal`, so an
> offline build resolves it from `mavenLocal()` identically.

## Use

```kotlin
val config = IdentityConfig(
    baseUrl = System.getenv("IDENTITY_BASE_URL"),       // e.g. https://identity.example.com
    serviceCredential = System.getenv("IDENTITY_CREDENTIAL"), // "<service-id>.<secret>"
)
val identity = IdentityClient(config)

// 1. Login: relay the browser's Google ID token, verify, open a session.
val auth = identity.signIn("google", googleIdToken)        // throws AuthRejected / IdentityUnavailable
val claims = identity.verify(auth.accessToken)             // RS256 + iss + aud + exp
val session = SessionPolicy(identity).newSession(claims, auth.refreshToken)
// ... sign `session` into your own HttpOnly, Secure cookie.

// 2. Per request: decode the cookie to an IdentitySession, then gate.
when (val decision = policy.evaluate(decodedSession)) {
    is SessionDecision.Authenticated -> {
        // re-encode decision.session onto the response (expiry/last-seen bumped)
        val userId = decision.session.uid
    }
    SessionDecision.Denied -> { /* 401, clear the cookie */ }
}

// 3. Logout.
identity.logout(session.rt)
```

`IdentityClient`, `AccessTokenVerifier`, and `SessionPolicy` are all synchronous
and blocking. From a coroutine, wrap the calls that touch identity (`signIn`,
`refresh`, `verify` on a cold cache, `evaluate` when it refreshes) in
`withContext(Dispatchers.IO)`.

### What stays on the consumer

The cookie's signing scheme is the consumer's own choice (each service signs with
its own secret; sessions are never shared across services), so it is deliberately
not part of this SDK. The login HTTP routes (`/login`, `/logout`, `/session`) and
the browser login module are likewise the consumer's; the shared browser module
lives in [`../web`](../web).

## Security invariants (do NOT weaken)

These are enforced in `AccessTokenVerifier` and covered by the tests:

- **RS256 pinned** from config, never read from the token header. `none` and every
  HMAC alg are rejected (alg-confusion forgery).
- Signature verified against the JWK matching the token's `kid`; then `iss ==
  "identity"`, `aud == serviceId`, and `exp` present and unexpired.
- JWKS cache bounded by a TTL; refetches on an unknown `kid` are rate-limited so
  they cannot amplify into a fetch DoS against identity.
- Every failure denies (fail closed). A 401 means the subject is invalid; an
  outage/5xx/malformed body also denies but says nothing about the subject.

## Develop

```sh
./gradlew test                # run the suite
./gradlew publishToMavenLocal  # what JitPack runs
```
