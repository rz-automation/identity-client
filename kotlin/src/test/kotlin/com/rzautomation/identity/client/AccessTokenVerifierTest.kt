package com.rzautomation.identity.client

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AccessTokenVerifierTest {

    private fun verifierWith(transport: FakeTransport, nano: () -> Long = System::nanoTime) =
        AccessTokenVerifier(TestSupport.config(), transport, nano)

    @Test
    fun `verifies a well-formed token and returns claims`() {
        val pair = TestSupport.keyPair()
        val transport = FakeTransport().apply {
            onGet("jwks") { HttpResult(200, TestSupport.jwksBody("k1", pair)) }
        }
        val claims = verifierWith(transport)
            .verify(TestSupport.mintToken(pair, sub = "user-uuid-0001", isAdmin = true))

        assertEquals("user-uuid-0001", claims.subject)
        assertEquals("identity", claims.issuer)
        assertTrue(TestSupport.SERVICE_ID in claims.audience)
        assertTrue(isAdminClaim(claims))
    }

    @Test
    fun `is_admin absent reads as not admin`() {
        val pair = TestSupport.keyPair()
        val transport = FakeTransport().apply {
            onGet("jwks") { HttpResult(200, TestSupport.jwksBody("k1", pair)) }
        }
        val claims = verifierWith(transport).verify(TestSupport.mintToken(pair, isAdmin = false))
        assertFalse(isAdminClaim(claims))
    }

    @Test
    fun `rejects an alg-confusion HMAC token`() {
        val pair = TestSupport.keyPair()
        val transport = FakeTransport().apply {
            onGet("jwks") { HttpResult(200, TestSupport.jwksBody("k1", pair)) }
        }
        // Must be rejected on the pinned-alg check, before any signature work.
        assertFailsWith<AuthRejected> {
            verifierWith(transport).verify(TestSupport.mintAlgConfusionToken(pair))
        }
    }

    @Test
    fun `rejects a token minted for another service (wrong aud)`() {
        val pair = TestSupport.keyPair()
        val transport = FakeTransport().apply {
            onGet("jwks") { HttpResult(200, TestSupport.jwksBody("k1", pair)) }
        }
        assertFailsWith<AuthRejected> {
            verifierWith(transport).verify(TestSupport.mintToken(pair, audiences = listOf("999")))
        }
    }

    @Test
    fun `accepts a multi-value aud array that includes this service`() {
        val pair = TestSupport.keyPair()
        val transport = FakeTransport().apply {
            onGet("jwks") { HttpResult(200, TestSupport.jwksBody("k1", pair)) }
        }
        val claims = verifierWith(transport)
            .verify(TestSupport.mintToken(pair, audiences = listOf("999", TestSupport.SERVICE_ID)))
        assertTrue(TestSupport.SERVICE_ID in claims.audience)
    }

    @Test
    fun `rejects an alg-none token at the header gate`() {
        val transport = FakeTransport()  // no JWKS route: must reject before any fetch
        assertFailsWith<AuthRejected> {
            verifierWith(transport).verify(TestSupport.craftedToken("""{"alg":"none","kid":"k1"}"""))
        }
    }

    @Test
    fun `rejects a token with no kid`() {
        val transport = FakeTransport()
        assertFailsWith<AuthRejected> {
            verifierWith(transport).verify(TestSupport.craftedToken("""{"alg":"RS256"}"""))
        }
    }

    @Test
    fun `rejects a signed token that carries no exp`() {
        val pair = TestSupport.keyPair()
        val transport = FakeTransport().apply {
            onGet("jwks") { HttpResult(200, TestSupport.jwksBody("k1", pair)) }
        }
        assertFailsWith<AuthRejected> {
            verifierWith(transport).verify(TestSupport.mintToken(pair, includeExp = false))
        }
    }

    @Test
    fun `stale cache refetches past the TTL and rejects a rotated-out key`() {
        val k1pair = TestSupport.keyPair()
        val k2pair = TestSupport.keyPair()
        var now = 1_000_000_000L
        // First fetch serves only k1; after rotation the endpoint serves only k2.
        var rotated = false
        val transport = FakeTransport().apply {
            onGet("jwks") {
                if (rotated) HttpResult(200, TestSupport.jwksBody("k2", k2pair))
                else HttpResult(200, TestSupport.jwksBody("k1", k1pair))
            }
        }
        // TTL 600s; drive the monotonic clock by hand (nanoseconds).
        val verifier = AccessTokenVerifier(TestSupport.config(jwksCacheTtlSeconds = 600), transport) { now }

        // k1 verifies and is cached.
        verifier.verify(TestSupport.mintToken(k1pair, kid = "k1"))
        assertEquals(1, transport.getCalls.size)

        // Rotate the JWKS and advance the clock past the TTL: the next verify must
        // refetch, and a token under the now-retired k1 must be rejected.
        rotated = true
        now += 601_000_000_000L  // 601s in ns
        assertFailsWith<AuthRejected> { verifier.verify(TestSupport.mintToken(k1pair, kid = "k1")) }
        assertEquals(2, transport.getCalls.size)         // TTL lapse forced a refetch

        // And a token under the new k2 now verifies.
        verifier.verify(TestSupport.mintToken(k2pair, kid = "k2"))
    }

    @Test
    fun `rejects a wrong issuer`() {
        val pair = TestSupport.keyPair()
        val transport = FakeTransport().apply {
            onGet("jwks") { HttpResult(200, TestSupport.jwksBody("k1", pair)) }
        }
        assertFailsWith<AuthRejected> {
            verifierWith(transport).verify(TestSupport.mintToken(pair, issuer = "evil"))
        }
    }

    @Test
    fun `rejects an expired token`() {
        val pair = TestSupport.keyPair()
        val transport = FakeTransport().apply {
            onGet("jwks") { HttpResult(200, TestSupport.jwksBody("k1", pair)) }
        }
        assertFailsWith<AuthRejected> {
            verifierWith(transport).verify(TestSupport.mintToken(pair, expiresInSeconds = -10))
        }
    }

    @Test
    fun `rejects a token signed by an unrelated key`() {
        val real = TestSupport.keyPair()
        val attacker = TestSupport.keyPair()
        val transport = FakeTransport().apply {
            onGet("jwks") { HttpResult(200, TestSupport.jwksBody("k1", real)) }
        }
        // Same kid, signed with a different private key: signature must fail.
        assertFailsWith<AuthRejected> {
            verifierWith(transport).verify(TestSupport.mintToken(attacker, kid = "k1"))
        }
    }

    @Test
    fun `unknown kid refetches once then is rate-limited`() {
        val pair = TestSupport.keyPair()
        val transport = FakeTransport().apply {
            onGet("jwks") { HttpResult(200, TestSupport.jwksBody("k1", pair)) }
        }
        // Freeze monotonic time so the refetch interval never lapses between calls.
        val verifier = verifierWith(transport) { 1_000_000_000L }
        val tokenUnknownKid = TestSupport.mintToken(pair, kid = "k2")

        assertFailsWith<AuthRejected> { verifier.verify(tokenUnknownKid) }
        assertFailsWith<AuthRejected> { verifier.verify(tokenUnknownKid) }
        // First call fetched; the second was rate-limited (no second fetch).
        assertEquals(1, transport.getCalls.size)
    }

    @Test
    fun `JWKS fetch failure surfaces as IdentityUnavailable`() {
        val pair = TestSupport.keyPair()
        val transport = FakeTransport().apply { getThrows = true }
        assertFailsWith<IdentityUnavailable> {
            verifierWith(transport).verify(TestSupport.mintToken(pair))
        }
    }
}
