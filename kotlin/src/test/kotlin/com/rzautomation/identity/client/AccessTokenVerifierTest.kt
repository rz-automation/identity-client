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
            verifierWith(transport).verify(TestSupport.mintToken(pair, audience = "999"))
        }
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
