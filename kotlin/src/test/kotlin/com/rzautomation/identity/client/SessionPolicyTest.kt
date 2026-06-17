package com.rzautomation.identity.client

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class SessionPolicyTest {

    private val pair = TestSupport.keyPair()

    /** An IdentityClient whose `/auth/refresh` returns a freshly minted token and
     *  whose JWKS endpoint serves the matching key. */
    private fun clientReturningRefreshToken(isAdmin: Boolean = false): Pair<IdentityClient, FakeTransport> {
        val transport = FakeTransport().apply {
            onGet("jwks") { HttpResult(200, TestSupport.jwksBody("k1", pair)) }
            onPost("/auth/refresh") {
                val token = TestSupport.mintToken(pair, isAdmin = isAdmin)
                HttpResult(200, """{"access_token":"$token","expires_at":"2026-01-01T00:00:00Z"}""")
            }
        }
        return IdentityClient(TestSupport.config(), transport) to transport
    }

    private fun session(axp: Long, iat: Long = NOW, seen: Long = NOW, adm: Boolean = false) =
        IdentitySession(
            uid = "user-uuid-0001", email = "player@example.test", rt = "refresh-token",
            axp = axp, adm = adm, iat = iat, seen = seen,
        )

    @Test
    fun `null session is denied`() {
        val (client, _) = clientReturningRefreshToken()
        val policy = SessionPolicy(client, clock = { NOW })
        assertIs<SessionDecision.Denied>(policy.evaluate(null))
    }

    @Test
    fun `a fresh session authenticates without refreshing`() {
        val (client, transport) = clientReturningRefreshToken()
        val policy = SessionPolicy(client, clock = { NOW })
        val decision = policy.evaluate(session(axp = NOW + 10_000))
        val authed = assertIs<SessionDecision.Authenticated>(decision)
        assertEquals(NOW, authed.session.seen)        // last-seen bumped
        assertTrue(transport.postCalls.isEmpty())     // no refresh call
    }

    @Test
    fun `a session past the absolute lifetime is denied`() {
        val (client, _) = clientReturningRefreshToken()
        val policy = SessionPolicy(client, clock = { NOW })
        val tooOld = session(axp = NOW + 10_000, iat = NOW - 8 * 24 * 3600)
        assertIs<SessionDecision.Denied>(policy.evaluate(tooOld))
    }

    @Test
    fun `an idle session is denied`() {
        val (client, _) = clientReturningRefreshToken()
        val policy = SessionPolicy(client, clock = { NOW })
        val idle = session(axp = NOW + 10_000, seen = NOW - 13 * 3600)
        assertIs<SessionDecision.Denied>(policy.evaluate(idle))
    }

    @Test
    fun `idle opt-out keeps a long-idle session alive`() {
        val (client, _) = clientReturningRefreshToken()
        val policy = SessionPolicy(client, idleTimeoutSeconds = null, clock = { NOW })
        val idle = session(axp = NOW + 10_000, seen = NOW - 13 * 3600)
        assertIs<SessionDecision.Authenticated>(policy.evaluate(idle))
    }

    @Test
    fun `a near-expiry access token triggers a refresh`() {
        val (client, transport) = clientReturningRefreshToken()
        val policy = SessionPolicy(client, clock = { NOW })
        // axp within the refresh skew window -> refresh.
        val decision = policy.evaluate(session(axp = NOW))
        val authed = assertIs<SessionDecision.Authenticated>(decision)
        assertTrue(transport.postCalls.any { it.first.contains("/auth/refresh") })
        assertTrue(authed.session.axp > NOW)          // axp advanced past the old value
    }

    @Test
    fun `a failed refresh fails closed`() {
        val transport = FakeTransport().apply {
            onGet("jwks") { HttpResult(200, TestSupport.jwksBody("k1", pair)) }
            onPost("/auth/refresh") { HttpResult(401, "") }
        }
        val client = IdentityClient(TestSupport.config(), transport)
        val policy = SessionPolicy(client, clock = { NOW })
        assertIs<SessionDecision.Denied>(policy.evaluate(session(axp = NOW)))
    }

    @Test
    fun `admin-only session ends when a refresh loses is_admin`() {
        val (client, _) = clientReturningRefreshToken(isAdmin = false)
        val policy = SessionPolicy(client, adminOnly = true, clock = { NOW })
        // Was admin, but the refreshed token is not -> demotion kill-switch.
        assertIs<SessionDecision.Denied>(policy.evaluate(session(axp = NOW, adm = true)))
    }

    private companion object {
        const val NOW = 1_000_000L   // fixed epoch seconds for deterministic bounds math
    }
}
