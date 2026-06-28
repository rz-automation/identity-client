package com.rzautomation.identity.client

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class IdentityClientTest {

    private fun clientWith(transport: FakeTransport) =
        IdentityClient(TestSupport.config(), transport)

    @Test
    fun `signIn google parses the auth response`() {
        val transport = FakeTransport().apply {
            onPost("/auth/google") {
                HttpResult(
                    200,
                    """{"access_token":"a","refresh_token":"r","expires_at":"2026-01-01T00:00:00Z",
                       "user":{"id":"user-uuid-0001","email":"player@example.test","is_new":true}}""",
                )
            }
        }
        val resp = clientWith(transport).signIn("google", "google-id-token")
        assertEquals("a", resp.accessToken)
        assertEquals("r", resp.refreshToken)
        assertEquals("user-uuid-0001", resp.user.id)
        assertTrue(resp.user.isNew)
    }

    @Test
    fun `401 maps to AuthRejected`() {
        val transport = FakeTransport().apply {
            onPost("/auth/google") { HttpResult(401, "") }
        }
        assertFailsWith<AuthRejected> { clientWith(transport).signIn("google", "x") }
    }

    @Test
    fun `5xx maps to IdentityUnavailable`() {
        val transport = FakeTransport().apply {
            onPost("/auth/google") { HttpResult(503, "down") }
        }
        assertFailsWith<IdentityUnavailable> { clientWith(transport).signIn("google", "x") }
    }

    @Test
    fun `non-JSON success body maps to IdentityUnavailable`() {
        val transport = FakeTransport().apply {
            onPost("/auth/refresh") { HttpResult(200, "not json") }
        }
        assertFailsWith<IdentityUnavailable> { clientWith(transport).refresh("r") }
    }

    @Test
    fun `transport failure maps to IdentityUnavailable`() {
        val transport = FakeTransport().apply { postThrows = true }
        assertFailsWith<IdentityUnavailable> { clientWith(transport).signIn("google", "x") }
    }

    @Test
    fun `unknown provider throws IllegalArgumentException`() {
        val transport = FakeTransport()
        assertFailsWith<IllegalArgumentException> { clientWith(transport).signIn("myspace", "x") }
    }

    @Test
    fun `password login surfaces an actionable 429 with its message`() {
        val transport = FakeTransport().apply {
            onPost("/auth/password/login") {
                HttpResult(429, """{"detail":{"error":"Too many attempts. Try again later."}}""")
            }
        }
        val ex = assertFailsWith<PasswordRejected> {
            clientWith(transport).passwordLogin("user@example.com", "pw")
        }
        assertEquals(429, ex.status)
        assertEquals("Too many attempts. Try again later.", ex.message)
    }

    @Test
    fun `password signup 401 is AuthRejected not PasswordRejected`() {
        val transport = FakeTransport().apply {
            onPost("/auth/password/signup") { HttpResult(401, "") }
        }
        assertFailsWith<AuthRejected> {
            clientWith(transport).passwordSignup("user@example.com", "pw")
        }
    }

    @Test
    fun `logout never throws even when the transport fails`() {
        val transport = FakeTransport().apply { postThrows = true }
        clientWith(transport).logout("r") // no exception
    }

    @Test
    fun `providers are cached and served stale when identity is unreachable`() {
        var calls = 0
        val transport = FakeTransport().apply {
            onGet("/auth-providers") {
                calls++
                HttpResult(200, """{"providers":[{"id":"google","client_id":"gcid-123"}]}""")
            }
        }
        val client = clientWith(transport)

        assertEquals("gcid-123", client.googleClientId())
        assertEquals("gcid-123", client.googleClientId()) // cache hit, no second fetch
        assertEquals(1, calls)

        // Now make the endpoint fail; the cached value is served.
        transport.getThrows = true
        assertEquals("gcid-123", client.googleClientId())
    }

    @Test
    fun `deleteAccount treats 200 and 404 alike as success`() {
        val ok = FakeTransport().apply { onPost("/delete") { HttpResult(200, """{"ok":true}""") } }
        clientWith(ok).deleteAccount("user-uuid-0001") // no throw

        val gone = FakeTransport().apply {
            onPost("/delete") { HttpResult(404, """{"detail":{"error":"User not found."}}""") }
        }
        clientWith(gone).deleteAccount("user-uuid-0001") // idempotent, no throw
    }

    @Test
    fun `deleteAccount 401 maps to AuthRejected`() {
        val transport = FakeTransport().apply { onPost("/delete") { HttpResult(401, "") } }
        assertFailsWith<AuthRejected> { clientWith(transport).deleteAccount("user-uuid-0001") }
    }

    @Test
    fun `deleteAccount 5xx maps to IdentityUnavailable`() {
        val transport = FakeTransport().apply { onPost("/delete") { HttpResult(500, "boom") } }
        assertFailsWith<IdentityUnavailable> { clientWith(transport).deleteAccount("user-uuid-0001") }
    }

    @Test
    fun `deleteAccount transport failure maps to IdentityUnavailable`() {
        val transport = FakeTransport().apply { postThrows = true }
        assertFailsWith<IdentityUnavailable> { clientWith(transport).deleteAccount("user-uuid-0001") }
    }

    @Test
    fun `discordStartUrl is null when discord is not advertised`() {
        val transport = FakeTransport().apply {
            onGet("/auth-providers") {
                HttpResult(200, """{"providers":[{"id":"google","client_id":"gcid-123"}]}""")
            }
        }
        assertNull(clientWith(transport).discordStartUrl())
    }

    @Test
    fun `discordStartUrl carries the service id when discord is enabled`() {
        val transport = FakeTransport().apply {
            onGet("/auth-providers") {
                HttpResult(200, """{"providers":[{"id":"google"},{"id":"discord"}]}""")
            }
        }
        assertEquals(
            "${TestSupport.BASE_URL}/auth/discord/start?service_id=${TestSupport.SERVICE_ID}",
            clientWith(transport).discordStartUrl(),
        )
    }

    // --- refresh coalescing ---

    private fun refreshPosts(transport: FakeTransport) =
        transport.postCalls.count { it.first.contains("/auth/refresh") }

    @Test
    fun `concurrent refresh of the same token coalesces to one call`() {
        val transport = FakeTransport().apply {
            onPost("/auth/refresh") {
                HttpResult(200, """{"access_token":"a","expires_at":"t"}""")
            }
        }
        val client = IdentityClient(TestSupport.config(), transport)

        val n = 12
        val barrier = java.util.concurrent.CyclicBarrier(n)
        val results = java.util.Collections.synchronizedList(mutableListOf<RefreshResponse>())
        val threads = (1..n).map {
            kotlin.concurrent.thread {
                barrier.await() // release all at once to maximise overlap
                results.add(client.refresh("r"))
            }
        }
        threads.forEach { it.join() }

        assertEquals(n, results.size)
        assertTrue(results.all { it.accessToken == "a" })
        assertEquals(1, refreshPosts(transport)) // twelve callers, one network refresh
    }

    @Test
    fun `refresh of different tokens does not coalesce`() {
        var n = 0
        val transport = FakeTransport().apply {
            onPost("/auth/refresh") { n++; HttpResult(200, """{"access_token":"a$n","expires_at":"t"}""") }
        }
        val client = IdentityClient(TestSupport.config(), transport)
        assertEquals("a1", client.refresh("r1").accessToken)
        assertEquals("a2", client.refresh("r2").accessToken)
        assertEquals(2, refreshPosts(transport)) // distinct tokens never share a refresh
    }

    @Test
    fun `refresh caches within the window then refetches after it`() {
        var n = 0
        val transport = FakeTransport().apply {
            onPost("/auth/refresh") { n++; HttpResult(200, """{"access_token":"a$n","expires_at":"t"}""") }
        }
        var now = 1_000L
        val client = IdentityClient(
            TestSupport.config(), transport, clock = { now }, refreshCoalesceMillis = 50,
        )
        assertEquals("a1", client.refresh("r").accessToken)
        assertEquals("a1", client.refresh("r").accessToken) // within window: reuse
        now = 1_100L                                         // window lapses
        assertEquals("a2", client.refresh("r").accessToken) // fresh network call
        assertEquals(2, refreshPosts(transport))
    }

    @Test
    fun `refresh coalescing can be disabled`() {
        var n = 0
        val transport = FakeTransport().apply {
            onPost("/auth/refresh") { n++; HttpResult(200, """{"access_token":"a$n","expires_at":"t"}""") }
        }
        val client = IdentityClient(TestSupport.config(), transport, refreshCoalesceMillis = 0)
        client.refresh("r")
        client.refresh("r")
        assertEquals(2, refreshPosts(transport)) // disabled: each call hits identity
    }

    @Test
    fun `a failed refresh is not cached`() {
        var c = 0
        val transport = FakeTransport().apply {
            onPost("/auth/refresh") {
                c++
                if (c == 1) HttpResult(401, "") else HttpResult(200, """{"access_token":"a","expires_at":"t"}""")
            }
        }
        val client = IdentityClient(TestSupport.config(), transport)
        assertFailsWith<AuthRejected> { client.refresh("r") }
        // The failure was not cached, so a later call actually retries identity.
        assertEquals("a", client.refresh("r").accessToken)
        assertEquals(2, refreshPosts(transport))
    }
}
