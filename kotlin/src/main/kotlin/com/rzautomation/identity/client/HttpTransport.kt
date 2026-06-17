package com.rzautomation.identity.client

import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

/**
 * Minimal HTTP seam so the client and verifier can be tested without a live
 * server, and so a consumer can plug in its own HTTP stack if it prefers. The
 * default ([JdkHttpTransport]) needs no third-party HTTP dependency.
 */
interface HttpTransport {
    fun get(url: String, headers: Map<String, String>): HttpResult
    fun post(url: String, headers: Map<String, String>, jsonBody: String): HttpResult
}

/** A transport response: the HTTP status and the raw (possibly empty) body. */
data class HttpResult(val status: Int, val body: String)

/**
 * Thrown by a transport when the request could not complete at all (DNS,
 * connect, timeout, reset). Distinct from an HTTP error *status*, which is a
 * normal [HttpResult] the caller maps to [IdentityUnavailable]/[AuthRejected].
 */
class TransportException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * Default [HttpTransport] backed by the JDK's built-in `java.net.http.HttpClient`
 * (no third-party HTTP dependency, usable from any JVM backend). Calls are
 * synchronous and blocking; an async caller runs them off its event loop.
 */
class JdkHttpTransport(private val timeout: Duration) : HttpTransport {
    private val client: HttpClient = HttpClient.newBuilder()
        .connectTimeout(timeout)
        .build()

    override fun get(url: String, headers: Map<String, String>): HttpResult =
        send(builder(url, headers).GET().build())

    override fun post(url: String, headers: Map<String, String>, jsonBody: String): HttpResult =
        send(
            builder(url, headers)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                .build(),
        )

    private fun builder(url: String, headers: Map<String, String>): HttpRequest.Builder {
        val b = HttpRequest.newBuilder(URI.create(url)).timeout(timeout)
        headers.forEach { (k, v) -> b.header(k, v) }
        return b
    }

    private fun send(request: HttpRequest): HttpResult =
        try {
            val resp = client.send(request, HttpResponse.BodyHandlers.ofString())
            HttpResult(resp.statusCode(), resp.body() ?: "")
        } catch (e: Exception) {
            throw TransportException("request failed: ${e.message}", e)
        }
}
