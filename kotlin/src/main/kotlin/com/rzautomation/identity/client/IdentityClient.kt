package com.rzautomation.identity.client

import io.jsonwebtoken.Claims
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** identity's `user` object: `{ id, email, is_new }`. */
@Serializable
data class IdentityUser(
    val id: String,
    val email: String? = null,
    @SerialName("is_new") val isNew: Boolean = false,
)

/** Body of a successful provider sign-in / password call. */
@Serializable
data class AuthResponse(
    @SerialName("access_token") val accessToken: String,
    @SerialName("refresh_token") val refreshToken: String,
    @SerialName("expires_at") val expiresAt: String,
    val user: IdentityUser,
)

/** Body of a successful `/auth/refresh`. */
@Serializable
data class RefreshResponse(
    @SerialName("access_token") val accessToken: String,
    @SerialName("expires_at") val expiresAt: String,
)

/** A login provider identity advertises for this service. */
@Serializable
data class Provider(
    val id: String,
    @SerialName("client_id") val clientId: String? = null,
)

/**
 * Server-to-server calls into identity, plus the bundled [verifier]. A consumer
 * creates one at startup and uses it for the whole login / refresh / logout
 * lifecycle. All calls are synchronous and blocking; an async caller runs them
 * off its event loop.
 *
 * Failure mapping (`../CONTRACT.md` §5, fail closed): an HTTP 401 is
 * [AuthRejected] (the subject is not/no longer valid); any other `>= 400`, a
 * transport failure, or a non-JSON body is [IdentityUnavailable] (still denies,
 * but says nothing about the subject). The password endpoints additionally
 * surface the actionable 4xx as [PasswordRejected].
 */
class IdentityClient(
    val config: IdentityConfig,
    private val transport: HttpTransport = JdkHttpTransport(config.requestTimeout),
    val verifier: AccessTokenVerifier = AccessTokenVerifier(config, transport),
    private val providersTtlMillis: Long = 3_600_000,
    private val clock: () -> Long = System::currentTimeMillis,
    /**
     * Refresh coalescing window (see [refresh]). Concurrent refreshes of the same
     * refresh token within this many milliseconds share one network call, so a page
     * load firing many authenticated requests at once does not multiply into one
     * refresh each. The default trades coalescing strength against revocation
     * latency: ~10s is well under identity's ~10-min access-token lifetime, so the
     * extra staleness it can add is negligible. Set to 0 to disable coalescing.
     */
    private val refreshCoalesceMillis: Long = 10_000,
) {
    private val lock = Any()
    private var cachedProviders: List<Provider>? = null
    private var providersAt: Long = 0

    // Refresh coalescing: a short result cache keyed by refresh token, plus a
    // per-token monitor so concurrent callers of the same token serialise onto one
    // network call. Different tokens never contend. Guarded by [refreshLock].
    private val refreshLock = Any()
    private val refreshInflight = HashMap<String, Any>()
    private val refreshCache = HashMap<String, Pair<Long, RefreshResponse>>()

    /**
     * Discover this service's enabled login providers from `/auth-providers`,
     * cached ~1h. Returns the stale cache (or empty if nothing is cached) when
     * identity is unreachable, so a login page degrades to "no buttons" rather
     * than erroring: correct under a hard cutover (no identity, no login).
     */
    fun providers(): List<Provider> {
        synchronized(lock) {
            cachedProviders?.let { if (clock() - providersAt < providersTtlMillis) return it }
        }
        // Fetch OUTSIDE the lock: holding the monitor across this blocking round-trip
        // would serialise every concurrent caller (and tie up threads) behind a slow
        // or hanging identity endpoint. Concurrent callers may each fetch once on a
        // cold cache; that is harmless and the result is then cached ~1h.
        val result = try {
            transport.get("${config.baseUrl}/auth-providers", config.authHeader)
        } catch (_: TransportException) {
            return staleOrEmpty()
        }
        if (result.status >= 400) return staleOrEmpty()
        val parsed = try {
            JSON.decodeFromString(ProvidersResponse.serializer(), result.body)
        } catch (_: Exception) {
            return staleOrEmpty()
        }
        return synchronized(lock) {
            cachedProviders = parsed.providers
            providersAt = clock()
            parsed.providers
        }
    }

    /** Serve the cached provider list (or empty) when a fresh fetch failed. */
    private fun staleOrEmpty(): List<Provider> = synchronized(lock) { cachedProviders ?: emptyList() }

    /**
     * This service's Google client id (from [providers]), or null. identity owns
     * it (it verifies the Google token's `aud` against its own configured value),
     * so consumers must not hardcode it: discovering it here makes the two match
     * by construction. Null means Google is not configured for this service, or
     * identity is unreachable with nothing cached.
     */
    fun googleClientId(): String? =
        providers().firstOrNull { it.id == "google" }?.clientId

    /**
     * Absolute URL that begins Discord sign-in, or null if Discord is not enabled
     * for this service. The browser navigates here at the top level (not a fetch);
     * identity runs the whole OAuth dance server-side and bounces back to this
     * service's registered return URL with a single-use exchange code, which the
     * backend swaps via `signIn("discord", code)`.
     */
    fun discordStartUrl(): String? {
        if (providers().none { it.id == "discord" }) return null
        return "${config.baseUrl}/auth/discord/start?service_id=${config.serviceId}"
    }

    /**
     * Exchange a provider credential for identity tokens.
     *
     *  - `provider == "google"`: [credential] is the relayed Google ID token.
     *  - `provider == "discord"`: [credential] is the single-use exchange code
     *    from the Discord return redirect.
     *
     * Throws [IllegalArgumentException] for an unknown provider.
     */
    fun signIn(provider: String, credential: String): AuthResponse = when (provider) {
        "google" -> post(
            "/auth/google",
            buildJsonObject { put("google_id_token", JsonPrimitive(credential)) },
            AuthResponse.serializer(),
        )
        "discord" -> post(
            "/auth/discord/exchange",
            buildJsonObject { put("code", JsonPrimitive(credential)) },
            AuthResponse.serializer(),
        )
        else -> throw IllegalArgumentException("unknown provider '$provider'")
    }

    /**
     * Create an account with the email+password provider. Throws [PasswordRejected]
     * on an actionable 4xx (400 weak password, 409 email taken, 404 not enabled),
     * [AuthRejected] on 401, and [IdentityUnavailable] otherwise.
     */
    fun passwordSignup(email: String, password: String): AuthResponse = postPassword(
        "/auth/password/signup",
        buildJsonObject { put("email", JsonPrimitive(email)); put("password", JsonPrimitive(password)) },
        AuthResponse.serializer(),
    )

    /**
     * Sign in with the email+password provider. Throws [PasswordRejected] on an
     * actionable 4xx (404 not enabled, 429 rate-limited), [AuthRejected] on 401
     * (wrong/unknown, generic on purpose), and [IdentityUnavailable] otherwise.
     */
    fun passwordLogin(email: String, password: String): AuthResponse = postPassword(
        "/auth/password/login",
        buildJsonObject { put("email", JsonPrimitive(email)); put("password", JsonPrimitive(password)) },
        AuthResponse.serializer(),
    )

    /**
     * Mint a fresh access token. Throws [AuthRejected] when the refresh token is
     * invalidated or the user/service is no longer valid (identity answers 401).
     *
     * Concurrent callers presenting the SAME refresh token are coalesced into a
     * single network call: the first does the POST, the rest reuse its result for
     * [refreshCoalesceMillis]. A stateless per-request session gate otherwise has
     * every in-flight request independently refresh the same about-to-expire token,
     * so one page load firing a dozen authenticated requests at once turns into a
     * dozen identical refreshes. Coalescing collapses that burst to one call. The
     * monitor is per token so unrelated sessions never block each other, and errors
     * are not cached (the next caller retries). A revoked refresh token stops minting
     * new access tokens after at most one window: within it, coalesced callers reuse
     * the already-minted access token (itself an independently-verified bearer token,
     * so this grants nothing they would not already have for its lifetime).
     * [RefreshResponse] is immutable, so sharing one instance across callers is safe.
     *
     * Assumes `/auth/refresh` does not rotate refresh tokens (the response carries no
     * new refresh token and the presented token stays valid): the cache is keyed by
     * the presented token, so if identity ever introduces rotation this must be
     * revisited.
     */
    fun refresh(refreshToken: String): RefreshResponse {
        if (refreshCoalesceMillis <= 0) return doRefresh(refreshToken)

        cachedRefresh(refreshToken)?.let { return it }
        val tokenLock = synchronized(refreshLock) {
            cachedRefresh(refreshToken)?.let { return it }
            refreshInflight.getOrPut(refreshToken) { Any() }
        }
        try {
            synchronized(tokenLock) {
                // Re-check: a concurrent caller may have refreshed while we waited.
                cachedRefresh(refreshToken)?.let { return it }
                val resp = doRefresh(refreshToken)
                synchronized(refreshLock) {
                    refreshCache[refreshToken] = clock() to resp
                    pruneRefreshCacheLocked()
                }
                return resp
            }
        } finally {
            // Drop the registry entry (success or failure) so it cannot accumulate;
            // waiters already hold their own reference to the monitor.
            synchronized(refreshLock) { refreshInflight.remove(refreshToken) }
        }
    }

    /** A still-fresh cached refresh result for [refreshToken], or null. */
    private fun cachedRefresh(refreshToken: String): RefreshResponse? =
        synchronized(refreshLock) {
            refreshCache[refreshToken]?.takeIf { clock() - it.first < refreshCoalesceMillis }?.second
        }

    /** Drop coalesce-cache entries older than the window. Holds [refreshLock]. */
    private fun pruneRefreshCacheLocked() {
        val cutoff = clock() - refreshCoalesceMillis
        refreshCache.entries.removeAll { it.value.first < cutoff }
    }

    private fun doRefresh(refreshToken: String): RefreshResponse = post(
        "/auth/refresh",
        buildJsonObject { put("refresh_token", JsonPrimitive(refreshToken)) },
        RefreshResponse.serializer(),
    )

    /**
     * Best-effort revoke of [refreshToken]. Never throws: logout must always be
     * able to tear the local session down, whether or not identity is reachable.
     */
    fun logout(refreshToken: String) {
        try {
            transport.post(
                "${config.baseUrl}/auth/logout",
                config.authHeader,
                buildJsonObject { put("refresh_token", JsonPrimitive(refreshToken)) }.toString(),
            )
        } catch (_: TransportException) {
            // best-effort
        }
    }

    /** Verify an access token (delegates to the bundled [verifier]). */
    fun verify(accessToken: String): Claims = verifier.verify(accessToken)

    /**
     * GDPR-delete [userId] in this service's realm
     * (`POST /api/v1/users/{id}/delete`). Realm-local erasure: identity
     * tombstones the account it holds for this service (null email, scrub
     * provider links, invalidate refresh tokens, set deleted), scoped to a user
     * this service serves. Back a "delete my account" control with it; the app
     * erases its own per-user rows separately.
     *
     * Idempotent: identity answers 404 when the user is already gone (already
     * tombstoned, or never in this service's scope), which this treats as
     * success: a retried or double-submitted delete still resolves to "the
     * account is gone."
     *
     * Throws [AuthRejected] on 401 (bad/inactive service credential) and
     * [IdentityUnavailable] if identity is unreachable or errors otherwise: a
     * delete that cannot be confirmed must fail loud, so the caller does not
     * report success or tear the session down on an unconfirmed erasure.
     */
    fun deleteAccount(userId: String) {
        val path = "/api/v1/users/$userId/delete"
        val result = try {
            transport.post("${config.baseUrl}$path", config.authHeader, "{}")
        } catch (e: TransportException) {
            throw IdentityUnavailable("identity $path unreachable: ${e.message}", e)
        }
        when {
            result.status == 200 || result.status == 404 -> return
            result.status == 401 -> throw AuthRejected("identity $path rejected (401)")
            else -> throw IdentityUnavailable("identity $path returned ${result.status}")
        }
    }

    // --- internals ---

    private fun <T> post(path: String, body: JsonObject, deserializer: KSerializer<T>): T {
        val result = try {
            transport.post("${config.baseUrl}$path", config.authHeader, body.toString())
        } catch (e: TransportException) {
            throw IdentityUnavailable("identity $path unreachable: ${e.message}", e)
        }
        if (result.status == 401) throw AuthRejected("identity $path rejected (401)")
        if (result.status >= 400) throw IdentityUnavailable("identity $path returned ${result.status}")
        return try {
            JSON.decodeFromString(deserializer, result.body)
        } catch (e: Exception) {
            throw IdentityUnavailable("identity $path returned a non-JSON body", e)
        }
    }

    private fun <T> postPassword(path: String, body: JsonObject, deserializer: KSerializer<T>): T {
        val result = try {
            transport.post("${config.baseUrl}$path", config.authHeader, body.toString())
        } catch (e: TransportException) {
            throw IdentityUnavailable("identity $path unreachable: ${e.message}", e)
        }
        when {
            result.status == 200 || result.status == 201 ->
                return try {
                    JSON.decodeFromString(deserializer, result.body)
                } catch (e: Exception) {
                    throw IdentityUnavailable("identity $path returned a non-JSON body", e)
                }
            result.status == 401 -> throw AuthRejected("identity $path rejected (401)")
            result.status in ACTIONABLE -> throw PasswordRejected(result.status, detailError(result.body))
            else -> throw IdentityUnavailable("identity $path returned ${result.status}")
        }
    }

    /** Pull `detail.error` (or a plain `detail` string) from an error body. */
    private fun detailError(body: String): String {
        val fallback = "request rejected"
        return try {
            val detail = JSON.parseToJsonElement(body).jsonObject["detail"] ?: return fallback
            when (detail) {
                is JsonObject -> detail["error"]?.jsonPrimitive?.contentOrNull ?: fallback
                is JsonPrimitive -> detail.contentOrNull ?: fallback
                else -> fallback
            }
        } catch (_: Exception) {
            fallback
        }
    }

    @Serializable
    private data class ProvidersResponse(val providers: List<Provider> = emptyList())

    private companion object {
        val JSON = Json { ignoreUnknownKeys = true }
        val ACTIONABLE = setOf(400, 404, 409, 429)
    }
}
