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
) {
    private val lock = Any()
    private var cachedProviders: List<Provider>? = null
    private var providersAt: Long = 0

    /**
     * Discover this service's enabled login providers from `/auth-providers`,
     * cached ~1h. Returns the stale cache (or empty if nothing is cached) when
     * identity is unreachable, so a login page degrades to "no buttons" rather
     * than erroring: correct under a hard cutover (no identity, no login).
     */
    fun providers(): List<Provider> = synchronized(lock) {
        val now = clock()
        cachedProviders?.let { if (now - providersAt < providersTtlMillis) return it }
        val result = try {
            transport.get("${config.baseUrl}/auth-providers", config.authHeader)
        } catch (_: TransportException) {
            return cachedProviders ?: emptyList()
        }
        if (result.status >= 400) return cachedProviders ?: emptyList()
        val parsed = try {
            JSON.decodeFromString(ProvidersResponse.serializer(), result.body)
        } catch (_: Exception) {
            return cachedProviders ?: emptyList()
        }
        cachedProviders = parsed.providers
        providersAt = now
        parsed.providers
    }

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
     */
    fun refresh(refreshToken: String): RefreshResponse = post(
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
