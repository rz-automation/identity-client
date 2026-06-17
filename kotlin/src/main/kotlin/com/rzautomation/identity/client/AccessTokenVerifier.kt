package com.rzautomation.identity.client

import io.jsonwebtoken.Claims
import io.jsonwebtoken.JwtException
import io.jsonwebtoken.Jwts
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.math.BigInteger
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.RSAPublicKeySpec
import java.util.Base64

/**
 * RS256-pinned verification of identity access tokens against its JWKS
 * (`../CONTRACT.md` §4). Maintains a small in-process cache of signing keys keyed
 * by `kid`; a new `kid` triggers a refetch (rate-limited), and the whole cache is
 * refreshed once its TTL lapses so a revoked key ages out within that window.
 *
 * Security invariants, do NOT weaken:
 *
 *  - Algorithm pinned to RS256 from OUR config, never read from the token header.
 *    `none` and every HMAC alg are rejected. (identity publishes its RSA *public*
 *    key, so an HMAC-accepting verifier could be handed a token HMAC-signed with
 *    that public key: the classic alg-confusion forgery.)
 *  - Verify the signature, then require `iss == "identity"`, `aud == serviceId`,
 *    and `exp` present and not in the past. The `aud` check is what stops a token
 *    identity minted for another service being replayed here.
 */
class AccessTokenVerifier(
    private val config: IdentityConfig,
    private val transport: HttpTransport = JdkHttpTransport(config.requestTimeout),
    private val nanoClock: () -> Long = System::nanoTime,
) {
    private val lock = Any()
    private var keys: Map<String, PublicKey> = emptyMap()
    private var fetchedAt: Long = Long.MIN_VALUE      // monotonic ns of last successful populate
    private var lastFetchAttempt: Long = Long.MIN_VALUE

    private val ttlNanos = config.jwksCacheTtl.toNanos()
    private val minRefetchNanos = config.jwksMinRefetchInterval.toNanos()

    /**
     * Verify [token] and return its claims, or throw.
     *
     * Throws [AuthRejected] for a token that is malformed, expired, has the wrong
     * `alg`/`iss`/`aud`, a bad signature, or a `kid` identity does not publish.
     * Throws [IdentityUnavailable] only if the JWKS could not be fetched when it
     * had to be.
     */
    fun verify(token: String): Claims {
        val header = parseHeader(token)

        // Pin the algorithm from OUR config, never from the token header.
        val alg = header["alg"]
        if (alg != "RS256") throw AuthRejected("unexpected alg '$alg'; only RS256")
        val kid = header["kid"] ?: throw AuthRejected("token header has no kid")

        val key = signingKey(kid)
        val claims = try {
            // JJWT has no explicit algorithm allow-list: it infers the alg from the
            // header and refuses to verify a MAC/none token with an RSA public key.
            // The hard RS256 pin is therefore the manual header check above (plus
            // that key-type incompatibility) — do NOT remove it believing JJWT pins
            // on its own.
            Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .payload
        } catch (e: JwtException) {
            // Covers a bad signature and an expired token (ExpiredJwtException).
            throw AuthRejected("token verification failed: ${e.message}", e)
        }

        // Require iss/aud/exp present and correct (CONTRACT.md §4).
        if (claims.issuer != config.issuer) {
            throw AuthRejected("wrong iss '${claims.issuer}'")
        }
        if (config.serviceId !in (claims.audience ?: emptySet())) {
            throw AuthRejected("token aud does not include this service")
        }
        if (claims.expiration == null) throw AuthRejected("token has no exp")
        return claims
    }

    // --- key cache ---

    private fun signingKey(kid: String): PublicKey {
        synchronized(lock) {
            val now = nanoClock()
            val fresh = fetchedAt != Long.MIN_VALUE && (now - fetchedAt) < ttlNanos
            if (fresh) keys[kid]?.let { return it }

            // Need a (re)fetch: an unknown kid or a stale cache. Rate-limit so
            // unknown-kid spam can't amplify into unbounded JWKS fetches.
            if (lastFetchAttempt != Long.MIN_VALUE && (now - lastFetchAttempt) < minRefetchNanos) {
                keys[kid]?.let { return it }      // serve stale rather than refetch
                throw AuthRejected("unknown kid (refetch rate-limited)")
            }
            lastFetchAttempt = now
            refreshKeys()
            return keys[kid] ?: throw AuthRejected("unknown kid '$kid' after JWKS refresh")
        }
    }

    /** Fetch and (on success, with at least one usable key) replace the cache. */
    private fun refreshKeys() {
        val result = try {
            transport.get(config.jwksUrl, emptyMap())
        } catch (e: TransportException) {
            throw IdentityUnavailable("could not fetch JWKS: ${e.message}", e)
        }
        if (result.status >= 400) {
            throw IdentityUnavailable("JWKS fetch returned ${result.status}")
        }
        val parsed = try {
            JSON.decodeFromString(JwksResponse.serializer(), result.body)
        } catch (e: Exception) {
            throw IdentityUnavailable("malformed JWKS body: ${e.message}", e)
        }
        val newKeys = buildMap {
            for (jwk in parsed.keys) {
                if (jwk.kty != "RSA" || jwk.kid == null || jwk.n == null || jwk.e == null) continue
                try {
                    val n = BigInteger(1, Base64.getUrlDecoder().decode(jwk.n))
                    val e = BigInteger(1, Base64.getUrlDecoder().decode(jwk.e))
                    put(jwk.kid, KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(n, e)))
                } catch (_: Exception) {
                    // skip a malformed entry
                }
            }
        }
        if (newKeys.isNotEmpty()) {
            keys = newKeys
            fetchedAt = nanoClock()
        }
    }

    /** Decode the JWT header segment and return its (string) fields. */
    private fun parseHeader(token: String): Map<String, String> {
        val parts = token.split(".")
        if (parts.size < 2) throw AuthRejected("malformed token")
        val headerJson = try {
            String(Base64.getUrlDecoder().decode(parts[0]))
        } catch (e: Exception) {
            throw AuthRejected("malformed token header", e)
        }
        return try {
            JSON.parseToJsonElement(headerJson).jsonObject
                .mapValues { it.value.jsonPrimitive.content }
        } catch (e: Exception) {
            throw AuthRejected("malformed token header JSON", e)
        }
    }

    @Serializable
    private data class JwksResponse(val keys: List<Jwk> = emptyList())

    @Serializable
    private data class Jwk(
        val kty: String = "",
        val kid: String? = null,
        val n: String? = null,
        val e: String? = null,
    )

    private companion object {
        val JSON = Json { ignoreUnknownKeys = true }
    }
}

/**
 * True iff the verified claims carry `is_admin` set to exactly `true`.
 *
 * identity emits `is_admin` ONLY when true (deliberately absent for non-admins),
 * so gate on the value being exactly `true`, not on presence: a future
 * serialization change to a truthy non-bool (a `1` or `"true"`) must not be
 * mistaken for admin.
 */
fun isAdminClaim(claims: Claims): Boolean = claims["is_admin"] == true
