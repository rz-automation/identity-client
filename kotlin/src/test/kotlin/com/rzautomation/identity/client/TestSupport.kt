package com.rzautomation.identity.client

import io.jsonwebtoken.Jwts
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPublicKey
import java.util.Base64
import java.util.Date
import javax.crypto.spec.SecretKeySpec

/**
 * Test-only helpers: synthetic RSA keys, JWKS bodies, and minted tokens. No real
 * users, emails, hostnames, or secrets appear here (this is a public repo); all
 * data is fabricated.
 */
object TestSupport {

    const val SERVICE_ID = "42"
    const val CREDENTIAL = "42.test-secret-not-real"
    const val BASE_URL = "https://identity.example.com"

    fun config(
        jwksCacheTtlSeconds: Long = 600,
        jwksMinRefetchSeconds: Long = 60,
    ) = IdentityConfig(
        baseUrl = BASE_URL,
        serviceCredential = CREDENTIAL,
        jwksCacheTtl = java.time.Duration.ofSeconds(jwksCacheTtlSeconds),
        jwksMinRefetchInterval = java.time.Duration.ofSeconds(jwksMinRefetchSeconds),
    )

    fun keyPair(): KeyPair =
        KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

    /** A JWKS JSON body advertising [kid] for the public half of [pair]. */
    fun jwksBody(kid: String, pair: KeyPair): String {
        val pub = pair.public as RSAPublicKey
        val n = b64(pub.modulus)
        val e = b64(pub.publicExponent)
        return """{"keys":[{"kty":"RSA","kid":"$kid","alg":"RS256","use":"sig","n":"$n","e":"$e"}]}"""
    }

    /** Mint a correctly signed RS256 access token. */
    fun mintToken(
        pair: KeyPair,
        kid: String = "k1",
        sub: String = "user-uuid-0001",
        issuer: String = "identity",
        audiences: List<String> = listOf(SERVICE_ID),
        email: String? = "player@example.test",
        isAdmin: Boolean = false,
        expiresInSeconds: Long = 600,
        includeExp: Boolean = true,
    ): String {
        val now = System.currentTimeMillis()
        val b = Jwts.builder().header().keyId(kid).and().subject(sub).issuer(issuer)
        val aud = b.audience()
        audiences.forEach { aud.add(it) }
        aud.and().issuedAt(Date(now))
        if (includeExp) b.expiration(Date(now + expiresInSeconds * 1000))
        if (email != null) b.claim("email", email)
        if (isAdmin) b.claim("is_admin", true)
        return b.signWith(pair.private, Jwts.SIG.RS256).compact()
    }

    /** A hand-crafted token with an arbitrary header and no signature, for testing
     *  the header gate (alg=none, missing kid) without a real signing key. */
    fun craftedToken(headerJson: String, payloadJson: String = """{"sub":"x"}"""): String {
        val enc = Base64.getUrlEncoder().withoutPadding()
        val h = enc.encodeToString(headerJson.toByteArray())
        val p = enc.encodeToString(payloadJson.toByteArray())
        return "$h.$p."
    }

    /**
     * Mint an HS256 token using the RSA *public* key bytes as the HMAC secret:
     * the alg-confusion forgery a correct verifier must reject before it ever
     * checks a signature.
     */
    fun mintAlgConfusionToken(pair: KeyPair, kid: String = "k1"): String {
        val secret = SecretKeySpec((pair.public as RSAPublicKey).encoded, "HmacSHA256")
        val now = System.currentTimeMillis()
        return Jwts.builder()
            .header().keyId(kid).and()
            .subject("attacker")
            .issuer("identity")
            .audience().add(SERVICE_ID).and()
            .expiration(Date(now + 600_000))
            .signWith(secret, Jwts.SIG.HS256)
            .compact()
    }

    private fun b64(i: BigInteger): String {
        var bytes = i.toByteArray()
        if (bytes.size > 1 && bytes[0].toInt() == 0) bytes = bytes.copyOfRange(1, bytes.size)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }
}

/**
 * Programmable [HttpTransport] for tests. Routes by a substring of the URL (the
 * path is enough). Each entry can be a canned [HttpResult] or a thunk (so a test
 * can count calls or vary responses). Set [getThrows]/[postThrows] to simulate a
 * transport-level failure.
 */
class FakeTransport : HttpTransport {
    val getCalls = mutableListOf<String>()
    val postCalls = mutableListOf<Pair<String, String>>()

    private val getRoutes = mutableListOf<Pair<String, () -> HttpResult>>()
    private val postRoutes = mutableListOf<Pair<String, () -> HttpResult>>()

    var getThrows = false
    var postThrows = false

    fun onGet(pathFragment: String, response: () -> HttpResult) {
        getRoutes.add(pathFragment to response)
    }

    fun onPost(pathFragment: String, response: () -> HttpResult) {
        postRoutes.add(pathFragment to response)
    }

    override fun get(url: String, headers: Map<String, String>): HttpResult {
        getCalls.add(url)
        if (getThrows) throw TransportException("simulated get failure")
        val route = getRoutes.lastOrNull { url.contains(it.first) }
            ?: error("no fake GET route for $url")
        return route.second()
    }

    override fun post(url: String, headers: Map<String, String>, jsonBody: String): HttpResult {
        postCalls.add(url to jsonBody)
        if (postThrows) throw TransportException("simulated post failure")
        val route = postRoutes.lastOrNull { url.contains(it.first) }
            ?: error("no fake POST route for $url")
        return route.second()
    }
}
