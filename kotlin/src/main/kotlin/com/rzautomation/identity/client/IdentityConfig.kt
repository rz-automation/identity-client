package com.rzautomation.identity.client

import java.time.Duration

/**
 * Everything a consumer needs to talk to identity.
 *
 * [serviceId] (the expected JWT `aud`) is derived from [serviceCredential]:
 * identity issues the credential as `<service-id>.<secret>` and mints the access
 * JWT with `aud == "<service-id>"`, so they are the same value. The secret is
 * server-side only and never reaches a browser.
 */
class IdentityConfig(
    baseUrl: String,
    val serviceCredential: String,
    val issuer: String = "identity",
    val requestTimeout: Duration = Duration.ofSeconds(5),
    /** TTL bounding the JWKS cache, so a revoked key ages out within the window. */
    val jwksCacheTtl: Duration = Duration.ofSeconds(600),
    /** Floor on JWKS refetches, so unknown-kid spam can't amplify into a fetch DoS. */
    val jwksMinRefetchInterval: Duration = Duration.ofSeconds(60),
) {
    val baseUrl: String = baseUrl.trimEnd('/')
    val serviceId: String

    init {
        require(serviceCredential.contains('.')) {
            "serviceCredential must be of the form '<service-id>.<secret>'"
        }
        // The secret is url-safe base64 (no dots), so the first dot splits id from
        // secret cleanly.
        serviceId = serviceCredential.substringBefore('.')
        require(serviceId.isNotEmpty()) { "serviceCredential has an empty service id" }
    }

    val jwksUrl: String get() = "$baseUrl/.well-known/jwks.json"

    internal val authHeader: Map<String, String>
        get() = mapOf("Authorization" to "Bearer $serviceCredential")
}
