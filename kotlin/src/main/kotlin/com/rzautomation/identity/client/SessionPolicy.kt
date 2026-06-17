package com.rzautomation.identity.client

import io.jsonwebtoken.Claims

/**
 * A logged-in session (`../CONTRACT.md` §6): the consumer backend owns it, signs
 * it into a single `HttpOnly`, `Secure` cookie, and never exposes [rt] (the only
 * long-lived secret here) to the browser. identity sets no cookie.
 *
 *  - [axp] is the verified access-token expiry (unix seconds), the refresh anchor.
 *  - [iat] is the login time, the absolute-lifetime anchor.
 *  - [seen] is the last-seen time, the idle-timeout anchor.
 */
data class IdentitySession(
    val uid: String,
    val email: String?,
    val rt: String,
    val axp: Long,
    val adm: Boolean,
    val iat: Long,
    val seen: Long,
)

/** Outcome of [SessionPolicy.evaluate]. */
sealed interface SessionDecision {
    /** Live session. Re-encode [session] so the bumped expiry/last-seen persist. */
    data class Authenticated(val session: IdentitySession) : SessionDecision

    /** No valid session: deny, and clear any cookie. */
    data object Denied : SessionDecision
}

/**
 * The framework-neutral session decisions (refresh / fail-closed / bounds),
 * bound to one [IdentityClient]. A binding supplies only the thin plumbing:
 * decode the request's signed cookie to an [IdentitySession], call [evaluate],
 * and re-encode the returned session onto the response. The policy never touches
 * a request, response, or cookie. The cookie's signing scheme is the binding's
 * own choice (each service signs with its own secret), so it is not part of the
 * cross-language contract.
 *
 * Every decision fails closed: a refresh that errors, returns a malformed body,
 * or (under [adminOnly]) loses the `is_admin` claim denies rather than degrading
 * to a stale-but-allowed session.
 *
 * @param idleTimeoutSeconds null opts out of the idle check entirely (the session
 *   then lives until the absolute lifetime or the refresh token lapses).
 * @param adminOnly tightens the policy for admin consoles: a refresh that loses
 *   `is_admin` ends the session (a demotion kill-switch).
 */
class SessionPolicy(
    private val client: IdentityClient,
    private val idleTimeoutSeconds: Long? = 12 * 3600,
    private val absoluteLifetimeSeconds: Long = 7 * 24 * 3600,
    private val refreshSkewSeconds: Long = 30,
    private val adminOnly: Boolean = false,
    private val clock: () -> Long = { System.currentTimeMillis() / 1000 },
) {
    /** Build a fresh session from a verified access token's claims. */
    fun newSession(claims: Claims, refreshToken: String): IdentitySession {
        val now = clock()
        val uid = claims.subject ?: throw AuthRejected("token has no sub")
        val exp = claims.expiration ?: throw AuthRejected("token has no exp")
        return IdentitySession(
            uid = uid,
            email = claims["email"] as? String,
            rt = refreshToken,
            axp = exp.time / 1000,
            adm = isAdminClaim(claims),
            iat = now,
            seen = now,
        )
    }

    /** True iff the session still holds a refresh token and is within both the
     *  absolute lifetime and (unless opted out) the idle timeout. */
    fun inBounds(session: IdentitySession): Boolean {
        if (session.rt.isEmpty()) return false
        val now = clock()
        if (now - session.iat >= absoluteLifetimeSeconds) return false
        idleTimeoutSeconds?.let { if (now - session.seen >= it) return false }
        return true
    }

    /**
     * Refresh the access token against identity; fail closed. Returns an updated
     * session (`axp`/`adm` bumped) only on a verified, unexpired token (and, when
     * [adminOnly], an admin one). Any other outcome (401, 5xx, timeout, malformed
     * body, or demotion under [adminOnly]) returns null so the caller denies.
     * Blocking: it talks to identity.
     */
    fun tryRefresh(session: IdentitySession): IdentitySession? {
        val claims = try {
            client.verify(client.refresh(session.rt).accessToken)
        } catch (_: IdentityException) {
            return null
        }
        if (adminOnly && !isAdminClaim(claims)) return null
        val exp = claims.expiration ?: return null
        return session.copy(axp = exp.time / 1000, adm = isAdminClaim(claims))
    }

    /**
     * Decide whether a decoded session is live, refreshing if stale. Pass the
     * session a binding decoded from its signed cookie, or null if there was no
     * valid cookie. Blocking when it refreshes.
     */
    fun evaluate(session: IdentitySession?): SessionDecision {
        if (session == null || !inBounds(session)) return SessionDecision.Denied
        var current = session
        if (clock() >= current.axp - refreshSkewSeconds) {
            current = tryRefresh(current) ?: return SessionDecision.Denied
        }
        return SessionDecision.Authenticated(current.copy(seen = clock()))
    }
}
