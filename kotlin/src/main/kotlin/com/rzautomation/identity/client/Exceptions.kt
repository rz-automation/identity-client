package com.rzautomation.identity.client

/**
 * Base: any identity interaction the caller must treat as an auth failure.
 *
 * The two subtypes below mean the same thing to a caller (deny); they are
 * distinguished only so the caller may log or measure them differently.
 */
open class IdentityException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * identity positively rejected the credential or token (HTTP 401, or a token
 * that failed verification). The subject is not, or is no longer, a valid
 * authorised user.
 */
class AuthRejected(message: String, cause: Throwable? = null) : IdentityException(message, cause)

/**
 * identity could not be reached or answered with a non-auth error (timeout,
 * connection error, 5xx, malformed body). Per the fail-closed rule this still
 * denies access, but it is *not* a statement about the subject.
 */
class IdentityUnavailable(message: String, cause: Throwable? = null) : IdentityException(message, cause)

/**
 * identity rejected an email+password signup/login with an *actionable* 4xx
 * (400 weak password, 409 email taken, 404 password not enabled, 429
 * rate-limited). Unlike the generic [IdentityUnavailable] collapse, this carries
 * the precise [status] and a human [message] so the caller can show the right
 * thing to the user.
 */
class PasswordRejected(val status: Int, message: String) : IdentityException(message)
