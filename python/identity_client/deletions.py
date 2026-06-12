"""GDPR-deletion reconciler: consume the identity deletion feed and purge.

A consuming service that holds pseudonymous per-user rows keyed on the global
identity user id must erase those rows when the user is deleted at identity. It
cannot learn of a deletion by waiting for the user to sign in again (a deleted
user never does), so it consumes the scoped deletion feed instead.

``DeletionReconciler`` is the framework-agnostic engine. You give it three hooks
it owns nothing about:

  * ``on_user_deleted(user_id)`` -- delete this app's own rows for that id. MUST be
    idempotent (it may be called more than once for the same id): a plain
    ``DELETE ... WHERE user_id = ?`` is exactly right.
  * ``get_cursor()`` / ``set_cursor(seq)`` -- read and persist the feed cursor (one
    integer) in your own store, in the SAME transaction boundary as the purge if
    you can, so a crash never advances the cursor past an un-purged row.

The reconciler reads a page, calls ``on_user_deleted`` per id **in seq order**, and
advances the cursor only after each purge succeeds. A crash mid-page retries from
the last good seq; the idempotent purge makes reprocessing harmless.

Head-of-line discipline (this is GDPR risk, so it is explicit): if a purge fails,
the reconciler does NOT advance past it and does NOT process later ids behind it --
it blocks on that seq and surfaces it via ``on_blocked`` so a repeatedly-failing
purge is visible, never silently skipped. Run exactly one reconciler instance (it
is single-writer on the cursor); the FastAPI helper in ``identity_client.fastapi``
drives it as one serialized loop.
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Optional

from .client import IdentityClient

logger = logging.getLogger(__name__)

# Number of consecutive failures of the SAME seq before on_blocked is treated as
# a "repeated" alert (the first failure is logged; a second confirms it is stuck,
# not a one-off transient).
_BLOCK_ALERT_AFTER = 2


class DeletionReconciler:
    """Consume the deletion feed and purge local rows, with safe cursor advance.

    Hooks:
      on_user_deleted(user_id) -- idempotent local purge for one id.
      get_cursor() -> int      -- current persisted feed cursor (0 to start).
      set_cursor(seq)          -- persist the advanced cursor.
      on_blocked(seq, count, exc) -- optional; called when a purge of *seq* fails
                                     (count = consecutive failures of that seq).
                                     Default logs; override to alert. A repeatedly
                                     failing seq blocks the feed by design, so this
                                     is where you wire your alerting.
    """

    def __init__(
        self,
        client: IdentityClient,
        *,
        on_user_deleted: Callable[[str], None],
        get_cursor: Callable[[], int],
        set_cursor: Callable[[int], None],
        on_blocked: Optional[Callable[[int, int, BaseException], None]] = None,
        limit: int = 100,
    ) -> None:
        self._client = client
        self._on_user_deleted = on_user_deleted
        self._get_cursor = get_cursor
        self._set_cursor = set_cursor
        self._on_blocked = on_blocked or self._default_on_blocked
        self._limit = limit
        # Head-of-line failure tracking (one stuck seq at a time, by construction).
        self._failed_seq: Optional[int] = None
        self._failed_count = 0

    def reconcile_page(self, wait: float = 0.0) -> int:
        """Fetch one feed page (optionally long-polling) and purge it.

        Returns the number of ids successfully purged this call. Processes ids in
        seq order, advancing the cursor only past a successful purge. Stops at the
        first failing purge (head-of-line block) without advancing past it. Lets
        ``IdentityUnavailable`` / ``AuthRejected`` propagate (the cursor is
        unchanged, so the caller can simply retry).
        """
        since = int(self._get_cursor())
        page = self._client.fetch_deletions(since, limit=self._limit, wait=wait)
        rows = page.get("deletions", []) or []
        watermark = page.get("cursor", since)

        processed = 0
        for row in rows:
            seq = int(row["seq"])
            user_id = row["user_id"]
            try:
                self._on_user_deleted(user_id)
            except Exception as exc:  # noqa: BLE001 - purge errors must not crash the loop
                self._note_failure(seq, exc)
                # Block-and-alert: do not advance past a failing seq, do not touch
                # later ids behind it. The next poll retries this same seq.
                return processed
            # Advance only after a successful purge.
            self._set_cursor(seq)
            self._clear_failure()
            processed += 1

        # Whole page purged (or empty): jump to the high-watermark cursor so a
        # scoped feed does not rescan filtered-out rows next time.
        if int(watermark) > int(self._get_cursor()):
            self._set_cursor(int(watermark))
        return processed

    # -- head-of-line failure bookkeeping --

    def _note_failure(self, seq: int, exc: BaseException) -> None:
        if seq == self._failed_seq:
            self._failed_count += 1
        else:
            self._failed_seq = seq
            self._failed_count = 1
        logger.warning(
            "deletion purge failed at seq=%s (attempt %d): %s",
            seq,
            self._failed_count,
            exc,
        )
        if self._failed_count >= _BLOCK_ALERT_AFTER:
            try:
                self._on_blocked(seq, self._failed_count, exc)
            except Exception:  # noqa: BLE001 - alerting must never break the loop
                logger.exception("deletion on_blocked hook raised")

    def _clear_failure(self) -> None:
        self._failed_seq = None
        self._failed_count = 0

    @staticmethod
    def _default_on_blocked(seq: int, count: int, exc: BaseException) -> None:
        logger.error(
            "deletion feed BLOCKED at seq=%s after %d consecutive failures: %s "
            "(later deletions are not being processed until this purge succeeds)",
            seq,
            count,
            exc,
        )


__all__ = ["DeletionReconciler"]
