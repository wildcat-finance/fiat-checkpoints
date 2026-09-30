"""The quarantine sweeper: expiry, reclaimed streams, spent records and quarantine deletion.

One pass, in a fixed order: give back streams whose lease expired, expire
candidates past their deadline, drop spent idempotency keys, login state,
sessions, tokens and capabilities, then delete every quarantine object that
is due and every object the store's 24-hour lifecycle has reached. A key is
marked for deletion in the database before the store deletes it and recorded
as deleted only after, so a pass that stops part-way is finished by the next.
The sweeper's only storage power is deleting quarantine keys (specification
section 6). See adr/seal-uploads-in-bounded-quarantine.
"""

from dataclasses import dataclass
import logging

from fiat_checkpoints.domain.coordination import require_now
from fiat_checkpoints.persistence.transfer import MAX_SWEEP, QUARANTINE_LIFETIME
from fiat_checkpoints.storage.quarantine import QuarantineError


LOGGER = logging.getLogger("fiat_checkpoints")
if not LOGGER.handlers:
    LOGGER.addHandler(logging.NullHandler())
KINDS = ("streams", "candidates", "idempotency", "sessions", "capabilities", "quarantine", "lifecycle")


@dataclass(frozen=True)
class SweepReport:
    """Counts for one pass, and how many quarantine deletions failed and wait for the next."""
    streams: int
    candidates: int
    idempotency: int
    sessions: int
    capabilities: int
    quarantine: int
    lifecycle: int
    delete_failures: int


class Sweeper:
    """Run one bounded sweep over the transfer records, the sessions and one quarantine store."""

    def __init__(self, transfers, sessions, quarantine, *, limit=MAX_SWEEP):
        self.transfers = transfers
        self.sessions = sessions
        self.quarantine = quarantine
        self.limit = limit

    def _delete(self, keys):
        deleted, failures = [], 0
        for key in keys:
            try:
                self.quarantine.delete(key)
            except QuarantineError:
                failures += 1
                continue
            deleted.append(key)
        return deleted, failures

    def run(self, now):
        now = require_now(now)
        transfers = self.transfers
        streams = transfers.reclaim_streams(now)
        candidates = transfers.expire_due(now, min(self.limit, 1000))
        idempotency = transfers.sweep_idempotency(now, self.limit)
        sessions = self.sessions.sweep(now, self.limit) if self.sessions is not None else 0
        capabilities = transfers.sweep_capabilities(now, self.limit)
        deleted, failures = self._delete(transfers.claim_deletions(now, self.limit))
        quarantine = transfers.mark_deleted(deleted, now)
        try:
            aged = self.quarantine.older_than((now - QUARANTINE_LIFETIME).timestamp(), self.limit)
        except QuarantineError:
            aged, failures = [], failures + 1
        expired, lifecycle_failures = self._delete(transfers.claim_lifecycle(aged, now))
        transfers.mark_deleted(expired, now)
        report = SweepReport(streams, candidates, idempotency, sessions, capabilities, quarantine, len(expired),
                             failures + lifecycle_failures)
        for kind in KINDS:
            LOGGER.info("sweep-completed", extra={"event": "sweep-completed", "kind": kind,
                                                  "count": getattr(report, kind)})
        if report.delete_failures:
            LOGGER.warning("quarantine-delete-failed", extra={"event": "quarantine-delete-failed",
                                                              "count": report.delete_failures})
        return report
