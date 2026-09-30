"""Candidate states and the closed transition table of specification section 11.

A transition is legal only when its pair is in `TRANSITIONS` and the caller
supplies exactly that row's evidence. The table decides nothing about whether
the evidence is true; the owning step checks it before naming it here. No
database field, downstream object or timestamp can add a transition.
"""

from dataclasses import dataclass
from enum import Enum


class State(Enum):
    ANNOUNCED = "announced"
    UPLOADING = "uploading"
    QUARANTINED = "quarantined"
    VALIDATING = "validating"
    PUBLISHING = "publishing"
    AWAITING_REPLICA = "awaiting_replica"
    AWAITING_SIGNATURE = "awaiting_signature"
    PUBLISHING_RECEIPT = "publishing_receipt"
    FINALIZING = "finalizing"
    PUBLISHING_FINALIZATION = "publishing_finalization"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    EXPIRED = "expired"
    REVOKED = "revoked"


class Evidence(Enum):
    RUN_GRANT = "current-run-grant"
    QUOTA_RESERVED = "quota-reservation"
    EXACT_SIZE_AND_DIGEST = "exact-size-and-digest"
    STREAM_COUNT_AND_HASH = "eof-count-and-hash-match"
    QUARANTINE_READ_BACK = "sealed-quarantine-read-back"
    CANDIDATE_UNEXPIRED = "unexpired-candidate"
    ISOLATED_WORKER = "available-isolated-worker"
    PROTOCOL_CHECKS = "complete-protocol-checks"
    RECONSTRUCTION = "reconstruction"
    IDENTITY = "identity-checks"
    AUTHORIZATION = "authorization-checks"
    DENIAL_CHECK = "denial-checks"
    PRIMARY_COPY = "primary-copy-verified"
    RECOVERY_COPY = "recovery-copy-verified"
    SIGNED_ENVELOPE = "valid-signer-envelope"
    RECEIPT_IN_BOTH_STORES = "receipt-envelope-in-both-stores"
    JOURNAL_FINALIZATION = "ordered-journal-finalization"
    FINALIZATION_IN_BOTH_STORES = "finalization-verified-in-both-accounts"
    ACCEPTED_PREDICATE = "complete-accepted-predicate"
    DETERMINISTIC_REFUSAL = "deterministic-refusal"
    NO_SIGNER_AUTHORIZATION = "no-signer-authorization"
    DEADLINE_ELAPSED = "deadline-elapsed"
    CANCELLATION_WON = "cancellation-won"
    SIGNED_DENIAL = "signed-denial-record"
    POISON_POLICY = "poison-policy"


class TransitionRefused(Exception):
    """A fixed code; the table is closed, so no state value is echoed."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class Transition:
    source: State
    target: State
    evidence: frozenset


def _row(source, target, *evidence):
    return (source, target), Transition(source, target, frozenset(evidence))


# Signer authorization happens on awaiting_signature -> publishing_receipt, so
# only the states before it may still end as rejected or expired.
PRE_AUTHORIZATION = (State.ANNOUNCED, State.UPLOADING, State.QUARANTINED, State.VALIDATING,
                     State.PUBLISHING, State.AWAITING_REPLICA, State.AWAITING_SIGNATURE)

TRANSITIONS = dict((
    _row(State.ANNOUNCED, State.UPLOADING,
         Evidence.RUN_GRANT, Evidence.QUOTA_RESERVED, Evidence.EXACT_SIZE_AND_DIGEST),
    _row(State.UPLOADING, State.QUARANTINED,
         Evidence.STREAM_COUNT_AND_HASH, Evidence.QUARANTINE_READ_BACK),
    _row(State.QUARANTINED, State.VALIDATING,
         Evidence.CANDIDATE_UNEXPIRED, Evidence.ISOLATED_WORKER),
    _row(State.VALIDATING, State.PUBLISHING,
         Evidence.PROTOCOL_CHECKS, Evidence.RECONSTRUCTION, Evidence.IDENTITY,
         Evidence.AUTHORIZATION, Evidence.DENIAL_CHECK),
    _row(State.PUBLISHING, State.AWAITING_REPLICA, Evidence.PRIMARY_COPY),
    _row(State.AWAITING_REPLICA, State.AWAITING_SIGNATURE, Evidence.RECOVERY_COPY),
    _row(State.AWAITING_SIGNATURE, State.PUBLISHING_RECEIPT, Evidence.SIGNED_ENVELOPE),
    _row(State.PUBLISHING_RECEIPT, State.FINALIZING, Evidence.RECEIPT_IN_BOTH_STORES),
    _row(State.FINALIZING, State.PUBLISHING_FINALIZATION, Evidence.JOURNAL_FINALIZATION),
    _row(State.PUBLISHING_FINALIZATION, State.ACCEPTED,
         Evidence.FINALIZATION_IN_BOTH_STORES, Evidence.ACCEPTED_PREDICATE),
    *(_row(state, State.REJECTED, Evidence.DETERMINISTIC_REFUSAL, Evidence.NO_SIGNER_AUTHORIZATION)
      for state in PRE_AUTHORIZATION),
    *(_row(state, State.EXPIRED, Evidence.DEADLINE_ELAPSED, Evidence.CANCELLATION_WON)
      for state in PRE_AUTHORIZATION),
    _row(State.ACCEPTED, State.REVOKED, Evidence.SIGNED_DENIAL, Evidence.POISON_POLICY),
))


def advance(source, target, evidence):
    """Return `target` when the row exists and exactly its evidence is named."""
    if not isinstance(source, State) or not isinstance(target, State):
        raise TransitionRefused("state-unknown")
    if type(evidence) not in (set, frozenset) or not all(isinstance(item, Evidence) for item in evidence):
        raise TransitionRefused("evidence-unknown")
    row = TRANSITIONS.get((source, target))
    if row is None:
        raise TransitionRefused("transition-illegal")
    if frozenset(evidence) != row.evidence:
        raise TransitionRefused("transition-evidence")
    return target
