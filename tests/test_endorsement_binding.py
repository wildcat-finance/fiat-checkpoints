"""Every field the service bound at announce is compared with the authenticated endorsement."""

from datetime import timedelta
import unittest
import uuid

from fiat_checkpoints.auth.refusals import AuthRefusal
from fiat_checkpoints.domain.coordination import RunScope
from fiat_checkpoints.domain.identities import CheckpointIdentities
from fiat_checkpoints.grants.endorsement import CandidateBinding, Challenge, challenge_nonce, check_binding
from tests import authority_fixtures as fixtures
from tests.auth_support import IDENTITIES, LENGTH, PARENT, SCOPE, T0, at, stamp


CANDIDATE = uuid.UUID("7d0c2d4e-3b1f-4c5a-9e8d-1a2b3c4d5e6f")
NONCE = "4" * 64
# The fields this service binds itself. The library authenticates the rest
# (policy, enrollment, grant, issuer, sequence) against the trust prefix.
BOUND = ("type", "actor_id", "service", "scope", "candidate_id", "nonce", "identities", "carrier_length",
         "parent", "issued_at", "expires_at")


def binding(**changes):
    values = dict(
        candidate_id=CANDIDATE, actor_id=41, scope=RunScope(SCOPE.service, SCOPE.repository_id, SCOPE.run_id),
        state="announced", expires_at=T0 + timedelta(hours=24),
        identities=CheckpointIdentities.from_protocol(IDENTITIES), declared_size=LENGTH,
        parent_sha256=PARENT["sha256"], challenge=Challenge(CANDIDATE, NONCE, at(0.25)))
    return CandidateBinding(**(values | changes))


def record(**changes):
    value = {
        "protocol": "checkpoint-authority/v1", "environment": "test", "service": SCOPE.service,
        "scope": {"repository_id": SCOPE.repository_id, "run_id": SCOPE.run_id}, "type": "upload-endorsement",
        "sequence": 1, "previous": None, "issued_at": stamp(0), "issuer": "f" * 64,
        "policy": {"type": "authority-policy", "sha256": "a" * 64}, "actor_id": 41,
        "enrollment": {"type": "key-enrollment", "sha256": "b" * 64}, "grant": {"type": "run-grant", "sha256": "c" * 64},
        "candidate_id": str(CANDIDATE), "nonce": NONCE, "expires_at": stamp(120), "identities": dict(IDENTITIES),
        "carrier_length": LENGTH, "parent": dict(PARENT)}
    return value | changes


# One substitute per bound field: the same JSON type, a different value.
SUBSTITUTES = {
    "type": "run-grant",
    "actor_id": 42,
    "service": "another-service",
    "scope": {"repository_id": SCOPE.repository_id, "run_id": "fiat-" + "b" * 64},
    "candidate_id": str(uuid.UUID(int=CANDIDATE.int + 1)),
    "nonce": "5" * 64,
    "identities": dict(IDENTITIES, outer_sha256="9" * 64),
    "carrier_length": LENGTH + 1,
    "parent": {"type": "parent-link", "sha256": "6" * 64},
    "issued_at": stamp(-1),
    "expires_at": stamp(0),
}


class BindingTests(unittest.TestCase):
    def refused(self, value, now=T0, bound=None):
        with self.assertRaises(AuthRefusal) as caught:
            check_binding(value, bound or binding(), 41, now)
        return caught.exception.code, caught.exception.reason

    def test_the_bound_endorsement_yields_its_references_and_times(self):
        terms = check_binding(record(), binding(), 41, T0)
        self.assertEqual((terms.policy_sha256, terms.enrollment_sha256, terms.grant),
                         ("a" * 64, "b" * 64, {"type": "run-grant", "sha256": "c" * 64}))
        self.assertEqual((terms.issued_at, terms.expires_at), (T0, at(120)))

    def test_every_field_the_service_bound_is_compared(self):
        self.assertEqual(set(SUBSTITUTES), set(BOUND))
        for field in BOUND:
            with self.subTest(field=field):
                self.refused(record(**{field: SUBSTITUTES[field]}))

    def test_actor_identities_and_length_are_identity_mismatches(self):
        self.assertEqual(self.refused(record(actor_id=42)), ("identity_mismatch", "endorsement-actor"))
        for value in (True, "41", 41.0, None):
            with self.subTest(actor=repr(value)):
                self.assertEqual(self.refused(record(actor_id=value))[0], "identity_mismatch")
        # The session's actor must be the endorsement's and the candidate's.
        with self.assertRaises(AuthRefusal) as caught:
            check_binding(record(), binding(), 42, T0)
        self.assertEqual(caught.exception.code, "identity_mismatch")
        swapped = dict(IDENTITIES, snapshot_id=IDENTITIES["controller_manifest_sha256"],
                       controller_manifest_sha256=IDENTITIES["snapshot_id"])
        for identities in (swapped, dict(IDENTITIES, snapshot_id="8" * 64), {"snapshot_id": "1" * 64},
                           dict(IDENTITIES, extra="x"), None):
            with self.subTest(identities=repr(identities)[:20]):
                self.assertEqual(self.refused(record(identities=identities)),
                                 ("identity_mismatch", "endorsement-identities"))
        for length in (LENGTH - 1, str(LENGTH), None):
            with self.subTest(length=repr(length)):
                self.assertEqual(self.refused(record(carrier_length=length)),
                                 ("identity_mismatch", "endorsement-length"))

    def test_candidate_nonce_run_and_parent_are_endorsement_refusals(self):
        for field, reason in (("candidate_id", "endorsement-candidate"), ("nonce", "endorsement-nonce"),
                              ("scope", "endorsement-run"), ("service", "endorsement-run"),
                              ("parent", "endorsement-parent")):
            with self.subTest(field=field):
                self.assertEqual(self.refused(record(**{field: SUBSTITUTES[field]})), ("endorsement_invalid", reason))
        self.assertEqual(self.refused(record(parent={"type": "acceptance", "sha256": PARENT["sha256"]})),
                         ("endorsement_invalid", "endorsement-parent"))
        self.assertEqual(self.refused(record(nonce=7)), ("endorsement_invalid", "endorsement-nonce"))

    def test_the_endorsement_must_be_signed_after_announce_and_unexpired_now(self):
        # Announce happened a quarter second into T0; its whole second counts as after it.
        self.assertEqual(self.refused(record(issued_at=stamp(-1))), ("endorsement_invalid", "endorsement-issued"))
        self.assertEqual(self.refused(record(issued_at=stamp(5), expires_at=stamp(60)), now=at(4)),
                         ("endorsement_invalid", "endorsement-issued"))
        self.assertEqual(self.refused(record(), now=at(120)), ("endorsement_invalid", "endorsement-expired"))
        check_binding(record(), binding(), 41, at(119.9))
        for value in ("2026-09-30 12:00:00", "", None, 1):
            with self.subTest(value=repr(value)):
                self.assertEqual(self.refused(record(issued_at=value)), ("endorsement_invalid", "endorsement-time"))

    def test_an_expired_candidate_refuses_first(self):
        self.assertEqual(self.refused(record(), bound=binding(expires_at=T0)), ("candidate_expired", "candidate-expired"))

    def test_missing_references_and_foreign_shapes_refuse(self):
        for field in ("policy", "enrollment", "grant"):
            with self.subTest(field=field):
                value = record()
                del value[field]
                self.assertEqual(self.refused(value), ("endorsement_invalid", "endorsement-references"))
        for value in (None, [], "record"):
            with self.subTest(value=repr(value)):
                self.assertEqual(self.refused(value)[0], "authority_unavailable")
        with self.assertRaises(AuthRefusal):
            check_binding(record(), {"candidate_id": CANDIDATE}, 41, T0)


class NonceTests(unittest.TestCase):
    def test_challenge_nonces_always_satisfy_the_released_record_pattern(self):
        # A base64url nonce starts with "-" or "_" about one time in 32, and the
        # released schema then refuses every endorsement for that candidate as
        # `schema-pattern`. 4096 draws leave the old generator no real chance.
        schema = fixtures.library().schema
        nonces = {challenge_nonce() for _ in range(4096)}
        self.assertEqual(len(nonces), 4096)
        for nonce in nonces:
            schema.validate(nonce, schema.ID)
