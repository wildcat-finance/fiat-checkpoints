"""Fresh challenges and endorsements for one candidate before signer authorization.

The store is exercised directly with synthetic verified envelopes, so no
verifier process starts; `tests.test_endorsement_flow` covers the same rules
over HTTP with signed records.
"""

from dataclasses import dataclass
import hashlib
from unittest import mock

from fiat_checkpoints.auth.refusals import AuthRefusal
from fiat_checkpoints.domain.transitions import Evidence
from fiat_checkpoints.grants import endorsement as endorsement_module
from fiat_checkpoints.grants.endorsement import EndorsementStore, Terms
from tests.persistence_support import ACTOR, IDENTITIES, SCOPE, T0, DatabaseCase, at, run_threads


PARENT = "5" * 64


@dataclass(frozen=True)
class Verified:
    """What `record` reads from a library-verified envelope."""
    envelope: bytes
    envelope_sha256: str
    key_fingerprint: str


def verified(label):
    envelope = ("synthetic-endorsement-" + label).encode()
    return Verified(envelope, hashlib.sha256(envelope).hexdigest(), "f" * 64)


def terms(issued, lifetime=120):
    return Terms("1" * 64, "2" * 64, {"type": "run-grant", "sha256": "3" * 64}, at(issued), at(issued + lifetime))


class RenewalTests(DatabaseCase):
    def setUp(self):
        super().setUp()
        self.store = EndorsementStore(self.database)
        self.candidate = self.announce().candidate_id
        # `record` compares the stored trust head it was given; nothing here verifies the row.
        policy = b"synthetic-policy"
        run_key = self.scalar("SELECT run_key FROM candidates WHERE candidate_id = %s", (self.candidate,))
        connection = self.database.connect()
        try:
            connection.execute("INSERT INTO trust_records (run_key, sequence, record_type, envelope, envelope_sha256, "
                               "ingested_at) VALUES (%s, 1, 'authority-policy', %s, %s, %s)",
                               (run_key, policy, hashlib.sha256(policy).hexdigest(), T0))
        finally:
            connection.close()
        self.head = (1, hashlib.sha256(policy).hexdigest())

    def bind(self, seconds):
        return self.store.bind(self.candidate, IDENTITIES, PARENT, at(seconds))

    def record(self, label, seconds, nonce=None, issued=None):
        binding = self.store.binding(ACTOR, self.candidate)
        if nonce is not None:
            binding = self.store.named(binding, nonce)
        return self.store.record(binding, verified(label), terms(seconds if issued is None else issued), self.head,
                                 at(seconds))

    def refusal(self, call):
        with self.assertRaises(AuthRefusal) as caught:
            call()
        return caught.exception.code, caught.exception.reason

    def endorsements(self):
        return self.scalar("SELECT count(*) FROM upload_endorsements WHERE candidate_id = %s", (self.candidate,))

    def test_a_spent_challenge_is_followed_by_a_fresh_one_on_announce_replay(self):
        first = self.bind(0)
        self.assertEqual(self.bind(1).nonce, first.nonce)
        self.record("one", 2)
        # The first endorsement expired at 122 s; one validation job alone may take 900 s.
        second = self.bind(130)
        self.assertNotEqual(second.nonce, first.nonce)
        self.assertEqual(self.bind(131), second)
        self.assertEqual(self.record("two", 132).replayed, False)
        bound = self.store.bound(ACTOR, self.candidate, at(133))
        self.assertEqual((bound.sequence, bound.envelope_sha256), (2, verified("two").envelope_sha256))
        self.assertEqual(self.endorsements(), 2)

    def test_the_latest_endorsement_is_bound_and_an_earlier_one_never_again(self):
        first = self.bind(0)
        self.record("one", 1)
        second = self.bind(10)
        self.assertNotEqual(second.nonce, first.nonce)
        # Before the next endorsement, an exact replay of the bound one still answers.
        self.assertEqual(self.record("one", 11, nonce=first.nonce).replayed, True)
        self.assertEqual(self.refusal(lambda: self.record("other", 12, nonce=first.nonce)),
                         ("endorsement_invalid", "nonce-consumed"))
        self.assertEqual(self.record("two", 13).replayed, False)
        self.assertEqual(self.refusal(lambda: self.record("one", 14, nonce=first.nonce)),
                         ("endorsement_invalid", "endorsement-superseded"))
        self.assertEqual(self.refusal(lambda: self.record("other", 15, nonce=second.nonce)),
                         ("endorsement_invalid", "nonce-consumed"))
        self.assertEqual(self.record("two", 16, nonce=second.nonce).replayed, True)
        self.assertEqual(self.store.bound(ACTOR, self.candidate, at(17)).sequence, 2)
        # A caller that needs the endorsement valid until later is refused rather than handed one that lapses.
        self.assertEqual(self.store.bound(ACTOR, self.candidate, at(17), until=at(132)).sequence, 2)
        self.assertEqual(self.refusal(lambda: self.store.bound(ACTOR, self.candidate, at(17), until=at(133))),
                         ("endorsement_invalid", "endorsement-expired"))
        # Once the bound endorsement expires it is refused, never replaced by an earlier one.
        self.assertEqual(self.refusal(lambda: self.store.bound(ACTOR, self.candidate, at(133))),
                         ("endorsement_invalid", "endorsement-expired"))
        self.assertEqual(self.refusal(lambda: self.store.bound(ACTOR + 1, self.candidate, at(17))),
                         ("not_found", "endorsement-absent"))
        self.assertEqual(self.endorsements(), 2)

    def test_two_endorsements_racing_for_one_fresh_challenge_record_one(self):
        first = self.bind(0)
        self.record("one", 1)
        self.assertNotEqual(self.bind(10).nonce, first.nonce)
        binding = self.store.binding(ACTOR, self.candidate)

        def endorse(index):
            return self.store.record(binding, verified(f"race-{index}"), terms(11), self.head, at(11))

        results = run_threads(2, endorse)
        recorded = [result for result in results if not isinstance(result, Exception)]
        refused = [(result.code, result.reason) for result in results if isinstance(result, AuthRefusal)]
        self.assertEqual((len(recorded), refused), (1, [("endorsement_invalid", "nonce-consumed")]))
        self.assertEqual(self.endorsements(), 2)

    def test_fresh_challenges_stop_at_the_ceiling_and_the_candidate_deadline(self):
        first = self.bind(0)
        self.record("one", 1)
        self.coordinator.begin_upload(SCOPE, ACTOR, self.candidate, {Evidence.RUN_GRANT}, at(2))
        # An upload in progress is still before signer authorization.
        second = self.bind(3)
        self.assertNotEqual(second.nonce, first.nonce)
        self.assertEqual(self.record("two", 4).replayed, False)
        with mock.patch.object(endorsement_module, "MAX_CHALLENGES", 2):
            self.assertEqual(self.refusal(lambda: self.bind(5)), ("quota_exceeded", "endorsement-limit"))
        third = self.bind(6)
        self.assertEqual(third.sequence, 3)
        self.record("three", 7)
        # After the candidate's deadline no challenge is issued and nothing is recorded.
        late = 24 * 3600
        self.assertEqual(self.bind(late), third)
        self.assertEqual(self.refusal(lambda: self.record("four", late)), ("candidate_expired", "candidate-expired"))
        self.assertEqual(self.endorsements(), 3)
