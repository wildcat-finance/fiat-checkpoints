"""Every ordered pair of candidate states, with and without each row's evidence."""

import itertools
import unittest

from fiat_checkpoints.domain.identities import CheckpointIdentities, IdentityMismatch
from fiat_checkpoints.domain.transitions import (PRE_AUTHORIZATION, TRANSITIONS, Evidence, State,
                                                 TransitionRefused, advance)


S = State
E = Evidence
# Specification section 11, written out independently of the implementation table.
EXPECTED = {
    (S.ANNOUNCED, S.UPLOADING): {E.RUN_GRANT, E.QUOTA_RESERVED, E.EXACT_SIZE_AND_DIGEST},
    (S.UPLOADING, S.QUARANTINED): {E.STREAM_COUNT_AND_HASH, E.QUARANTINE_READ_BACK},
    (S.QUARANTINED, S.VALIDATING): {E.CANDIDATE_UNEXPIRED, E.ISOLATED_WORKER},
    (S.VALIDATING, S.PUBLISHING): {E.PROTOCOL_CHECKS, E.RECONSTRUCTION, E.IDENTITY,
                                   E.AUTHORIZATION, E.DENIAL_CHECK},
    (S.PUBLISHING, S.AWAITING_REPLICA): {E.PRIMARY_COPY},
    (S.AWAITING_REPLICA, S.AWAITING_SIGNATURE): {E.RECOVERY_COPY},
    (S.AWAITING_SIGNATURE, S.PUBLISHING_RECEIPT): {E.SIGNED_ENVELOPE},
    (S.PUBLISHING_RECEIPT, S.FINALIZING): {E.RECEIPT_IN_BOTH_STORES},
    (S.FINALIZING, S.PUBLISHING_FINALIZATION): {E.JOURNAL_FINALIZATION},
    (S.PUBLISHING_FINALIZATION, S.ACCEPTED): {E.FINALIZATION_IN_BOTH_STORES, E.ACCEPTED_PREDICATE},
    (S.ACCEPTED, S.REVOKED): {E.SIGNED_DENIAL, E.POISON_POLICY},
}
for state in (S.ANNOUNCED, S.UPLOADING, S.QUARANTINED, S.VALIDATING, S.PUBLISHING,
              S.AWAITING_REPLICA, S.AWAITING_SIGNATURE):
    EXPECTED[(state, S.REJECTED)] = {E.DETERMINISTIC_REFUSAL, E.NO_SIGNER_AUTHORIZATION}
    EXPECTED[(state, S.EXPIRED)] = {E.DEADLINE_ELAPSED, E.CANCELLATION_WON}
# Specification lines 344 and 350: signer-authorized work ends in complete
# publication or a signed denial. Looked up by value so the guard fails, rather
# than errors, on a table without the state (S2-R1-03).
DENIED = next((state for state in State if state.value == "denied"), None)
AFTER_AUTHORIZATION = {S.PUBLISHING_RECEIPT: S.FINALIZING, S.FINALIZING: S.PUBLISHING_FINALIZATION,
                       S.PUBLISHING_FINALIZATION: S.ACCEPTED}
if DENIED is not None:
    for state in AFTER_AUTHORIZATION:
        EXPECTED[(state, DENIED)] = {E.SIGNED_DENIAL}


class TransitionMatrixTests(unittest.TestCase):
    def test_table_is_the_specification_table(self):
        self.assertEqual({pair: set(row.evidence) for pair, row in TRANSITIONS.items()}, EXPECTED)
        self.assertEqual(len(State), 15)
        self.assertEqual(len(TRANSITIONS), 28)

    def test_every_pair_is_legal_only_with_exactly_its_evidence(self):
        checked = 0
        for source, target in itertools.product(State, repeat=2):
            required = EXPECTED.get((source, target))
            with self.subTest(source=source.value, target=target.value):
                if required is None:
                    for evidence in (set(), set(Evidence)):
                        with self.assertRaises(TransitionRefused) as caught:
                            advance(source, target, evidence)
                        self.assertEqual(caught.exception.code, "transition-illegal")
                else:
                    self.assertIs(advance(source, target, frozenset(required)), target)
                    for missing in required:
                        with self.assertRaises(TransitionRefused) as caught:
                            advance(source, target, required - {missing})
                        self.assertEqual(caught.exception.code, "transition-evidence")
                    for extra in set(Evidence) - required:
                        with self.assertRaises(TransitionRefused) as caught:
                            advance(source, target, required | {extra})
                        self.assertEqual(caught.exception.code, "transition-evidence")
            checked += 1
        self.assertEqual(checked, len(State) ** 2)

    def test_terminal_states_have_no_successor(self):
        for state in (S.REJECTED, S.EXPIRED, S.REVOKED, DENIED):
            self.assertFalse([pair for pair in TRANSITIONS if pair[0] == state])
        self.assertEqual([pair[1] for pair in TRANSITIONS if pair[0] == S.ACCEPTED], [S.REVOKED])

    def test_only_pre_authorization_states_can_reject_or_expire(self):
        for target in (S.REJECTED, S.EXPIRED):
            sources = {pair[0] for pair in TRANSITIONS if pair[1] == target}
            self.assertEqual(sources, set(PRE_AUTHORIZATION))
        for state in (S.PUBLISHING_RECEIPT, S.FINALIZING, S.PUBLISHING_FINALIZATION, S.ACCEPTED):
            self.assertNotIn(state, PRE_AUTHORIZATION)

    def test_signer_authorized_work_ends_in_publication_or_signed_denial(self):
        self.assertIsNotNone(DENIED)
        for state, forward in AFTER_AUTHORIZATION.items():
            with self.subTest(state=state.value):
                self.assertEqual({pair[1] for pair in TRANSITIONS if pair[0] == state}, {forward, DENIED})
                self.assertIs(advance(state, DENIED, {E.SIGNED_DENIAL}), DENIED)
                for evidence in ({E.SIGNED_DENIAL, E.POISON_POLICY}, {E.DEADLINE_ELAPSED, E.CANCELLATION_WON}):
                    with self.assertRaises(TransitionRefused):
                        advance(state, DENIED, evidence)
        self.assertEqual({pair[0] for pair in TRANSITIONS if pair[1] == DENIED}, set(AFTER_AUTHORIZATION))
        self.assertEqual([pair[1] for pair in TRANSITIONS if pair[0] == S.ACCEPTED], [S.REVOKED])

    def test_happy_path_never_skips_a_phase(self):
        order = [S.ANNOUNCED, S.UPLOADING, S.QUARANTINED, S.VALIDATING, S.PUBLISHING, S.AWAITING_REPLICA,
                 S.AWAITING_SIGNATURE, S.PUBLISHING_RECEIPT, S.FINALIZING, S.PUBLISHING_FINALIZATION,
                 S.ACCEPTED]
        state = order[0]
        for target in order[1:]:
            state = advance(state, target, TRANSITIONS[(state, target)].evidence)
        self.assertIs(state, S.ACCEPTED)
        for index, source in enumerate(order):
            for later in order[index + 2:]:
                with self.assertRaises(TransitionRefused):
                    advance(source, later, set(Evidence))

    def test_untyped_inputs_refuse(self):
        for source, target, evidence, code in (
            ("announced", S.UPLOADING, set(), "state-unknown"),
            (S.ANNOUNCED, "uploading", set(), "state-unknown"),
            (S.ANNOUNCED, S.UPLOADING, ["current-run-grant"], "evidence-unknown"),
            (S.ANNOUNCED, S.UPLOADING, {"current-run-grant"}, "evidence-unknown"),
            (S.ANNOUNCED, S.UPLOADING, None, "evidence-unknown"),
        ):
            with self.subTest(code=code), self.assertRaises(TransitionRefused) as caught:
                advance(source, target, evidence)
            self.assertEqual(caught.exception.code, code)


class IdentityTests(unittest.TestCase):
    VALUES = {"snapshot_id": "1" * 64, "controller_manifest_sha256": "2" * 64, "outer_sha256": "3" * 64}

    def test_protocol_roles_map_to_service_names(self):
        identities = CheckpointIdentities.from_protocol(self.VALUES)
        self.assertEqual(identities.archive_sha256, "3" * 64)
        self.assertEqual(identities.protocol(), self.VALUES)

    def test_each_role_substitution_refuses(self):
        expected = CheckpointIdentities.from_protocol(self.VALUES)
        for first, second in itertools.combinations(self.VALUES, 2):
            swapped = dict(self.VALUES, **{first: self.VALUES[second], second: self.VALUES[first]})
            with self.subTest(swap=(first, second)), self.assertRaises(IdentityMismatch) as caught:
                expected.require(CheckpointIdentities.from_protocol(swapped))
            self.assertEqual(caught.exception.code, "identity_mismatch")
        for role in self.VALUES:
            changed = dict(self.VALUES, **{role: "f" * 64})
            with self.subTest(role=role), self.assertRaises(IdentityMismatch):
                expected.require(CheckpointIdentities.from_protocol(changed))
        self.assertIs(expected.require(CheckpointIdentities.from_protocol(dict(self.VALUES))), expected)

    def test_malformed_identities_refuse_without_echo(self):
        for value in ({**self.VALUES, "archive_sha256": "3" * 64}, {"snapshot_id": "1" * 64},
                      dict(self.VALUES, snapshot_id="A" * 64), dict(self.VALUES, outer_sha256="3" * 63),
                      dict(self.VALUES, controller_manifest_sha256=None), ["1" * 64] * 3):
            with self.subTest(value=str(value)[:40]), self.assertRaises(IdentityMismatch) as caught:
                CheckpointIdentities.from_protocol(value)
            self.assertEqual(caught.exception.code, "identity_malformed")
            self.assertNotIn("1" * 64, str(caught.exception))
        with self.assertRaises(IdentityMismatch):
            CheckpointIdentities.from_protocol(self.VALUES).require(self.VALUES)


if __name__ == "__main__":
    unittest.main()
