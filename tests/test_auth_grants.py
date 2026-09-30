"""Operator-approved enrollment and grants from signed records, revocation, run isolation and key history."""

import base64
from contextlib import contextmanager
import hashlib
import json
import subprocess
import unittest
from unittest import mock

from fiat_checkpoints.auth.refusals import AuthRefusal
from fiat_checkpoints.grants.intake import Intake
from fiat_checkpoints.grants.projection import Projections
from tests import authority_fixtures as fixtures
from tests.auth_support import (ACTOR, FAR, OTHER_ACTOR, OTHER_SCOPE, T0, Operator, at, common, contributor_journal,
                                proof, ref, run_authority, stamp)
from tests.persistence_support import DatabaseCase, recorded_events


@contextmanager
def counted_processes():
    """Count child processes started inside the block; each is one pinned verifier run."""
    started = []
    original = subprocess.Popen

    def counting(*arguments, **options):
        started.append(arguments[0][0] if arguments else options.get("args", [None])[0])
        return original(*arguments, **options)

    with mock.patch.object(subprocess, "Popen", counting):
        yield started


def tampered(envelope):
    """The same carrier with one payload byte changed, so its signature no longer holds."""
    value = json.loads(envelope)
    payload = bytearray(base64.b64decode(value["payload"]))
    payload[payload.index(b"test")] = ord("T")
    value["payload"] = base64.b64encode(bytes(payload)).decode()
    return json.dumps(value, separators=(",", ":")).encode()


def granted_or_code(projections, actor):
    """`any_grant`'s answer, or the public code it refused with."""
    try:
        return projections.any_grant(actor, T0)
    except AuthRefusal as refusal:
        return refusal.code


class AnyGrantTests(unittest.TestCase):
    """The loop over allowlisted runs, with each run's projection stubbed; no verifier runs."""

    def projections(self, answers):
        projections = Projections.__new__(Projections)
        projections._runs = {name: name for name in answers}

        def current(run):
            answer = answers[run]
            if isinstance(answer, AuthRefusal):
                raise answer
            return mock.Mock(any_grant=mock.Mock(return_value=answer))

        projections.current = current
        return projections

    def test_a_run_that_refuses_does_not_hide_a_grant_in_another_run(self):
        broken = AuthRefusal("authority_unavailable", "trust-prefix-refused")
        self.assertIs(granted_or_code(self.projections({"broken": broken, "granting": True}), ACTOR), True)
        self.assertIs(granted_or_code(self.projections({"granting": True, "broken": broken}), ACTOR), True)
        self.assertEqual(granted_or_code(self.projections({"broken": broken, "silent": False}), ACTOR),
                         "authority_unavailable")
        self.assertIs(granted_or_code(self.projections({"silent": False}), ACTOR), False)


class TrustCase(DatabaseCase):
    spawns_child_process = True

    @classmethod
    def setUpClass(cls):
        cls.operator_key, cls.contributor, cls.other, cls.stranger = (fixtures.Signer() for _ in range(4))

    @classmethod
    def tearDownClass(cls):
        for signer in (cls.operator_key, cls.contributor, cls.other, cls.stranger):
            signer.close()

    def setUp(self):
        super().setUp()
        self.operator = Operator(self.operator_key)
        self.other_operator = Operator(self.operator_key, OTHER_SCOPE)
        self.run, self.other_run = run_authority(self.operator), run_authority(self.other_operator)
        self.projections = Projections(self.database, (self.run, self.other_run))

    def sync(self, run=None, operator=None):
        """Ingest every journal record the run has not stored yet, in order."""
        run, operator = run or self.run, operator or self.operator
        stored = self.projections.current(run).count
        for envelope in operator.envelopes[stored:]:
            self.projections.ingest(run, envelope, T0)
        return self.projections.current(run)

    def refusal(self, call):
        with self.assertRaises(AuthRefusal) as caught:
            call()
        self.assertIsNone(caught.exception.__cause__)
        return caught.exception.code, caught.exception.protocol_code

    def stored(self):
        return self.scalar("SELECT count(*) FROM trust_records")


class EnrollmentTests(TrustCase):
    def test_only_operator_signed_enrollment_and_grant_authorize_an_actor(self):
        self.assertEqual(self.refusal(lambda: self.sync().grant(ACTOR, "announce", T0)), ("not_found", None))
        enrollment, grant = contributor_journal(self.operator, self.contributor)
        projection = self.sync()
        self.assertEqual(projection.grant(ACTOR, "announce", T0), ref("run-grant", grant))
        self.assertEqual(projection.grant(ACTOR, "upload", T0), ref("run-grant", grant))
        self.assertEqual(projection.upload_terms(ACTOR, T0),
                         {"grant": ref("run-grant", grant), "enrollment": ref("key-enrollment", enrollment)})
        for actor, permission in ((ACTOR, "download"), (OTHER_ACTOR, "announce")):
            with self.subTest(actor=actor, permission=permission):
                self.assertEqual(self.refusal(lambda: projection.grant(actor, permission, T0))[0], "not_found")
        rows = self.query("SELECT envelope FROM trust_records ORDER BY sequence")
        self.assertEqual([bytes(row["envelope"]) for row in rows], self.operator.envelopes)

    def test_a_refused_record_writes_nothing(self):
        self.sync()
        challenge = self.operator.challenge(ACTOR, self.contributor.key, -3600)
        enrollment = self.operator.enroll(ACTOR, self.contributor.key, challenge,
                                          proof(self.contributor, self.operator.record_of(challenge)), -3590)
        endorsement = fixtures.envelope(common("upload-endorsement", 1, None, stamp(0),
                                               self.contributor.key["fingerprint"], fixtures.SCOPE) | {
            "policy": self.operator.policy, "actor_id": ACTOR, "enrollment": ref("key-enrollment", enrollment),
            "grant": {"type": "run-grant", "sha256": "8" * 64}, "candidate_id": "candidate-1", "nonce": "n-1",
            "expires_at": stamp(60), "identities": {"snapshot_id": "1" * 64, "controller_manifest_sha256": "2" * 64,
                                                    "outer_sha256": "3" * 64}, "carrier_length": 1,
            "parent": {"type": "parent-link", "sha256": "5" * 64}}, self.contributor)
        for label, envelope in (("tampered", tampered(challenge)), ("out-of-order", enrollment),
                                ("not-a-trust-record", endorsement)):
            with self.subTest(label=label):
                code, protocol_code = self.refusal(lambda: self.projections.ingest(self.run, envelope, T0))
                self.assertEqual(code, "protocol_refused")
                self.assertIsNotNone(protocol_code)
                self.assertEqual(self.stored(), 1)
        for envelope in (b"", "text", b"x" * 65_537, bytearray(challenge)):
            with self.subTest(size=len(envelope)):
                self.assertEqual(self.refusal(lambda: self.projections.ingest(self.run, envelope, T0))[0],
                                 "request_invalid")
        self.assertEqual(self.refusal(lambda: self.projections.ingest(self.other_run, challenge, T0)),
                         ("protocol_refused", "bootstrap-required"))
        self.projections.ingest(self.run, challenge, T0)
        self.assertEqual(self.stored(), 2)

    def test_a_carried_key_cannot_enroll_itself(self):
        self.sync()
        challenge = self.operator.challenge(ACTOR, self.stranger.key, -3600)
        self.sync()
        own = self.operator.next("key-enrollment", -3590) | {
            "issuer": self.stranger.key["fingerprint"], "actor_id": ACTOR, "key": self.stranger.key,
            "proof": {"challenge": ref("enrollment-challenge", challenge),
                      "signature": base64.b64encode(proof(self.stranger, self.operator.record_of(challenge))).decode()},
            "not_before": stamp(-3590), "not_after": FAR}
        self.assertEqual(self.refusal(lambda: self.projections.ingest(
            self.run, fixtures.envelope(own, self.stranger), T0)), ("protocol_refused", "issuer-untrusted"))
        own_challenge = self.operator.next("enrollment-challenge", -3590) | {
            "issuer": self.stranger.key["fingerprint"], "actor_id": ACTOR, "key": self.stranger.key,
            "nonce": "self-made", "expires_at": stamp(-3400)}
        self.assertEqual(self.refusal(lambda: self.projections.ingest(
            self.run, fixtures.envelope(own_challenge, self.stranger), T0)), ("protocol_refused", "issuer-untrusted"))
        self.assertEqual(self.stored(), 2)
        projection = self.projections.current(self.run)
        self.assertEqual(self.refusal(lambda: projection.historical_signers(
            [({"type": "key-enrollment", "sha256": "9" * 64}, self.stranger.key["fingerprint"])]))[0],
            "signer_not_enrolled")
        self.assertFalse(projection.any_grant(ACTOR, T0))


class GrantStateTests(TrustCase):
    def test_a_revocation_stops_the_grant_at_the_next_request(self):
        enrollment, _grant = contributor_journal(self.operator, self.contributor)
        self.assertTrue(self.sync().any_grant(ACTOR, T0))
        self.operator.revoke(ACTOR, enrollment, -60)
        projection = self.sync()
        self.assertEqual(self.refusal(lambda: projection.grant(ACTOR, "announce", T0)),
                         ("not_found", "enrollment-inactive"))
        self.assertFalse(self.projections.any_grant(ACTOR, T0))

    def test_an_expired_grant_refuses_from_its_not_after(self):
        contributor_journal(self.operator, self.contributor, grant_not_after=stamp(60))
        projection = self.sync()
        projection.grant(ACTOR, "announce", at(59))
        self.assertEqual(self.refusal(lambda: projection.grant(ACTOR, "announce", at(60))),
                         ("not_found", "grant-expired"))


class RunIsolationTests(TrustCase):
    def test_runs_never_see_each_others_records_or_grants(self):
        enrollment, grant = contributor_journal(self.operator, self.contributor)
        self.sync()
        other = self.sync(self.other_run, self.other_operator)
        self.assertEqual(self.refusal(lambda: other.grant(ACTOR, "announce", T0))[0], "not_found")
        self.assertEqual(self.refusal(lambda: self.projections.ingest(self.other_run, grant, T0))[0],
                         "protocol_refused")
        self.assertEqual(self.refusal(lambda: other.historical_signers(
            [(ref("key-enrollment", enrollment), self.contributor.key["fingerprint"])]))[0], "signer_not_enrolled")
        self.assertEqual(self.projections.run(fixtures.SCOPE.repository_id, fixtures.SCOPE.run_id), self.run)
        for repository, run_id in ((fixtures.SCOPE.repository_id, "unknown-run"), (8, fixtures.SCOPE.run_id),
                                   ("7", fixtures.SCOPE.run_id), (True, fixtures.SCOPE.run_id)):
            with self.subTest(repository=repr(repository), run=run_id[:8]):
                self.assertEqual(self.refusal(lambda: self.projections.run(repository, run_id))[0], "not_found")


class HistoricalSignerTests(TrustCase):
    def test_only_keys_this_run_approved_can_be_historical_signers(self):
        first, _ = contributor_journal(self.operator, self.contributor)
        second, _ = contributor_journal(self.operator, self.other, actor=OTHER_ACTOR, issued=-3000)
        projection = self.sync()
        history = projection.historical_signers([(ref("key-enrollment", first), self.contributor.key["fingerprint"]),
                                                 (ref("key-enrollment", second), self.other.key["fingerprint"])])
        self.assertEqual(history, [ref("key-enrollment", first), ref("key-enrollment", second)])
        cases = (
            ([(ref("key-enrollment", first), self.stranger.key["fingerprint"])], None),
            ([(ref("key-enrollment", first), self.other.key["fingerprint"])], None),
            ([({"type": "key-enrollment", "sha256": "9" * 64}, self.stranger.key["fingerprint"])], "trust-reference"),
            ([(ref("key-rotation", first), self.contributor.key["fingerprint"])], "trust-reference"),
            ([(ref("run-grant", first), self.contributor.key["fingerprint"])], "request_invalid"),
        )
        for signers, protocol_code in cases:
            with self.subTest(protocol_code=protocol_code):
                code, observed = self.refusal(lambda: projection.historical_signers(signers))
                if protocol_code == "request_invalid":
                    self.assertEqual(code, "request_invalid")
                else:
                    self.assertEqual((code, observed), ("signer_not_enrolled", protocol_code))
        for signers in ([], None, [("x", "y")], [(ref("key-enrollment", first),)], [(ref("key-enrollment", first), 7)],
                        [(ref("key-enrollment", first), "f")] * 65):
            with self.subTest(signers=repr(signers)[:20]):
                self.assertEqual(self.refusal(lambda: projection.historical_signers(signers))[0], "request_invalid")

    def test_a_later_revocation_keeps_the_signer_historical_and_visible(self):
        first, _ = contributor_journal(self.operator, self.contributor)
        revocation = self.operator.revoke(ACTOR, first, -60, reason="retired")
        projection = self.sync()
        self.assertEqual(projection.historical_signers([(ref("key-enrollment", first),
                                                         self.contributor.key["fingerprint"])]),
                         [ref("key-enrollment", first), ref("key-revocation", revocation)])


class StoredTrustTests(TrustCase):
    def test_stored_rows_that_no_longer_verify_stop_the_run(self):
        contributor_journal(self.operator, self.contributor)
        self.sync()
        connection = self.database.connect()
        try:
            connection.execute("ALTER TABLE trust_records DISABLE TRIGGER trust_records_immutable")
            original = bytes(connection.execute("SELECT envelope FROM trust_records WHERE sequence = 2")
                             .fetchone()["envelope"])
            changed = tampered(original)
            for label, digest in (("bytes-only", None), ("bytes-and-digest", "match")):
                with self.subTest(label=label):
                    connection.execute("UPDATE trust_records SET envelope = %s, envelope_sha256 = "
                                       "coalesce(%s, envelope_sha256) WHERE sequence = 2",
                                       (changed, None if digest is None else hashlib.sha256(changed).hexdigest()))
                    restarted = Projections(self.database, (self.run, self.other_run))
                    code, _ = self.refusal(lambda: restarted.current(self.run))
                    self.assertEqual(code, "authority_unavailable")
                    self.assertEqual(self.refusal(lambda: restarted.any_grant(ACTOR, T0))[0], "authority_unavailable")
        finally:
            connection.close()

    def test_a_run_that_no_longer_verifies_freezes_only_that_run(self):
        contributor_journal(self.operator, self.contributor)
        self.sync()
        self.sync(self.other_run, self.other_operator)
        connection = self.database.connect()
        try:
            connection.execute("ALTER TABLE trust_records DISABLE TRIGGER trust_records_immutable")
            run_key = Projections._run_key(connection, self.other_run)
            original = bytes(connection.execute("SELECT envelope FROM trust_records WHERE run_key = %s "
                                                "AND sequence = 1", (run_key,)).fetchone()["envelope"])
            connection.execute("UPDATE trust_records SET envelope = %s WHERE run_key = %s AND sequence = 1",
                               (tampered(original), run_key))
        finally:
            connection.close()
        # The broken run comes first, so pairing reaches it before the run that grants.
        restarted = Projections(self.database, (self.other_run, self.run))
        self.assertEqual(self.refusal(lambda: restarted.current(self.other_run))[0], "authority_unavailable")
        self.assertIs(granted_or_code(restarted, ACTOR), True)
        self.assertEqual(granted_or_code(restarted, OTHER_ACTOR), "authority_unavailable")

    def test_authority_events_name_kinds_and_codes_never_digests(self):
        with recorded_events() as events:
            self.sync()
            challenge = self.operator.challenge(ACTOR, self.contributor.key, -3600)
            self.refusal(lambda: self.projections.ingest(self.run, tampered(challenge), T0))
            restarted = Projections(self.database, (self.run, self.other_run))
            connection = self.database.connect()
            try:
                connection.execute("ALTER TABLE trust_records DISABLE TRIGGER trust_records_immutable")
                connection.execute("UPDATE trust_records SET envelope_sha256 = %s", ("0" * 64,))
            finally:
                connection.close()
            self.refusal(lambda: restarted.current(self.run))
        kinds = [(event["event"], event.get("kind"), event.get("code"), event.get("reason")) for event in events]
        self.assertIn(("authority-record-ingested", "authority-policy", None, None), kinds)
        self.assertIn(("authority-record-refused", None, "protocol_refused", "trust-record-refused"), kinds)
        self.assertEqual(kinds[-1], ("trust-projection-refused", None, "authority_unavailable", "trust-record-drift"))
        text = repr(events)
        for envelope in self.operator.envelopes:
            self.assertNotIn(hashlib.sha256(envelope).hexdigest(), text)
        self.assertNotIn(self.operator_key.key["fingerprint"], text)

    def test_the_projection_is_verified_once_per_head(self):
        contributor_journal(self.operator, self.contributor)
        self.sync()
        restarted = Projections(self.database, (self.run, self.other_run))
        with counted_processes() as first:
            restarted.current(self.run)
        # Four envelope signatures and the enrollment's proof of possession.
        self.assertEqual(first, [fixtures.OPENSSL_PATH] * 5)
        with counted_processes() as second:
            restarted.current(self.run)
            restarted.any_grant(ACTOR, T0)
        self.assertEqual(second, [])
        self.operator.challenge(OTHER_ACTOR, self.other.key, -100)
        with counted_processes() as ingest:
            restarted.ingest(self.run, self.operator.envelopes[-1], T0)
        with counted_processes() as after:
            restarted.current(self.run)
        self.assertEqual((len(ingest), after), (6, []))


class ProofOfPossessionTests(TrustCase):
    def setUp(self):
        super().setUp()
        self.intake = Intake(self.database, self.coordinator, self.projections)
        self.challenge = self.operator.challenge(ACTOR, self.contributor.key, -60)
        self.sync()
        self.sync(self.other_run, self.other_operator)

    def body(self, signer=None, challenge=None):
        challenge = challenge or self.challenge
        signature = proof(signer or self.contributor, self.operator.record_of(challenge))
        return {"challenge": ref("enrollment-challenge", challenge), "signature": base64.b64encode(signature).decode()}

    def prove(self, body, actor=ACTOR, scope=fixtures.SCOPE, now=T0):
        return self.intake.prove_enrollment(actor, scope.repository_id, scope.run_id, body, now)

    def test_the_authenticated_actor_proves_possession_of_its_challenged_key(self):
        body = self.body()
        self.assertFalse(self.prove(body).replayed)
        self.assertTrue(self.prove(body).replayed)
        self.assertEqual(self.refusal(lambda: self.prove(self.body()))[0], "idempotency_conflict")
        row = self.query("SELECT actor_id, signature FROM enrollment_proofs")[0]
        self.assertEqual((row["actor_id"], row["signature"]), (ACTOR, body["signature"]))

    def test_proofs_for_another_actor_key_run_or_time_refuse(self):
        self.assertEqual(self.refusal(lambda: self.prove(self.body(), actor=OTHER_ACTOR))[0], "not_found")
        self.assertEqual(self.refusal(lambda: self.prove(self.body(self.stranger))),
                         ("signer_not_enrolled", "signature-invalid"))
        self.assertEqual(self.refusal(lambda: self.prove(self.body(), scope=OTHER_SCOPE))[0], "not_found")
        self.assertEqual(self.refusal(lambda: self.prove(self.body(), now=at(240))),
                         ("signer_not_enrolled", None))
        self.assertEqual(self.refusal(lambda: self.prove(
            {"challenge": {"type": "enrollment-challenge", "sha256": "9" * 64}, "signature": "AAAA"}))[0], "not_found")
        self.assertEqual(self.refusal(lambda: self.prove(dict(self.body(), signature="%%%")))[0],
                         "signer_not_enrolled")
        self.assertEqual(self.scalar("SELECT count(*) FROM enrollment_proofs"), 0)

    def test_a_consumed_challenge_takes_no_further_proof(self):
        body = self.body()
        self.operator.enroll(ACTOR, self.contributor.key, self.challenge,
                             proof(self.contributor, self.operator.record_of(self.challenge)), -50)
        self.sync()
        self.assertEqual(self.refusal(lambda: self.prove(body))[0], "not_found")
