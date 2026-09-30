"""Announce, signed upload endorsement and status over HTTP against real operator-signed records."""

import base64
import hashlib
import uuid

from fiat_checkpoints.auth.refusals import AuthRefusal
from fiat_checkpoints.grants.endorsement import check_binding
from fiat_checkpoints.grants.projection import Projections
from tests import authority_fixtures as fixtures
from tests.auth_support import (ACTOR, IDENTITIES, OTHER_ACTOR, OTHER_SCOPE, PARENT, T0, Clock, Operator,
                                announce_body, build, contributor_journal, endorsement_record, proof, ref, request,
                                run_authority, session_headers, stamp)
from tests.persistence_support import DatabaseCase, recorded_events
from tests.test_auth_grants import counted_processes


class FlowCase(DatabaseCase):
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
        self.clock = Clock()
        self.operator = Operator(self.operator_key)
        self.other_operator = Operator(self.operator_key, OTHER_SCOPE)
        self.enrollment, self.grant = contributor_journal(self.operator, self.contributor)
        self.other_enrollment, self.other_grant = contributor_journal(
            self.operator, self.other, actor=OTHER_ACTOR, issued=-3000)
        self.run, self.other_run = run_authority(self.operator), run_authority(self.other_operator)
        projections = Projections(self.database, (self.run, self.other_run))
        self.app, self.services = build(self.database, self.clock, projections=projections)
        self.sync()
        for envelope in self.other_operator.envelopes:
            projections.ingest(self.other_run, envelope, T0)
        self.session = self.services.sessions.open_session(ACTOR, T0)
        self.other_session = self.services.sessions.open_session(OTHER_ACTOR, T0)

    def sync(self):
        projections = self.services.projections
        for envelope in self.operator.envelopes[projections.current(self.run).count:]:
            projections.ingest(self.run, envelope, T0)

    def call(self, method, path, session=None, **options):
        headers = session_headers(session or self.session) | options.pop("headers", {})
        return request(self.app, method, path, headers=headers, **options)

    def announce(self, key="announce-key-0001", session=None, **changes):
        return self.call("POST", "/v1/candidates", session, headers={"idempotency-key": key},
                         json=announce_body(**changes))

    def endorse(self, announced, envelope, session=None):
        return self.call("POST", f"/v1/candidates/{announced['candidate_id']}/endorsement", session, content=envelope)

    def signed(self, announced, signer=None, **changes):
        record = endorsement_record(announced, self.enrollment, self.grant, self.contributor, **changes)
        return fixtures.envelope(record, signer or self.contributor)

    def assert_refused(self, response, status, code):
        self.assertEqual((response.status_code, response.json()["code"]), (status, code), response.text)

    def recorded(self):
        return self.scalar("SELECT count(*) FROM upload_endorsements")


class AnnounceTests(FlowCase):
    def test_announce_needs_a_current_announce_grant_and_binds_a_challenge(self):
        stranger = self.services.sessions.open_session(77, T0)
        self.assert_refused(self.announce(session=stranger), 404, "not_found")
        created = self.announce()
        self.assertEqual(created.status_code, 201, created.text)
        body = created.json()
        challenge = body["endorsement"]
        self.assertEqual((body["state"], challenge["candidate_id"], challenge["not_before"]),
                         ("announced", body["candidate_id"], "2026-09-30T12:00:00Z"))
        self.assertRegex(challenge["nonce"], r"^[0-9a-f]{64}$")
        self.assertEqual(challenge["policy"], self.operator.policy)
        self.assertEqual(challenge["upload"], {"grant": ref("run-grant", self.grant),
                                               "enrollment": ref("key-enrollment", self.enrollment)})
        self.assertEqual((challenge["environment"], challenge["service"], challenge["scope"]),
                         ("test", fixtures.SCOPE.service, {"repository_id": fixtures.SCOPE.repository_id,
                                                           "run_id": fixtures.SCOPE.run_id}))
        replayed = self.announce()
        self.assertEqual(replayed.status_code, 200)
        self.assertEqual((replayed.json()["candidate_id"], replayed.json()["endorsement"]["nonce"]),
                         (body["candidate_id"], challenge["nonce"]))
        self.assert_refused(self.announce(identities=dict(IDENTITIES, snapshot_id="8" * 64)), 409,
                            "idempotency_conflict")

    def test_announce_in_a_run_without_a_grant_or_unknown_is_not_found(self):
        self.assert_refused(self.announce(scope=OTHER_SCOPE), 404, "not_found")
        self.assert_refused(self.announce(run={"repository_id": 7, "run_id": "unknown-run"}), 404, "not_found")
        self.assert_refused(self.announce(run={"repository_id": 8, "run_id": fixtures.SCOPE.run_id}), 404, "not_found")
        self.assertEqual(self.scalar("SELECT count(*) FROM candidates"), 0)


class EndorsementTests(FlowCase):
    def test_a_signed_endorsement_binds_the_exact_upload(self):
        announced = self.announce().json()
        envelope = self.signed(announced)
        done = self.endorse(announced, envelope)
        self.assertEqual(done.status_code, 200, done.text)
        self.assertEqual(done.json()["endorsement_sha256"], hashlib.sha256(envelope).hexdigest())
        self.assertEqual((done.json()["replayed"], done.json()["expires_at"]), (False, stamp(120)))
        row = self.query("SELECT envelope, key_fingerprint, grant_sha256 FROM upload_endorsements")[0]
        self.assertEqual((bytes(row["envelope"]), row["key_fingerprint"], row["grant_sha256"]),
                         (envelope, self.contributor.key["fingerprint"], ref("run-grant", self.grant)["sha256"]))
        self.assertEqual(self.scalar("SELECT count(*) FROM audit_events WHERE event = 'endorsement-verified'"), 1)
        with recorded_events() as events:
            again = self.endorse(announced, envelope)
        self.assertEqual((again.status_code, again.json()["replayed"]), (200, True))
        self.assertEqual([(event["event"], event.get("candidate"), event.get("kind")) for event in events][0],
                         ("endorsement-verified", announced["candidate_id"], "replayed"))
        text = repr(events)
        for value in (hashlib.sha256(envelope).hexdigest(), self.contributor.key["fingerprint"],
                      announced["endorsement"]["nonce"]):
            self.assertNotIn(value, text)

    def test_altered_digests_lengths_and_bindings_refuse_and_record_nothing(self):
        announced = self.announce().json()
        swapped = dict(IDENTITIES, snapshot_id=IDENTITIES["controller_manifest_sha256"],
                       controller_manifest_sha256=IDENTITIES["snapshot_id"])
        cases = (
            ({"identities": dict(IDENTITIES, outer_sha256="9" * 64)}, "identity_mismatch"),
            ({"identities": dict(IDENTITIES, snapshot_id="8" * 64)}, "identity_mismatch"),
            ({"identities": swapped}, "identity_mismatch"),
            ({"carrier_length": 4097}, "identity_mismatch"),
            ({"parent": dict(PARENT, sha256="6" * 64)}, "endorsement_invalid"),
            ({"candidate_id": str(uuid.uuid4())}, "endorsement_invalid"),
            ({"nonce": "n" * 43}, "endorsement_invalid"),
        )
        for changes, code in cases:
            with self.subTest(changes=sorted(changes)):
                self.assert_refused(self.endorse(announced, self.signed(announced, **changes)), 422, code)
        self.assertEqual(self.recorded(), 0)
        self.assertEqual(self.endorse(announced, self.signed(announced)).status_code, 200)

    def test_endorsement_replay_and_expiry(self):
        first = self.announce("announce-key-0001").json()
        second = self.announce("announce-key-0002").json()
        envelope = self.signed(first)
        self.assertEqual(self.endorse(first, envelope).status_code, 200)
        # The same signed bytes cannot move to another candidate, and the first nonce is spent.
        self.assert_refused(self.endorse(second, envelope), 422, "endorsement_invalid")
        self.assert_refused(self.endorse(first, self.signed(first, lifetime=90)), 422, "endorsement_invalid")
        self.assert_refused(self.endorse(second, self.signed(second, issued=-1)), 422, "endorsement_invalid")
        self.assert_refused(self.endorse(second, self.signed(second, issued=5)), 422, "endorsement_invalid")
        late = self.signed(second, lifetime=60)
        self.clock.advance(60)
        self.assert_refused(self.endorse(second, late), 422, "endorsement_invalid")
        self.clock.advance(60)
        self.assert_refused(self.endorse(first, envelope), 422, "endorsement_invalid")
        self.assertEqual(self.recorded(), 1)
        self.clock.advance(1)
        self.assertEqual(self.endorse(second, self.signed(second, issued=121, lifetime=60)).status_code, 200)

    def test_another_actor_key_run_or_carried_key_refuses(self):
        announced = self.announce().json()
        self.assert_refused(self.endorse(announced, self.signed(announced), self.other_session), 404, "not_found")
        self.assert_refused(self.endorse(announced, self.signed(announced, self.stranger)), 422,
                            "endorsement_invalid")
        # Another actor's enrolled key, signing for this actor, has no live enrollment for it.
        borrowed = endorsement_record(announced, self.other_enrollment, self.other_grant, self.other)
        self.assert_refused(self.endorse(announced, fixtures.envelope(borrowed, self.other)), 422,
                            "signer_not_enrolled")
        theirs = endorsement_record(announced, self.other_enrollment, self.other_grant, self.other,
                                    actor=OTHER_ACTOR)
        self.assert_refused(self.endorse(announced, fixtures.envelope(theirs, self.other)), 422, "identity_mismatch")
        foreign = endorsement_record(announced, self.enrollment, self.grant, self.contributor, scope=OTHER_SCOPE)
        refused = self.endorse(announced, fixtures.envelope(foreign, self.contributor))
        self.assert_refused(refused, 422, "endorsement_invalid")
        self.assertEqual(refused.json()["protocol_code"], "foreign-scope")
        carried = dict(endorsement_record(announced, self.enrollment, self.grant, self.stranger),
                       enrollment={"type": "key-enrollment", "sha256": "9" * 64})
        self.assert_refused(self.endorse(announced, fixtures.envelope(carried, self.stranger)), 422,
                            "signer_not_enrolled")
        self.assertEqual(self.recorded(), 0)

    def test_malformed_envelopes_refuse_by_a_fixed_code(self):
        announced = self.announce().json()
        for envelope in (b"{", b"[]", b'{"payloadType":"x"}', b"\xff" * 10, self.signed(announced)[:-2]):
            with self.subTest(size=len(envelope)):
                response = self.endorse(announced, envelope)
                self.assertEqual(response.status_code, 422)
                self.assertIn(response.json()["code"], {"endorsement_invalid", "request_invalid"})
        self.assert_refused(self.endorse(announced, b""), 400, "request_invalid")
        self.assertEqual(self.recorded(), 0)


class CurrentAuthorityTests(FlowCase):
    def test_a_revocation_after_announce_refuses_the_endorsement(self):
        announced = self.announce().json()
        self.operator.revoke(ACTOR, self.enrollment, -60)
        self.sync()
        self.assert_refused(self.endorse(announced, self.signed(announced)), 422, "signer_not_enrolled")
        self.assert_refused(self.call("GET", f"/v1/candidates/{announced['candidate_id']}"), 404, "not_found")
        self.assertEqual(self.recorded(), 0)

    def test_a_grant_that_expired_after_signing_refuses(self):
        short = self.operator.grant(ACTOR, self.enrollment, ["announce", "upload"], -100, stamp(30))
        self.sync()
        announced = self.announce().json()
        record = endorsement_record(announced, self.enrollment, short, self.contributor)
        self.clock.advance(30)
        self.assert_refused(self.endorse(announced, fixtures.envelope(record, self.contributor)), 422,
                            "endorsement_invalid")

    def test_a_trust_head_that_moved_before_the_commit_asks_for_a_retry(self):
        announced = self.announce().json()
        intake = self.services.intake
        binding = intake.endorsements.binding(ACTOR, announced["candidate_id"])
        projection = self.services.projections.current(self.run)
        verified = projection.authenticate(self.signed(announced))
        terms = check_binding(verified.record, binding, ACTOR, T0)
        self.operator.challenge(OTHER_ACTOR, self.other.key, -30)
        self.sync()
        with self.assertRaises(AuthRefusal) as caught:
            intake.endorsements.record(binding, verified, terms, (projection.count, projection.tail), T0)
        self.assertEqual((caught.exception.code, caught.exception.reason), ("policy_unavailable", "trust-head-moved"))
        self.assertEqual(self.recorded(), 0)
        self.assertEqual(self.endorse(announced, self.signed(announced)).status_code, 200)

    def test_an_endorsement_starts_one_verifier_process_once_the_projection_is_current(self):
        announced = self.announce().json()
        envelope = self.signed(announced)
        with counted_processes() as started:
            self.assertEqual(self.endorse(announced, envelope).status_code, 200)
        self.assertEqual(started, [fixtures.OPENSSL_PATH])


class StatusAndProofTests(FlowCase):
    def test_status_is_the_owners_and_hidden_from_everyone_else(self):
        announced = self.announce().json()
        path = f"/v1/candidates/{announced['candidate_id']}"
        seen = self.call("GET", path)
        self.assertEqual((seen.status_code, seen.json()["state"], seen.json()["code"]), (200, "announced", None))
        hidden = self.call("GET", path, self.other_session)
        unknown = self.call("GET", f"/v1/candidates/{uuid.uuid4()}")
        for response in (hidden, unknown):
            self.assert_refused(response, 404, "not_found")
            self.assertEqual(set(response.json()), {"request_id", "code"})

    def test_proof_of_possession_over_http(self):
        newcomer = self.services.sessions.open_session(43, T0)
        challenge = self.operator.challenge(43, self.stranger.key, -30)
        self.sync()
        signature = base64.b64encode(proof(self.stranger, self.operator.record_of(challenge))).decode()
        path = f"/v1/runs/{fixtures.SCOPE.repository_id}/{fixtures.SCOPE.run_id}/enrollment-proofs"
        body = {"challenge": ref("enrollment-challenge", challenge), "signature": signature}
        first = self.call("POST", path, newcomer, json=body)
        self.assertEqual((first.status_code, first.json()["state"], first.json()["replayed"]),
                         (202, "awaiting_operator", False))
        self.assertTrue(self.call("POST", path, newcomer, json=body).json()["replayed"])
        self.assert_refused(request(self.app, "POST", path, headers={"cookie": session_headers(newcomer)["cookie"]},
                                    json=body), 401, "auth_required")
        self.assert_refused(self.call("POST", path, json=body), 404, "not_found")
        # Recording a proof grants nothing until the operator's own records arrive.
        self.assert_refused(self.announce(session=newcomer), 404, "not_found")
