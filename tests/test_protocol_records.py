"""Authority records through the released library: vectors, substitutions and exact bytes."""

import base64
import hashlib
import json
import unittest

from fiat_checkpoints.domain.identities import CheckpointIdentities, IdentityMismatch
from fiat_checkpoints.records.authority import (OPENSSL_PATH, OPENSSL_SHA256, AuthorityRecords,
                                                ServiceScope, tool_pins)
from fiat_checkpoints.records.refusals import PROTOCOL, SERVICE, RecordRefusal, from_protocol
from tests import authority_fixtures as fixtures


def released_bootstrap():
    lib = fixtures.library()
    return lib.verifier.bootstrap_from(fixtures.released_bytes("fixtures/demo-bootstrap.json"))


def released_history():
    return fixtures.released_bytes("fixtures/demo-history.jsonl").splitlines()


def released_records():
    bootstrap = released_bootstrap()
    scope = ServiceScope(bootstrap.environment, bootstrap.service, bootstrap.repository_id, bootstrap.run_id)
    return fixtures.records(bootstrap.roots, scope)


def carrier(envelope):
    return json.loads(envelope)


def encode(value):
    return json.dumps(value, separators=(",", ":")).encode()


class RefusalShapeTests(unittest.TestCase):
    def test_protocol_code_passes_only_from_the_library(self):
        lib = fixtures.library()
        refusal = from_protocol("protocol_refused", lib.canonical.Refusal("foreign-scope"))
        self.assertEqual(refusal.event(), {"event": "record-refused", "code": "protocol_refused",
                                           "producer": PROTOCOL, "protocol_code": "foreign-scope",
                                           "stage": "record"})
        self.assertEqual(RecordRefusal("request_invalid").event()["producer"], SERVICE)
        for bad in ({"producer": PROTOCOL}, {"protocol_code": "forged"}, {"producer": "worker"}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                RecordRefusal("protocol_refused", **bad)

    def test_openssl_is_the_pinned_image_executable(self):
        pins = tool_pins(fixtures.release())
        self.assertEqual((pins["openssl"].path, pins["openssl"].sha256), (OPENSSL_PATH, OPENSSL_SHA256))
        with open(OPENSSL_PATH, "rb") as stream:
            self.assertEqual(hashlib.sha256(stream.read()).hexdigest(), OPENSSL_SHA256)

    def test_scope_and_roots_are_typed_configuration(self):
        release = fixtures.release()
        for scope, roots in ((ServiceScope("staging", "s", 1, "r"), (b"x",)),
                             (fixtures.SCOPE, [b"x"]), (fixtures.SCOPE, ("x",))):
            with self.subTest(scope=scope.environment), self.assertRaises(RecordRefusal) as caught:
                AuthorityRecords(release, scope, roots, tool_pins(release))
            self.assertEqual(caught.exception.code, "authority_unavailable")


class MalformedEnvelopeTests(unittest.TestCase):
    """DSSE carriers the library refuses before any public-key command runs."""

    @classmethod
    def setUpClass(cls):
        cls.records = released_records()
        cls.policy = released_history()[0]

    def refusal(self, envelope):
        with self.assertRaises(RecordRefusal) as caught:
            self.records.trust_prefix([envelope])
        return caught.exception

    def mutated(self, change):
        value = carrier(self.policy)
        change(value)
        return encode(value)

    def test_each_malformed_vector_refuses_by_its_library_code(self):
        signature = carrier(self.policy)["signatures"][0]["sig"]
        der = base64.b64decode(signature)
        payload = base64.b64decode(carrier(self.policy)["payload"])
        canonical = fixtures.library().canonical.canonical
        cases = (
            ("payload-type", lambda value: value.update(payloadType="application/json")),
            ("signature-count", lambda value: value["signatures"].append({"keyid": "", "sig": signature})),
            ("signature-count", lambda value: value.update(signatures=[])),
            ("key-hint", lambda value: value["signatures"][0].update(keyid="root")),
            ("envelope-fields", lambda value: value.update(extra="")),
            ("invalid-base64", lambda value: value.update(payload=value["payload"] + "===")),
            ("invalid-base64", lambda value: value.update(payload="*" + value["payload"])),
            ("mixed-base64", lambda value: value.update(payload="+-" + value["payload"][2:])),
            ("noncanonical-json", lambda value: value.update(
                payload=base64.b64encode(json.dumps(json.loads(payload), indent=1).encode()).decode())),
            ("statement-fields", lambda value: value.update(
                payload=base64.b64encode(canonical(json.loads(payload) | {"extra": 1})).decode())),
            ("invalid-der", lambda value: value["signatures"][0].update(
                sig=base64.b64encode(der + b"\x00").decode())),
            ("invalid-der", lambda value: value["signatures"][0].update(
                sig=base64.b64encode(b"\x30\x06\x02\x01\x00\x02\x01\x01").decode())),
        )
        for code, change in cases:
            with self.subTest(code=code):
                refusal = self.refusal(self.mutated(change))
                self.assertEqual((refusal.code, refusal.producer, refusal.protocol_code),
                                 ("protocol_refused", PROTOCOL, code))

    def test_duplicate_keys_and_bounds_refuse(self):
        duplicate = b'{"payloadType":"a","payloadType":"b","payload":"","signatures":[]}'
        self.assertEqual(self.refusal(duplicate).protocol_code, "duplicate-key")
        for envelope in (b"", "text", bytearray(self.policy), b" " * (128 * 1024 + 1)):
            with self.subTest(size=len(envelope)):
                refusal = self.refusal(envelope)
                self.assertEqual((refusal.code, refusal.producer), ("request_invalid", SERVICE))

    def test_refusals_carry_no_input_bytes(self):
        refusal = self.refusal(self.mutated(lambda value: value["signatures"][0].update(keyid="marker-value")))
        self.assertNotIn("marker-value", json.dumps(refusal.event()))


class ReleasedVectorTests(unittest.TestCase):
    """The released demonstration bundle, named by the digests the release binds."""

    spawns_child_process = True

    def test_released_history_replays_to_the_released_expectation(self):
        lib = fixtures.library()
        expected = json.loads(fixtures.released_bytes("fixtures/demo-expected.json"))
        native = lib.verifier.native_from(fixtures.released_bytes("fixtures/demo-native.json"))
        result = lib.verifier.verify(iter(released_history()), released_bootstrap(), tool_pins(fixtures.release()),
                                     native=native)
        replay = result["result"]
        self.assertEqual((replay["records"], replay["bytes"], len(replay["accepted"]),
                          replay["historical_permits"], replay["head_sha256"]),
                         (expected["records"], expected["bytes"], expected["accepted"],
                          expected["historical_permits"], expected["head_sha256"]))
        self.assertEqual(hashlib.sha256(fixtures.released_bytes("fixtures/demo-history.jsonl")).hexdigest(),
                         expected["history_sha256"])
        self.assertFalse(result["current_eligibility_established"])

    def test_released_policy_keeps_exact_bytes(self):
        policy = released_history()[0]
        _, accepted = released_records().trust_prefix([policy])
        verified = accepted[0]
        self.assertIs(type(verified.envelope), bytes)
        self.assertEqual(verified.envelope, policy)
        self.assertEqual(verified.envelope_sha256, hashlib.sha256(policy).hexdigest())
        self.assertEqual(verified.payload, base64.b64decode(carrier(policy)["payload"]))
        self.assertEqual(verified.record_type, "authority-policy")

    def test_url_safe_carrier_is_kept_as_received(self):
        policy = released_history()[0]
        value = carrier(policy)
        value["payload"] = value["payload"].replace("+", "-").replace("/", "_").rstrip("=")
        value["signatures"][0]["sig"] = value["signatures"][0]["sig"].replace("+", "-").replace("/", "_")
        variant = encode(value)
        self.assertNotEqual(variant, policy)
        _, accepted = released_records().trust_prefix([variant])
        self.assertEqual(accepted[0].envelope, variant)
        self.assertEqual(accepted[0].envelope_sha256, hashlib.sha256(variant).hexdigest())
        self.assertEqual(accepted[0].payload, base64.b64decode(carrier(policy)["payload"]))

    def test_changed_payload_byte_fails_the_signature(self):
        policy = carrier(released_history()[0])
        statement = json.loads(base64.b64decode(policy["payload"]))
        statement["predicate"]["max_head_age_seconds"] = 1
        policy["payload"] = base64.b64encode(fixtures.library().canonical.canonical(statement)).decode()
        with self.assertRaises(RecordRefusal) as caught:
            released_records().trust_prefix([encode(policy)])
        self.assertEqual(caught.exception.protocol_code, "signature-invalid")

    def test_untrusted_root_refuses_the_released_history(self):
        signer = fixtures.Signer()
        self.addCleanup(signer.close)
        bootstrap = released_bootstrap()
        scope = ServiceScope(bootstrap.environment, bootstrap.service, bootstrap.repository_id, bootstrap.run_id)
        with self.assertRaises(RecordRefusal) as caught:
            fixtures.records((fixtures.root_bytes(signer),), scope).trust_prefix(released_history()[:1])
        self.assertEqual(caught.exception.protocol_code, "bootstrap-required")


class SyntheticRecordTests(unittest.TestCase):
    """Records signed with keys generated here, so each check is reached with a valid signature."""

    spawns_child_process = True

    @classmethod
    def setUpClass(cls):
        cls.operator, cls.contributor, cls.stranger = fixtures.Signer(), fixtures.Signer(), fixtures.Signer()
        cls.chain = fixtures.Chain(cls.operator, cls.contributor)
        cls.records = fixtures.records((fixtures.root_bytes(cls.operator),))

    @classmethod
    def tearDownClass(cls):
        for signer in (cls.operator, cls.contributor, cls.stranger):
            signer.close()

    def prefix(self):
        prefix, accepted = self.records.trust_prefix(self.chain.envelopes)
        self.assertEqual([item.record_type for item in accepted],
                         ["authority-policy", "enrollment-challenge", "key-enrollment", "run-grant"])
        return prefix

    def endorsement_refusal(self, record, signer=None, *, statement=None):
        envelope = fixtures.envelope(record, signer or self.contributor, statement=statement)
        with self.assertRaises(RecordRefusal) as caught:
            self.records.authenticate(self.prefix(), envelope)
        return caught.exception.protocol_code

    def test_enrolled_key_endorsement_authenticates_with_exact_bytes(self):
        envelope = fixtures.envelope(self.chain.endorsement(), self.contributor)
        verified = self.records.authenticate(self.prefix(), envelope)
        self.assertEqual((verified.envelope, verified.record_type, verified.key_fingerprint),
                         (envelope, "upload-endorsement", self.contributor.key["fingerprint"]))
        self.assertEqual(verified.record_bytes, fixtures.library().canonical.canonical(self.chain.endorsement()))

    def test_two_signatures_over_one_payload_keep_distinct_envelopes(self):
        record = self.chain.endorsement()
        first = fixtures.envelope(record, self.contributor)
        second = fixtures.envelope(record, self.contributor)
        self.assertNotEqual(first, second)
        prefix = self.prefix()
        one, two = self.records.authenticate(prefix, first), self.records.authenticate(prefix, second)
        self.assertEqual(one.payload, two.payload)
        self.assertNotEqual(one.envelope_sha256, two.envelope_sha256)
        self.assertEqual((one.envelope, two.envelope), (first, second))

    def test_environment_service_and_run_substitutions_refuse(self):
        for change in ({"environment": "production"}, {"service": "another-service"},
                       {"scope": {"repository_id": 8, "run_id": fixtures.SCOPE.run_id}},
                       {"scope": {"repository_id": 7, "run_id": "fiat-" + "b" * 64}}):
            with self.subTest(change=sorted(change)):
                self.assertEqual(self.endorsement_refusal(self.chain.endorsement(**change)), "foreign-scope")

    def test_production_bootstrap_refuses_a_test_root(self):
        scope = ServiceScope("production", fixtures.SCOPE.service, fixtures.SCOPE.repository_id, fixtures.SCOPE.run_id)
        with self.assertRaises(RecordRefusal) as caught:
            fixtures.records((fixtures.root_bytes(self.operator, "test"),), scope)
        self.assertEqual(caught.exception.protocol_code, "test-production-separation")

    def test_predicate_and_statement_substitutions_refuse(self):
        lib = fixtures.library()
        record = self.chain.endorsement()
        statement = fixtures.statement(record)
        self.assertEqual(lib.canonical.canonical(statement),
                         lib.signatures.statement_bytes(lib.canonical.canonical(record)))
        wrong_predicate = dict(statement, predicateType="https://example.invalid/predicate/v1")
        self.assertEqual(self.endorsement_refusal(record, statement=wrong_predicate), "statement-fields")
        swapped = dict(statement, subject=[dict(statement["subject"][1], name="snapshot_id"),
                                           dict(statement["subject"][0], name="controller_manifest_sha256"),
                                           statement["subject"][2]])
        self.assertEqual(self.endorsement_refusal(record, statement=swapped), "subject-roles")

    def test_schema_substitutions_refuse(self):
        self.assertEqual(self.endorsement_refusal(self.chain.endorsement(extra="field")), "schema-fields")
        self.assertEqual(self.endorsement_refusal(self.chain.endorsement(protocol="checkpoint-authority/v2")),
                         "unsupported-protocol")
        self.assertEqual(self.endorsement_refusal(self.chain.endorsement(carrier_length=0)), "schema-integer")
        self.assertEqual(self.endorsement_refusal(self.chain.endorsement(expires_at="2026-09-30T02:00:00Z")),
                         "expiry-interval")

    def test_signature_and_key_substitutions_refuse(self):
        self.assertEqual(self.endorsement_refusal(self.chain.endorsement(), self.stranger), "signature-invalid")
        # The enrolled key signs, but the record names another issuer.
        misnamed = self.chain.endorsement(issuer=self.stranger.key["fingerprint"])
        self.assertEqual(self.endorsement_refusal(misnamed), "issuer-key")
        unenrolled = self.chain.endorsement(enrollment={"type": "key-enrollment", "sha256": "6" * 64})
        self.assertEqual(self.endorsement_refusal(unenrolled), "enrollment-inactive")

    def test_digest_substitutions_refuse(self):
        other_policy = self.chain.endorsement(policy={"type": "authority-policy", "sha256": "7" * 64})
        self.assertEqual(self.endorsement_refusal(other_policy), "policy-predecessor")
        other_grant = self.chain.endorsement(grant={"type": "run-grant", "sha256": "8" * 64})
        self.assertEqual(self.endorsement_refusal(other_grant), "trust-reference")

    def test_carried_key_cannot_enroll_itself(self):
        chain = self.chain
        record = dict(chain.records[2], issuer=self.contributor.key["fingerprint"])
        envelopes = [*chain.envelopes[:2], fixtures.envelope(record, self.contributor)]
        with self.assertRaises(RecordRefusal) as caught:
            self.records.trust_prefix(envelopes)
        self.assertEqual(caught.exception.protocol_code, "issuer-untrusted")

    def test_identity_substitution_is_refused_by_role(self):
        verified = self.records.authenticate(self.prefix(), fixtures.envelope(self.chain.endorsement(), self.contributor))
        expected = CheckpointIdentities.from_protocol(fixtures.IDENTITIES)
        expected.require(CheckpointIdentities.from_protocol(verified.record["identities"]))
        swapped = dict(fixtures.IDENTITIES, snapshot_id=fixtures.IDENTITIES["controller_manifest_sha256"],
                       controller_manifest_sha256=fixtures.IDENTITIES["snapshot_id"])
        substituted = self.records.authenticate(self.prefix(), fixtures.envelope(
            self.chain.endorsement(identities=swapped), self.contributor))
        with self.assertRaises(IdentityMismatch):
            expected.require(CheckpointIdentities.from_protocol(substituted.record["identities"]))


class ParentAndCustodyTests(unittest.TestCase):
    """Parent evidence and native custody refuse through the released functions."""

    @classmethod
    def setUpClass(cls):
        cls.records = released_records()

    def refusal(self, operation):
        with self.assertRaises(RecordRefusal) as caught:
            operation()
        self.assertEqual(caught.exception.producer, PROTOCOL)
        return caught.exception.protocol_code

    def test_missing_parent_evidence_refuses(self):
        validation = {"output_sha256": "0" * 64}
        self.assertEqual(self.refusal(lambda: self.records.native_parent(None, b"", validation)),
                         "native-evidence-required")
        self.assertEqual(self.refusal(lambda: self.records.native_parent(object(), b"ledger", validation)),
                         "native-evidence-required")
        lib = fixtures.library()
        unrelated = lib.native.NativeResult(b"{}", fixtures.ROOT)
        self.assertEqual(self.refusal(lambda: self.records.native_parent(unrelated, b"", validation)),
                         "native-evidence-binding")

    def test_root_parent_without_root_permission_refuses(self):
        registration = {"initial_base": "a" * 40, "native_anchor_sha256": "b" * 64, "source": {},
                        "root_authorized": False, "initial_parent": None}
        native = {"initial_base": "a" * 40, "anchor": "b" * 64, "run_id": "run", "producer": "c" * 64,
                  "count": 1, "prefixes": ("c" * 64,)}
        link = {"registration": {"type": "run-registration", "sha256": "d" * 64}, "initial_base": "a" * 40,
                "native": {}, "producer_prefix_sha256": "c" * 64, "parents": [], "prior_receipts": []}
        acceptance = {"initial_base": "a" * 40, "native": {}, "scope": {"run_id": "run"},
                      "parent_acceptance_ids": [], "transition": {"kind": "registered-root",
                                                                  "registration": link["registration"]}}
        self.assertEqual(self.refusal(lambda: self.records.check_parent(
            link, registration, native, {}, acceptance, "d" * 64)), "root-permission")
        self.assertEqual(self.refusal(lambda: self.records.check_parent(
            link, dict(registration, root_authorized=True), dict(native, anchor="e" * 64), {}, acceptance,
            "d" * 64)), "parent-run-base")

    def custody_state(self):
        return {"receipts": {"study": {}, "runbook": {}}, "steps": [{"receipts": {"implement": {}}}]}

    def test_supported_history_passes_custody(self):
        self.assertIsNone(self.records.check_custody(self.custody_state(), [{"event": "init", "data": {}}]))

    def test_unsupported_custody_and_relocation_refuse(self):
        state = self.custody_state()
        cases = (
            ("native-nested-restore-unavailable", state, [{"event": "checkpoint:restore", "data": {}}]),
            ("native-history-class-unavailable", state, [{"event": "replace", "data": {}}]),
            ("native-history-class-unavailable", state, [{"event": "record", "data": {"key": "private"}}]),
            ("native-history-class-unavailable", dict(state, replacement={}), []),
            ("native-history-class-unavailable", dict(state, integrate={}), []),
            ("native-private-custody-unavailable", dict(state, receipts={"private_locator": {}}), []),
            ("native-private-custody-unavailable",
             dict(state, receipts={"runbook": {"known_failure_inventory": []}}), []),
            ("native-private-custody-unavailable", dict(state, steps=[{"receipts": {"replacement": {}}}]), []),
        )
        for code, value, entries in cases:
            with self.subTest(code=code, entries=len(entries)):
                self.assertEqual(self.refusal(lambda: self.records.check_custody(value, entries)), code)

    def test_malformed_shapes_leave_as_fixed_service_codes(self):
        # S2-R1-01: the library raises KeyError, TypeError or AttributeError on
        # shapes it never checks; none may leave the records boundary.
        state = self.custody_state()
        cases = (
            ("validation_failed", lambda: self.records.check_custody(state, ["entry"])),
            ("validation_failed", lambda: self.records.check_custody(state, [{"data": {}}])),
            ("validation_failed", lambda: self.records.check_custody(state, [{"event": "record", "data": []}])),
            ("validation_failed", lambda: self.records.check_custody([], [])),
            ("authority_unavailable", lambda: self.records.check_parent({}, {}, {}, {}, {}, "d" * 64)),
        )
        for code, operation in cases:
            with self.subTest(code=code):
                try:
                    operation()
                except Exception as error:  # the unfixed boundary leaks the library's exception
                    caught = error
                else:
                    self.fail("malformed input was accepted")
                self.assertIsInstance(caught, RecordRefusal)
                self.assertEqual(caught.event(), {"event": "record-refused", "code": code,
                                                  "producer": SERVICE, "protocol_code": None, "stage": None})
                self.assertIsNone(caught.__cause__)
                self.assertTrue(caught.__suppress_context__)


if __name__ == "__main__":
    unittest.main()
