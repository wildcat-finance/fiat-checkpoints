"""Announce, a real signed endorsement, its capability and the gateway, against operator-signed records."""

import hashlib
from pathlib import Path
import tempfile

from fiat_checkpoints.api.gateway import GatewayServices, create_gateway_app
from fiat_checkpoints.persistence.transfer import Transfers
from fiat_checkpoints.storage.quarantine import DirectoryQuarantine
from fiat_checkpoints.upload.capability import IssuedCapability
from fiat_checkpoints.upload.staging import StagingArea
from tests import authority_fixtures as fixtures
from tests.auth_support import ACTOR, IDENTITIES, SETTINGS, endorsement_record
from tests.test_endorsement_flow import FlowCase
from tests.upload_support import CHUNK, body_steps, effect, exchange, payload, run


class UploadFlowTests(FlowCase):
    """The whole Step 5 path with the released verifier, so these checks start child processes."""

    spawns_child_process = True

    def setUp(self):
        super().setUp()
        directory = tempfile.TemporaryDirectory(prefix="fiat-checkpoints-flow-")
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        for name in ("staging", "quarantine"):
            (root / name).mkdir(mode=0o700)
        self.quarantine_root = root / "quarantine"
        staging = StagingArea(root / "staging", capacity_bytes=16 * CHUNK)
        quarantine = DirectoryQuarantine(self.quarantine_root)
        self.addCleanup(staging.close)
        self.addCleanup(quarantine.close)
        intake = self.services.intake
        self.gateway = create_gateway_app(SETTINGS, GatewayServices(
            Transfers.from_coordinator(intake.coordinator), intake.endorsements, self.services.projections, staging,
            quarantine, self.clock))
        self.data = payload(5 * CHUNK + 3, b"flow")
        self.identities = dict(IDENTITIES, outer_sha256=hashlib.sha256(self.data).hexdigest())

    def endorsed(self):
        announced = self.announce(identities=self.identities, carrier_length=len(self.data)).json()
        record = endorsement_record(announced, self.enrollment, self.grant, self.contributor,
                                    identities=self.identities, carrier_length=len(self.data))
        envelope = fixtures.envelope(record, self.contributor)
        done = self.endorse(announced, envelope)
        self.assertEqual(done.status_code, 200, done.text)
        return announced, envelope, done.json()

    def put(self, candidate, upload, steps):
        headers = [("authorization", "Upload " + upload["capability"]), ("content-length", str(len(self.data))),
                   ("content-type", "application/octet-stream")]
        return run(exchange(self.gateway, "PUT", f"/v1/candidates/{candidate}/content", headers, steps))

    def test_a_signed_endorsement_yields_a_capability_that_seals_the_exact_bytes(self):
        announced, envelope, body = self.endorsed()
        upload = body["upload"]
        self.assertEqual((body["state"], upload["attempt"], upload["length"], upload["sha256"]),
                         ("uploading", 1, len(self.data), self.identities["outer_sha256"]))
        self.assertNotIn(upload["capability"], repr(IssuedCapability(upload["capability"], None, 1, None, 1, "", False)))
        sealed = self.put(announced["candidate_id"], upload, body_steps(self.data))
        self.assertEqual((sealed.status, sealed.body["state"]), (202, "quarantined"), sealed.text)
        status = self.call("GET", f"/v1/candidates/{announced['candidate_id']}")
        self.assertEqual(status.json()["state"], "quarantined")
        # The exact replay of the endorsement now answers with the sealed state and no capability.
        again = self.endorse(announced, envelope)
        self.assertEqual((again.status_code, again.json()["replayed"], again.json()["state"], again.json()["upload"]),
                         (200, True, "quarantined", None))
        [name] = [path.name for path in self.quarantine_root.iterdir()]
        self.assertEqual((self.quarantine_root / name).read_bytes(), self.data)

    def test_a_revocation_ingested_during_the_transfer_stops_the_seal(self):
        announced, _envelope, body = self.endorsed()

        def revoke():
            self.operator.revoke(ACTOR, self.enrollment, 0)
            self.sync()

        steps = body_steps(self.data)
        steps.insert(2, effect(revoke))
        refused = self.put(announced["candidate_id"], body["upload"], steps)
        self.assertEqual((refused.status, refused.body["code"]), (422, "signer_not_enrolled"), refused.text)
        self.assertEqual(self.scalar("SELECT state FROM upload_attempts"), "failed")
        self.assertEqual(list(self.quarantine_root.iterdir()), [])
