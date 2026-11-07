"""The issue #1 intake-to-validation demonstration over real HTTP, PostgreSQL 16 and gVisor.

`scripts/demo.sh --scenario intake-validation --profile local` calls `main`.
It runs as the validator image's supervisor (`scripts/sandbox-env.sh run`)
with the PostgreSQL 16 test server up (`scripts/linux-env.sh db-start`). The
intake API and the upload gateway are served by uvicorn on loopback sockets,
contributors log in through an in-process identity provider, and every
contributor request goes over HTTP. Sealed inputs then go through the real
validator: staging, a fresh gVisor sandbox and the pinned native sequence.

Every key is generated for the run in a temporary directory and every record
is signed with it. Every archive is the released synthetic fixture or a
specimen rebuilt from it. The released fixture's private key was destroyed by
its producer, so no operator can enroll it: commit signers are approved by the
fixture's own test approval (`FixedTrust`), while the run's scope, grants,
registration and revocations come from the verified projection of
operator-signed records. This module holds no test case; `tests/test_demo.py`
runs it, and `scripts/latency.py` measures metadata latency with
`measure_metadata`.
"""

import argparse
from contextlib import ExitStack
from dataclasses import dataclass
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import platform
import re
import socket
import sys
import tempfile
import threading
import time
from urllib.parse import urlencode
import uuid
import zipfile

import uvicorn

from fiat_checkpoints.api.gateway import GatewayServices, create_gateway_app
from fiat_checkpoints.grants.projection import Projections
from fiat_checkpoints.persistence.migrations import migrate
from fiat_checkpoints.persistence.scratch import ScratchDatabase
from fiat_checkpoints.persistence.transfer import Transfers
from fiat_checkpoints.records.trees import REPOSITORY
from fiat_checkpoints.storage.quarantine import DirectoryQuarantine
from fiat_checkpoints.upload.staging import StagingArea
from fiat_checkpoints.validation import fixture, pins
from fiat_checkpoints.validation.sandbox import Sandbox
from fiat_checkpoints.validation.service import SCHEMA_EVIDENCE, Validator, service_binds
from fiat_checkpoints.validation.specimens import Corpus
from fiat_checkpoints.validation.trust import FixedTrust, canonical
from tests import authority_fixtures as fixtures
from tests.auth_support import (SCOPE, SETTINGS, Clock, FakeProvider, Operator, build, contributor_journal,
                                endorsement_record, run_authority, user_document)
from tests.upload_support import payload


SCHEMA = "fiat-checkpoints-demo/v1"
SCENARIOS = ("intake-validation",)
PROFILES = ("local",)
CONTRIBUTOR, OTHER, REVOKED = 41, 42, 43
PERMISSIONS = ("announce", "upload", "read_status")
PARENT = {"type": "parent-link", "sha256": "5" * 64}
HTTP_TIMEOUT_SECONDS = 60
START_SECONDS = 30
MAX_RESPONSE_BYTES = 1_048_576
# Contributor metadata routes; the login routes call the identity provider and are left out.
METADATA_ROUTES = ("announce", "endorsement", "complete", "status")
# Source the demonstration ran, hashed file by file; nothing outside these is read.
SOURCE_PARTS = ("src", "scripts", "tests", "migrations", "config", "containers")
SOURCE_FILES = ("protocol.lock.json", "protocol.trees.json", "pyproject.toml", "uv.lock")
# A container cannot read its own image id, so `scripts/sandbox-env.sh run` passes
# the three image ids in; the demonstration refuses without all of them (S7-R1-05).
IMAGE_ENVIRONMENT = (("validator", "FIAT_IMAGE_VALIDATOR"), ("test", "FIAT_IMAGE_TEST"),
                     ("postgres", "FIAT_IMAGE_POSTGRES"))
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")


class DemoRefusal(Exception):
    """A fixed code; no supplied value, path or library message."""


# HTTP over loopback ---------------------------------------------------------


class Served:
    """One ASGI app served by uvicorn on a fresh loopback port, in a thread of this process."""

    def __init__(self, app):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(("127.0.0.1", 0))
        self.port = self.socket.getsockname()[1]
        config = uvicorn.Config(app, lifespan="off", log_config=None, access_log=False, server_header=False,
                                proxy_headers=False, log_level="critical", timeout_keep_alive=5,
                                timeout_graceful_shutdown=5)
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, kwargs={"sockets": [self.socket]},
                                       name="demo-http-%d" % self.port, daemon=True)

    def start(self):
        self.thread.start()
        deadline = time.monotonic() + START_SECONDS
        while not self.server.started:
            if not self.thread.is_alive() or time.monotonic() > deadline:
                self.close()
                raise DemoRefusal("http-server-unavailable")
            time.sleep(0.05)
        return self

    def close(self):
        self.server.should_exit = True
        if self.thread.is_alive():
            self.thread.join(START_SECONDS)
        self.socket.close()


@dataclass(frozen=True)
class Reply:
    status: int
    headers: tuple
    body: bytes
    request_id: str | None
    elapsed_ms: float

    def json(self):
        return json.loads(self.body) if self.body else None

    def cookie(self, name):
        for key, value in self.headers:
            if key.lower() == "set-cookie":
                pair = value.split(";", 1)[0]
                cookie, _, content = pair.partition("=")
                if cookie.strip() == name:
                    return content.strip().strip('"')
        return None

    def code(self):
        body = self.json()
        return body.get("code") if type(body) is dict else None


class Client:
    """One plain HTTP/1.1 client; a new connection per request and no cookie store."""

    def __init__(self, port, timings=None):
        self.port = port
        self.timings = timings if timings is not None else []

    def request(self, method, path, *, body=None, headers=None, route=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=HTTP_TIMEOUT_SECONDS)
        try:
            started = time.perf_counter_ns()
            connection.request(method, path, body=body, headers=dict(headers or {}))
            response = connection.getresponse()
            data = response.read(MAX_RESPONSE_BYTES + 1)
            elapsed = (time.perf_counter_ns() - started) / 1_000_000
            if len(data) > MAX_RESPONSE_BYTES:
                raise DemoRefusal("http-response-too-large")
            reply = Reply(response.status, tuple(response.getheaders()), data,
                          response.getheader("x-request-id"), elapsed)
        except (OSError, http.client.HTTPException):
            raise DemoRefusal("http-request-failed") from None
        finally:
            connection.close()
        if route is not None:
            self.timings.append((route, elapsed))
        return reply


def p95(values):
    """Nearest-rank 95th percentile of a non-empty sequence."""
    ordered = sorted(values)
    if not ordered:
        raise DemoRefusal("no-samples")
    return ordered[max(0, -(-95 * len(ordered) // 100) - 1)]


def latency(timings):
    """Per-route and overall samples, median and p95 in milliseconds, for metadata routes only."""
    rows = {}
    for route in METADATA_ROUTES:
        values = [value for name, value in timings if name == route]
        if values:
            rows[route] = {"count": len(values), "median_ms": round(sorted(values)[len(values) // 2], 3),
                           "p95_ms": round(p95(values), 3), "max_ms": round(max(values), 3),
                           "samples_ms": [round(value, 3) for value in values]}
    every = [value for name, value in timings if name in METADATA_ROUTES]
    return {"routes": rows, "count": len(every), "p95_ms": round(p95(every), 3) if every else None}


# The service ----------------------------------------------------------------


class Service:
    """A migrated scratch database, one operator journal, and the intake and gateway apps over HTTP."""

    def __init__(self, stack, *, contributors=(CONTRIBUTOR, OTHER, REVOKED), registration=True):
        self.stack = stack
        self.release = fixtures.release()
        self.value, _public = fixture.released(self.release)
        scratch = ScratchDatabase()
        stack.callback(scratch.close)
        self.database = scratch.database
        migrate(self.database)
        self.clock = Clock()
        self.provider = FakeProvider()
        self.operator_key = fixtures.Signer()
        stack.callback(self.operator_key.close)
        self.operator = Operator(self.operator_key)
        self.keys, self.enrollments, self.grants = {}, {}, {}
        for index, actor in enumerate(contributors):
            signer = fixtures.Signer()
            stack.callback(signer.close)
            self.keys[actor] = signer
            self.enrollments[actor], self.grants[actor] = contributor_journal(
                self.operator, signer, actor=actor, permissions=PERMISSIONS, issued=-3600 + 600 * index)
        if registration:
            self.operator.add(self.operator.next("run-registration", -1200) | self.registration_fields())
        self.run = run_authority(self.operator)
        directory = tempfile.TemporaryDirectory(prefix="fiat-checkpoints-demo-")
        stack.callback(directory.cleanup)
        self.root = Path(directory.name)
        for name in ("staging", "quarantine", "jobs"):
            (self.root / name).mkdir(mode=0o700)
        self.staging = StagingArea(self.root / "staging", capacity_bytes=64 * 1_048_576)
        stack.callback(self.staging.close)
        self.quarantine = DirectoryQuarantine(self.root / "quarantine")
        stack.callback(self.quarantine.close)
        self.servers = []
        self.start()
        for envelope in self.operator.envelopes:
            self.projections.ingest(self.run, envelope, self.clock())

    def registration_fields(self):
        """The root-anchor registration of the released fixture's run, as an operator signs it."""
        lock = self.release.lock_check
        identity = self.value["original_outputs"]["identity"]["identity"]
        return {"native_anchor_sha256": hashlib.sha256(canonical(identity["run"])).hexdigest(),
                "initial_base": self.value["initial_base"],
                "source": {key: lock["native"][key] for key in ("source_commit", "executable_sha256", "profile")},
                "owner_id": CONTRIBUTOR, "permitted_protocols": ["checkpoint-authority/v1"],
                "initial_parent": None, "root_authorized": True}

    def start(self):
        """Build every service object from the database alone, as a restarted process would."""
        self.projections = Projections(self.database, (self.run,))
        self.app, self.services = build(self.database, self.clock, provider=self.provider,
                                        projections=self.projections)
        intake = self.services.intake
        self.transfers = Transfers.from_coordinator(intake.coordinator)
        self.gateway = create_gateway_app(SETTINGS, GatewayServices(
            self.transfers, intake.endorsements, self.projections, self.staging, self.quarantine, self.clock))
        self.timings = []
        intake_server, gateway_server = Served(self.app), Served(self.gateway)
        self.servers = [intake_server.start(), gateway_server.start()]
        self.intake_http = Client(intake_server.port, self.timings)
        self.gateway_http = Client(gateway_server.port, self.timings)

    def stop(self):
        for server in self.servers:
            server.close()
        self.servers = []

    def restart(self):
        timings = self.timings
        self.stop()
        self.start()
        self.timings[:0] = timings

    def validator(self, sandbox):
        return Validator(self.transfers, self.quarantine, sandbox, self.release, self.projections,
                         FixedTrust(fixture.run_trust(self.release)), staging_root=self.root / "jobs",
                         clock=self.clock, service_binds=service_binds(REPOSITORY))

    def revoke(self, actor):
        envelope = self.operator.revoke(actor, self.enrollments[actor], 0)
        self.projections.ingest(self.run, envelope, self.clock())

    # Queries --------------------------------------------------------------

    def rows(self, statement, parameters=()):
        connection = self.database.connect()
        try:
            return connection.execute(statement, parameters).fetchall()
        finally:
            connection.close()

    def count(self, statement, parameters=()):
        return next(iter(self.rows(statement, parameters)[0].values()))

    def intents(self, candidate_id):
        return self.rows("SELECT intent_id, archive_sha256, snapshot_id, controller_manifest_sha256, evidence, "
                         "evidence_sha256 FROM publication_intents WHERE candidate_id = %s", (candidate_id,))


class Contributor:
    """One actor's browser session, opened over HTTP through the identity provider."""

    def __init__(self, service, actor):
        self.service, self.actor = service, actor
        self.signer = service.keys[actor]
        self.enrollment, self.grant = service.enrollments[actor], service.grants[actor]
        self.login()

    def login(self):
        http = self.service.intake_http
        begun = http.request("POST", "/v1/login", body=b"")
        binding = begun.cookie("__Host-fiat-login")
        if begun.status != 200 or binding is None:
            raise DemoRefusal("login-refused")
        state, code = self.service.provider.authorize(begun.json()["authorization_url"],
                                                      user_document(self.actor, "synthetic-%d" % self.actor))
        done = http.request("GET", "/v1/login/callback?" + urlencode({"code": code, "state": state}),
                            headers={"cookie": "__Host-fiat-login=" + binding})
        secret = done.cookie("__Host-fiat-session")
        if done.status != 200 or secret is None:
            raise DemoRefusal("login-refused")
        self.headers = {"cookie": "__Host-fiat-session=" + secret, "x-csrf-token": done.json()["csrf_token"]}

    def announce(self, label, identities, length):
        body = {"run": {"repository_id": SCOPE.repository_id, "run_id": SCOPE.run_id},
                "identities": dict(identities), "carrier_length": length, "parent": dict(PARENT)}
        key = ("demo-%d-%s" % (self.actor, label)).ljust(16, "x")
        return self.service.intake_http.request(
            "POST", "/v1/candidates", body=json.dumps(body).encode(), route="announce",
            headers=self.headers | {"idempotency-key": key, "content-type": "application/json"})

    def signed(self, announced, identities, length, signer=None, enrollment=None, grant=None, actor=None,
               **changes):
        record = endorsement_record(announced, enrollment or self.enrollment, grant or self.grant,
                                    signer or self.signer, actor=actor or self.actor,
                                    identities=dict(identities), carrier_length=length, **changes)
        return fixtures.envelope(record, signer or self.signer)

    def endorse(self, candidate_id, envelope):
        return self.service.intake_http.request(
            "POST", "/v1/candidates/%s/endorsement" % candidate_id, body=envelope, headers=self.headers,
            route="endorsement")

    def upload(self, candidate_id, capability, data):
        return self.service.gateway_http.request(
            "PUT", "/v1/candidates/%s/content" % candidate_id, body=data,
            headers={"authorization": "Upload " + capability, "content-type": "application/octet-stream"})

    def complete(self, candidate_id, attempt, data):
        claim = {"attempt": attempt, "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        return self.service.intake_http.request(
            "POST", "/v1/candidates/%s/complete" % candidate_id, body=json.dumps(claim).encode(),
            headers=self.headers | {"content-type": "application/json"}, route="complete")

    def status(self, candidate_id):
        return self.service.intake_http.request("GET", "/v1/candidates/%s" % candidate_id, headers=self.headers,
                                                route="status")

    def submit(self, label, identities, data, *, sent=None):
        """Announce, endorse, upload and complete; returns the candidate id and every reply."""
        steps = []
        announced = self.announce(label, identities, len(data))
        steps.append(step("announce", announced))
        if announced.status not in (200, 201):
            return None, steps
        body = announced.json()
        endorsed = self.endorse(body["candidate_id"], self.signed(body, identities, len(data)))
        steps.append(step("endorsement", endorsed))
        if endorsed.status != 200 or endorsed.json()["upload"] is None:
            return body["candidate_id"], steps
        upload = endorsed.json()["upload"]
        put = self.upload(body["candidate_id"], upload["capability"], data if sent is None else sent)
        steps.append(step("upload", put))
        if put.status == 202:
            steps.append(step("complete", self.complete(body["candidate_id"], upload["attempt"], data)))
        return body["candidate_id"], steps


def step(route, reply):
    """What a report keeps of one reply: route, status, public code and the correlating request id."""
    return {"route": route, "status": reply.status, "code": reply.code(), "request_id": reply.request_id}


def identities_of(value, archive):
    return {"snapshot_id": value["snapshot_id"], "controller_manifest_sha256": value["controller_manifest_sha256"],
            "outer_sha256": hashlib.sha256(archive).hexdigest()}


def carried_snapshot(archive):
    """The snapshot id an archive carries in its identity member, as a contributor would announce it."""
    with zipfile.ZipFile(io.BytesIO(archive)) as container:
        return json.loads(container.read("identity/checkpoint-identity.json"))["snapshot_id"]


# The scenario ---------------------------------------------------------------


def outcome_of(outcome):
    if outcome is None:
        return {"claimed": False}
    refusal = outcome.refusal
    return {"claimed": True, "job_id": outcome.job_id, "intent_recorded": outcome.intent_id is not None,
            "code": None if refusal is None else refusal.code,
            "reason": None if refusal is None else refusal.reason,
            "protocol_code": None if refusal is None else refusal.protocol_code,
            "wall_ms": None if not outcome.resources else outcome.resources.get("wall_ms")}


def images(environ=None):
    """The validator, test and PostgreSQL image ids the launcher passed in; any absent one refuses."""
    environ = os.environ if environ is None else environ
    found = {}
    for name, variable in IMAGE_ENVIRONMENT:
        value = environ.get(variable)
        if type(value) is not str or IMAGE_ID.fullmatch(value) is None:
            raise DemoRefusal("image-digest-missing")
        found[name] = value
    return found


def run_scenario(sandbox=None):
    """Run every case once and return the report; a broken precondition raises `DemoRefusal`."""
    image_ids = images()
    sandbox = Sandbox() if sandbox is None else sandbox
    with ExitStack() as stack:
        service = Service(stack)
        stack.callback(service.stop)
        return _scenario(service, sandbox, image_ids)


def _scenario(service, sandbox, image_ids):
    release, value = service.release, service.value
    archive = fixture.valid_archive(release)
    valid = identities_of(value, archive)
    corpus = Corpus.released(release)
    forged = corpus.build("identity-mismatch")
    contributor, other = Contributor(service, CONTRIBUTOR), Contributor(service, OTHER)
    validator = service.validator(sandbox)
    cases = {}

    # One authorized exact upload validates in the sandbox and records one intent.
    candidate, steps = contributor.submit("valid", valid, archive)
    quarantined = contributor.status(candidate)
    steps.append(step("status", quarantined))
    outcome = validator.run_once()
    after = contributor.status(candidate)
    steps.append(step("status", after))
    [intent] = service.intents(candidate) or [None]
    cases["valid"] = {"candidate_id": candidate, "steps": steps, "state_before": quarantined.json()["state"],
                      "state": after.json()["state"], "validation": outcome_of(outcome),
                      "intents": len(service.intents(candidate))}
    evidence = None if intent is None else bytes(intent["evidence"])

    # A carried identity forged inside the archive: the pinned inspect refuses it.
    identities = dict(valid, outer_sha256=forged.archive_sha256, snapshot_id=carried_snapshot(forged.archive))
    candidate, steps = contributor.submit("forged", identities, forged.archive)
    outcome = validator.run_once()
    seen = contributor.status(candidate)
    steps.append(step("status", seen))
    cases["forged-identity"] = {"candidate_id": candidate, "steps": steps, "state": seen.json()["state"],
                                "validation": outcome_of(outcome), "intents": len(service.intents(candidate)),
                                "specimen_sha256": forged.archive_sha256,
                                "declared": {"refusal": forged.asserted_refusal, "stage": forged.native_stage}}

    # The same length with one byte changed never seals.
    changed = bytes([archive[0] ^ 0x01]) + archive[1:]
    candidate, steps = contributor.submit("changed", valid, archive, sent=changed)
    seen = contributor.status(candidate)
    steps.append(step("status", seen))
    cases["changed-bytes"] = {"candidate_id": candidate, "steps": steps, "state": seen.json()["state"],
                              "intents": len(service.intents(candidate))}

    # Another enrolled actor can neither endorse nor see the contributor's candidate,
    # and the contributor cannot present the other actor's signed endorsement.
    announced = contributor.announce("wrong-actor", valid, len(archive))
    body = announced.json()
    steps = [step("announce", announced)]
    steps.append(step("endorsement", other.endorse(body["candidate_id"], other.signed(body, valid, len(archive)))))
    steps.append(step("status", other.status(body["candidate_id"])))
    steps.append(step("endorsement", contributor.endorse(body["candidate_id"], other.signed(body, valid, len(archive)))))
    seen = contributor.status(body["candidate_id"])
    steps.append(step("status", seen))
    cases["wrong-actor"] = {"candidate_id": body["candidate_id"], "steps": steps, "state": seen.json()["state"],
                            "intents": len(service.intents(body["candidate_id"]))}

    # An endorsement signed for a protocol version the pinned release does not carry.
    announced = contributor.announce("protocol", valid, len(archive))
    body = announced.json()
    steps = [step("announce", announced)]
    mismatched = contributor.signed(body, valid, len(archive), protocol="checkpoint-authority/v2")
    steps.append(step("endorsement", contributor.endorse(body["candidate_id"], mismatched)))
    seen = contributor.status(body["candidate_id"])
    steps.append(step("status", seen))
    cases["protocol-mismatch"] = {"candidate_id": body["candidate_id"], "steps": steps,
                                  "state": seen.json()["state"], "intents": len(service.intents(body["candidate_id"]))}

    # A sealed upload whose uploader's enrollment the operator revokes before validation.
    revoked = Contributor(service, REVOKED)
    candidate, steps = revoked.submit("revoked", valid, archive)
    service.revoke(REVOKED)
    outcome = validator.run_once()
    cases["revoked-scope"] = {"candidate_id": candidate, "steps": steps,
                              "state": service.count("SELECT state FROM candidates WHERE candidate_id = %s",
                                                     (candidate,)),
                              "validation": outcome_of(outcome), "intents": len(service.intents(candidate))}

    # With no usable gVisor runtime the validator claims nothing and nothing falls back.
    candidate, steps = other.submit("isolation", valid, archive)
    missing = Validator(service.transfers, service.quarantine, Sandbox(runsc=service.root / "no-runsc"),
                        release, service.projections, FixedTrust(fixture.run_trust(release)),
                        staging_root=service.root / "jobs", clock=service.clock,
                        service_binds=service_binds(REPOSITORY))
    outcome = missing.run_once()
    seen = other.status(candidate)
    steps.append(step("status", seen))
    cases["unavailable-isolation"] = {"candidate_id": candidate, "steps": steps, "state": seen.json()["state"],
                                      "validation": outcome_of(outcome), "intents": len(service.intents(candidate))}

    # A restarted service rebuilds from PostgreSQL and serves the same outcome.
    service.restart()
    contributor = Contributor(service, CONTRIBUTOR)
    seen = contributor.status(cases["valid"]["candidate_id"])
    [again] = service.intents(cases["valid"]["candidate_id"]) or [None]
    restart = {"steps": [step("status", seen)], "state": seen.json()["state"],
               "evidence_sha256": None if again is None else again["evidence_sha256"]}

    authority = {
        "trust_records": service.count("SELECT count(*) FROM trust_records"),
        "operator_records": len(service.operator.envelopes),
        "intents": service.count("SELECT count(*) FROM publication_intents"),
        "accepted": service.count("SELECT count(*) FROM candidates WHERE state = 'accepted'"),
        "publish_jobs": service.count("SELECT count(*) FROM outbox_jobs WHERE kind = 'publish-intent'"),
    }
    return report(service, cases, restart, authority, evidence, archive, image_ids)


def report(service, cases, restart, authority, evidence, archive, image_ids):
    release = service.release
    decoded = None if evidence is None else json.loads(evidence)
    result = {
        "schema": SCHEMA, "scenario": "intake-validation", "profile": "local",
        "source": source_digest(), "runtime": runtime(),
        "release": {"lock_sha256": release.lock_sha256, "trees_sha256": release.trees_sha256},
        "pins": pins.record(), "images": dict(image_ids),
        "fixture": {"outer_sha256": hashlib.sha256(archive).hexdigest(), "bytes": len(archive),
                    "snapshot_id": service.value["snapshot_id"]},
        "cases": cases, "restart": restart, "authority": authority,
        "intent": None if decoded is None else {
            "evidence_sha256": hashlib.sha256(evidence).hexdigest(), "schema": decoded.get("schema"),
            "coverage": decoded.get("coverage"), "fields": sorted(decoded), "evidence": decoded},
        "metadata_latency": latency(service.timings),
    }
    result["expectations"] = expectations(result, decoded)
    result["passed"] = all(result["expectations"].values())
    return result


def _no_intent(case):
    return case["intents"] == 0


def expectations(result, evidence):
    cases, authority = result["cases"], result["authority"]
    valid = cases["valid"]
    signature_fields = {"signature", "signatures", "payloadType", "envelope", "receipt", "acceptance"}
    return {
        "valid-intent-recorded": (valid["state_before"], valid["state"], valid["intents"],
                                  valid["validation"].get("code")) == ("quarantined", "publishing", 1, None),
        "valid-intent-exact": evidence is not None and evidence.get("schema") == SCHEMA_EVIDENCE
        and evidence["input"]["archive_sha256"] == result["fixture"]["outer_sha256"]
        and evidence["identities"]["snapshot_id"] == result["fixture"]["snapshot_id"],
        "forged-identity-no-intent": _no_intent(cases["forged-identity"])
        and cases["forged-identity"]["state"] == "rejected",
        "changed-bytes-no-intent": _no_intent(cases["changed-bytes"])
        and [item["code"] for item in cases["changed-bytes"]["steps"] if item["route"] == "upload"]
        == ["upload_integrity"],
        "wrong-actor-no-intent": _no_intent(cases["wrong-actor"]) and cases["wrong-actor"]["state"] == "announced",
        "protocol-mismatch-no-intent": _no_intent(cases["protocol-mismatch"])
        and cases["protocol-mismatch"]["state"] == "announced"
        and [item["status"] for item in cases["protocol-mismatch"]["steps"] if item["route"] == "endorsement"]
        == [422],
        "revoked-scope-no-intent": _no_intent(cases["revoked-scope"]) and cases["revoked-scope"]["state"] == "rejected",
        "unavailable-isolation-no-intent": _no_intent(cases["unavailable-isolation"])
        and cases["unavailable-isolation"]["validation"] == {"claimed": False}
        and cases["unavailable-isolation"]["state"] == "quarantined",
        "no-authority-object": authority["trust_records"] == authority["operator_records"]
        and authority["intents"] == 1 and authority["accepted"] == 0,
        "no-signature": evidence is not None and not signature_fields & set(evidence)
        and evidence["coverage"]["accepted"] is False,
        "restart-same-outcome": result["restart"]["state"] == "publishing"
        and result["restart"]["evidence_sha256"] is not None
        and result["intent"] is not None
        and result["restart"]["evidence_sha256"] == result["intent"]["evidence_sha256"],
    }


def source_digest():
    """SHA-256 over each tracked-kind source file's path and digest, in path order."""
    rows = []
    for part in SOURCE_PARTS:
        for path in sorted((REPOSITORY / part).rglob("*")):
            relative = path.relative_to(REPOSITORY)
            if path.is_file() and not path.is_symlink() and "__pycache__" not in relative.parts:
                rows.append((relative.as_posix(), hashlib.sha256(path.read_bytes()).hexdigest()))
    for name in SOURCE_FILES:
        rows.append((name, hashlib.sha256((REPOSITORY / name).read_bytes()).hexdigest()))
    rows.sort()
    joined = "".join("%s  %s\n" % (digest, name) for name, digest in rows).encode()
    return {"files": len(rows), "sha256": hashlib.sha256(joined).hexdigest()}


def runtime():
    uname = os.uname()
    return {"python": platform.python_version(), "kernel": uname.release, "machine": uname.machine,
            "python_sha256": hashlib.sha256(Path(sys.executable).resolve().read_bytes()).hexdigest()}


# Four actors at the per-actor ceiling of five live candidates fill the
# per-run ceiling of 20, so each metadata route gets 20 samples.
LATENCY_ACTORS = (51, 52, 53, 54)
CANDIDATES_PER_ACTOR = 5


def measure_metadata():
    """Announce, endorse, upload, complete and read 20 candidates over HTTP; return the latency record.

    The first request verifies the run's whole trust prefix and is reported
    apart as `first_request_ms`; the samples start once that projection is
    cached, as it is for a running service whose trust head has not moved.
    """
    with ExitStack() as stack:
        service = Service(stack, contributors=LATENCY_ACTORS, registration=False)
        stack.callback(service.stop)
        contributors = [Contributor(service, actor) for actor in LATENCY_ACTORS]
        first = contributors[0].status(uuid.uuid4())
        del service.timings[:]
        refused = []
        for contributor in contributors:
            for index in range(CANDIDATES_PER_ACTOR):
                label = "latency-%d" % index
                data = payload(65_536, ("%d-%s" % (contributor.actor, label)).encode())
                identities = {"snapshot_id": "1" * 64, "controller_manifest_sha256": "2" * 64,
                              "outer_sha256": hashlib.sha256(data).hexdigest()}
                candidate, steps = contributor.submit(label, identities, data)
                status = contributor.status(candidate)
                refused.extend(item for item in steps if item["status"] >= 400)
                if status.status != 200 or status.json()["state"] != "quarantined":
                    refused.append({"route": "status", "status": status.status, "code": status.code()})
        record = latency(service.timings)
        record["first_request_ms"] = round(first.elapsed_ms, 3)
        record["refused"] = refused
        return record


def main(argv=None):
    parser = argparse.ArgumentParser(description="Demonstrate issue #1 intake to validation locally")
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--out")
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return 2
    if args.scenario not in SCENARIOS:
        # `--scenario end-to-end` is issue #3's; no other scenario exists here.
        print("demo-refused: scenario-not-enabled", file=sys.stderr)
        return 2
    if args.profile not in PROFILES:
        print("demo-refused: profile-not-enabled", file=sys.stderr)
        return 2
    from fiat_checkpoints.telemetry.logging import configure_logging
    configure_logging()
    try:
        result = run_scenario()
    except DemoRefusal as error:
        print("demo-refused: " + str(error), file=sys.stderr)
        return 2
    except Exception:
        # The exception text may hold a path or a library message; only a fixed code leaves.
        print("demo-refused: demo-failed", file=sys.stderr)
        return 2
    text = json.dumps(result, sort_keys=True, separators=(",", ":"))
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    print(text)
    print(json.dumps({"schema": SCHEMA + "-digest", "report_sha256": hashlib.sha256((text + "\n").encode()).hexdigest(),
                      "passed": result["passed"]}, sort_keys=True))
    return 0 if result["passed"] else 1
