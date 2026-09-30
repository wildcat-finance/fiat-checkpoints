"""Shared set-up for the authentication and endorsement groups.

The identity provider is an in-process fake: no network exists in the test
environment, and every value it returns is synthetic. Keys are generated for
each run by `tests.authority_fixtures` in ignored temporary directories. The
operator's trust records are signed here with those keys, in journal order.
"""

import asyncio
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit
import warnings

import httpx

from fiat_checkpoints.api.intake import SESSION_COOKIE, IntakeServices, create_intake_app
from fiat_checkpoints.auth.identity import IdentityProvider
from fiat_checkpoints.auth.sessions import SessionStore
from fiat_checkpoints.auth.tokens import new_secret, pkce_challenge
from fiat_checkpoints.config import load_config
from fiat_checkpoints.domain.coordination import QuotaPolicy
from fiat_checkpoints.grants.intake import Intake
from fiat_checkpoints.grants.projection import Projections, RunAuthority
from fiat_checkpoints.persistence.coordinator import Coordinator
from fiat_checkpoints.records.authority import ServiceScope
from tests import authority_fixtures as fixtures


ROOT = Path(__file__).resolve().parents[1]
T0 = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)
SETTINGS = load_config(ROOT / "config/local.json")
SCOPE = fixtures.SCOPE
OTHER_SCOPE = ServiceScope("test", SCOPE.service, SCOPE.repository_id, "fiat-" + "b" * 64)
ACTOR = 41
OTHER_ACTOR = 42
IDENTITIES = {"snapshot_id": "1" * 64, "controller_manifest_sha256": "2" * 64, "outer_sha256": "3" * 64}
LENGTH = 4096
PARENT = {"type": "parent-link", "sha256": "5" * 64}
FAR = "2026-12-31T00:00:00Z"


def at(seconds):
    return T0 + timedelta(seconds=seconds)


def stamp(seconds):
    return at(seconds).strftime("%Y-%m-%dT%H:%M:%SZ")


def user_document(user_id, login):
    """A synthetic `GET /user` body; only `id` is identity."""
    return json.dumps({"login": login, "id": user_id, "type": "User", "site_admin": False}).encode()


class Clock:
    """The service clock under test control."""

    def __init__(self, now=T0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += timedelta(seconds=seconds)
        return self.now


class FakeProvider(IdentityProvider):
    """In-process provider: a code works once, and only with the PKCE verifier it was issued for.

    With `secret` set it resolves its client secret reference at exchange
    time, as a live adapter would, and refuses unless the value matches.
    """

    def __init__(self, secret=None):
        self.pending, self.codes, self.exchanged = {}, {}, []
        self.secret = secret

    def authorization_url(self, state, code_challenge):
        self.pending[state] = code_challenge
        return "https://identity.invalid/login/oauth/authorize?" + urlencode({
            "client_id": "synthetic-client", "state": state, "code_challenge": code_challenge,
            "code_challenge_method": "S256"})

    def authorize(self, url, document):
        """The user approves in the provider's page: return the state and a fresh code."""
        state = parse_qs(urlsplit(url).query)["state"][0]
        code = new_secret()
        self.codes[code] = (self.pending.pop(state), document)
        return state, code

    def user_document(self, code, code_verifier):
        challenge, document = self.codes.pop(code)
        if pkce_challenge(code_verifier) != challenge:
            raise PermissionError("verifier")
        if self.secret is not None:
            reference, mount, expected = self.secret
            if reference.resolve(mount).reveal() != expected:
                raise PermissionError("client")
        self.exchanged.append(code)
        return document


class StubProjections:
    """Grant answers for the session-only route checks, which start no verifier process."""

    environment = "test"

    def __init__(self, granted=()):
        self.granted = set(granted)

    def any_grant(self, actor_id, _now):
        return actor_id in self.granted


def request(app, method, path, *, cookies=None, headers=None, **options):
    """Send one request through HTTPX's ASGI transport over https, with warnings as errors."""
    headers = dict(headers or {})
    if cookies:
        headers["cookie"] = "; ".join(f"{name}={value}" for name, value in cookies.items())

    async def send():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="https://testserver") as client:
            return await client.request(method, path, headers=headers, **options)

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        return asyncio.run(send())


def set_cookies(response):
    """Name to (value, attributes) for every Set-Cookie header of a response."""
    found = {}
    for header in response.headers.get_list("set-cookie"):
        pair, _, attributes = header.partition(";")
        name, _, value = pair.partition("=")
        found[name.strip()] = (value.strip().strip('"'), attributes)
    return found


def session_headers(opened):
    """Cookie and CSRF headers for one opened browser session."""
    return {"cookie": f"{SESSION_COOKIE}={opened.secret}", "x-csrf-token": opened.csrf_token}


def build(database, clock, *, provider=None, projections=None, runs=None, quotas=None):
    """The intake app and its services over one migrated database."""
    sessions = SessionStore(database, audience=SETTINGS.service_id, environment=SETTINGS.environment_id)
    if projections is None:
        projections = Projections(database, runs)
    coordinator = Coordinator(database, quotas=quotas or QuotaPolicy())
    intake = Intake(database, coordinator, projections)
    services = IntakeServices(sessions, provider or FakeProvider(), projections, intake, clock)
    return create_intake_app(SETTINGS, services), services


# Operator-signed trust records --------------------------------------------------


def common(kind, sequence, previous, issued, issuer, scope):
    return {"protocol": "checkpoint-authority/v1", "environment": scope.environment, "service": scope.service,
            "scope": {"repository_id": scope.repository_id, "run_id": scope.run_id}, "type": kind,
            "sequence": sequence, "previous": previous, "issued_at": issued, "issuer": issuer}


def ref(kind, envelope):
    return {"type": kind, "sha256": hashlib.sha256(envelope).hexdigest()}


class Operator:
    """One run's operator journal: a policy first, then challenges, enrollments, grants, revocations."""

    def __init__(self, signer, scope=SCOPE, start=-7200):
        self.signer, self.scope = signer, scope
        self.records, self.envelopes = [], []
        lock = fixtures.release().lock_check
        self.add(common("authority-policy", 1, None, stamp(start), signer.key["fingerprint"], scope) | {
            "authorities": [{"key": signer.key, "roles": ["policy", "operator"], "not_before": stamp(start),
                             "not_after": "2027-01-01T00:00:00Z"}],
            "allowed_protocols": ["checkpoint-authority/v1"], "signature_profile": "dsse-p256-sha256-der/v1",
            "native": {key: lock["native"][key] for key in ("source_commit", "executable_sha256", "profile")},
            "release": {"source_commit": lock["source_commit"], **{key: lock["pins"][key] for key in (
                "artifact_sha256", "schema_set_sha256", "verifier_sha256", "fixture_corpus_sha256")}},
            "storage_policy_sha256": "4" * 64,
            "locations": [
                {"role": "primary", "location_id": "primary-eu", "account_id": "account-a", "jurisdiction": "EU"},
                {"role": "recovery", "location_id": "recovery-eu", "account_id": "account-b",
                 "jurisdiction": "EU"}],
            "max_head_age_seconds": 60})
        self.policy = ref("authority-policy", self.envelopes[0])

    def next(self, kind, issued):
        previous = ref(self.records[-1]["type"], self.envelopes[-1])
        return common(kind, len(self.records) + 1, previous, stamp(issued), self.signer.key["fingerprint"],
                      self.scope) | {"policy": self.policy}

    def add(self, record, signer=None):
        envelope = fixtures.envelope(record, signer or self.signer)
        self.records.append(record)
        self.envelopes.append(envelope)
        return envelope

    def challenge(self, actor, key, issued, lifetime=300, nonce=None):
        return self.add(self.next("enrollment-challenge", issued) | {
            "actor_id": actor, "key": key, "nonce": nonce or "challenge-" + new_secret()[:16],
            "expires_at": stamp(issued + lifetime)})

    def record_of(self, envelope):
        return self.records[self.envelopes.index(envelope)]

    def enroll(self, actor, key, challenge, proof, issued, not_after=FAR):
        return self.add(self.next("key-enrollment", issued) | {
            "actor_id": actor, "key": key,
            "proof": {"challenge": ref("enrollment-challenge", challenge),
                      "signature": base64.b64encode(proof).decode()},
            "not_before": stamp(issued), "not_after": not_after})

    def grant(self, actor, enrollment, permissions, issued, not_after=FAR):
        return self.add(self.next("run-grant", issued) | {
            "actor_id": actor, "enrollment": ref("key-enrollment", enrollment), "permissions": list(permissions),
            "not_before": stamp(issued), "not_after": not_after})

    def revoke(self, actor, enrollment, issued, reason="permission-removed"):
        return self.add(self.next("key-revocation", issued) | {
            "actor_id": actor, "enrollment": ref("key-enrollment", enrollment), "effective_at": stamp(issued),
            "reason": reason})


def proof(contributor, challenge_record):
    """The contributor's proof of possession over one challenge, as the protocol defines it."""
    return contributor.sign(fixtures.library().trust.proof_message(challenge_record))


def contributor_journal(operator, contributor, actor=ACTOR, permissions=("announce", "upload", "read_status"),
                        issued=-3600, grant_not_after=FAR):
    """Challenge, proof, enrollment and grant for one contributor; returns (enrollment, grant) envelopes."""
    challenge = operator.challenge(actor, contributor.key, issued)
    enrollment = operator.enroll(actor, contributor.key, challenge, proof(contributor, operator.record_of(challenge)),
                                 issued + 10)
    grant = operator.grant(actor, enrollment, permissions, issued + 20, grant_not_after)
    return enrollment, grant


def run_authority(operator, scope=None):
    scope = scope or operator.scope
    return RunAuthority(fixtures.records((fixtures.root_bytes(operator.signer),), scope))


def endorsement_record(announced, enrollment, grant, contributor, *, actor=ACTOR, issued=0, lifetime=120,
                       scope=SCOPE, **changes):
    """An upload endorsement for one announce response body; `changes` replace fields."""
    challenge = announced["endorsement"]
    record = common("upload-endorsement", 1, None, stamp(issued), contributor.key["fingerprint"], scope) | {
        "policy": challenge["policy"], "actor_id": actor, "enrollment": ref("key-enrollment", enrollment),
        "grant": ref("run-grant", grant), "candidate_id": announced["candidate_id"], "nonce": challenge["nonce"],
        "expires_at": stamp(issued + lifetime), "identities": dict(IDENTITIES), "carrier_length": LENGTH,
        "parent": dict(PARENT)}
    return record | changes


def announce_body(scope=SCOPE, **changes):
    body = {"run": {"repository_id": scope.repository_id, "run_id": scope.run_id}, "identities": dict(IDENTITIES),
            "carrier_length": LENGTH, "parent": dict(PARENT)}
    return body | changes
