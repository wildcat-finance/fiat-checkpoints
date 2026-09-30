"""Authenticate authority records through the released library, keeping exact bytes.

Nothing here defines a record, a signature rule or a trust rule: the pinned
`checkpoint_authority` package does. This module fixes the service inputs
(scope, external roots, tool pins), bounds what reaches the library and keeps
the exact envelope bytes the service received. Every library refusal leaves as
`protocol_refused` carrying the library's own code and stage. Any other
exception a malformed input raises inside the library leaves as one fixed
service code with no protocol code, message or traceback.
"""

from dataclasses import dataclass
import hashlib

from fiat_checkpoints.records.refusals import RecordRefusal, from_protocol


OPENSSL_PATH = "/usr/bin/openssl"
# OpenSSL 3.5.6 as shipped in the digest-pinned python:3.14.6-slim-trixie base image.
OPENSSL_SHA256 = "38633817061f9d161c8b14c1ff72c9f223e8208d977a4c15d843010611a5dded"
ENVIRONMENTS = ("test", "production")
# The library refuses by `Refusal`; these are what it raises on a shape it never checked.
UNEXPECTED = (LookupError, TypeError, AttributeError, ValueError, RecursionError)


@dataclass(frozen=True)
class ServiceScope:
    """Operator configuration; never read from an envelope."""
    environment: str
    service: str
    repository_id: int
    run_id: str


@dataclass(frozen=True)
class VerifiedEnvelope:
    """The envelope exactly as received, and the exact signed payload inside it."""
    envelope: bytes
    envelope_sha256: str
    payload: bytes
    record_bytes: bytes
    record_type: str
    key_fingerprint: str
    _verified: object

    @property
    def record(self):
        """A fresh parsed copy; the stored bytes above are what the service keeps."""
        return self._verified.record


def tool_pins(release):
    """The single public-key verifier the service admits, pinned by path and digest."""
    pin = release.library.signatures.ToolPin("openssl", OPENSSL_PATH, OPENSSL_SHA256)
    try:
        pin.check()
    except release.refusal_type as error:
        raise from_protocol("tool_unavailable", error) from None
    return {"openssl": pin}


class AuthorityRecords:
    """One service scope, its external roots and its pinned tools."""

    def __init__(self, release, scope, roots, tools):
        if not isinstance(scope, ServiceScope) or scope.environment not in ENVIRONMENTS:
            raise RecordRefusal("authority_unavailable")
        if type(roots) is not tuple or not all(type(root) is bytes for root in roots):
            raise RecordRefusal("authority_unavailable")
        self.release = release
        self.library = release.library
        self.scope = scope
        self.tools = dict(tools)
        self.bootstrap = self.library.trust.Bootstrap(
            scope.environment, scope.service, scope.repository_id, scope.run_id, roots)
        self._call(lambda: self.library.trust.TrustPrefix(self.bootstrap, self.tools))

    def _call(self, operation, unexpected="authority_unavailable"):
        try:
            return operation()
        except self.release.refusal_type as error:
            raise from_protocol("protocol_refused", error) from None
        except UNEXPECTED:
            # The library did not emit a code, so none passes through (study section 11).
            raise RecordRefusal(unexpected) from None

    def _bounded(self, envelope):
        if type(envelope) is not bytes or not 0 < len(envelope) <= self.library.signatures.MAX_ENVELOPE_BYTES:
            raise RecordRefusal("request_invalid")
        # The service keeps its own copy, so a caller's buffer cannot change it later.
        return bytes(envelope)

    def _wrap(self, envelope, verified):
        if verified.envelope_sha256 != hashlib.sha256(envelope).hexdigest():
            raise RecordRefusal("authority_unavailable")
        record = verified.record
        return VerifiedEnvelope(envelope, verified.envelope_sha256, verified.payload,
                                verified.record_bytes, record["type"], verified.key_fingerprint, verified)

    def trust_prefix(self, envelopes):
        """Authenticate policy, key and grant records in order from the external roots."""
        prefix = self._call(lambda: self.library.trust.TrustPrefix(self.bootstrap, self.tools))
        accepted = []
        for envelope in envelopes:
            exact = self._bounded(envelope)
            accepted.append(self._wrap(exact, self._call(lambda: prefix.append(exact))))
        if prefix.policy is None:
            raise RecordRefusal("protocol_refused", producer="checkpoint-authority",
                                protocol_code="bootstrap-required", stage="trust")
        return prefix, tuple(accepted)

    def authenticate(self, prefix, envelope):
        """Authenticate one later record against an already verified trust prefix."""
        exact = self._bounded(envelope)
        return self._wrap(exact, self._call(lambda: prefix.authenticate(exact)))

    def verify_with_key(self, envelope, key):
        """Authenticate one envelope with an already trusted key, in this service scope."""
        exact = self._bounded(envelope)
        scope = self.bootstrap.scope
        return self._wrap(exact, self._call(
            lambda: self.library.signatures.verify_envelope(exact, key, self.tools, scope=scope)))

    def native_parent(self, result, producer, validation):
        """Project caller-owned native evidence; absent evidence refuses by the library's code."""
        return self._call(lambda: self.library.parents.native_projection(result, producer, validation),
                          "validation_failed")

    def check_parent(self, link, registration, native, decisions, acceptance, registration_id):
        return self._call(lambda: self.library.parents.check_parent(
            link, registration, native, decisions, acceptance, registration_id))

    def check_custody(self, state, entries):
        """Refuse history classes the pinned native profile cannot restore or relocate."""
        return self._call(lambda: self.library.native_records.custody(state, entries), "validation_failed")

    def acceptance_id(self, payload):
        return self._call(lambda: self.library.records.acceptance_id(payload))
