"""Issue upload capabilities in the API role and confirm a sealed upload.

A capability comes only from the candidate's bound endorsement, after the
grant that endorsement names is checked current for `upload` again. Its start
window closes at the earliest of 15 minutes, the endorsement's expiry and the
candidate's deadline, so a capability can never outlive the endorsement it
came from. `complete` compares the client's claim with what the gateway
sealed and trusts nothing the client declares. The API role holds no
quarantine credential. See adr/seal-uploads-in-bounded-quarantine.
"""

import hmac
import re

from fiat_checkpoints.auth.refusals import AuthRefusal
from fiat_checkpoints.domain.coordination import positive_int, require_now
from fiat_checkpoints.grants.projection import reference
from fiat_checkpoints.persistence.transfer import START_WINDOW, Completed, Transfers
from fiat_checkpoints.upload.capability import IssuedCapability, capability_sha256, new_capability


SHA256 = re.compile(r"[0-9a-f]{64}")
COMPLETE_FIELDS = frozenset({"attempt", "length", "sha256"})


class UploadIssuer:
    """Capability issue and completion over Step 4's intake services."""

    def __init__(self, intake, *, environment):
        self.transfers = Transfers.from_coordinator(intake.coordinator)
        self.endorsements = intake.endorsements
        self.projections = intake.projections
        self.environment = environment

    def _authorized(self, actor_id, candidate_id, now):
        """The candidate's binding, run and bound endorsement, with its named grant current for `upload`."""
        binding = self.endorsements.binding(actor_id, candidate_id)
        run = self.projections.run_for(binding.scope)
        bound = self.endorsements.bound(actor_id, binding.candidate_id, now)
        self.projections.current(run).named_grant(reference("run-grant", bound.grant_sha256), actor_id, "upload",
                                                  now)
        return binding, run, bound

    def issue(self, actor_id, candidate_id, now):
        """A fresh capability for the actor's own candidate, or its sealed result as `Completed`."""
        positive_int(actor_id)
        now = require_now(now)
        binding, run, bound = self._authorized(actor_id, candidate_id, now)
        value = new_capability()
        start_expires_at = min(now + START_WINDOW, bound.expires_at, binding.expires_at)
        issued = self.transfers.issue(run.scope, actor_id, binding.candidate_id, bound, capability_sha256(value),
                                      self.environment, start_expires_at, now)
        if isinstance(issued, Completed):
            return issued
        return IssuedCapability(value, binding.candidate_id, issued.lease.attempt_number, issued.start_expires_at,
                                issued.declared_size, issued.archive_sha256, issued.renewed)

    def complete(self, actor_id, candidate_id, body, now):
        """The sealed result when the claim names exactly the sealed attempt, length and digest.

        An attempt still open is `upload_in_progress`; anything else the
        gateway did not seal is `upload_integrity`.
        """
        positive_int(actor_id)
        now = require_now(now)
        if type(body) is not dict or set(body) != COMPLETE_FIELDS:
            raise AuthRefusal("request_invalid", "body-fields")
        attempt, length, sha256 = body["attempt"], body["length"], body["sha256"]
        if (type(attempt) is not int or not 1 <= attempt <= 16 or type(length) is not int or length < 1
                or type(sha256) is not str or SHA256.fullmatch(sha256) is None):
            raise AuthRefusal("request_invalid", "body-fields")
        binding = self.endorsements.binding(actor_id, candidate_id)
        run = self.projections.run_for(binding.scope)
        self.projections.current(run).grant(actor_id, "upload", now)
        seen = self.transfers.attempt_state(run.scope, actor_id, binding.candidate_id)
        if isinstance(seen, Completed):
            if ((seen.attempt_number, seen.sealed_size) == (attempt, length)
                    and hmac.compare_digest(seen.sealed_sha256, sha256)):
                return seen
            raise AuthRefusal("upload_integrity", "complete-mismatch")
        _state, current = seen
        if current is not None and current["attempt_number"] == attempt:
            raise AuthRefusal("upload_in_progress", "attempt-open")
        raise AuthRefusal("upload_integrity", "attempt-unsealed")
