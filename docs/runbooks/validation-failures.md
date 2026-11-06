# Validation failures and sandbox unavailability

A validation job stages one sealed input, runs the pinned native sequence in
a fresh gVisor sandbox and records an intent only after every check passes.
See the [validator decision](../decisions/drafts/isolate-validator-trust.md)
for the codes, the ceilings and what the checks do not cover.

## What fired

Any of these:

- `validation-finished` events with code `validation_failed` repeat for one
  candidate, or its validation job reaches `held`;
- `validation-worker-unavailable` events repeat and candidates stay
  `quarantined`;
- `sandbox-finished` events carry a reason ending in `-limit`;
- `sandbox-cleanup-failed` at error level.

## First check

1. Read the event's `reason`. `sandbox-runsc-pin`, `sandbox-rootfs-pin`,
   `sandbox-runtime-missing` or `sandbox-cgroup-unavailable` mean the host
   cannot run the pinned sandbox: no job runs and no candidate is claimed
   until it can. Run `scripts/sandbox-env.sh facts` and compare runsc's
   version with `release-20261019.0`. Do not replace runsc with any other
   runtime.
2. A reason ending in `-limit` is a ceiling: `memory-limit`, `cpu-limit`,
   `wall-limit`, `stdout-limit` or `stderr-limit`. It is not evidence that the
   archive is hostile. Compare the job's `sandbox-resources` bytes with the
   measured row in the decision record before raising anything; a ceiling is
   lowered by configuration and never raised without a new decision.
3. `native-command-unmapped` means a native command failed with a diagnostic
   that is not one listed class. The diagnostic stays private by design
   (Skills #1647); only its SHA-256 is kept. Reproduce with
   `scripts/sandbox-env.sh run scripts/reject-case.sh --all` to confirm the
   corpus still refuses as declared, then investigate the candidate's own
   input in an isolated environment.
4. For `sandbox-cleanup-failed`, list leftovers with
   `fiat_checkpoints.validation.sandbox.leftovers()` as root inside the
   supervisor. A left job directory or cgroup holds no credential, but stop
   new jobs until it is gone.

Never rerun a failed job outside the sandbox, never pass a job a private key
or agent socket, and never accept a result that is not the current job's.

## Who to wake

The fiat-checkpoints service operator on call. If runsc or the root
filesystem fails its pin, also the owner of the validator image.
