# Publication intent handoff to issue #2

Issue #1 ends at an immutable publication intent. This document gives
[issue #2](https://github.com/wildcat-finance/fiat-checkpoints/issues/2) the
exact intent it consumes, what each field binds, what the validator checked
and what it did not, one example built from a synthetic run, and every stable
refusal code the service returns. An intent is not an accepted checkpoint, a
receipt or a signed record. Nothing in this service signs, and production stays
closed.

## Run the demonstration

The intake path runs on one machine with the PostgreSQL 16 test server up and
the validator image built (`SKILLS_REPO=<skills clone> scripts/sandbox-env.sh build`):

```sh
scripts/linux-env.sh db-start
scripts/sandbox-env.sh run scripts/demo.sh --scenario intake-validation --profile local
```

`scripts/sandbox-env.sh run` is required because the demonstration starts
gVisor. The intake API and the upload gateway are served over HTTP on
loopback. Contributors log in through an in-process identity provider, announce,
sign an upload endorsement with an operator-enrolled key, upload through the
gateway and complete. The validator then stages the sealed bytes and runs the
pinned native sequence in a fresh gVisor sandbox. The report lists the source,
protocol, runtime, sandbox and fixture digests, each reply's status, code and
request id, and the observed refusals:

| Case | What happens | Intent |
| --- | --- | --- |
| Valid | The released valid fixture is announced, endorsed, uploaded, sealed and validated | One, state `publishing` |
| Wrong actor | Another enrolled actor endorses or reads the candidate: `404 not_found`; the owner presents the other actor's endorsement: `422 identity_mismatch` | None |
| Changed bytes | One byte differs at the declared length: `422 upload_integrity` | None |
| Protocol mismatch | The endorsement names `checkpoint-authority/v2`: `422 endorsement_invalid` | None |
| Forged carried identity | The `identity-mismatch` specimen's carried snapshot id is changed; the sandboxed inspect refuses it | None, state `rejected` |
| Revoked scope | The operator revokes the uploader's enrollment after the seal; `endorsement_invalid` before any sandbox starts | None, state `rejected` |
| Unavailable isolation | No usable `runsc`: the validator claims nothing and nothing falls back | None, state `quarantined` |

A restart then rebuilds every service object from PostgreSQL and serves the
same state and evidence digest. The run creates no trust record, accepted
state, signature or receipt.

The released native fixture's private key was destroyed by its producer, so no
operator can enroll the key that signed its commits. The demonstration
therefore approves commit signers from the fixture's own test approval. The run
scope, grants, root-anchor registration and revocation come from operator-signed
records verified through the released library. Production approval reads the
enrolled OpenPGP keys from that projection instead (`ProjectionTrust`).

## The intent

When validation passes, one transaction moves the candidate from `validating`
to `publishing`, inserts one `publication_intents` row and queues one
`publish-intent` outbox job for issue #2's worker. The row cannot be updated,
deleted or truncated.

| Column | Content |
| --- | --- |
| `intent_id` | Random UUID |
| `candidate_id` | The candidate; unique, so a candidate has at most one intent |
| `validation_attempt`, `fence` | The validation attempt and the fencing number of the lease that wrote it |
| `archive_sha256`, `snapshot_id`, `controller_manifest_sha256` | The three checkpoint identities |
| `evidence` | The evidence record below as canonical JSON (sorted keys, no spaces, ASCII escapes), at most 65,536 bytes |
| `evidence_sha256` | SHA-256 of `evidence` |
| `created_at` | Service clock, UTC |

### Evidence fields

The evidence schema is `fiat-checkpoints-validation-evidence/v1`.

| Field | Content |
| --- | --- |
| `candidate_id` | The candidate as 32 lowercase hex characters |
| `coverage` | What was and was not checked; see the table below |
| `endorsement` | The upload endorsement used: `sequence`, `envelope_sha256`, `enrollment_sha256`, `grant_sha256` |
| `fence` | The validation lease's fencing number |
| `finished_at` | Service clock when the job's checks ended |
| `identities` | `snapshot_id`, `controller_manifest_sha256` and `archive_sha256` the candidate announced and the job reminted |
| `input` | The sealed input: `archive_sha256`, `length` and the sealed `upload_attempt` |
| `job_id` | The sandbox job, 32 random hex characters |
| `native_result` | The released `checkpoint-authority-native-result/v1` record: the request, native commit, profile and executable, tool pins, the four stage results, reminted identity, status digest, next directive and commit-signature coverage |
| `native_result_sha256` | SHA-256 of `native_result` in canonical form |
| `parent` | The announced `parent-link` reference; the record it names was not verified |
| `pins` | gVisor release and digests, the native file the image adds and the five tool pins |
| `registration_sha256` | Envelope digest of the operator-signed run registration that authorized the root anchor |
| `release` | Digests of `protocol.lock.json` and `protocol.trees.json` |
| `resources` | The job's wall time, CPU time, peak memory (scratch included) and peak host tasks |
| `schema` | `fiat-checkpoints-validation-evidence/v1` |
| `started_at` | Service clock when the job started |
| `trust` | `public_trust_sha256` of the injected keyring, `approval_sha256` of the approved history and the `historical_signers` that resolved |
| `trust_head` | `count` and `tail` of the run's trust records when the job started; the same head was read when it ended |
| `validation_attempt` | The validation attempt number |

### Coverage

| Flag | Value | Meaning |
| --- | --- | --- |
| `inspect` | true | The pinned inspect ran on the exact sealed bytes |
| `fresh_restore` | true | Restore ran into a new private destination with exit 0 |
| `verify_observations` | true | Controller verification with observations ran with exit 0 |
| `identity_reminted` | true | The reminted identity equals the announced and carried ones |
| `commit_signature_coverage` | true | Every required receipted commit is covered by a verified signature |
| `historical_signers_approved` | true | Every signer resolved to an approved key |
| `run_and_key_scope` | true | The uploader's grant was current at the start and the end |
| `registered_root_anchor` | true | The reminted run anchor and base equal the registration's |
| `trust_head_unchanged` | true | The trust head did not move during the job |
| `gvisor_isolation` | true | The job ran in a fresh gVisor sandbox with no network |
| `parent_link_record_verified` | false | The signed parent-link record was not verified |
| `external_freshness_head` | false | Freshness was checked against the stored trust head only |
| `decompressed_git_object_secret_scan` | false | No scan of decompressed Git objects; the inspector's raw-member scan stands |
| `accepted` | false | Nothing was accepted |

## Evidence contract

Before issue #2 acts on an intent, it:

1. reads the row and checks that `evidence` hashes to `evidence_sha256`,
   decodes as canonical JSON with this schema, and repeats the row's three
   identities in `identities`, in `input.archive_sha256` and in
   `native_result.request`;
2. checks that `native_result` hashes to `native_result_sha256` and that
   `release` and `pins` match the deployed validator;
3. reads the sealed quarantine object for `input.upload_attempt` in full and
   checks its length and SHA-256 again before any copy;
4. verifies the signed parent-link record and the current external freshness
   head, because both coverage flags are false;
5. rechecks the uploader's grant and revocations at the signer's ordered control
   head, because `trust_head` is only what the validator read; and
6. treats every coverage flag that is false as unproved.

The validator's reservation stays held while the candidate is `publishing`;
releasing it at acceptance or a signed denial belongs to issue #2. The
specification's step 9 attestation of the job and result binding to the
independent signer is also issue #2's.

## Example intent

Built by the demonstration from the released valid fixture and synthetic keys
on 2026-11-07. The row's `evidence_sha256` is
`b893731183ec741739c83daf5513c154d0b7088380a3562679b9fb6e0cdef48b`.
The block below is the same record with indentation; its canonical form is
the stored bytes.

```json
{
  "candidate_id": "c37a9e29a0f9478ca4b8607162a641af",
  "coverage": {
    "accepted": false,
    "commit_signature_coverage": true,
    "decompressed_git_object_secret_scan": false,
    "external_freshness_head": false,
    "fresh_restore": true,
    "gvisor_isolation": true,
    "historical_signers_approved": true,
    "identity_reminted": true,
    "inspect": true,
    "parent_link_record_verified": false,
    "registered_root_anchor": true,
    "run_and_key_scope": true,
    "trust_head_unchanged": true,
    "verify_observations": true
  },
  "endorsement": {
    "enrollment_sha256": "e9c684f93a37a35777b4076f1354848106460877784e59e1cd12ec7c7fa6fe4e",
    "envelope_sha256": "c215116188cd095632447101ee99cedc45a4a796c0cf76e36a3f1f8d8c502495",
    "grant_sha256": "e492d5e7e314f0b3f0e555be5e52288244fba7568c06a3fa5fe1970a343a55c1",
    "sequence": 1
  },
  "fence": 2,
  "finished_at": "2026-09-30T12:00:00+00:00",
  "identities": {
    "archive_sha256": "56e76497927756bdcb1658dae79a4babcb7c0c00c580c306773a189af7bbe95e",
    "controller_manifest_sha256": "b437779ea4e4745db9a3bcf3f4f6c3e2a5f937918f0b6c5812914d136516f8b6",
    "snapshot_id": "21af06cacb59d1b2958b67db63dbdeac18d68b1987f9f10266c6ed47157f2245"
  },
  "input": {
    "archive_sha256": "56e76497927756bdcb1658dae79a4babcb7c0c00c580c306773a189af7bbe95e",
    "length": 59603,
    "upload_attempt": 1
  },
  "job_id": "d4046ed1f714ae36987c3496035bd441",
  "native_result": {
    "complete": true,
    "coverage": {
      "approved_history_sha256": "2289020fa98a98ec75012913ef34ad1b66a3b2e3bdf287529be87b2efd242403",
      "base_history": {
        "evidence_class": "approved-base-endpoints",
        "initial_base": "87a8a2963d84bf36432ef6801830a9ffafe55821",
        "local_governed_signature_claim": false,
        "start_commit": "be5807dec84293045eac7b9ca35e8a23e0c6070e"
      },
      "complete": true,
      "historical_required": [
        "551bb2c16af0cb88d86c86402b5674d0438914ef",
        "a4beb0aca4b6558694dbe00f6cb3425cc545b87d"
      ],
      "native_expected": [
        "7e34f4403fd21e1be1feb9f2d79b5e974eb8568b",
        "9ca111552e796783e0cbc9a795995f176c5750d5"
      ],
      "platform_commits": [],
      "ranges": [
        {
          "base": "be5807dec84293045eac7b9ca35e8a23e0c6070e",
          "commits": [
            "551bb2c16af0cb88d86c86402b5674d0438914ef"
          ],
          "head": "551bb2c16af0cb88d86c86402b5674d0438914ef",
          "kind": "implementation",
          "step": 1
        },
        {
          "base": "be5807dec84293045eac7b9ca35e8a23e0c6070e",
          "commits": [
            "551bb2c16af0cb88d86c86402b5674d0438914ef",
            "a4beb0aca4b6558694dbe00f6cb3425cc545b87d"
          ],
          "head": "a4beb0aca4b6558694dbe00f6cb3425cc545b87d",
          "kind": "push",
          "step": 1
        },
        {
          "base": "a4beb0aca4b6558694dbe00f6cb3425cc545b87d",
          "commits": [
            "7e34f4403fd21e1be1feb9f2d79b5e974eb8568b"
          ],
          "head": "7e34f4403fd21e1be1feb9f2d79b5e974eb8568b",
          "kind": "implementation",
          "step": 2
        },
        {
          "base": "a4beb0aca4b6558694dbe00f6cb3425cc545b87d",
          "commits": [
            "7e34f4403fd21e1be1feb9f2d79b5e974eb8568b",
            "9ca111552e796783e0cbc9a795995f176c5750d5"
          ],
          "head": "9ca111552e796783e0cbc9a795995f176c5750d5",
          "kind": "push",
          "step": 2
        }
      ],
      "required": [
        "551bb2c16af0cb88d86c86402b5674d0438914ef",
        "7e34f4403fd21e1be1feb9f2d79b5e974eb8568b",
        "9ca111552e796783e0cbc9a795995f176c5750d5",
        "a4beb0aca4b6558694dbe00f6cb3425cc545b87d"
      ],
      "steps": {
        "551bb2c16af0cb88d86c86402b5674d0438914ef": [
          1
        ],
        "7e34f4403fd21e1be1feb9f2d79b5e974eb8568b": [
          2
        ],
        "9ca111552e796783e0cbc9a795995f176c5750d5": [
          2
        ],
        "a4beb0aca4b6558694dbe00f6cb3425cc545b87d": [
          1
        ]
      },
      "verified": [
        {
          "commit": "551bb2c16af0cb88d86c86402b5674d0438914ef",
          "enrollment": {
            "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "type": "key-enrollment"
          },
          "evidence_class": "local-signature",
          "fingerprint": "0F4CA4D6F2C4A42C86D923A48CF45B322E7748BF",
          "native_current_boundary": false
        },
        {
          "commit": "7e34f4403fd21e1be1feb9f2d79b5e974eb8568b",
          "enrollment": {
            "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "type": "key-enrollment"
          },
          "evidence_class": "local-signature",
          "fingerprint": "0F4CA4D6F2C4A42C86D923A48CF45B322E7748BF",
          "native_current_boundary": true
        },
        {
          "commit": "9ca111552e796783e0cbc9a795995f176c5750d5",
          "enrollment": {
            "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "type": "key-enrollment"
          },
          "evidence_class": "local-signature",
          "fingerprint": "0F4CA4D6F2C4A42C86D923A48CF45B322E7748BF",
          "native_current_boundary": true
        },
        {
          "commit": "a4beb0aca4b6558694dbe00f6cb3425cc545b87d",
          "enrollment": {
            "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "type": "key-enrollment"
          },
          "evidence_class": "local-signature",
          "fingerprint": "0F4CA4D6F2C4A42C86D923A48CF45B322E7748BF",
          "native_current_boundary": false
        }
      ]
    },
    "current_eligibility": "unknown",
    "executable_sha256": "326817a508a2d0be382e8e44071ec1d5957411a9cb6091764d7a33e9e032ff30",
    "historical_commands_executed": false,
    "identity": {
      "identity": {
        "boundary": {
          "kind": "post-push",
          "step": 2,
          "working_commit_sha": "9ca111552e796783e0cbc9a795995f176c5750d5"
        },
        "evidence": {
          "ledger_entries": 16,
          "ledger_sha256": "4a39dd085805a7ed6468b5c8b005aca58292d03d40d7a376cf7f22a8680c2e2c",
          "ledger_tail": "c9f46f1273ef832fae0b62aedea5592c39c6e4c24ad0e8585b84a4cccc0bd39d",
          "observation_bindings": 2,
          "observation_sha256": "f9dab847d36f364cd013d556c25a8bb5f08566aeedfd0ac9322dcf2090323b2f",
          "observation_status": "bound",
          "policy_sha256": "3f68fdebb6b10ab6448f1e24c7befb17a68324905e5ac48c59c51c1e6b8fc296",
          "run_anchor_sha256": "4d6c10bb09dbb5525ffd3dcecf50162eddb6f9ebf5267e928aac9fb1e63c316f",
          "runbook_sha256": "2feb2caf420c6b68a199f264831129fbf824992766cdbc8d364670e7c0d61427",
          "state_fingerprint": "f3cf026be43e5e79e4a29cf6ffe917e95a0df2e890bf7f7e351a66358d78f646",
          "study_sha256": "f2b65ef8cbc9eb07521220d1eaf235bdbf5209f1cad5f20e227b029fa4551a52"
        },
        "run": {
          "controller": {
            "name": "hexctl",
            "state_version": 1,
            "version": "fiat-v6.61.1"
          },
          "initial_base_sha": "87a8a2963d84bf36432ef6801830a9ffafe55821",
          "integration_branch": "main",
          "repository": "wildcat-finance/example",
          "run_branch": "fiat/test-topic",
          "run_id": "fiat-c3c778f1d02a6fc5f0c484ce29f0bfc2313629fd832ba917c70fa25b00f565d9",
          "schema": "fiat-run-anchor/v1",
          "task": {
            "kind": "none"
          }
        },
        "schema": "fiat-checkpoint-identity/v1"
      },
      "schema": "fiat-checkpoint-identity-result/v1",
      "snapshot_id": "21af06cacb59d1b2958b67db63dbdeac18d68b1987f9f10266c6ed47157f2245"
    },
    "native_results": [
      {
        "attempt_id": "attempt-1-2",
        "duration_ms": 9418,
        "exit": 0,
        "input_sha256": "56e76497927756bdcb1658dae79a4babcb7c0c00c580c306773a189af7bbe95e",
        "log_bytes": 0,
        "log_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "output_bytes": 1102,
        "output_sha256": "28815c434a98a77f5fd8bb870a20d79a18421953a2fb8c037084961b22465053",
        "stage": "inspect"
      },
      {
        "attempt_id": "attempt-1-2",
        "duration_ms": 28757,
        "exit": 0,
        "input_sha256": "56e76497927756bdcb1658dae79a4babcb7c0c00c580c306773a189af7bbe95e",
        "log_bytes": 0,
        "log_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "output_bytes": 1545,
        "output_sha256": "416af618ecd7d4c5703f6e27f0b8df12afe18fdf1d9d3a4a65faa49774dbbdf4",
        "stage": "restore"
      },
      {
        "attempt_id": "attempt-1-2",
        "duration_ms": 20882,
        "exit": 0,
        "input_sha256": "56e76497927756bdcb1658dae79a4babcb7c0c00c580c306773a189af7bbe95e",
        "log_bytes": 0,
        "log_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "output_bytes": 87,
        "output_sha256": "0846d246fa75f93897da436509df4de9101f2fbc605920dd10d12a8b581c93ef",
        "stage": "verify"
      },
      {
        "attempt_id": "attempt-1-2",
        "duration_ms": 22827,
        "exit": 0,
        "input_sha256": "56e76497927756bdcb1658dae79a4babcb7c0c00c580c306773a189af7bbe95e",
        "log_bytes": 0,
        "log_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "output_bytes": 1424,
        "output_sha256": "e5c546d6c8e794aa1ca5bcd02605e7b8fce7a7ccd56886e0b5112eb7d22dfac7",
        "stage": "identity"
      }
    ],
    "next": {
      "branch": "fiat/test-topic-step-3-third",
      "branch_from": "fiat/test-topic-step-2-second",
      "do": "implement",
      "merge_now": false,
      "pr_base": "fiat/test-topic-step-2-second",
      "run_branch": "fiat/test-topic",
      "step": 3,
      "title": "Third"
    },
    "operation_ran": true,
    "profile": "native-1d4e4eeb-openpgp-v1",
    "public_trust_sha256": "53cdca6e6619914a2fecf91e42677897f784a0dd8857a4b2ceb2a36370d59ed5",
    "request": {
      "attempt_id": "attempt-1-2",
      "candidate_id": "c37a9e29a0f9478ca4b8607162a641af",
      "carrier_length": 59603,
      "controller_manifest_sha256": "b437779ea4e4745db9a3bcf3f4f6c3e2a5f937918f0b6c5812914d136516f8b6",
      "lease_id": "lease-2",
      "outer_sha256": "56e76497927756bdcb1658dae79a4babcb7c0c00c580c306773a189af7bbe95e",
      "snapshot_id": "21af06cacb59d1b2958b67db63dbdeac18d68b1987f9f10266c6ed47157f2245"
    },
    "resources": {
      "duration_ms": 103275,
      "input_bytes": 59603,
      "output_bytes": 4158
    },
    "schema": "checkpoint-authority-native-result/v1",
    "service_acceptance": "unavailable",
    "source_commit": "1d4e4eebcba1825d0eb3192bf08a6c509bdc0d74",
    "source_profile_sha256": "dca86cde305bd5b1bce7daf6bfac7b86c71a855504d8733baaa768dd07e1389e",
    "status_sha256": "5fcec3540574c32632841c2a5d813f2eda6ba753ffe8999070d0cd43fada779f",
    "tools": [
      {
        "name": "python",
        "sha256": "30a7def0b3e8d24a36d3829202717542bef124c0a40608b2232b7c837b271bc9"
      },
      {
        "name": "git",
        "sha256": "356db14e102d68a1a37d8a1ac577dfd678d45d46e92f468bef8b7154e7bfdc60"
      },
      {
        "name": "gpg",
        "sha256": "7c9d2f9416aabcd10199e2984439f49612644a948279ac56bdf70d69c8958ddf"
      },
      {
        "name": "gpgconf",
        "sha256": "17ea11378c9d71166df855b73a66333fbf8095cb8da7d3a474bd325e3ca726db"
      }
    ]
  },
  "native_result_sha256": "6fab4053cda200a6a2315f13ed9b410cd573ea27ae4780b13f456c3b66ae2585",
  "parent": {
    "sha256": "5555555555555555555555555555555555555555555555555555555555555555",
    "type": "parent-link"
  },
  "pins": {
    "gvisor": {
      "archive_sha256": "1298e8ed9c3fee900f00d2ea96ec2d79d80ed93f2175812f29b7e7da718041a3",
      "archive_sha512": "7cbc2aeeee809dcccfb40e612504a1b76f2c119790cee59e482f7b35428cccc4f71705e7e322442d07d1f7d29b5d9e72e31319fc3088d6dcbec9fc7c1f0d8881",
      "platform": "systrap",
      "release": "release-20261019.0",
      "runsc_sha256": "5b4016fa43a9d35835253925cb6d05d3e42fdb9eb8bcd426c8b25444090e93e6",
      "runsc_sha512": "1ab7bb68955a028d3a82bac6406ee0f9ac0efaf2d6c49adef1d2448251d2b1131486674c0fe8c2599d680ccd04765f76040d1d8c202f8f9a49ea4c366494f266"
    },
    "native_extra": [
      {
        "path": "scripts/run_observation.py",
        "sha256": "712f2afc40f7703cc64a92cd850559684a28f1b98e3241652a67ac6b48124d40"
      }
    ],
    "tools": [
      {
        "name": "python",
        "path": "/usr/local/bin/python3.14",
        "sha256": "30a7def0b3e8d24a36d3829202717542bef124c0a40608b2232b7c837b271bc9",
        "version": "3.14.6"
      },
      {
        "name": "git",
        "path": "/usr/bin/git",
        "sha256": "356db14e102d68a1a37d8a1ac577dfd678d45d46e92f468bef8b7154e7bfdc60",
        "version": "1:2.47.3-0+deb13u1"
      },
      {
        "name": "gpg",
        "path": "/usr/bin/gpg",
        "sha256": "7c9d2f9416aabcd10199e2984439f49612644a948279ac56bdf70d69c8958ddf",
        "version": "2.4.7-21+deb13u1+b4"
      },
      {
        "name": "gpgconf",
        "path": "/usr/bin/gpgconf",
        "sha256": "17ea11378c9d71166df855b73a66333fbf8095cb8da7d3a474bd325e3ca726db",
        "version": "2.4.7-21+deb13u1+b4"
      },
      {
        "name": "ssh-keygen",
        "path": "/usr/bin/ssh-keygen",
        "sha256": "4a16f170f7c80d6643d3ffada36d396c9d7b1d63238a218628e37af38d6107c0",
        "version": "1:10.0p1-7+deb13u4"
      }
    ]
  },
  "registration_sha256": "3c744ae79152016ab1b21bf71b155fea77f65718e8300b67591ec4b23304cb87",
  "release": {
    "lock_sha256": "2fb8ba52d22c1d66e3bd1f70b4ab4af79ff0666fcc8ac5594dce4cdd3df7f49e",
    "trees_sha256": "43ef8e0ff615f1b7e7d972d1c461f48ba859172fd25515725a5b0f6494061697"
  },
  "resources": {
    "cpu_us": 147564669,
    "memory_peak_bytes": 143495168,
    "oom_kills": 0,
    "pids_peak": 38,
    "wall_ms": 116074
  },
  "schema": "fiat-checkpoints-validation-evidence/v1",
  "started_at": "2026-09-30T12:00:00+00:00",
  "trust": {
    "approval_sha256": "2289020fa98a98ec75012913ef34ad1b66a3b2e3bdf287529be87b2efd242403",
    "historical_signers": [
      {
        "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "type": "key-enrollment"
      }
    ],
    "public_trust_sha256": "53cdca6e6619914a2fecf91e42677897f784a0dd8857a4b2ceb2a36370d59ed5"
  },
  "trust_head": {
    "count": 11,
    "tail": "3c744ae79152016ab1b21bf71b155fea77f65718e8300b67591ec4b23304cb87"
  },
  "validation_attempt": 1
}
```

## Stable refusals

### HTTP refusals

Every refusal body is `{"request_id", "code"}`, plus `retry_after_seconds` and
a `Retry-After` header for 429 and 503, plus `protocol_code` only when the
pinned library produced one for a code marked "yes".

| Code | HTTP | Retry-After | Protocol code | Client action |
| --- | --- | --- | --- | --- |
| `auth_required` | 401 | none | no | Log in again; never replay another actor's credential |
| `not_found` | 404 | none | no | Nothing is said about whether the run or candidate exists |
| `request_invalid` | 400 | none | no | Correct the request |
| `protocol_unsupported` | 422 | none | no | Correct the request; no schema downgrade |
| `identity_mismatch` | 422 | none | yes | New valid evidence is required |
| `endorsement_invalid` | 422 | none | yes | Sign a new endorsement for the current challenge |
| `signer_not_enrolled` | 422 | none | yes | The operator must enroll the key |
| `protocol_refused` | 422 | none | yes | Fix the named contract failure |
| `length_required` | 411 | none | no | Send one exact `Content-Length` |
| `upload_too_large` | 413 | none | no | The carrier is over the ceiling |
| `upload_integrity` | 422 | none | no | Send the exact declared bytes; nothing partial is kept |
| `quota_exceeded` | 429 | 60 | no | Retry after the wait |
| `idempotency_conflict` | 409 | none | no | Query the existing operation |
| `upload_in_progress` | 409 | none | no | Wait for the open attempt |
| `candidate_expired` | 410 | none | no | Announce again |
| `checkpoint_ineligible` | 409 | none | no | Do not resume |
| `policy_unavailable` | 503 | 30 | no | Retry the same operation after the wait |
| `validation_failed` | 503 | 30 | no | Retry the same operation after the wait |
| `authority_unavailable` | 503 | 30 | no | Retry the same operation after the wait |
| `storage_unavailable` | 503 | 30 | no | Retry the same operation after the wait |
| `capability_not_enabled` | 501 | none | no | The capability is not built; infer nothing from it |

### Validation outcomes

A validation outcome reaches the contributor as the `code` of
`GET /v1/candidates/{id}`. A rejected candidate shows its code and stops. A
retried one keeps its phase and shows no code but `retry_after_seconds: 30`;
`validation_failed` is held for an operator after the attempt limit.

| Code | Candidate | When |
| --- | --- | --- |
| `protocol_refused` | rejected | A native stage refused with a class the release lists for it; `protocol_code` names it |
| `identity_mismatch` | rejected | The archive is not the announced one, or the reminted identity differs |
| `signer_not_enrolled` | rejected | A commit signer is outside the approved keys |
| `endorsement_invalid` | rejected | The uploader's grant is no longer current |
| `checkpoint_ineligible` | rejected | The run has no registration, or the reminted anchor is not the registered one |
| `capability_not_enabled` | rejected | A parent other than a registered root |
| `validation_failed` | retried | A tool failure, malformed output or a resource ceiling; not evidence the archive is hostile |
| `sandbox_unavailable` | retried | The pinned gVisor runtime, root filesystem or cgroups are unusable; no job is claimed |
| `policy_unavailable` | retried | The trust projection is unavailable or its head moved during the job |
| `storage_unavailable` | retried | The sealed input could not be read |
| `authority_unavailable` | retried | The candidate's binding or sealed bytes changed under it |

Startup refusals are operator codes, not contributor codes;
[`config/README.md`](../config/README.md) lists them. Every production start
refuses with at least `isolation-unavailable` and `scaffold-only`.

## Carried forward

| Item | Owner |
| --- | --- |
| Verifying the signed parent-link record and the external freshness head; intents record both as unverified (S6-R1-01) | [issue #2](https://github.com/wildcat-finance/fiat-checkpoints/issues/2) |
| The reservation an intent holds until acceptance or denial (S3-R2-02) | [issue #2](https://github.com/wildcat-finance/fiat-checkpoints/issues/2) |
| The GitHub App login adapter and `POST /internal/v1/authority-records`, neither built | A fiat-checkpoints issue filed at integration |
| Live R2 adapter timeouts | [Skills #863](https://github.com/wildcat-finance/skills/issues/863) |
| The 100,000-node ceiling, not enforced: gVisor's tmpfs ignores `nr_inodes`, so nodes are bounded only by memory | This service |
| Scratch measured apart from memory: tmpfs pages are sandbox memory | This service |
| `scripts/run_observation.py`, omitted from the released native profile and added by the validator image | [Skills #2161](https://github.com/wildcat-finance/skills/issues/2161) |
| The start commit, which comes from operator configuration because the released run registration has no field for it | This service |

[Skills #863](https://github.com/wildcat-finance/skills/issues/863) still owns
the production proof: the external signer and its journal, keys, buckets,
accounts and credentials, the live identity provider, deployment evidence,
provider throughput and cost. Until it passes, production startup refuses and
no intent can become an accepted checkpoint.
