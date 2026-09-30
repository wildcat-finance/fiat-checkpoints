-- Login state, sessions, access tokens, each run's operator-signed trust
-- records, contributor proofs of possession, endorsement challenges and
-- verified upload endorsements. A secret is kept only as its SHA-256. Trust
-- records keep their exact envelope bytes and are verified again through the
-- released library before any use, so no row here is authority by itself.
-- Custody and lifetimes: adr/bind-uploads-to-enrolled-keys.

CREATE TABLE login_states (
    state_sha256 text PRIMARY KEY CHECK (state_sha256 ~ '^[0-9a-f]{64}$'),
    binding_sha256 text NOT NULL CHECK (binding_sha256 ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
        CHECK (expires_at > created_at AND expires_at <= created_at + interval '5 minutes'),
    consumed_at timestamptz CHECK (consumed_at IS NULL OR consumed_at >= created_at)
);

CREATE INDEX login_states_live ON login_states (expires_at) WHERE consumed_at IS NULL;

CREATE TABLE sessions (
    session_id uuid PRIMARY KEY,
    secret_sha256 text NOT NULL UNIQUE CHECK (secret_sha256 ~ '^[0-9a-f]{64}$'),
    actor_id bigint NOT NULL REFERENCES actors,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
        CHECK (expires_at > created_at AND expires_at <= created_at + interval '8 hours'),
    revoked_at timestamptz CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE INDEX sessions_live ON sessions (actor_id, created_at) WHERE revoked_at IS NULL;

CREATE TABLE access_tokens (
    token_sha256 text PRIMARY KEY CHECK (token_sha256 ~ '^[0-9a-f]{64}$'),
    session_id uuid NOT NULL REFERENCES sessions ON DELETE CASCADE,
    audience text NOT NULL CHECK (audience ~ '^[a-z][a-z0-9-]{0,63}$'),
    environment text NOT NULL CHECK (environment ~ '^[a-z][a-z0-9-]{0,63}$'),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
        CHECK (expires_at > created_at AND expires_at <= created_at + interval '15 minutes'),
    revoked_at timestamptz CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE INDEX access_tokens_live ON access_tokens (session_id, created_at) WHERE revoked_at IS NULL;

-- One run's trust prefix in journal order. The sequence and predecessor are
-- the signed record's own; the library refuses any other order.
CREATE TABLE trust_records (
    run_key bigint NOT NULL REFERENCES run_registrations,
    sequence integer NOT NULL CHECK (sequence BETWEEN 1 AND 256),
    record_type text NOT NULL CHECK (record_type IN (
        'authority-policy', 'enrollment-challenge', 'key-enrollment', 'key-rotation',
        'key-revocation', 'run-grant', 'run-registration')),
    envelope bytea NOT NULL CHECK (octet_length(envelope) BETWEEN 1 AND 65536),
    envelope_sha256 text NOT NULL CHECK (envelope_sha256 ~ '^[0-9a-f]{64}$'),
    ingested_at timestamptz NOT NULL,
    PRIMARY KEY (run_key, sequence),
    UNIQUE (run_key, envelope_sha256)
);

CREATE TABLE enrollment_proofs (
    run_key bigint NOT NULL REFERENCES run_registrations,
    challenge_sha256 text NOT NULL CHECK (challenge_sha256 ~ '^[0-9a-f]{64}$'),
    actor_id bigint NOT NULL REFERENCES actors,
    signature text NOT NULL
        CHECK (octet_length(signature) BETWEEN 1 AND 21848 AND signature ~ '^[A-Za-z0-9+/_-]+={0,2}$'),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (run_key, challenge_sha256)
);

-- What announce bound beside the candidate row: the other two identities, the
-- parent link and the nonce the endorsement must carry.
CREATE TABLE endorsement_challenges (
    candidate_id uuid PRIMARY KEY REFERENCES candidates,
    nonce text NOT NULL UNIQUE CHECK (nonce ~ '^[0-9a-f]{64}$'),
    snapshot_id text NOT NULL CHECK (snapshot_id ~ '^[0-9a-f]{64}$'),
    controller_manifest_sha256 text NOT NULL CHECK (controller_manifest_sha256 ~ '^[0-9a-f]{64}$'),
    parent_sha256 text NOT NULL CHECK (parent_sha256 ~ '^[0-9a-f]{64}$'),
    issued_at timestamptz NOT NULL
);

CREATE TABLE upload_endorsements (
    candidate_id uuid PRIMARY KEY REFERENCES endorsement_challenges,
    envelope bytea NOT NULL CHECK (octet_length(envelope) BETWEEN 1 AND 65536),
    envelope_sha256 text NOT NULL UNIQUE CHECK (envelope_sha256 ~ '^[0-9a-f]{64}$'),
    policy_sha256 text NOT NULL CHECK (policy_sha256 ~ '^[0-9a-f]{64}$'),
    enrollment_sha256 text NOT NULL CHECK (enrollment_sha256 ~ '^[0-9a-f]{64}$'),
    grant_sha256 text NOT NULL CHECK (grant_sha256 ~ '^[0-9a-f]{64}$'),
    key_fingerprint text NOT NULL CHECK (key_fingerprint ~ '^[A-Za-z0-9:+/]{40,71}$'),
    trust_count integer NOT NULL CHECK (trust_count BETWEEN 1 AND 256),
    trust_tail_sha256 text NOT NULL CHECK (trust_tail_sha256 ~ '^[0-9a-f]{64}$'),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
        CHECK (expires_at > issued_at AND expires_at <= issued_at + interval '5 minutes'),
    verified_at timestamptz NOT NULL CHECK (verified_at >= issued_at AND verified_at < expires_at)
);

CREATE TRIGGER trust_records_immutable BEFORE UPDATE OR DELETE ON trust_records
    FOR EACH ROW EXECUTE FUNCTION refuse_rewrite();
CREATE TRIGGER trust_records_no_truncate BEFORE TRUNCATE ON trust_records
    FOR EACH STATEMENT EXECUTE FUNCTION refuse_rewrite();
CREATE TRIGGER endorsement_challenges_immutable BEFORE UPDATE OR DELETE ON endorsement_challenges
    FOR EACH ROW EXECUTE FUNCTION refuse_rewrite();
CREATE TRIGGER endorsement_challenges_no_truncate BEFORE TRUNCATE ON endorsement_challenges
    FOR EACH STATEMENT EXECUTE FUNCTION refuse_rewrite();
CREATE TRIGGER upload_endorsements_immutable BEFORE UPDATE OR DELETE ON upload_endorsements
    FOR EACH ROW EXECUTE FUNCTION refuse_rewrite();
CREATE TRIGGER upload_endorsements_no_truncate BEFORE TRUNCATE ON upload_endorsements
    FOR EACH STATEMENT EXECUTE FUNCTION refuse_rewrite();
CREATE TRIGGER enrollment_proofs_immutable BEFORE UPDATE OR DELETE ON enrollment_proofs
    FOR EACH ROW EXECUTE FUNCTION refuse_rewrite();
CREATE TRIGGER enrollment_proofs_no_truncate BEFORE TRUNCATE ON enrollment_proofs
    FOR EACH STATEMENT EXECUTE FUNCTION refuse_rewrite();
