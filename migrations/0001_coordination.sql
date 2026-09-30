-- Coordination tables for candidates, reservations, fenced attempts, immutable
-- publication intents and the transactional outbox. PostgreSQL indexes and
-- coordinates work; it never holds accepted truth (specification section 11).
-- Layout and scope: adr/coordinate-intake-with-fenced-leases.

CREATE TABLE actors (
    actor_id bigint PRIMARY KEY CHECK (actor_id > 0),
    first_seen_at timestamptz NOT NULL
);

CREATE TABLE run_registrations (
    run_key bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    service_id text NOT NULL CHECK (service_id ~ '^[a-z][a-z0-9-]{0,63}$'),
    repository_id bigint NOT NULL CHECK (repository_id > 0),
    run_id text NOT NULL CHECK (run_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    registered_at timestamptz NOT NULL,
    UNIQUE (service_id, repository_id, run_id)
);

-- The closed table of fiat_checkpoints.domain.transitions, repeated so that no
-- SQL statement can move a candidate along a pair the table lacks.
CREATE TABLE candidate_transitions (
    source text NOT NULL,
    target text NOT NULL,
    PRIMARY KEY (source, target)
);

INSERT INTO candidate_transitions (source, target) VALUES
    ('accepted', 'revoked'),
    ('announced', 'expired'),
    ('announced', 'rejected'),
    ('announced', 'uploading'),
    ('awaiting_replica', 'awaiting_signature'),
    ('awaiting_replica', 'expired'),
    ('awaiting_replica', 'rejected'),
    ('awaiting_signature', 'expired'),
    ('awaiting_signature', 'publishing_receipt'),
    ('awaiting_signature', 'rejected'),
    ('finalizing', 'denied'),
    ('finalizing', 'publishing_finalization'),
    ('publishing', 'awaiting_replica'),
    ('publishing', 'expired'),
    ('publishing', 'rejected'),
    ('publishing_finalization', 'accepted'),
    ('publishing_finalization', 'denied'),
    ('publishing_receipt', 'denied'),
    ('publishing_receipt', 'finalizing'),
    ('quarantined', 'expired'),
    ('quarantined', 'rejected'),
    ('quarantined', 'validating'),
    ('uploading', 'expired'),
    ('uploading', 'quarantined'),
    ('uploading', 'rejected'),
    ('validating', 'expired'),
    ('validating', 'publishing'),
    ('validating', 'rejected');

CREATE TABLE candidates (
    candidate_id uuid PRIMARY KEY,
    run_key bigint NOT NULL REFERENCES run_registrations,
    actor_id bigint NOT NULL REFERENCES actors,
    state text NOT NULL CHECK (state IN (
        'announced', 'uploading', 'quarantined', 'validating', 'publishing',
        'awaiting_replica', 'awaiting_signature', 'publishing_receipt', 'finalizing',
        'publishing_finalization', 'accepted', 'rejected', 'expired', 'revoked', 'denied')),
    version bigint NOT NULL CHECK (version > 0),
    fence bigint NOT NULL CHECK (fence >= 0),
    archive_sha256 text NOT NULL CHECK (archive_sha256 ~ '^[0-9a-f]{64}$'),
    declared_size bigint NOT NULL CHECK (declared_size BETWEEN 1 AND 1073741824),
    sealed_attempt integer CHECK (sealed_attempt BETWEEN 1 AND 16),
    retry_reason text CHECK (retry_reason ~ '^[a-z][a-z0-9_]{0,63}$'),
    terminal_code text CHECK (terminal_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    announced_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > announced_at),
    updated_at timestamptz NOT NULL
);

-- No uniqueness on archive_sha256: unrelated runs must not learn of each other.
CREATE INDEX candidates_scope ON candidates (run_key, actor_id);
CREATE INDEX candidates_expiry ON candidates (expires_at)
    WHERE state IN ('announced', 'uploading', 'quarantined', 'validating');

CREATE FUNCTION refuse_illegal_transition() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'announced' OR NEW.version <> 1 OR NEW.fence <> 0 THEN
            RAISE EXCEPTION 'candidate-insert-refused' USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.candidate_id <> OLD.candidate_id OR NEW.run_key <> OLD.run_key
       OR NEW.actor_id <> OLD.actor_id OR NEW.archive_sha256 <> OLD.archive_sha256
       OR NEW.declared_size <> OLD.declared_size OR NEW.announced_at <> OLD.announced_at
       OR NEW.expires_at <> OLD.expires_at THEN
        RAISE EXCEPTION 'candidate-binding-immutable' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.version <> OLD.version + 1 OR NEW.fence < OLD.fence THEN
        RAISE EXCEPTION 'candidate-version-refused' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state <> OLD.state AND NOT EXISTS (
        SELECT 1 FROM candidate_transitions WHERE source = OLD.state AND target = NEW.state
    ) THEN
        RAISE EXCEPTION 'transition-illegal' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER candidates_transition BEFORE INSERT OR UPDATE ON candidates
    FOR EACH ROW EXECUTE FUNCTION refuse_illegal_transition();

CREATE TABLE idempotency_keys (
    actor_id bigint NOT NULL REFERENCES actors,
    operation text NOT NULL CHECK (operation IN ('announce')),
    idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[!-~]{16,128}$'),
    fingerprint text NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    candidate_id uuid NOT NULL REFERENCES candidates DEFERRABLE INITIALLY DEFERRED,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > created_at),
    PRIMARY KEY (actor_id, operation, idempotency_key)
);

-- One row per scope; a conditional UPDATE against each ceiling is the admission.
CREATE TABLE quota_usage (
    scope_kind text NOT NULL CHECK (scope_kind IN ('global', 'run', 'actor')),
    scope_key bigint NOT NULL CHECK (scope_key >= 0),
    candidates integer NOT NULL DEFAULT 0 CHECK (candidates >= 0),
    reserved_bytes bigint NOT NULL DEFAULT 0 CHECK (reserved_bytes >= 0),
    streams integer NOT NULL DEFAULT 0 CHECK (streams >= 0),
    PRIMARY KEY (scope_kind, scope_key),
    CHECK ((scope_kind = 'global') = (scope_key = 0))
);

INSERT INTO quota_usage (scope_kind, scope_key) VALUES ('global', 0);

CREATE TABLE upload_attempts (
    candidate_id uuid NOT NULL REFERENCES candidates,
    attempt_number integer NOT NULL CHECK (attempt_number BETWEEN 1 AND 16),
    fence bigint NOT NULL CHECK (fence > 0),
    state text NOT NULL CHECK (state IN ('open', 'sealed', 'abandoned', 'failed')),
    lease_expires_at timestamptz NOT NULL,
    sealed_size bigint CHECK (sealed_size BETWEEN 1 AND 1073741824),
    sealed_sha256 text CHECK (sealed_sha256 ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (candidate_id, attempt_number),
    CHECK ((state = 'sealed') = (sealed_size IS NOT NULL AND sealed_sha256 IS NOT NULL))
);

CREATE UNIQUE INDEX upload_attempts_one_open ON upload_attempts (candidate_id) WHERE state = 'open';

CREATE TABLE reservations (
    reservation_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    candidate_id uuid NOT NULL REFERENCES candidates,
    kind text NOT NULL CHECK (kind IN ('candidate', 'stream')),
    attempt_number integer,
    reserved_bytes bigint NOT NULL CHECK (reserved_bytes >= 0),
    created_at timestamptz NOT NULL,
    released_at timestamptz,
    CHECK ((kind = 'stream') = (attempt_number IS NOT NULL)),
    CHECK (released_at IS NULL OR released_at >= created_at)
);

CREATE UNIQUE INDEX reservations_one_candidate ON reservations (candidate_id) WHERE kind = 'candidate';
CREATE UNIQUE INDEX reservations_one_stream ON reservations (candidate_id, attempt_number)
    WHERE kind = 'stream';

CREATE TABLE outbox_jobs (
    job_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind text NOT NULL CHECK (kind IN ('validate-candidate', 'publish-intent')),
    candidate_id uuid NOT NULL REFERENCES candidates,
    state text NOT NULL CHECK (state IN ('pending', 'leased', 'done', 'held', 'cancelled')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 100000),
    available_at timestamptz NOT NULL,
    lease_fence bigint CHECK (lease_fence > 0),
    lease_expires_at timestamptz,
    retry_reason text CHECK (retry_reason ~ '^[a-z][a-z0-9_]{0,63}$'),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK ((state = 'leased') = (lease_expires_at IS NOT NULL))
);

CREATE UNIQUE INDEX outbox_jobs_one_live ON outbox_jobs (kind, candidate_id)
    WHERE state IN ('pending', 'leased', 'held');
CREATE INDEX outbox_jobs_ready ON outbox_jobs (kind, available_at) WHERE state = 'pending';
CREATE INDEX outbox_jobs_lease ON outbox_jobs (kind, lease_expires_at) WHERE state = 'leased';

CREATE TABLE validation_attempts (
    candidate_id uuid NOT NULL REFERENCES candidates,
    attempt_number integer NOT NULL CHECK (attempt_number BETWEEN 1 AND 4096),
    fence bigint NOT NULL CHECK (fence > 0),
    job_id bigint NOT NULL REFERENCES outbox_jobs,
    input_attempt integer NOT NULL,
    state text NOT NULL CHECK (state IN ('running', 'passed', 'refused', 'retry', 'abandoned')),
    lease_expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (candidate_id, attempt_number),
    FOREIGN KEY (candidate_id, input_attempt) REFERENCES upload_attempts
);

CREATE UNIQUE INDEX validation_attempts_one_running ON validation_attempts (candidate_id)
    WHERE state = 'running';

-- Immutable hand-off to publication. It grants no accepted status.
CREATE TABLE publication_intents (
    intent_id uuid PRIMARY KEY,
    candidate_id uuid NOT NULL UNIQUE REFERENCES candidates,
    validation_attempt integer NOT NULL,
    fence bigint NOT NULL CHECK (fence > 0),
    archive_sha256 text NOT NULL CHECK (archive_sha256 ~ '^[0-9a-f]{64}$'),
    snapshot_id text NOT NULL CHECK (snapshot_id ~ '^[0-9a-f]{64}$'),
    controller_manifest_sha256 text NOT NULL CHECK (controller_manifest_sha256 ~ '^[0-9a-f]{64}$'),
    evidence bytea NOT NULL CHECK (octet_length(evidence) BETWEEN 1 AND 65536),
    evidence_sha256 text NOT NULL CHECK (evidence_sha256 ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL,
    FOREIGN KEY (candidate_id, validation_attempt) REFERENCES validation_attempts
);

CREATE TABLE audit_events (
    event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    candidate_id uuid REFERENCES candidates,
    event text NOT NULL CHECK (event ~ '^[a-z][a-z0-9-]{0,63}$'),
    from_state text,
    to_state text,
    fence bigint,
    code text CHECK (code ~ '^[a-z][a-z0-9_]{0,63}$'),
    created_at timestamptz NOT NULL
);

CREATE FUNCTION refuse_rewrite() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'record-immutable' USING ERRCODE = 'check_violation';
END;
$$;

CREATE TRIGGER publication_intents_immutable BEFORE UPDATE OR DELETE ON publication_intents
    FOR EACH ROW EXECUTE FUNCTION refuse_rewrite();
CREATE TRIGGER publication_intents_no_truncate BEFORE TRUNCATE ON publication_intents
    FOR EACH STATEMENT EXECUTE FUNCTION refuse_rewrite();
CREATE TRIGGER audit_events_immutable BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION refuse_rewrite();
CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION refuse_rewrite();
