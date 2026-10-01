-- Upload capabilities, stream starts and quarantine objects for bounded
-- transfer. A capability is kept only as its SHA-256. It names one attempt,
-- the exact declared size and carrier digest, the endorsement it was issued
-- from and its environment. A sealed attempt and its quarantine object never
-- change, and an attempt a capability names seals only beside a quarantine
-- object sealed with the same size and digest.
-- Lifetimes and custody: adr/seal-uploads-in-bounded-quarantine.

ALTER TABLE upload_attempts ADD COLUMN stream_started_at timestamptz;
ALTER TABLE upload_attempts ADD CONSTRAINT upload_attempts_stream_started
    CHECK (stream_started_at IS NULL OR stream_started_at >= created_at);

CREATE TABLE upload_capabilities (
    candidate_id uuid NOT NULL,
    attempt_number integer NOT NULL,
    capability_sha256 text NOT NULL UNIQUE CHECK (capability_sha256 ~ '^[0-9a-f]{64}$'),
    actor_id bigint NOT NULL REFERENCES actors,
    environment text NOT NULL CHECK (environment ~ '^[a-z][a-z0-9-]{0,63}$'),
    endorsement_sequence integer NOT NULL,
    endorsement_sha256 text NOT NULL CHECK (endorsement_sha256 ~ '^[0-9a-f]{64}$'),
    declared_size bigint NOT NULL CHECK (declared_size BETWEEN 1 AND 1073741824),
    archive_sha256 text NOT NULL CHECK (archive_sha256 ~ '^[0-9a-f]{64}$'),
    issued_at timestamptz NOT NULL,
    start_expires_at timestamptz NOT NULL
        CHECK (start_expires_at > issued_at AND start_expires_at <= issued_at + interval '15 minutes'),
    issues integer NOT NULL CHECK (issues BETWEEN 1 AND 1024),
    PRIMARY KEY (candidate_id, attempt_number),
    FOREIGN KEY (candidate_id, attempt_number) REFERENCES upload_attempts,
    FOREIGN KEY (candidate_id, endorsement_sequence) REFERENCES upload_endorsements
);

CREATE TABLE quarantine_objects (
    object_key text PRIMARY KEY
        CHECK (object_key ~ '^quarantine/[0-9a-f]{32}/[0-9]{2}-[0-9a-f]{32}$'),
    candidate_id uuid NOT NULL,
    attempt_number integer NOT NULL,
    state text NOT NULL CHECK (state IN ('writing', 'sealed', 'held', 'deleting', 'deleted')),
    sealed_size bigint CHECK (sealed_size BETWEEN 1 AND 1073741824),
    sealed_sha256 text CHECK (sealed_sha256 ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL CHECK (updated_at >= created_at),
    UNIQUE (candidate_id, attempt_number),
    FOREIGN KEY (candidate_id, attempt_number) REFERENCES upload_attempts,
    CHECK ((sealed_size IS NULL) = (sealed_sha256 IS NULL)),
    CHECK (state <> 'sealed' OR sealed_size IS NOT NULL)
);

CREATE INDEX quarantine_objects_live ON quarantine_objects (created_at) WHERE state <> 'deleted';

-- A capability is renewed only while its attempt is open and no stream has
-- started; what it binds never changes.
CREATE FUNCTION refuse_capability_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.candidate_id <> OLD.candidate_id OR NEW.attempt_number <> OLD.attempt_number
       OR NEW.actor_id <> OLD.actor_id OR NEW.environment <> OLD.environment
       OR NEW.declared_size <> OLD.declared_size OR NEW.archive_sha256 <> OLD.archive_sha256
       OR NEW.issues <> OLD.issues + 1 THEN
        RAISE EXCEPTION 'capability-binding-immutable' USING ERRCODE = 'check_violation';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM upload_attempts WHERE candidate_id = NEW.candidate_id
        AND attempt_number = NEW.attempt_number AND state = 'open' AND stream_started_at IS NULL
    ) THEN
        RAISE EXCEPTION 'capability-renewal-refused' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER upload_capabilities_renewal BEFORE UPDATE ON upload_capabilities
    FOR EACH ROW EXECUTE FUNCTION refuse_capability_change();

-- Writing, then sealed, held or deleting; sealed or held, then deleting;
-- deleting, then deleted. A held object failed its read-back and stays as
-- evidence until an operator releases it. The key, its attempt and a sealed
-- size and digest never change.
CREATE FUNCTION refuse_quarantine_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'quarantine-record-immutable' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.object_key <> OLD.object_key OR NEW.candidate_id <> OLD.candidate_id
       OR NEW.attempt_number <> OLD.attempt_number OR NEW.created_at <> OLD.created_at
       OR (OLD.sealed_size IS NOT NULL AND (NEW.sealed_size IS DISTINCT FROM OLD.sealed_size
           OR NEW.sealed_sha256 IS DISTINCT FROM OLD.sealed_sha256)) THEN
        RAISE EXCEPTION 'quarantine-binding-immutable' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state <> OLD.state AND NOT (
        (OLD.state = 'writing' AND NEW.state IN ('sealed', 'held', 'deleting'))
        OR (OLD.state IN ('sealed', 'held') AND NEW.state = 'deleting')
        OR (OLD.state = 'deleting' AND NEW.state = 'deleted')
    ) THEN
        RAISE EXCEPTION 'quarantine-transition-illegal' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER quarantine_objects_transition BEFORE UPDATE OR DELETE ON quarantine_objects
    FOR EACH ROW EXECUTE FUNCTION refuse_quarantine_change();
CREATE TRIGGER quarantine_objects_no_truncate BEFORE TRUNCATE ON quarantine_objects
    FOR EACH STATEMENT EXECUTE FUNCTION refuse_rewrite();

-- A sealed attempt never changes. An attempt a capability names seals only
-- beside its quarantine object, already sealed with the same size and digest.
CREATE FUNCTION refuse_unread_seal() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.state = 'sealed' THEN
            RAISE EXCEPTION 'attempt-sealed-immutable' USING ERRCODE = 'check_violation';
        END IF;
        RETURN OLD;
    END IF;
    IF OLD.state = 'sealed' THEN
        RAISE EXCEPTION 'attempt-sealed-immutable' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state = 'sealed' AND EXISTS (
        SELECT 1 FROM upload_capabilities WHERE candidate_id = NEW.candidate_id
        AND attempt_number = NEW.attempt_number
    ) AND NOT EXISTS (
        SELECT 1 FROM quarantine_objects WHERE candidate_id = NEW.candidate_id
        AND attempt_number = NEW.attempt_number AND state = 'sealed'
        AND sealed_size = NEW.sealed_size AND sealed_sha256 = NEW.sealed_sha256
    ) THEN
        RAISE EXCEPTION 'attempt-seal-unread' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER upload_attempts_sealed BEFORE UPDATE OR DELETE ON upload_attempts
    FOR EACH ROW EXECUTE FUNCTION refuse_unread_seal();
