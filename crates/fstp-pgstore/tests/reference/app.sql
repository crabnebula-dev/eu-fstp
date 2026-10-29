-- Reference application schema for the fstp-pgstore schema tests.
--
-- Written by the W2e test author from M3 design sections 4.1, 4.2 and 7.1
-- and ADR-007, independently of the production migrations. It lets the
-- harness, the predicates and their teeth run before lane W2e lands
-- fstp_pgstore::MIGRATIONS. It never ships.
--
-- Readings of the reference, where the design text leaves a choice:
-- - The cell id of the genesis link is read from the database name
--   c_<hex>, so the trigger needs no grant on fstp_meta.
-- - apply_grant also grants USAGE on the table's schema, since the
--   design's grammar has no schema grant and a table grant alone cannot
--   be used without it.

CREATE SCHEMA fstp_meta;

CREATE TABLE fstp_meta.placement (
  cell_id    bytea    NOT NULL CHECK (octet_length(cell_id) = 16),
  cluster_id bytea    NOT NULL CHECK (octet_length(cluster_id) = 16),
  kind       smallint NOT NULL CHECK (kind = 1)
);

CREATE FUNCTION fstp_meta.refuse_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'append-only' USING ERRCODE = '42501';
END $$;

CREATE FUNCTION fstp_meta.apply_grant(privs text, object text, suffix text) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
  cell text := current_setting('fstp.cell');
  grantee text;
BEGIN
  IF cell !~ '^[0-9a-f]{32}$' THEN RAISE EXCEPTION 'bad cell id'; END IF;
  IF privs !~ '^(SELECT|INSERT|UPDATE|DELETE)(, (SELECT|INSERT|UPDATE|DELETE))*$' THEN RAISE EXCEPTION 'bad privileges'; END IF;
  IF object !~ '^[a-z_]{1,30}\.[a-z_]{1,30}$' THEN RAISE EXCEPTION 'bad object'; END IF;
  IF suffix !~ '^(migrator|writer|app|keys|auditor|vault)$' THEN RAISE EXCEPTION 'bad role'; END IF;
  grantee := left(current_database(), 1) || '_' || cell || '_' || suffix;
  EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I', split_part(object, '.', 1), grantee);
  EXECUTE format('GRANT %s ON %I.%I TO %I', privs, split_part(object, '.', 1), split_part(object, '.', 2), grantee);
END $$;

CREATE SCHEMA ledger;

CREATE TABLE ledger.command (
  command   bytea  PRIMARY KEY CHECK (octet_length(command) = 16),
  first_seq bigint NOT NULL,
  last_seq  bigint NOT NULL,
  at        bigint NOT NULL
);

CREATE TABLE ledger.entry (
  seq     bigint   PRIMARY KEY CHECK (seq >= 1),
  at      bigint   NOT NULL,
  command bytea    NOT NULL REFERENCES ledger.command,
  schema  smallint NOT NULL CHECK (schema >= 1),
  key_ix  integer  NOT NULL,
  body    bytea    NOT NULL
);

CREATE TRIGGER entry_no_update BEFORE UPDATE OR DELETE ON ledger.entry
  FOR EACH ROW EXECUTE FUNCTION fstp_meta.refuse_mutation();
CREATE TRIGGER entry_no_truncate BEFORE TRUNCATE ON ledger.entry
  FOR EACH STATEMENT EXECUTE FUNCTION fstp_meta.refuse_mutation();

CREATE SCHEMA audit;

CREATE TABLE audit.chain (
  n           bigint   PRIMARY KEY CHECK (n >= 1),
  at          bigint   NOT NULL,
  kind        smallint NOT NULL,
  ledger_seq  bigint   UNIQUE REFERENCES ledger.entry(seq),
  stored_hash bytea    NOT NULL CHECK (octet_length(stored_hash) = 32),
  body        bytea,
  link        bytea    NOT NULL CHECK (octet_length(link) = 32),
  CHECK ((kind = 1 AND ledger_seq IS NOT NULL AND body IS NULL)
      OR (kind = 2 AND ledger_seq IS NULL AND body IS NOT NULL))
);

CREATE FUNCTION audit.check_link() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  cell bytea := decode(substr(current_database(), 3), 'hex');
  prev bytea;
  payload bytea;
  sh bytea;
  e ledger.entry%ROWTYPE;
BEGIN
  IF NEW.n = 1 THEN
    prev := sha256(convert_to('fstp-audit-genesis-v1', 'UTF8') || cell || '\x01'::bytea);
  ELSE
    SELECT link INTO prev FROM audit.chain WHERE n = NEW.n - 1;
    IF NOT FOUND THEN RAISE EXCEPTION 'chain gap' USING ERRCODE = '23514'; END IF;
  END IF;
  IF NEW.kind = 1 THEN
    SELECT * INTO e FROM ledger.entry WHERE seq = NEW.ledger_seq;
    IF NOT FOUND THEN RAISE EXCEPTION 'no ledger entry' USING ERRCODE = '23514'; END IF;
    payload := int8send(NEW.ledger_seq) || int8send(e.at) || e.command || int2send(e.schema)
      || int4send(e.key_ix) || int4send(octet_length(e.body)) || e.body;
  ELSE
    payload := int4send(octet_length(NEW.body)) || NEW.body;
  END IF;
  sh := sha256(convert_to('fstp-audit-row-v1', 'UTF8') || int2send(NEW.kind) || int8send(NEW.at) || payload);
  IF sh <> NEW.stored_hash THEN RAISE EXCEPTION 'stored hash mismatch' USING ERRCODE = '23514'; END IF;
  IF sha256(convert_to('fstp-audit-v1', 'UTF8') || cell || '\x01'::bytea || int8send(NEW.n) || prev || sh) <> NEW.link THEN
    RAISE EXCEPTION 'link mismatch' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER chain_link_check BEFORE INSERT ON audit.chain
  FOR EACH ROW EXECUTE FUNCTION audit.check_link();
CREATE TRIGGER chain_no_update BEFORE UPDATE OR DELETE ON audit.chain
  FOR EACH ROW EXECUTE FUNCTION fstp_meta.refuse_mutation();
CREATE TRIGGER chain_no_truncate BEFORE TRUNCATE ON audit.chain
  FOR EACH STATEMENT EXECUTE FUNCTION fstp_meta.refuse_mutation();

CREATE TABLE audit.anchor (
  n           bigint PRIMARY KEY REFERENCES audit.chain(n),
  link        bytea  NOT NULL,
  at          bigint NOT NULL,
  signature   bytea  NOT NULL,
  witness_seq bigint NOT NULL,
  receipt     bytea  NOT NULL
);

CREATE SCHEMA blob;

CREATE TABLE blob.text (
  id       uuid  PRIMARY KEY,
  dek      uuid  NOT NULL UNIQUE,
  envelope bytea NOT NULL
);

CREATE SCHEMA keystore;

CREATE TABLE keystore.root (
  chain smallint, epoch bigint, backend smallint NOT NULL, handle bytea NOT NULL,
  wrapped_seal_key bytea NOT NULL, state smallint NOT NULL, created_at bigint NOT NULL,
  destroyed_at bigint, receipt bytea, PRIMARY KEY (chain, epoch)
);
CREATE TABLE keystore.group_key (
  chain smallint, purpose smallint, group_id uuid, generation integer,
  public_key bytea NOT NULL, sealed_secret bytea NOT NULL, epoch bigint NOT NULL, state smallint NOT NULL,
  PRIMARY KEY (group_id, generation)
);
CREATE TABLE keystore.data_key (
  id uuid PRIMARY KEY, group_id uuid NOT NULL, generation integer NOT NULL,
  sealed bytea NOT NULL, state smallint NOT NULL
);
CREATE TABLE keystore.erasure_intent (
  id uuid PRIMARY KEY, chain smallint NOT NULL, plan bytea NOT NULL, phase smallint NOT NULL
);

CREATE SCHEMA auth;

CREATE TABLE auth.session (
  token_hash bytea PRIMARY KEY, session_id uuid UNIQUE NOT NULL, account_id uuid NOT NULL,
  method smallint NOT NULL, created_at bigint NOT NULL, last_seen_at bigint NOT NULL,
  idle_expiry bigint NOT NULL, absolute_expiry bigint NOT NULL
);
CREATE TABLE auth.challenge (
  id uuid PRIMARY KEY, session_id uuid, purpose smallint NOT NULL,
  action_digest bytea, challenge bytea NOT NULL, issued_at bigint NOT NULL
);
CREATE TABLE auth.sign_count (
  credential_key bytea PRIMARY KEY, sign_count bigint NOT NULL, last_used_at bigint
);
CREATE TABLE auth.token (
  token_hash bytea PRIMARY KEY, kind smallint NOT NULL, account_id uuid,
  expires_at bigint NOT NULL, consumed_at bigint
);

CREATE SCHEMA auth_log;

CREATE TABLE auth_log.stepup_consumed (
  challenge_id uuid PRIMARY KEY, ledger_seq bigint NOT NULL REFERENCES ledger.entry(seq)
);
CREATE TABLE auth_log.session_end (
  session_id uuid PRIMARY KEY, at bigint NOT NULL, cause smallint NOT NULL,
  ledger_seq bigint NOT NULL REFERENCES ledger.entry(seq)
);

CREATE TRIGGER stepup_no_update BEFORE UPDATE OR DELETE ON auth_log.stepup_consumed
  FOR EACH ROW EXECUTE FUNCTION fstp_meta.refuse_mutation();
CREATE TRIGGER stepup_no_truncate BEFORE TRUNCATE ON auth_log.stepup_consumed
  FOR EACH STATEMENT EXECUTE FUNCTION fstp_meta.refuse_mutation();
CREATE TRIGGER session_end_no_update BEFORE UPDATE OR DELETE ON auth_log.session_end
  FOR EACH ROW EXECUTE FUNCTION fstp_meta.refuse_mutation();
CREATE TRIGGER session_end_no_truncate BEFORE TRUNCATE ON auth_log.session_end
  FOR EACH STATEMENT EXECUTE FUNCTION fstp_meta.refuse_mutation();

CREATE SCHEMA ops;

CREATE TABLE ops.outbox (
  id uuid PRIMARY KEY, kind smallint NOT NULL, idem bytea UNIQUE NOT NULL,
  dek uuid NOT NULL, body bytea NOT NULL, created_at bigint NOT NULL
);
CREATE TABLE ops.checkpoint (seq bigint PRIMARY KEY, key_ix integer NOT NULL, body bytea NOT NULL);
CREATE TABLE ops.licence_state (
  id smallint PRIMARY KEY CHECK (id = 1), sealed_token bytea,
  last_refresh_ok bigint, last_refresh_attempt bigint
);
