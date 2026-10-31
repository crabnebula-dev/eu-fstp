-- The application database c_<cell> (M3 design sections 4.2 and 7.1,
-- ADR-007, ADR-010). fstp_pgstore::CATALOGUE lists every table and
-- column below, in this order.
--
-- No column holds an amount (I-16). Content, wrapped keys and plans are
-- sealed; clear columns are ids, sequences, times, enums and digests
-- (R-NF-08). Grants come later, one fstp_meta.apply_grant call per row of
-- the cell role plan.

CREATE SCHEMA ledger;

-- One row per appended command: the first and last entry it wrote.
CREATE TABLE ledger.command (
  command   bytea  PRIMARY KEY CHECK (octet_length(command) = 16),
  first_seq bigint NOT NULL CHECK (first_seq >= 1),
  last_seq  bigint NOT NULL CHECK (last_seq >= first_seq),
  at        bigint NOT NULL
);

-- body: random nonce (12) || AES-256-GCM ciphertext || tag (16) of the
-- record's RFC 8785 text, sealed under the ledger key generation key_ix.
CREATE TABLE ledger.entry (
  seq     bigint   PRIMARY KEY CHECK (seq >= 1),
  at      bigint   NOT NULL,
  command bytea    NOT NULL REFERENCES ledger.command,
  schema  smallint NOT NULL CHECK (schema >= 1),
  key_ix  integer  NOT NULL,
  body    bytea    NOT NULL CHECK (octet_length(body) >= 28)
);

CREATE TRIGGER command_no_update BEFORE UPDATE OR DELETE ON ledger.command
  FOR EACH ROW EXECUTE FUNCTION fstp_meta.refuse_mutation();
CREATE TRIGGER command_no_truncate BEFORE TRUNCATE ON ledger.command
  FOR EACH STATEMENT EXECUTE FUNCTION fstp_meta.refuse_mutation();
-- The generation check of ADR-004: a process start refuses a key_ix that
-- already names a stored row.
CREATE INDEX entry_key_ix ON ledger.entry (key_ix);

CREATE TRIGGER entry_no_update BEFORE UPDATE OR DELETE ON ledger.entry
  FOR EACH ROW EXECUTE FUNCTION fstp_meta.refuse_mutation();
CREATE TRIGGER entry_no_truncate BEFORE TRUNCATE ON ledger.entry
  FOR EACH STATEMENT EXECUTE FUNCTION fstp_meta.refuse_mutation();

CREATE SCHEMA audit;

-- The App chain (design section 7.1). Kind 1 records a ledger entry,
-- kind 2 an audit event with a sealed body.
CREATE TABLE audit.chain (
  n           bigint   PRIMARY KEY CHECK (n >= 1),
  at          bigint   NOT NULL,
  kind        smallint NOT NULL,
  ledger_seq  bigint   UNIQUE REFERENCES ledger.entry(seq),
  stored_hash bytea    NOT NULL CHECK (octet_length(stored_hash) = 32),
  body        bytea,
  link        bytea    NOT NULL CHECK (octet_length(link) = 32),
  CHECK ((kind = 1 AND ledger_seq IS NOT NULL AND body IS NULL)
      OR (kind = 2 AND ledger_seq IS NULL AND body IS NOT NULL AND octet_length(body) <= 65536))
);

-- The second implementation of the fstp-audit link function (ADR-010
-- "Database link trigger"). It recomputes the stored hash from the row
-- and, for kind 1, from its stored ledger entry, then the link from the
-- previous row, and refuses any mismatch:
--   genesis     = SHA-256("fstp-audit-genesis-v1" || cell || chain)
--   row bytes   = "fstp-audit-row-v1" || be16(kind) || be64(at) || payload
--     kind 1:     payload = be64(seq) || be64(entry at) || command
--                           || be16(schema) || be32(key_ix) || be32(len) || body
--     kind 2:     payload = be32(len) || body
--   link_n      = SHA-256("fstp-audit-v1" || cell || chain || be64(n)
--                         || link_{n-1} || SHA-256(row bytes))
-- The cell id is the database name c_<cell>, which provisioning renders
-- from a closed grammar (ADR-011). The App chain byte is 1.
CREATE FUNCTION audit.check_link() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  db text := current_database();
  cell bytea;
  prev bytea;
  payload bytea;
  sh bytea;
  e ledger.entry%ROWTYPE;
BEGIN
  IF db !~ '^c_[0-9a-f]{32}$' THEN
    RAISE EXCEPTION 'not a cell database' USING ERRCODE = '23514';
  END IF;
  cell := decode(substr(db, 3), 'hex');
  IF NEW.n = 1 THEN
    prev := sha256(convert_to('fstp-audit-genesis-v1', 'UTF8') || cell || '\x01'::bytea);
  ELSE
    SELECT c.link INTO prev FROM audit.chain c WHERE c.n = NEW.n - 1;
    IF NOT FOUND THEN RAISE EXCEPTION 'chain gap' USING ERRCODE = '23514'; END IF;
  END IF;
  IF NEW.kind = 1 THEN
    SELECT * INTO e FROM ledger.entry le WHERE le.seq = NEW.ledger_seq;
    IF NOT FOUND THEN RAISE EXCEPTION 'no ledger entry' USING ERRCODE = '23514'; END IF;
    payload := int8send(e.seq) || int8send(e.at) || e.command || int2send(e.schema)
      || int4send(e.key_ix) || int4send(octet_length(e.body)) || e.body;
  ELSIF NEW.kind = 2 THEN
    payload := int4send(octet_length(NEW.body)) || NEW.body;
  ELSE
    RAISE EXCEPTION 'unknown row kind' USING ERRCODE = '23514';
  END IF;
  sh := sha256(convert_to('fstp-audit-row-v1', 'UTF8') || int2send(NEW.kind) || int8send(NEW.at) || payload);
  IF sh IS DISTINCT FROM NEW.stored_hash THEN
    RAISE EXCEPTION 'stored hash mismatch' USING ERRCODE = '23514';
  END IF;
  IF sha256(convert_to('fstp-audit-v1', 'UTF8') || cell || '\x01'::bytea || int8send(NEW.n) || prev || sh)
     IS DISTINCT FROM NEW.link THEN
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

-- The anchor of each committed head and the witness's receipt for it,
-- inserted in the append transaction before COMMIT (design section 7.2).
-- signature: the composite anchor signature. receipt: the receipt as
-- fstp_audit::anchor::encode_receipt writes it.
-- link is a PublicDigest and signature a Signature (design section 4.5):
-- 32 bytes, and the composite of 3373 bytes, mldsaSig (3309) then
-- tradSig (64) (ADR-010 "Composite encoding").
CREATE TABLE audit.anchor (
  n           bigint PRIMARY KEY REFERENCES audit.chain(n),
  link        bytea  NOT NULL CHECK (octet_length(link) = 32),
  at          bigint NOT NULL,
  signature   bytea  NOT NULL CHECK (octet_length(signature) = 3373),
  witness_seq bigint NOT NULL CHECK (witness_seq >= 1),
  receipt     bytea  NOT NULL
);

-- An anchor names the link its chain row holds.
CREATE FUNCTION audit.check_anchor() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF NOT EXISTS (SELECT FROM audit.chain c WHERE c.n = NEW.n AND c.link = NEW.link) THEN
    RAISE EXCEPTION 'anchor link differs from its chain row' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER anchor_link_check BEFORE INSERT ON audit.anchor
  FOR EACH ROW EXECUTE FUNCTION audit.check_anchor();
CREATE TRIGGER anchor_no_update BEFORE UPDATE OR DELETE ON audit.anchor
  FOR EACH ROW EXECUTE FUNCTION fstp_meta.refuse_mutation();
CREATE TRIGGER anchor_no_truncate BEFORE TRUNCATE ON audit.anchor
  FOR EACH STATEMENT EXECUTE FUNCTION fstp_meta.refuse_mutation();

CREATE SCHEMA blob;

-- envelope: the sealed blob of salt (32) || text under the data key dek
-- (ADR-007, design section 5.6). The salt never sits in a clear column.
CREATE TABLE blob.text (
  id       uuid  PRIMARY KEY,
  dek      uuid  NOT NULL UNIQUE,
  envelope bytea NOT NULL
);

CREATE SCHEMA keystore;

CREATE TABLE keystore.root (
  chain            smallint,
  epoch            bigint,
  backend          smallint NOT NULL,
  handle           bytea    NOT NULL,
  wrapped_seal_key bytea    NOT NULL,
  state            smallint NOT NULL,
  created_at       bigint   NOT NULL,
  destroyed_at     bigint,
  receipt          bytea,
  PRIMARY KEY (chain, epoch)
);

CREATE TABLE keystore.group_key (
  chain         smallint,
  purpose       smallint,
  group_id      uuid,
  generation    integer,
  public_key    bytea    NOT NULL,
  sealed_secret bytea    NOT NULL,
  epoch         bigint   NOT NULL,
  state         smallint NOT NULL,
  PRIMARY KEY (group_id, generation)
);

CREATE TABLE keystore.data_key (
  id         uuid     PRIMARY KEY,
  group_id   uuid     NOT NULL,
  generation integer  NOT NULL,
  sealed     bytea    NOT NULL,
  state      smallint NOT NULL
);

CREATE TABLE keystore.erasure_intent (
  id    uuid     PRIMARY KEY,
  chain smallint NOT NULL,
  plan  bytea    NOT NULL,
  phase smallint NOT NULL
);

CREATE SCHEMA auth;

-- Ended only by a row in auth_log.session_end.
CREATE TABLE auth.session (
  token_hash      bytea    PRIMARY KEY CHECK (octet_length(token_hash) = 32),
  session_id      uuid     UNIQUE NOT NULL,
  account_id      uuid     NOT NULL,
  method          smallint NOT NULL,
  created_at      bigint   NOT NULL,
  last_seen_at    bigint   NOT NULL,
  idle_expiry     bigint   NOT NULL,
  absolute_expiry bigint   NOT NULL
);

-- Consumed only by a row in auth_log.stepup_consumed.
CREATE TABLE auth.challenge (
  id            uuid     PRIMARY KEY,
  session_id    uuid,
  purpose       smallint NOT NULL,
  action_digest bytea,
  challenge     bytea    NOT NULL,
  issued_at     bigint   NOT NULL
);

-- credential_key: HMAC of the credential id under the CredLookup key.
CREATE TABLE auth.sign_count (
  credential_key bytea  PRIMARY KEY CHECK (octet_length(credential_key) = 32),
  sign_count     bigint NOT NULL,
  last_used_at   bigint
);

-- Invitations, magic links, enrolment and recovery tokens.
CREATE TABLE auth.token (
  token_hash  bytea    PRIMARY KEY CHECK (octet_length(token_hash) = 32),
  kind        smallint NOT NULL,
  account_id  uuid,
  expires_at  bigint   NOT NULL,
  consumed_at bigint
);

CREATE SCHEMA auth_log;

-- Insert-only side effects of an append (design section 5.3 step 6). A
-- second consumption of a step-up, or a second end of a session, violates
-- the primary key and aborts the whole append (I-77, I-78).
CREATE TABLE auth_log.stepup_consumed (
  challenge_id uuid   PRIMARY KEY,
  ledger_seq   bigint NOT NULL REFERENCES ledger.entry(seq)
);

CREATE TABLE auth_log.session_end (
  session_id uuid     PRIMARY KEY,
  at         bigint   NOT NULL,
  cause      smallint NOT NULL,
  ledger_seq bigint   NOT NULL REFERENCES ledger.entry(seq)
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

-- Sealed messages for later dispatch (M6). Kind 1 is a PossibleDeletion
-- alert of the in-doubt rule (design section 7.2), keyed by its idem
-- digest over (n, link).
CREATE TABLE ops.outbox (
  id         uuid     PRIMARY KEY,
  kind       smallint NOT NULL,
  idem       bytea    UNIQUE NOT NULL,
  dek        uuid     NOT NULL,
  body       bytea    NOT NULL,
  created_at bigint   NOT NULL
);

-- body: random nonce || ciphertext || tag of the folded state, sealed
-- under the ledger key generation key_ix, like ledger.entry.
CREATE TABLE ops.checkpoint (
  seq    bigint  PRIMARY KEY CHECK (seq >= 1),
  key_ix integer NOT NULL,
  body   bytea   NOT NULL CHECK (octet_length(body) >= 28)
);

CREATE INDEX checkpoint_key_ix ON ops.checkpoint (key_ix);

CREATE TABLE ops.licence_state (
  id                   smallint PRIMARY KEY CHECK (id = 1),
  sealed_token         bytea,
  last_refresh_ok      bigint,
  last_refresh_attempt bigint
);
