-- The vault database v_<cell> (M3 design section 4.3).
-- fstp_vault::CATALOGUE lists every table and column below.

CREATE SCHEMA vault;

-- Insert-only tables refuse UPDATE, DELETE and TRUNCATE.
CREATE FUNCTION vault.refuse_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'insert-only table' USING ERRCODE = 'insufficient_privilege';
END;
$$;

-- One row per epoch. state 1 is provisional or queued, 2 is effective.
-- Only the acknowledgement turns 1 into 2, and it records the cell's
-- reaction sequence and chain link (NOTE 4 step 5).
CREATE TABLE vault.epoch (
  epoch      bigint   PRIMARY KEY CHECK (epoch >= 1),
  state      smallint NOT NULL CHECK (state IN (1, 2)),
  created_at bigint   NOT NULL,
  affected   bytea    NOT NULL,
  ack_seq    bigint,
  ack_link   bytea    CHECK (ack_link IS NULL OR octet_length(ack_link) = 32),
  acked_at   bigint,
  CHECK ((state = 1 AND ack_seq IS NULL AND acked_at IS NULL)
      OR (state = 2 AND ack_seq IS NOT NULL AND acked_at IS NOT NULL))
);

CREATE FUNCTION vault.epoch_ack_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP <> 'UPDATE' OR OLD.state <> 1 OR NEW.state <> 2
     OR NEW.epoch <> OLD.epoch OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'an epoch changes only by its acknowledgement'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER epoch_ack_only BEFORE UPDATE OR DELETE ON vault.epoch
  FOR EACH ROW EXECUTE FUNCTION vault.epoch_ack_only();
CREATE TRIGGER epoch_no_truncate BEFORE TRUNCATE ON vault.epoch
  FOR EACH STATEMENT EXECUTE FUNCTION vault.refuse_mutation();

-- Facts: the sealed stored fact body of each write, at its epoch.
CREATE TABLE vault.fact (
  fact_id     uuid     PRIMARY KEY,
  epoch       bigint   NOT NULL UNIQUE REFERENCES vault.epoch,
  kind        smallint NOT NULL CHECK (kind BETWEEN 1 AND 13 AND kind <> 5),
  subject     uuid     NOT NULL,
  dek         uuid     NOT NULL,
  body        bytea    NOT NULL,
  ended_epoch bigint   REFERENCES vault.epoch
);

-- The identity match key: HMAC under the Match key, rotated by erasure
-- (design section 3.5).
CREATE TABLE vault.identity (
  identity_id uuid  PRIMARY KEY,
  match_key   bytea UNIQUE NOT NULL CHECK (octet_length(match_key) = 32)
);

CREATE TABLE vault.account (
  account_id     uuid   PRIMARY KEY,
  identity_id    uuid   REFERENCES vault.identity,
  verified_epoch bigint REFERENCES vault.epoch
);

CREATE TABLE vault.document (
  doc_id            uuid   PRIMARY KEY,
  account_id        uuid   NOT NULL,
  dek               uuid   NOT NULL,
  sealed_object_ref bytea  NOT NULL,
  uploaded_at       bigint NOT NULL,
  erased_epoch      bigint REFERENCES vault.epoch
);

-- The negotiation fact the cell pushes when NEGOTIATION opens (design
-- section 6.5, second guard).
CREATE TABLE vault.negotiation (
  proposal_id     uuid   PRIMARY KEY,
  sealed_accounts bytea  NOT NULL,
  opened_seq      bigint NOT NULL,
  closed_seq      bigint
);

-- Single use (ADR-009 "Tickets"): a second use violates the primary key.
CREATE TABLE vault.ticket_used (
  ticket_id bytea  PRIMARY KEY CHECK (octet_length(ticket_id) = 16),
  used_at   bigint NOT NULL
);
CREATE TRIGGER ticket_used_insert_only BEFORE UPDATE OR DELETE ON vault.ticket_used
  FOR EACH ROW EXECUTE FUNCTION vault.refuse_mutation();
CREATE TRIGGER ticket_used_no_truncate BEFORE TRUNCATE ON vault.ticket_used
  FOR EACH STATEMENT EXECUTE FUNCTION vault.refuse_mutation();

CREATE TABLE vault.query_log (
  n            bigint  PRIMARY KEY CHECK (n >= 1),
  at           bigint  NOT NULL,
  query_digest bytea   NOT NULL CHECK (octet_length(query_digest) = 32),
  holds        boolean NOT NULL,
  epoch        bigint  NOT NULL
);
CREATE TRIGGER query_log_insert_only BEFORE UPDATE OR DELETE ON vault.query_log
  FOR EACH ROW EXECUTE FUNCTION vault.refuse_mutation();
CREATE TRIGGER query_log_no_truncate BEFORE TRUNCATE ON vault.query_log
  FOR EACH STATEMENT EXECUTE FUNCTION vault.refuse_mutation();

-- The P-17 condition of each programme (NOTE 6): its countries as a
-- canonical JSON array of ascending codes. Not in design section 4.3
-- (reported to Daniel). Insert-only, so a condition is fixed once set.
CREATE TABLE vault.p17_condition (
  programme_id uuid  PRIMARY KEY,
  countries    bytea NOT NULL
);
CREATE TRIGGER p17_condition_insert_only BEFORE UPDATE OR DELETE ON vault.p17_condition
  FOR EACH ROW EXECUTE FUNCTION vault.refuse_mutation();
CREATE TRIGGER p17_condition_no_truncate BEFORE TRUNCATE ON vault.p17_condition
  FOR EACH STATEMENT EXECUTE FUNCTION vault.refuse_mutation();

-- The vault's own chain and anchors (I-24), with the shapes of section 4.2.
-- kind 1 records a vault epoch, kind 2 an event such as a ticket use.
CREATE SCHEMA vault_audit;
CREATE TABLE vault_audit.chain (
  n           bigint   PRIMARY KEY CHECK (n >= 1),
  at          bigint   NOT NULL,
  kind        smallint NOT NULL,
  epoch       bigint   UNIQUE REFERENCES vault.epoch,
  stored_hash bytea    NOT NULL CHECK (octet_length(stored_hash) = 32),
  body        bytea,
  link        bytea    NOT NULL CHECK (octet_length(link) = 32),
  CHECK ((kind = 1 AND epoch IS NOT NULL AND body IS NULL)
      OR (kind = 2 AND epoch IS NULL AND body IS NOT NULL))
);
CREATE TRIGGER chain_insert_only BEFORE UPDATE OR DELETE ON vault_audit.chain
  FOR EACH ROW EXECUTE FUNCTION vault.refuse_mutation();
CREATE TRIGGER chain_no_truncate BEFORE TRUNCATE ON vault_audit.chain
  FOR EACH STATEMENT EXECUTE FUNCTION vault.refuse_mutation();
CREATE TABLE vault_audit.anchor (
  n           bigint PRIMARY KEY REFERENCES vault_audit.chain(n),
  link        bytea  NOT NULL,
  at          bigint NOT NULL,
  signature   bytea  NOT NULL,
  witness_seq bigint NOT NULL,
  receipt     bytea  NOT NULL
);

-- The vault chain's keys, with the shapes of section 4.2.
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
