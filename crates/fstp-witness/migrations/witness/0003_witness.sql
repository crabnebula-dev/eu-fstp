-- The witness tables (M3 design section 4.4, ADR-010 "Prepare, receipt,
-- commit", "Abort", "In doubt" and "Witnesses", open point 4).
-- fstp_witness::CATALOGUE lists every table and column below.
--
-- Each cell and chain has its own witness chain. Its records are
-- numbered by witness_seq from 1 with no gap, over the prepares in
-- witness.anchor and the withdrawals in witness.withdrawal together. Every
-- table is insert-only: witness_service holds INSERT and SELECT only, and
-- the triggers refuse UPDATE, DELETE and TRUNCATE for every role.
--
-- Reading of lane int5, reported to Daniel and the lead (fstp_witness
-- module documentation): design section 4.4 declares witness_seq UNIQUE
-- over the whole table and PRIMARY KEY (cell_id, chain, n). Witness
-- sequences count per cell and chain, and ADR-010 lets a cell prepare the
-- same n again with another link once its abort is recorded. So the key
-- is (cell_id, chain, witness_seq), and (cell_id, chain, n, link) is
-- unique, since a withdrawn head is never receipted again. The columns
-- are the design's.

CREATE SCHEMA witness;

-- A receipted prepare: the anchor the cell signed, and where it sits in
-- the witness chain.
CREATE TABLE witness.anchor (
  cell_id      bytea    NOT NULL CHECK (octet_length(cell_id) = 16),
  chain        smallint NOT NULL CHECK (chain IN (1, 2)),
  n            bigint   NOT NULL CHECK (n >= 1),
  link         bytea    NOT NULL CHECK (octet_length(link) = 32),
  at           bigint   NOT NULL,
  signature    bytea    NOT NULL,
  received_at  bigint   NOT NULL,
  witness_seq  bigint   NOT NULL CHECK (witness_seq >= 1),
  witness_link bytea    NOT NULL CHECK (octet_length(witness_link) = 32),
  PRIMARY KEY (cell_id, chain, witness_seq),
  UNIQUE (cell_id, chain, n, link)
);

-- The composite signature of the receipt the witness gave for a prepare
-- (ADR-010 "Receipt"). The signed fields are the prepare's row.
CREATE TABLE witness.receipt (
  cell_id     bytea    NOT NULL,
  chain       smallint NOT NULL,
  witness_seq bigint   NOT NULL,
  signature   bytea    NOT NULL,
  PRIMARY KEY (cell_id, chain, witness_seq),
  FOREIGN KEY (cell_id, chain, witness_seq) REFERENCES witness.anchor (cell_id, chain, witness_seq)
);

-- An abort (kind 2) or an in-doubt record (kind 3) of the outstanding
-- prepare (ADR-010 "Abort" and "In doubt"). The codes are those of
-- fstp_audit::witness::RecordKind.
CREATE TABLE witness.withdrawal (
  cell_id      bytea    NOT NULL CHECK (octet_length(cell_id) = 16),
  chain        smallint NOT NULL CHECK (chain IN (1, 2)),
  witness_seq  bigint   NOT NULL CHECK (witness_seq >= 1),
  kind         smallint NOT NULL CHECK (kind IN (2, 3)),
  n            bigint   NOT NULL CHECK (n >= 1),
  link         bytea    NOT NULL CHECK (octet_length(link) = 32),
  received_at  bigint   NOT NULL,
  witness_link bytea    NOT NULL CHECK (octet_length(witness_link) = 32),
  PRIMARY KEY (cell_id, chain, witness_seq),
  UNIQUE (cell_id, chain, n, link)
);

-- The cell CAs the witness pins, registered at provisioning (ADR-010
-- "Witnesses", design section 9.2), as their DER certificates. A
-- cell-witness or vault-witness certificate is accepted only from its own
-- cell's CA.
CREATE TABLE witness.cell_ca (
  cell_id       bytea  PRIMARY KEY CHECK (octet_length(cell_id) = 16),
  ca_cert       bytea  NOT NULL,
  registered_at bigint NOT NULL
);

-- The anchor key history of each chain (ADR-010 "Keys"): the composite
-- public keys a prepare's anchor signature may verify under. Old keys
-- stay, so anchors signed before a rotation still verify.
CREATE TABLE witness.anchor_key (
  cell_id       bytea    NOT NULL REFERENCES witness.cell_ca (cell_id),
  chain         smallint NOT NULL CHECK (chain IN (1, 2)),
  public_key    bytea    NOT NULL,
  registered_at bigint   NOT NULL,
  PRIMARY KEY (cell_id, chain, public_key)
);

-- Refuses UPDATE, DELETE and TRUNCATE for every role, the owner included.
CREATE TRIGGER anchor_no_update BEFORE UPDATE OR DELETE ON witness.anchor
  FOR EACH ROW EXECUTE FUNCTION fstp_meta.refuse_mutation();
CREATE TRIGGER anchor_no_truncate BEFORE TRUNCATE ON witness.anchor
  FOR EACH STATEMENT EXECUTE FUNCTION fstp_meta.refuse_mutation();
CREATE TRIGGER receipt_no_update BEFORE UPDATE OR DELETE ON witness.receipt
  FOR EACH ROW EXECUTE FUNCTION fstp_meta.refuse_mutation();
CREATE TRIGGER receipt_no_truncate BEFORE TRUNCATE ON witness.receipt
  FOR EACH STATEMENT EXECUTE FUNCTION fstp_meta.refuse_mutation();
CREATE TRIGGER withdrawal_no_update BEFORE UPDATE OR DELETE ON witness.withdrawal
  FOR EACH ROW EXECUTE FUNCTION fstp_meta.refuse_mutation();
CREATE TRIGGER withdrawal_no_truncate BEFORE TRUNCATE ON witness.withdrawal
  FOR EACH STATEMENT EXECUTE FUNCTION fstp_meta.refuse_mutation();
CREATE TRIGGER cell_ca_no_update BEFORE UPDATE OR DELETE ON witness.cell_ca
  FOR EACH ROW EXECUTE FUNCTION fstp_meta.refuse_mutation();
CREATE TRIGGER cell_ca_no_truncate BEFORE TRUNCATE ON witness.cell_ca
  FOR EACH STATEMENT EXECUTE FUNCTION fstp_meta.refuse_mutation();
CREATE TRIGGER anchor_key_no_update BEFORE UPDATE OR DELETE ON witness.anchor_key
  FOR EACH ROW EXECUTE FUNCTION fstp_meta.refuse_mutation();
CREATE TRIGGER anchor_key_no_truncate BEFORE TRUNCATE ON witness.anchor_key
  FOR EACH STATEMENT EXECUTE FUNCTION fstp_meta.refuse_mutation();

-- The next record of a witness chain takes the next witness_seq, over
-- prepares and withdrawals together, with no gap and no repeat. The
-- advisory lock per cell and chain orders concurrent inserts.
CREATE FUNCTION witness.check_seq() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  last bigint;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended(encode(NEW.cell_id, 'hex') || ':' || NEW.chain::text, 0));
  SELECT coalesce(max(s), 0) INTO last FROM (
    SELECT witness_seq AS s FROM witness.anchor WHERE cell_id = NEW.cell_id AND chain = NEW.chain
    UNION ALL
    SELECT witness_seq FROM witness.withdrawal WHERE cell_id = NEW.cell_id AND chain = NEW.chain
  ) r;
  IF NEW.witness_seq <> last + 1 THEN
    RAISE EXCEPTION 'witness sequence out of order' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER anchor_seq BEFORE INSERT ON witness.anchor
  FOR EACH ROW EXECUTE FUNCTION witness.check_seq();
CREATE TRIGGER withdrawal_seq BEFORE INSERT ON witness.withdrawal
  FOR EACH ROW EXECUTE FUNCTION witness.check_seq();
