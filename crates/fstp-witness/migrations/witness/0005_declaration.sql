-- Restore declarations at the SaaS witness (ADR-012 record of lane
-- m10/saas-declare, interim, pending Daniel). fstp_witness::CATALOGUE lists
-- every table and column below.
--
-- fstp-control declares a restore of one cell's chain with a statement
-- signed by the restore declaration key. The witness records it as kind 4
-- of the witness chain: the head the restored chain resumes from, the
-- highest lost row, the job, and the witness fields. signature is the
-- witness receipt key's over those fields (context fstp-restore-v1), and
-- statement the restore declaration key's over the statement (context
-- fstp-restore-statement-v1). Both are composite signatures of 3373 bytes.
--
-- The table is insert-only like every witness record, refuses a revoked
-- cell, and joins the witness sequence of its cell and chain.

CREATE TABLE witness.declaration (
  cell_id      bytea    NOT NULL REFERENCES witness.cell_ca (cell_id),
  chain        smallint NOT NULL CHECK (chain IN (1, 2)),
  witness_seq  bigint   NOT NULL CHECK (witness_seq >= 1),
  head_n       bigint   NOT NULL CHECK (head_n >= 0),
  head_link    bytea    NOT NULL CHECK (octet_length(head_link) = 32),
  lost_to      bigint   NOT NULL CHECK (lost_to >= head_n),
  job          bytea    NOT NULL CHECK (octet_length(job) = 16),
  received_at  bigint   NOT NULL,
  witness_link bytea    NOT NULL CHECK (octet_length(witness_link) = 32),
  signature    bytea    NOT NULL CHECK (octet_length(signature) = 3373),
  statement    bytea    NOT NULL CHECK (octet_length(statement) = 3373),
  PRIMARY KEY (cell_id, chain, witness_seq),
  UNIQUE (cell_id, chain, job)
);

-- Refuses UPDATE, DELETE and TRUNCATE for every role, the owner included.
CREATE TRIGGER declaration_no_update BEFORE UPDATE OR DELETE ON witness.declaration
  FOR EACH ROW EXECUTE FUNCTION fstp_meta.refuse_mutation();
CREATE TRIGGER declaration_no_truncate BEFORE TRUNCATE ON witness.declaration
  FOR EACH STATEMENT EXECUTE FUNCTION fstp_meta.refuse_mutation();

-- A revoked cell's chains gain no declaration either.
CREATE TRIGGER declaration_not_revoked BEFORE INSERT ON witness.declaration
  FOR EACH ROW EXECUTE FUNCTION witness.refuse_revoked();

-- The witness sequence now counts declarations too: the next record of a
-- witness chain takes the next witness_seq over prepares, withdrawals and
-- declarations together, with no gap and no repeat.
CREATE OR REPLACE FUNCTION witness.check_seq() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  last bigint;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended(encode(NEW.cell_id, 'hex') || ':' || NEW.chain::text, 0));
  SELECT coalesce(max(s), 0) INTO last FROM (
    SELECT witness_seq AS s FROM witness.anchor WHERE cell_id = NEW.cell_id AND chain = NEW.chain
    UNION ALL
    SELECT witness_seq FROM witness.withdrawal WHERE cell_id = NEW.cell_id AND chain = NEW.chain
    UNION ALL
    SELECT witness_seq FROM witness.declaration WHERE cell_id = NEW.cell_id AND chain = NEW.chain
  ) r;
  IF NEW.witness_seq <> last + 1 THEN
    RAISE EXCEPTION 'witness sequence out of order' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER declaration_seq BEFORE INSERT ON witness.declaration
  FOR EACH ROW EXECUTE FUNCTION witness.check_seq();
