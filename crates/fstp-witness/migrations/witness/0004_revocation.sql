-- The revocation of a cell at the witness (R-SW-02, design section 3.7
-- step 2, ADR-004 "Decided by Daniel, 2026-11-15 (late)").
-- fstp_witness::CATALOGUE lists every table and column below.
--
-- A cell erasure appends one row here. From then on the witness pins no
-- CA of the cell, refuses every request of the cell, and refuses a new
-- registration of it. witness.cell_ca stays append-only, and the anchor,
-- receipt and withdrawal rows of the cell keep their references. The
-- cell's secret key material is destroyed in custody, not here.

CREATE TABLE witness.cell_revocation (
  cell_id    bytea  PRIMARY KEY REFERENCES witness.cell_ca (cell_id),
  revoked_at bigint NOT NULL
);

-- Refuses UPDATE, DELETE and TRUNCATE for every role, the owner included.
CREATE TRIGGER cell_revocation_no_update BEFORE UPDATE OR DELETE ON witness.cell_revocation
  FOR EACH ROW EXECUTE FUNCTION fstp_meta.refuse_mutation();
CREATE TRIGGER cell_revocation_no_truncate BEFORE TRUNCATE ON witness.cell_revocation
  FOR EACH STATEMENT EXECUTE FUNCTION fstp_meta.refuse_mutation();

-- A revoked cell gains no anchor key.
CREATE FUNCTION witness.refuse_revoked() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM witness.cell_revocation WHERE cell_id = NEW.cell_id) THEN
    RAISE EXCEPTION 'the cell is revoked' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER anchor_key_not_revoked BEFORE INSERT ON witness.anchor_key
  FOR EACH ROW EXECUTE FUNCTION witness.refuse_revoked();
-- A revoked cell's chains gain no record either. The service refuses the
-- cell first; these triggers hold for every other role too.
CREATE TRIGGER anchor_not_revoked BEFORE INSERT ON witness.anchor
  FOR EACH ROW EXECUTE FUNCTION witness.refuse_revoked();
CREATE TRIGGER withdrawal_not_revoked BEFORE INSERT ON witness.withdrawal
  FOR EACH ROW EXECUTE FUNCTION witness.refuse_revoked();
