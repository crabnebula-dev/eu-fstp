-- The witness database: placement and the shared trigger function (M3
-- design sections 4.1, 4.4 and 9.2, ADR-010 "Witnesses").
-- fstp_witness::CATALOGUE lists every table and column below.
-- Migration 2 (0002_apply_grant.sql) is fstp_migrate::catalogue::APPLY_GRANT_SQL,
-- which defines fstp_meta.apply_grant, then APPLY_GRANT_REVOKE_SQL, as in
-- the application and vault sets. Migration 3 holds the witness tables.

CREATE SCHEMA fstp_meta;

-- Written once at provisioning. Kind 4 is a witness database on a witness
-- cluster (I-83, cp.cluster kinds 1 to 4). The witness serves many cells,
-- so the row names its cluster only.
CREATE TABLE fstp_meta.placement (
  cluster_id bytea    NOT NULL CHECK (octet_length(cluster_id) = 16),
  kind       smallint NOT NULL CHECK (kind = 4)
);

-- At most one placement row: a unique index over a constant.
CREATE UNIQUE INDEX placement_one_row ON fstp_meta.placement ((true));

-- Refuses UPDATE, DELETE and TRUNCATE for every role, the owner and the
-- superuser included (ADR-010 "Database link trigger").
CREATE FUNCTION fstp_meta.refuse_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  RAISE EXCEPTION 'append-only' USING ERRCODE = '42501';
END $$;

CREATE TRIGGER placement_no_update BEFORE UPDATE OR DELETE ON fstp_meta.placement
  FOR EACH ROW EXECUTE FUNCTION fstp_meta.refuse_mutation();
CREATE TRIGGER placement_no_truncate BEFORE TRUNCATE ON fstp_meta.placement
  FOR EACH STATEMENT EXECUTE FUNCTION fstp_meta.refuse_mutation();
