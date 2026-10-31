-- The application database c_<cell>: placement and the shared trigger
-- function (M3 design section 4.1).
-- fstp_pgstore::CATALOGUE lists every table and column below.
-- Migration 2 (0002_apply_grant.sql) is fstp_migrate::catalogue::APPLY_GRANT_SQL,
-- which defines fstp_meta.apply_grant, then APPLY_GRANT_REVOKE_SQL. Migration 3
-- holds the application tables.

CREATE SCHEMA fstp_meta;

-- Written once at provisioning. Kind 1 is an application database; the
-- vault set uses kind 2 (I-83).
CREATE TABLE fstp_meta.placement (
  cell_id    bytea    NOT NULL CHECK (octet_length(cell_id) = 16),
  cluster_id bytea    NOT NULL CHECK (octet_length(cluster_id) = 16),
  kind       smallint NOT NULL CHECK (kind = 1)
);

-- At most one placement row: a unique index over a constant.
CREATE UNIQUE INDEX placement_one_row ON fstp_meta.placement ((true));

-- Refuses UPDATE, DELETE and TRUNCATE for every role, the owner and the
-- superuser included (ADR-007 "Database link trigger").
CREATE FUNCTION fstp_meta.refuse_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  RAISE EXCEPTION 'append-only' USING ERRCODE = '42501';
END $$;

-- The placement row names this database's own cell: the 32 hex digits of
-- the name c_<cell>, which provisioning renders from a closed grammar
-- (ADR-011). The link trigger and apply_grant trust the same name.
CREATE FUNCTION fstp_meta.check_placement() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  db text := current_database();
BEGIN
  IF db !~ '^c_[0-9a-f]{32}$' THEN
    RAISE EXCEPTION 'not a cell database' USING ERRCODE = '23514';
  END IF;
  IF NEW.cell_id IS DISTINCT FROM decode(substr(db, 3), 'hex') THEN
    RAISE EXCEPTION 'placement of another cell' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER placement_cell_check BEFORE INSERT ON fstp_meta.placement
  FOR EACH ROW EXECUTE FUNCTION fstp_meta.check_placement();
CREATE TRIGGER placement_no_update BEFORE UPDATE OR DELETE ON fstp_meta.placement
  FOR EACH ROW EXECUTE FUNCTION fstp_meta.refuse_mutation();
CREATE TRIGGER placement_no_truncate BEFORE TRUNCATE ON fstp_meta.placement
  FOR EACH STATEMENT EXECUTE FUNCTION fstp_meta.refuse_mutation();
