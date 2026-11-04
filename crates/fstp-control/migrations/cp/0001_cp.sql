-- The control-plane database cp (M3 design section 4.4).
-- fstp_control::CATALOGUE lists every table and column below, in order.
-- The database holds registered metadata only: random ids, closed enums,
-- times, counts and opaque references. No tenant name, account id or
-- identity attribute (I-19, I-20, B6).

CREATE SCHEMA cp;

-- Refuses the change for every role, the owner and the superuser
-- included.
CREATE FUNCTION cp.refuse_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  RAISE EXCEPTION 'immutable' USING ERRCODE = '42501';
END $$;

-- A registered database cluster. Its kind never changes (I-83): 1
-- application, 2 vault, 3 control, 4 witness.
CREATE TABLE cp.cluster (
  cluster_id  bytea    PRIMARY KEY CHECK (octet_length(cluster_id) = 16),
  kind        smallint NOT NULL CHECK (kind BETWEEN 1 AND 4),
  region      smallint NOT NULL,
  endpoint    text     NOT NULL CHECK (endpoint ~ '^[a-z0-9.-]{1,253}:[0-9]{1,5}$'),
  server_spki bytea    NOT NULL,
  created_at  bigint   NOT NULL
);
CREATE TRIGGER cluster_kind_immutable BEFORE UPDATE OF kind ON cp.cluster
  FOR EACH ROW EXECUTE FUNCTION cp.refuse_mutation();

-- A cell. One cluster never holds both of its databases (I-83).
CREATE TABLE cp.cell (
  cell_id       bytea    PRIMARY KEY CHECK (octet_length(cell_id) = 16),
  status        smallint NOT NULL,
  mode          smallint NOT NULL,
  app_cluster   bytea    NOT NULL REFERENCES cp.cluster,
  vault_cluster bytea    NOT NULL REFERENCES cp.cluster,
  app_backend   smallint NOT NULL,
  vault_backend smallint NOT NULL,
  org_ref       bytea    NOT NULL,
  created_at    bigint   NOT NULL,
  erased_at     bigint,
  CHECK (app_cluster <> vault_cluster)
);

-- A verified host and the cell and kind it routes to.
CREATE TABLE cp.route (
  host        text     PRIMARY KEY,
  cell_id     bytea    NOT NULL REFERENCES cp.cell,
  kind        smallint NOT NULL,
  verified_at bigint   NOT NULL
);

CREATE TABLE cp.custody_entry (
  cell_id bytea,
  chain   smallint,
  backend smallint,
  key_ref bytea,
  PRIMARY KEY (cell_id, chain)
);

-- Counts per day (ADR-009 metadata register).
CREATE TABLE cp.metering (
  cell_id bytea,
  period  bigint,
  counter smallint,
  value   bigint,
  PRIMARY KEY (cell_id, period, counter)
);

CREATE TABLE cp.staff (
  staff_id   uuid   PRIMARY KEY,
  created_at bigint NOT NULL
);

CREATE TABLE cp.staff_credential (
  cred_id  bytea PRIMARY KEY,
  staff_id uuid  NOT NULL,
  cose_key bytea NOT NULL
);

-- case_ref is the cell's opaque case reference, never an account id
-- (I-20).
CREATE TABLE cp.operator_ticket (
  id          uuid     PRIMARY KEY,
  cell_id     bytea    NOT NULL,
  kind        smallint NOT NULL,
  case_ref    bytea    NOT NULL,
  approved_by bytea    NOT NULL,
  issued_at   bigint   NOT NULL
);

-- Every fstp-pgagent job, with its approvals (ADR-011).
CREATE TABLE cp.job (
  id          uuid     PRIMARY KEY,
  cluster_id  bytea    NOT NULL,
  kind        smallint NOT NULL,
  state       smallint NOT NULL,
  approved_by bytea,
  at          bigint   NOT NULL
);
