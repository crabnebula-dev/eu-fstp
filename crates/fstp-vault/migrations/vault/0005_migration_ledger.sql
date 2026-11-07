-- The migration ledger fstp_migrate.schema_migrations (M3 design sections
-- 4.5 and 4.6, I-16). The fstp-migrate runner creates it, with this exact
-- shape, before it applies migration 1, so under the runner both
-- statements change nothing. A set applied without the runner, such as
-- the catalogue tests apply it, gets the same table, so the database
-- holds every table fstp_vault::CATALOGUE lists.

CREATE SCHEMA IF NOT EXISTS fstp_migrate;

CREATE TABLE IF NOT EXISTS fstp_migrate.schema_migrations (
  version         int8        PRIMARY KEY CHECK (version > 0),
  name            text        NOT NULL CHECK (name ~ '^[a-z0-9_]+$'),
  checksum        bytea       NOT NULL CHECK (octet_length(checksum) = 32),
  applied_at      timestamptz NOT NULL DEFAULT now(),
  statement_count int4        NOT NULL CHECK (statement_count >= 0)
);
