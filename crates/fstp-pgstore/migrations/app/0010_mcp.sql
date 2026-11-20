-- The durable records of the cell's OAuth 2.1 authorisation server
-- (ADR-013 amendment of 2026-11-20, lane L2, production-mcp-design.md
-- G5). fstp_pgstore::CATALOGUE lists every column below, in this order.
--
-- fstp-oauth is sans-IO. fstp-cell writes the journal of one endpoint
-- call in one transaction before it sends the reply, and restores the
-- server from these rows at start. Pending consents, codes, access
-- tokens and registration counts live in memory only, so a restart burns
-- them.
--
-- No column holds a token, a code, a consent handle or client text:
--
-- * client_id is the 16 random bytes of the RFC 7591 client_id.
-- * metadata_text names the sealed text that holds the registration
--   metadata, the redirect URIs and the untrusted client name.
-- * account is the raw account id. No identity attribute is stored
--   (I-86).
-- * current_hash and refresh.hash are labelled SHA-256 digests of 256-bit
--   random tokens (ADR-013 "Token storage").
--
-- Times are microseconds on the cell clock, as fstp_oauth::Micros.
-- method: 1 passkey, 2 magic link, 3 OPAQUE, 4 EUDI Wallet.
-- scopes: bit i is the scope at position i of fstp_oauth::Scope::ALL.
-- version: a family row is replaced only by a higher version.
CREATE SCHEMA mcp;

CREATE TABLE mcp.client (
  number        bigint  PRIMARY KEY CHECK (number > 0),
  client_id     bytea   NOT NULL UNIQUE CHECK (octet_length(client_id) = 16),
  metadata_text bytea   NOT NULL CHECK (octet_length(metadata_text) = 16),
  registered_at bigint  NOT NULL
);

CREATE TABLE mcp.family (
  id           bigint   PRIMARY KEY CHECK (id >= 0),
  client       bigint   NOT NULL REFERENCES mcp.client (number) ON DELETE CASCADE,
  account      bytea    NOT NULL CHECK (octet_length(account) = 16),
  scopes       integer  NOT NULL CHECK (scopes BETWEEN 1 AND 65535),
  started_at   bigint   NOT NULL,
  ends_at      bigint   NOT NULL,
  current_hash bytea    NOT NULL CHECK (octet_length(current_hash) = 32),
  refreshes    integer  NOT NULL CHECK (refreshes >= 0),
  revoked      boolean  NOT NULL,
  method       smallint NOT NULL CHECK (method BETWEEN 1 AND 4),
  version      bigint   NOT NULL CHECK (version > 0),
  CHECK (ends_at > started_at)
);

CREATE INDEX family_account ON mcp.family (account);

CREATE TABLE mcp.refresh (
  hash   bytea  PRIMARY KEY CHECK (octet_length(hash) = 32),
  family bigint NOT NULL REFERENCES mcp.family (id) ON DELETE CASCADE
);

CREATE INDEX refresh_family ON mcp.refresh (family);
