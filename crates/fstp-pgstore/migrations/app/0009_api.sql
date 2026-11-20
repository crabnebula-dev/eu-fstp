-- The API core's state beside the ledger (ADR-026, M4 design section
-- 4.3, production design gaps G3 and G4): pending actions (I-85) and
-- sealed workspaces (I-21). fstp_pgstore::CATALOGUE lists every table and
-- column below, in this order.
--
-- No column holds an amount (I-16). The pending request and the workspace
-- value are sealed under the ledger key generation key_ix; clear columns
-- are ids, times, enums and digests (R-NF-08). Grants come later, one
-- fstp_meta.apply_grant call per row of the cell role plan.

CREATE SCHEMA api;

-- One prepared action of an agent (I-85). request: random nonce (12) ||
-- AES-256-GCM ciphertext || tag (16) of the canonical pending request
-- and the request the user sees, under the AAD
-- "fstp-api-pending-v1" || cell || id. status records a discard or an
-- expiry mark only: a confirmation is a row of api.pending_confirmed.
CREATE TABLE api.pending_actions (
  id         bytea    PRIMARY KEY CHECK (octet_length(id) = 16),
  account    bytea    NOT NULL CHECK (octet_length(account) = 16),
  client_id  bytea    NOT NULL CHECK (octet_length(client_id) = 16),
  op_kind    text     NOT NULL CHECK (op_kind ~ '^[a-z][a-z0-9_.]{0,63}$'),
  key_ix     integer  NOT NULL,
  request    bytea    NOT NULL CHECK (octet_length(request) BETWEEN 28 AND 2097152),
  digest     bytea    NOT NULL CHECK (octet_length(digest) = 32),
  created_at bigint   NOT NULL,
  expires_at bigint   NOT NULL CHECK (expires_at > created_at),
  status     text     NOT NULL CHECK (status IN ('open', 'expired', 'discarded')),
  closed_at  bigint,
  CHECK ((status = 'open') = (closed_at IS NULL))
);
CREATE INDEX pending_actions_account ON api.pending_actions (account);

-- The one confirmation of a pending action: inserted by the ledger writer
-- in the append transaction of the command it executed (ADR-026 "Pending
-- actions"). A second confirmation violates the primary key, and the
-- whole append aborts (I-85).
CREATE TABLE api.pending_confirmed (
  id         bytea  PRIMARY KEY REFERENCES api.pending_actions,
  ledger_seq bigint NOT NULL UNIQUE REFERENCES ledger.entry(seq)
);

CREATE TRIGGER pending_confirmed_no_update BEFORE UPDATE OR DELETE ON api.pending_confirmed
  FOR EACH ROW EXECUTE FUNCTION fstp_meta.refuse_mutation();
CREATE TRIGGER pending_confirmed_no_truncate BEFORE TRUNCATE ON api.pending_confirmed
  FOR EACH STATEMENT EXECUTE FUNCTION fstp_meta.refuse_mutation();

CREATE SCHEMA workspace;

-- One sealed value per proposal and slot (I-21, `Workspaces` port).
-- slot: 'draft', or 'submitted:' and the plan version id in hex.
-- sealed: random nonce (12) || ciphertext || tag (16) under the AAD
-- "fstp-workspace-v1" || cell || proposal.
CREATE TABLE workspace.drafts (
  proposal   bytea   NOT NULL CHECK (octet_length(proposal) = 16),
  slot       text    NOT NULL CHECK (slot ~ '^(draft|submitted:[0-9a-f]{32})$'),
  revision   bigint  NOT NULL CHECK (revision > 0),
  key_ix     integer NOT NULL,
  sealed     bytea   NOT NULL CHECK (octet_length(sealed) BETWEEN 28 AND 2097152),
  updated_at bigint  NOT NULL,
  PRIMARY KEY (proposal, slot)
);
