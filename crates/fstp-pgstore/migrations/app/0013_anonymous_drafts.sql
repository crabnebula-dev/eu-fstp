-- Anonymous drafts with a resume link (ADR-032, Daniel 2026-11-22).
-- fstp_pgstore::CATALOGUE lists every column below, in this order.
--
-- A row is form text kept under a secret link: it is no proposal, names
-- no account and holds no identity data (R-SB-01). token_hash is the
-- SHA-256 of the 32-byte random token of the link; the token itself is
-- never stored. sealed: random nonce (12) || ciphertext || tag (16) of
-- the three workspace sections under the ledger key generation key_ix,
-- with the AAD "fstp-anondraft-v1" || cell || token_hash (R-NF-08).
-- A claim or a discard deletes the row; the draft sweep deletes every
-- row past expires_at, which is 30 days after started_at or the call's
-- deadline if that is earlier. Grants come from the cell role plan.

CREATE TABLE workspace.anonymous_drafts (
  token_hash bytea   PRIMARY KEY CHECK (octet_length(token_hash) = 32),
  call       bytea   NOT NULL CHECK (octet_length(call) = 16),
  key_ix     integer NOT NULL,
  sealed     bytea   NOT NULL CHECK (octet_length(sealed) BETWEEN 28 AND 2097152),
  started_at bigint  NOT NULL,
  updated_at bigint  NOT NULL CHECK (updated_at >= started_at),
  expires_at bigint  NOT NULL CHECK (expires_at > started_at)
);

CREATE INDEX anonymous_drafts_expires ON workspace.anonymous_drafts (expires_at);
