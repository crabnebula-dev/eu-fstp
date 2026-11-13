-- The vault chain's entries (ADR-010 open point 5, decided by Daniel on
-- 2026-11-13, m3-finish Q-C). Each committed fact batch and each identity
-- release or read is a kind 1 row. The vault has no ledger, so a kind 1
-- row carries its own entry: the entry sequence, its command id, its
-- entry schema (1 fact batch, 2 release, 3 read) and its sealed body.
-- The row's at is the entry's time. A KeyOp stays a kind 2 event.
-- The epoch column names the highest epoch a fact batch wrote, if any.
ALTER TABLE vault_audit.chain
  ADD COLUMN entry_seq bigint UNIQUE CHECK (entry_seq >= 1),
  ADD COLUMN entry_command bytea CHECK (octet_length(entry_command) = 16),
  ADD COLUMN entry_schema smallint CHECK (entry_schema IN (1, 2, 3));
ALTER TABLE vault_audit.chain DROP CONSTRAINT chain_check;
ALTER TABLE vault_audit.chain ADD CONSTRAINT chain_kind CHECK (
  (kind = 1 AND entry_seq IS NOT NULL AND entry_command IS NOT NULL
     AND entry_schema IS NOT NULL AND body IS NOT NULL)
  OR (kind = 2 AND entry_seq IS NULL AND entry_command IS NULL
     AND entry_schema IS NULL AND epoch IS NULL AND body IS NOT NULL));
