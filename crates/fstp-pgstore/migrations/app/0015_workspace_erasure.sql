-- Per-workspace erasure keys (F-017, ADR-026 section "Written by the M10
-- fix lane"; I-81, I-82, TH-30).
--
-- A workspace value is now sealed under its proposal's own workspace key,
-- whose keystore.data_key id is the proposal id. The ledger key, which no
-- erasure destroys, no longer seals one, so the key_ix column goes.
--
-- Rows sealed under the ledger key cannot be erased by key destruction.
-- No real data exists yet, so this migration deletes every row of
-- workspace.drafts before it drops the column.
--
-- A row is then deleted only by the cell's own keys role c_<cell>_keys,
-- and only once no keystore.data_key row holds its proposal's workspace
-- key: the erasure batch removed the key at its commit, before it
-- destroyed the root epoch. TRUNCATE is refused for every role, the owner
-- included. The app role keeps INSERT, SELECT and UPDATE for its saves.

DELETE FROM workspace.drafts;

ALTER TABLE workspace.drafts DROP COLUMN key_ix;

CREATE FUNCTION fstp_meta.workspace_drafts_delete_check() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF TG_OP = 'DELETE'
     AND current_user = current_database() || '_keys'
     AND NOT EXISTS (
       SELECT 1 FROM keystore.data_key k
        WHERE k.id = encode(OLD.proposal, 'hex')::uuid
     ) THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'workspace rows leave only with their key' USING ERRCODE = '42501';
END $$;

CREATE TRIGGER drafts_delete_erased BEFORE DELETE ON workspace.drafts
  FOR EACH ROW EXECUTE FUNCTION fstp_meta.workspace_drafts_delete_check();
CREATE TRIGGER drafts_no_truncate BEFORE TRUNCATE ON workspace.drafts
  FOR EACH STATEMENT EXECUTE FUNCTION fstp_meta.refuse_mutation();
