-- The deletion of an erased document's sealed row (ADR-007 section
-- "Decided by Daniel on 2026-11-23", decision 2, lane L39; I-81).
--
-- doc.blob stays append-only for every role but the cell's own keys role
-- c_<cell>_keys. That role may delete a row once no keystore.data_key row
-- holds the row's data key: the erasure batch removed the key at its
-- commit, before it destroyed the root epoch. UPDATE and TRUNCATE stay
-- refused for every role, the owner included.

CREATE FUNCTION fstp_meta.doc_blob_delete_check() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF TG_OP = 'DELETE'
     AND current_user = current_database() || '_keys'
     AND NOT EXISTS (SELECT 1 FROM keystore.data_key k WHERE k.id = OLD.dek) THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'append-only' USING ERRCODE = '42501';
END $$;

DROP TRIGGER blob_no_update ON doc.blob;

CREATE TRIGGER blob_no_update BEFORE UPDATE ON doc.blob
  FOR EACH ROW EXECUTE FUNCTION fstp_meta.refuse_mutation();
CREATE TRIGGER blob_delete_erased BEFORE DELETE ON doc.blob
  FOR EACH ROW EXECUTE FUNCTION fstp_meta.doc_blob_delete_check();
