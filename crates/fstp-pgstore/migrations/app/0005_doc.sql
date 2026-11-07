-- Write-once document storage (M5 design section 4.3, I-30): every
-- contract PDF revision, sealed draft, report and payment record file.
-- fstp_pgstore::CATALOGUE lists every column below, in this order.
--
-- digest is the SHA-256 of the clear document, as the ledger records it.
-- The document itself is sealed under the data key dek (ADR-007), as
-- blob.text is. A second insert of a digest fails on the primary key, so
-- a digest never maps to other bytes. The app role holds INSERT and
-- SELECT only, and the triggers refuse UPDATE, DELETE and TRUNCATE for
-- every role, the owner included.
-- kind: 1 contract revision, 2 sealed draft, 3 report or payment record.

CREATE SCHEMA doc;

CREATE TABLE doc.blob (
  digest    bytea    PRIMARY KEY CHECK (octet_length(digest) = 32),
  kind      smallint NOT NULL CHECK (kind >= 1),
  dek       uuid     NOT NULL UNIQUE,
  envelope  bytea    NOT NULL,
  stored_at bigint   NOT NULL
);

CREATE TRIGGER blob_no_update BEFORE UPDATE OR DELETE ON doc.blob
  FOR EACH ROW EXECUTE FUNCTION fstp_meta.refuse_mutation();
CREATE TRIGGER blob_no_truncate BEFORE TRUNCATE ON doc.blob
  FOR EACH STATEMENT EXECUTE FUNCTION fstp_meta.refuse_mutation();
