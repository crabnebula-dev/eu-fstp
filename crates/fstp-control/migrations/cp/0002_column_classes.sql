-- The checks of the column classes Daniel gave on 2026-11-07 (Q-A,
-- m4-design section 15.0, design section 4.5, R-NF-08, I-19).
-- fstp_control::CATALOGUE lists the classes.

-- Infrastructure (ADR-009): a host name of the closed grammar the
-- endpoint check already uses. endpoint keeps its check of migration 1.
ALTER TABLE cp.route ADD CONSTRAINT route_host_grammar
  CHECK (host ~ '^[a-z0-9.-]{1,253}$');

-- PublicKeyMaterial: a DER SubjectPublicKeyInfo and a COSE public key,
-- whose encodings have no fixed length, so each is bounded.
ALTER TABLE cp.cluster ADD CONSTRAINT cluster_server_spki_len
  CHECK (octet_length(server_spki) BETWEEN 1 AND 4096);
ALTER TABLE cp.staff_credential ADD CONSTRAINT staff_credential_cose_key_len
  CHECK (octet_length(cose_key) BETWEEN 1 AND 4096);

-- OpaqueReference: 1 to 64 bytes
-- (fstp_migrate::catalogue::OPAQUE_REFERENCE_MAX_LEN).
ALTER TABLE cp.cell ADD CONSTRAINT cell_org_ref_len
  CHECK (octet_length(org_ref) BETWEEN 1 AND 64);
ALTER TABLE cp.custody_entry ADD CONSTRAINT custody_entry_key_ref_len
  CHECK (key_ref IS NULL OR octet_length(key_ref) BETWEEN 1 AND 64);
ALTER TABLE cp.operator_ticket ADD CONSTRAINT operator_ticket_case_ref_len
  CHECK (octet_length(case_ref) BETWEEN 1 AND 64);
