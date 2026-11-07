-- The checks of the column classes Daniel gave on 2026-11-07 (Q-A,
-- m4-design section 15.0, design section 4.5, R-NF-08), as the
-- application set's migration 8 adds them. The links and ack_link
-- already have their 32-byte checks.

-- The encoded witness receipt, at most
-- fstp_audit::anchor::RECEIPT_ENCODED_LEN (3479) bytes (Signature).
ALTER TABLE vault_audit.anchor ADD CONSTRAINT anchor_receipt_len
  CHECK (octet_length(receipt) BETWEEN 1 AND 3479);

-- The custody handle (OpaqueReference) and destroy receipt (Signature).
ALTER TABLE keystore.root ADD CONSTRAINT root_handle_len
  CHECK (octet_length(handle) BETWEEN 1 AND 64);
ALTER TABLE keystore.root ADD CONSTRAINT root_receipt_len
  CHECK (receipt IS NULL OR octet_length(receipt) BETWEEN 1 AND 3479);

-- A group public key, at most the composite public key of 1984 bytes
-- (PublicKeyMaterial).
ALTER TABLE keystore.group_key ADD CONSTRAINT group_key_public_key_len
  CHECK (octet_length(public_key) BETWEEN 1 AND 1984);
