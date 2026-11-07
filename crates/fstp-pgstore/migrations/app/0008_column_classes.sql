-- The checks of the column classes Daniel gave on 2026-11-07 (Q-A,
-- m4-design section 15.0, design section 4.5, R-NF-08). Each column of a
-- public class or of the opaque reference class is a bytea checked by
-- length, so it never holds content.

-- A SHA-256 over the command (PublicDigest).
ALTER TABLE auth.challenge ADD CONSTRAINT challenge_action_digest_len
  CHECK (action_digest IS NULL OR octet_length(action_digest) = 32);

-- The encoded witness receipt, fields and composite signature together:
-- at most fstp_audit::anchor::RECEIPT_ENCODED_LEN (3479) bytes
-- (Signature).
ALTER TABLE audit.anchor ADD CONSTRAINT anchor_receipt_len
  CHECK (octet_length(receipt) BETWEEN 1 AND 3479);

-- The custody handle, at most fstp_custody::keyd::MAX_HANDLE_LEN (64)
-- bytes (OpaqueReference), and the custody destroy receipt (Signature),
-- bounded like the anchor receipt.
ALTER TABLE keystore.root ADD CONSTRAINT root_handle_len
  CHECK (octet_length(handle) BETWEEN 1 AND 64);
ALTER TABLE keystore.root ADD CONSTRAINT root_receipt_len
  CHECK (receipt IS NULL OR octet_length(receipt) BETWEEN 1 AND 3479);

-- A group public key, at most the composite public key of 1984 bytes,
-- the longest public key the keystore holds (PublicKeyMaterial).
ALTER TABLE keystore.group_key ADD CONSTRAINT group_key_public_key_len
  CHECK (octet_length(public_key) BETWEEN 1 AND 1984);

-- The idempotency key, a 32-byte digest (OpaqueReference).
ALTER TABLE ops.outbox ADD CONSTRAINT outbox_idem_len
  CHECK (octet_length(idem) BETWEEN 1 AND 64);
