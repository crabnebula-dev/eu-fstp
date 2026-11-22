-- The display name index of the App chain (SA-11 amendment, ADR-004
-- section "Written by lane L26"). Only c_<cell>_keys writes it, as every
-- keystore table. Each account's display name is a text sealed under its
-- data key in keystore.text. Its fingerprint is HMAC-SHA-256 of the
-- normalised name under a key derived from the Lookup key (KeyedDigest),
-- which erasure replaces. One fingerprint names one account in the
-- tenant: the UNIQUE constraint refuses a second as a second guard.
CREATE TABLE keystore.display_name (
  account     uuid  PRIMARY KEY,
  text_id     uuid  NOT NULL UNIQUE,
  fingerprint bytea NOT NULL UNIQUE,
  CONSTRAINT display_name_fingerprint_len CHECK (octet_length(fingerprint) = 32)
);
