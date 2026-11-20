-- The keystore of the App chain in its tables (ADR-004, decided by
-- Daniel on 2026-11-20; design section 3.5 of the production MCP design).
-- Only c_<cell>_keys writes them. Every column that holds key material or
-- content is sealed: wrapped seal keys and the chain state under custody,
-- group and signer secrets under S(e), data keys under their group key,
-- and texts under their data key.

-- The digest of the custody destroy receipt (PublicDigest). The full
-- receipt column of migration 3 stays empty: the keystore keeps the
-- digest only, as the KeyEpochDestroyed record names it.
ALTER TABLE keystore.root ADD COLUMN receipt_digest bytea;
ALTER TABLE keystore.root ADD CONSTRAINT root_receipt_digest_len
  CHECK (receipt_digest IS NULL OR octet_length(receipt_digest) = 32);

-- The planner's chain state, sealed under S(epoch) (Sealed), with the
-- epoch it is sealed under, the keyed index groups, and the request id
-- of the start-up unwrap whose key record is still owed (ADR-004
-- "Reconciliation", the start-up exception).
CREATE TABLE keystore.chain (
  chain          smallint PRIMARY KEY,
  epoch          bigint   NOT NULL,
  state          bytea    NOT NULL,
  lookup_group   uuid,
  login_group    uuid,
  startup_unwrap uuid
);

-- A text sealed under its data key, in the FSB1 form, with the group
-- generation of its seal context (design section 5.6).
CREATE TABLE keystore.text (
  id         uuid    PRIMARY KEY,
  dek        uuid    NOT NULL UNIQUE,
  generation integer NOT NULL,
  envelope   bytea   NOT NULL
);

-- A composite level 2 signing key, by purpose and generation. The current
-- generation holds its secret sealed under S(epoch). A replaced one keeps
-- its public key only, so earlier signatures stay verifiable.
CREATE TABLE keystore.signer (
  purpose       smallint,
  generation    integer,
  public_key    bytea    NOT NULL,
  created_at    bigint   NOT NULL,
  epoch         bigint,
  sealed_secret bytea,
  PRIMARY KEY (purpose, generation),
  CONSTRAINT signer_public_key_len
    CHECK (octet_length(public_key) BETWEEN 1 AND 1984),
  CONSTRAINT signer_sealed_with_epoch
    CHECK ((epoch IS NULL) = (sealed_secret IS NULL))
);

-- The keyed login email index (design section 4.2, Q22): the account of
-- each HMAC-SHA-256(Lookup, normalised address) (KeyedDigest).
CREATE TABLE keystore.login_digest (
  digest  bytea PRIMARY KEY,
  account uuid  NOT NULL,
  CONSTRAINT login_digest_len CHECK (octet_length(digest) = 32)
);

-- The text that holds each account's login email.
CREATE TABLE keystore.login_text (
  account uuid PRIMARY KEY,
  text_id uuid NOT NULL UNIQUE
);

-- The texts whose ledger erasure request joined the chain state.
CREATE TABLE keystore.erasure_request (
  text_id uuid PRIMARY KEY
);
