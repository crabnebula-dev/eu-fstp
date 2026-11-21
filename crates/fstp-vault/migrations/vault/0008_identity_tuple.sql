-- The identity attribute tuples of the Vault chain (ADR-004 record of
-- lane L11, design section 3.5, G24). Each tuple is sealed in the FSB1
-- form under its own data key, whose keystore.data_key id is the
-- identity id. The key sits in an Attribute group, so an erasure batch
-- that removes it leaves every copy of the tuple sealed to a group
-- generation whose secret dies with the old root. The keys role writes
-- this table with the data key and the chain state in one transaction.
CREATE TABLE keystore.identity_tuple (
  identity_id uuid  PRIMARY KEY,
  group_id    uuid  NOT NULL,
  envelope    bytea NOT NULL CHECK (octet_length(envelope) BETWEEN 35 AND 4131)
);
