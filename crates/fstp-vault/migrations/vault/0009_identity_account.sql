-- The identity registration of each account (ADR-004 record of lane
-- L13). A registration binds an account to the vault identity whose
-- tuple data key T(X) derives the fact key F(X) of its bank details and
-- hardship evidence. identity_id is NULL once that identity is erased, so
-- the account must register again, as a new identity. The vault login
-- writes it with SELECT, INSERT and UPDATE, as every vault table.
CREATE TABLE vault.identity_account (
  account_id    uuid   PRIMARY KEY,
  identity_id   uuid   REFERENCES vault.identity,
  registered_at bigint NOT NULL
);
