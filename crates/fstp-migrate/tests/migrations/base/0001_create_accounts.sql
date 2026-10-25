-- Accounts of a synthetic test tenant. Test fixture only.
CREATE TABLE accounts (
    id bigint PRIMARY KEY,
    handle text NOT NULL UNIQUE
);

COMMENT ON TABLE accounts IS 'synthetic; test only';
