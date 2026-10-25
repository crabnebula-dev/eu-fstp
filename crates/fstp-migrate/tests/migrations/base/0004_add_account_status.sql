-- R-NF-06: an update that changes the schema and keeps the data.
ALTER TABLE accounts ADD COLUMN status text NOT NULL DEFAULT 'active';
UPDATE accounts SET status = 'legacy' WHERE id = 1;
