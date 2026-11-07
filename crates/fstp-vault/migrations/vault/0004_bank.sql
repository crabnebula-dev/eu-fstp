-- M5 lane L-VAULT: the bank and hardship fact kinds 14 to 18 (I-33, I-86,
-- R-PR-04, M5 design 12.1). Their bodies are sealed like every other fact.
ALTER TABLE vault.fact DROP CONSTRAINT fact_kind_check;
ALTER TABLE vault.fact ADD CONSTRAINT fact_kind_check
  CHECK (kind BETWEEN 1 AND 18 AND kind <> 5);
