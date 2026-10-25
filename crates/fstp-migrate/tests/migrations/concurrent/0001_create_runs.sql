CREATE TABLE runs (migration int NOT NULL, backend int NOT NULL DEFAULT pg_backend_pid());
-- Hold the transaction open so that concurrent runners overlap.
SELECT pg_sleep(0.3);
INSERT INTO runs (migration) VALUES (1);
