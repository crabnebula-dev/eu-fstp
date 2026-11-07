-- The delivery log of the M6 dispatcher (M6 design sections 3.2 and 5.1,
-- I-25, I-26). fstp_pgstore::CATALOGUE lists every column below, in this
-- order.
--
-- One row per step of an attempt to send one ops.outbox message. Rows are
-- inserted only: the app role holds INSERT and SELECT, and a trigger
-- refuses UPDATE, DELETE and TRUNCATE for every role, the owner included.
-- The head of a message is its row with the highest (attempt, phase).
--
-- phase: 1 CLAIMED, 2 COMMITTING, 3 SENT, 4 TRANSIENT, 5 PERMANENT,
-- 6 IN_DOUBT. SENT, PERMANENT and IN_DOUBT are terminal, and a message has
-- at most one terminal row.
--
-- event and template_version are in clear on the COMMITTING row only, so
-- the I-25 trace reads without opening the body. They name no person.
-- body_digest is the SHA-256 of the rendered body sent at that attempt.
CREATE TABLE ops.delivery (
  outbox_id        uuid     NOT NULL REFERENCES ops.outbox (id),
  attempt          integer  NOT NULL CHECK (attempt >= 1),
  phase            smallint NOT NULL CHECK (phase BETWEEN 1 AND 6),
  at               bigint   NOT NULL,
  worker           uuid     NOT NULL,
  lease_until      bigint,
  event            bytea    CHECK (octet_length(event) = 32),
  template_version integer  CHECK (template_version BETWEEN 0 AND 65535),
  body_digest      bytea    CHECK (octet_length(body_digest) = 32),
  reply_code       smallint CHECK (reply_code BETWEEN 200 AND 599),
  PRIMARY KEY (outbox_id, attempt, phase),
  CHECK ((phase IN (1, 2)) = (lease_until IS NOT NULL)),
  CHECK ((phase = 2) = (event IS NOT NULL)),
  CHECK ((phase = 2) = (template_version IS NOT NULL)),
  CHECK ((phase = 2) = (body_digest IS NOT NULL)),
  CHECK (reply_code IS NULL OR phase IN (3, 4, 5))
);

CREATE UNIQUE INDEX delivery_one_terminal ON ops.delivery (outbox_id)
  WHERE phase IN (3, 5, 6);

CREATE TRIGGER delivery_no_update BEFORE UPDATE OR DELETE ON ops.delivery
  FOR EACH ROW EXECUTE FUNCTION fstp_meta.refuse_mutation();
CREATE TRIGGER delivery_no_truncate BEFORE TRUNCATE ON ops.delivery
  FOR EACH STATEMENT EXECUTE FUNCTION fstp_meta.refuse_mutation();
