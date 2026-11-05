-- The journey read model (ADR-015 "Storage and roles", SPEC/12-journey-ui.md
-- section 11, I-92, I-97). fstp_pgstore::CATALOGUE lists every table and
-- column below, in this order.
--
-- The rows are a projection of the ledger, which a replay rebuilds byte
-- for byte. Ids are 16 bytes and times are microseconds since the epoch
-- in UTC. No column holds text: a diary sentence is built at read time
-- from summary_key and the source record, and a text is a reference, an
-- id with its salted digest (R-NF-08). The app role holds INSERT and
-- SELECT only, so every row is append-only, the cursor included.

CREATE SCHEMA journey;

-- One diary entry of section 7.1. source_seq names a ledger entry.
-- subject_kind: 1 proposal or grant, 2 call, 3 payment request.
-- kind: the entry kind of section 7.2. deadline_zone: an index into the
-- shipped zone table. scope_mask: the coarse set of role classes.
CREATE TABLE journey.entry (
  entry_id      bytea    PRIMARY KEY CHECK (octet_length(entry_id) = 16),
  source_seq    bigint   NOT NULL CHECK (source_seq >= 1),
  subject_kind  smallint NOT NULL CHECK (subject_kind >= 1),
  subject_id    bytea    NOT NULL CHECK (octet_length(subject_id) = 16),
  kind          smallint NOT NULL CHECK (kind >= 1),
  occurred_at   bigint   NOT NULL,
  deadline_zone smallint CHECK (deadline_zone >= 0),
  scope_mask    integer  NOT NULL CHECK (scope_mask >= 0),
  summary_key   smallint NOT NULL CHECK (summary_key >= 1),
  supersedes    bytea    REFERENCES journey.entry (entry_id)
);

CREATE INDEX entry_subject ON journey.entry (subject_kind, subject_id, occurred_at);

-- The text references of an entry (I-97): ids and salted digests only.
CREATE TABLE journey.entry_text (
  entry_id bytea    NOT NULL REFERENCES journey.entry (entry_id),
  ord      smallint NOT NULL CHECK (ord >= 0),
  text_id  bytea    NOT NULL CHECK (octet_length(text_id) = 16),
  digest   bytea    NOT NULL CHECK (octet_length(digest) = 32),
  PRIMARY KEY (entry_id, ord)
);

-- One folded ledger entry per row. The last folded entry is the highest
-- last_ledger_seq of the projector.
CREATE TABLE journey.projection_cursor (
  projector       smallint NOT NULL CHECK (projector >= 1),
  last_ledger_seq bigint   NOT NULL CHECK (last_ledger_seq >= 1),
  PRIMARY KEY (projector, last_ledger_seq)
);

-- One completed leg of a proposal's route: one Transitioned record.
-- from_state and to_state: the position of the state in the domain's
-- state list, from 1.
CREATE TABLE journey.leg (
  proposal_id bytea    NOT NULL CHECK (octet_length(proposal_id) = 16),
  ord         integer  NOT NULL CHECK (ord >= 0),
  from_state  smallint NOT NULL CHECK (from_state >= 1),
  to_state    smallint NOT NULL CHECK (to_state >= 1),
  at          bigint   NOT NULL,
  source_seq  bigint   NOT NULL CHECK (source_seq >= 1),
  PRIMARY KEY (proposal_id, ord)
);

-- The start of a proposal's route at DRAFT, with the call it was
-- created in, whose frozen policy drives the overlay (NOTE 8).
CREATE TABLE journey.route_start (
  proposal_id bytea  PRIMARY KEY CHECK (octet_length(proposal_id) = 16),
  call_id     bytea  NOT NULL CHECK (octet_length(call_id) = 16),
  at          bigint NOT NULL,
  source_seq  bigint NOT NULL CHECK (source_seq >= 1)
);

-- The proposal of each assignment, which score and conflict records name
-- by the assignment only.
CREATE TABLE journey.assignment (
  assignment_id bytea  PRIMARY KEY CHECK (octet_length(assignment_id) = 16),
  proposal_id   bytea  NOT NULL CHECK (octet_length(proposal_id) = 16),
  source_seq    bigint NOT NULL CHECK (source_seq >= 1)
);
