# M6 design: timeline engine, dispatcher and email

Milestone M6 in `SPEC/09-milestones.md`: "Timeline engine, dispatcher, email". Exit: I-25 to I-27 green under crash injection.

M6 also takes over three items that earlier milestones left to it: dispatch of the M4 outbox records (R-SB-04, R-EV-04, R-IR-02), corrigendum notification (I-53, M4 Q37 C) and the contractual notice email (I-40, M5 design section 0).

Status: draft for Daniel's review, written for a weekend build. Labels such as `L6-SMTP` or `Q1` exist only in this document. Crate, type, op and table names are proposals. Every `I-`, `R-`, `P-`, `TH-` and `ADR-` identifier is quoted from the repository.

Sources read: `SPEC/09-milestones.md`, `02-domain/{invariants,contractual-notices,policy-parameters}.md`, `01-requirements/functional.md` (R-NT, R-SB-04, R-GA-03, R-JV-04, R-PG-05), `03-architecture/{notifications,messaging}.md`, `07-test-plan/test-plan.md`, `06-threat-model` (TH-21), `docs/design/03-applicant-screens.md`, `docs/handoff/m4-design.md`, `m5-design.md`, and on `main`: `fstp-pgstore` (`ops.outbox`, `OutboxRow`), `fstp-domain/src/record.rs` (`OutboxEvent`), `fstp-cell/src/{engine/pg.rs,tasks/timeline.rs,egress.rs}`, `fstp-engine/src/sweep.rs`, `fstp-tls`, `fstp-mc`, `fstp-celltest/src/canary.rs` and the e2e cell's `auth.rs`, `control.rs` and `demo.rs`.

---

## 1. Scope

| In M6 | Out of M6 |
| --- | --- |
| Timeline engine: derive, schedule, cancel and fire events, persisted in the ledger | Matrix (B-05) and WhatsApp (B-03), so M8 stays deferred |
| Dispatcher over the existing `ops.outbox`, with a delivery log and at-most-once sending | Asynchronous bounces (DSN). They need an inbound mailbox. Synchronous 5xx replies are recorded |
| In-house SMTP submission client over `fstp-tls`, with a reply-parser fuzz target | SPF and DMARC probes. They need DNS, so the `Prober` keeps failing closed (M4 Q5) |
| In-house MIME builder, versioned default templates in English, DKIM signing | Tenant-edited templates and locales beyond English. The template record already carries a locale |
| Event sources: M4 outbox records, call windows (P-07, P-08), milestone reminders (P-31, P-33), corrigenda, contractual notices | Payment service levels, P-59, complaints (P-61 to P-64) and funder reporting periods. They join the derivation when their sources exist |
| The D13 sweep folds into the timeline engine | Full IANA zone rules. M6 renders UTC plus the offset recorded with the deadline |

### 1.1 What exists

- `ops.outbox` (`0003_app.sql`) with a unique `idem`, a per-row data key and sealed body. `OutboxRow` is a side effect of an append, but `fstp-cell/src/engine/pg.rs` always passes `outbox: Vec::new()`.
- `Record::OutboxEnqueued(OutboxEvent)` with `ProposalOutcome`, `IrcConcern`, `NotifiableConflict` and `BindingEnded`.
- `fstp-cell/src/tasks/timeline.rs`: a tick that issues System commands under ids bound to their occurrence, so a repeat is a duplicate.
- `fstp-engine/src/sweep.rs`: the four sweep kinds.
- `fstp-tls`: TLS 1.3 client and server over `fstp_rt::Connection`, roots from PEM.
- `fstp-mc` model checker, `fstp-prop`, `fstp-celltest` canaries, `fstp-pgtest`.
- The e2e cell's mailbox (`Mail { to, kind, link }`, `GET /test/mailbox`), shown on `/demo`.

---

## 2. Readings

Each reading is interim until Daniel confirms it. None weakens an invariant.

1. **Delivered means accepted.** For I-26, a message is delivered when the submission server answers 250 to the end of DATA. The dispatcher sends at most once. A message whose outcome is unknown becomes IN_DOUBT and is never sent again automatically.
2. **One path for every automated message (I-25).** Every `OutboxEnqueued` record becomes an immediate timeline event. No code sends mail except the dispatcher. Sign-in and invitation mails move onto it too, keyed by invitation id (last item of L6-API).
3. **Content rule (I-27).** Every email carries ids, states, dates, a link and the fixed bank-details sentence (`notifications.md`). No proposal title, text, score, concern text or person name appears. The IRC concern email says a notice is waiting. The contractual notice email carries the sealed notice text that M5 renders, which is the notice itself, not proposal content.
4. **R-SB-04 copy.** The copy email holds ids and times only, as `docs/design/03-applicant-screens.md` decides. The address the applicant gives is stored sealed in the text store. A rate limit of three copies per proposal per day applies (TH-21).
5. **Corrigendum recipients (I-53).** Every account with a proposal in the call: each lead and each bound team member, resolved when the event fires.
6. **Published Guides stay byte-identical.** `{{timeline.table}}` switches to the timeline engine only for publications after the switch. A test checks the bytes of an M4 Guide are unchanged.

---

## 3. Records and storage

### 3.1 Ledger records (envelope `CellRecord::Timeline`, new)

| Record | Fields | Rule |
| --- | --- | --- |
| `TemplateVersionRecorded` | template, version, locale, digest | Recorded once at first use. A version never changes (I-25) |
| `EventScheduled` | event, kind, source ref, source version, due, recorded offset | R-NT-01 |
| `EventCancelled` | event, superseded by | R-NT-01 AC: cancelled, never deleted |
| `EventFired` | event, messages: list of (outbox id, idem, template, version) | Same entry as the `OutboxRow`s it lists, and as any System command the event issues |

`event` is SHA-256 over `"fstp-event-v1" || kind || source ref || source version || offset`. For an immediate event the source is (ledger seq, record index). The fold refuses a second `EventFired` for an event.

`idem` is SHA-256 over `"fstp-msg-v1" || event || recipient || channel`. The recipient is the account id, or the digest of the given address for R-SB-04. This fixes the form the pgstore catalogue left open. The channel byte is 1 for email.

### 3.2 Database (`fstp-pgstore`, next free migration number)

`ops.outbox` stays as it is. One new table holds the delivery log:

```
ops.delivery (outbox_id uuid, attempt int, phase smallint, at bigint,
  worker uuid, lease_until bigint, event bytea, template_version int,
  body_digest bytea, reply_code smallint,
  PRIMARY KEY (outbox_id, attempt, phase))
```

- Phases: 1 CLAIMED, 2 COMMITTING, 3 SENT, 4 TRANSIENT, 5 PERMANENT, 6 IN_DOUBT.
- A partial unique index allows one terminal row (SENT, PERMANENT, IN_DOUBT) per `outbox_id`.
- The `app` role has INSERT and SELECT only. A trigger refuses UPDATE, DELETE and TRUNCATE (as `auth_log`).
- `event` and `template_version` are in clear on the COMMITTING row. They name no person, and they make the I-25 log readable without opening the body.
- The head of a message is its row with the highest (attempt, phase).

---

## 4. Timeline engine (`fstp-timeline`)

`derive(state, policy) -> BTreeSet<Event>` is a pure function of engine state. It reads the core state only (I-10). Kinds in M6:

| Kind | Source | Due | Recipients |
| --- | --- | --- | --- |
| `Immediate(OutboxEvent)` | Every `OutboxEnqueued` record | Its entry time | Per event: applicant, coordinator, or group removal for M8 (no email) |
| `Stage2Expiry`, `ReEnter`, `StartExecution`, `Complete` | The D13 sweep kinds | As `fstp_domain::due` | None. The fire entry carries the System command |
| `MilestoneReminder(offset)` | Effective contract milestones | Due minus 14 days, minus 3 days, due date (P-31) | Lead |
| `MilestoneOverdue` | Same | Due plus 7 days (P-33) | Lead and programme manager |
| `Corrigendum(n)` | `Tightening` of the effective-limits record | Its entry time | Reading 5 |
| `NoticeIssued` | M5 contractual notice record with its sealed PDF digest | Its entry time | Grantee parties |
| `CopyRequested` | New `OutboxEvent::CopyRequested { proposal, address }` | Its entry time | The given address |

Working days use the tenant calendar in `fstp-domain/src/time.rs` (P-40).

The task in `fstp-cell/src/tasks/timeline.rs` runs each tick:

1. Diff `derive` against the scheduled set. Append `EventScheduled` for new events and `EventCancelled` for events whose source version is superseded. An amended due date therefore cancels and reschedules (R-NT-01 AC).
2. For each scheduled event due at `now` and not fired, render each message and append one entry: `EventFired`, its `OutboxRow`s and any System command. The command id stays bound to the occurrence, as today.
3. A `NoticeIssued` event fires only when the notice record with its digest is folded and `doc.blob` holds the PDF (I-40). Otherwise it waits.

`sweep.rs` becomes a thin shim over `derive` for the four sweep kinds, so the M5 code that calls it still compiles.

---

## 5. Dispatcher (`fstp-dispatch`) and email

### 5.1 Attempt protocol

Each step is a named `Step`, which is also a crash point in tests.

| Step | Action |
| --- | --- |
| S1 claim | One transaction: `pg_advisory_xact_lock(outbox id)`, read the head, insert CLAIMED with attempt n and a lease (60 s) |
| S2 render | Open the sealed body, render the template version, compute `body_digest`. No write |
| S3 stage | TLS connect, EHLO, AUTH PLAIN, MAIL FROM, RCPT TO, DATA, stream the body without the final `.` |
| S4 commit point | Transaction with the lock: the head must still be this worker's CLAIMED attempt n. Insert COMMITTING with event, template version and digest. Otherwise QUIT without `.` |
| S5 send | Write `\r\n.\r\n`, read the reply |
| S6 record | Insert SENT on 250, TRANSIENT on 4xx, PERMANENT on 5xx |

Recovery, by any worker after a lease ends or at start:

- Head CLAIMED: a new attempt may start. The server never saw the end of DATA, so it discarded the message.
- Head COMMITTING: write IN_DOUBT. This covers a crash after S4, a lost reply in S5 and an S4 commit with an unknown outcome.
- Head TRANSIENT: retry with backoff (1, 5, 30 minutes, then hourly) up to 8 attempts, then PERMANENT.
- A permanent failure or IN_DOUBT raises an alert on the tenant admin's delivery list.

The attempt number is the fencing token. A stalled worker whose lease was taken over fails S4 and never sends `.`. So at most one end of DATA exists per message, and I-26 holds even with two workers and a lost lease.

### 5.2 SMTP client (`fstp-smtp`)

- Implicit TLS on port 465 only (RFC 8314), through `fstp-tls`. No STARTTLS, so no downgrade path.
- Reply parser for multi-line replies with bounded line length (1000 octets) and line count. Fuzz target `smtp_reply` from the first commit.
- Dot-stuffing and CRLF normalisation on the body. The client checks EHLO lists `AUTH PLAIN` and `8BITMIME` or sends 7-bit only.
- Timeouts per command (RFC 5321 section 4.5.3.2 values). Credentials are cell secrets and never logged.
- The client runs over any `fstp_rt::Connection`, so tests use the in-memory duplex.

### 5.3 Messages and templates (`fstp-mail`)

- RFC 5322 headers, RFC 2047 encoded words, quoted-printable text part, base64 PDF part when P-48 says attach.
- `Message-ID` is `<hex(idem)@sending-domain>`, stable across attempts, so a receiver can drop a duplicate. Headers `X-FSTP-Event` and `X-FSTP-Template` carry the event id and version.
- Templates are Rust values with a version and a digest. Placeholders come from a closed enum: ids, state tags, dates, amounts, links and counts. No variant holds a `TextRef`, a name or free text. A test enumerates the enum (I-27).
- Every template ends with the fixed bank-details sentence. Contractual notice wording and the non-selection wording are `TODO(legal)`.
- DKIM: relaxed/relaxed canonicalisation in-house, rsa-sha256 through aws-lc-rs. The per-tenant key is held in cell custody (ADR-004). DKIM lands last, behind a config flag.

### 5.4 Egress

A new `Destination::MailSubmission { host }` in `fstp-cell/src/egress.rs`, with the host from tenant configuration and port 465 only. The enum is closed under ADR-009, so ADR-018 amends it (Q2). The I-16 test that enumerates the enum gains the variant.

---

## 6. Ops and reads

| Op or read | Actor | Effect |
| --- | --- | --- |
| `proposal.request_copy` (exists) | Lead | Appends `OutboxEnqueued(CopyRequested)`, rate limited (reading 4) |
| `me.notices` (exists) | Any account | Reads real outbox rows for the account and their delivery phase |
| `tenant.deliveries` | Tenant admin | Per message: kind, event, template version, phase, attempts, reply code. No body, no address |
| `programme.timeline` | Programme manager | Scheduled, cancelled and fired events of a programme |

All are web only. MCP answers `Deny(NotExposed)`, as M5 reading 9. The authorisation matrix gains the two new reads.

---

## 7. Tests first: crash injection for I-25 to I-27

Each test names its ID. The property tests land red before the code.

**T1, simulated property test (`fstp-dispatch/tests/i25_i26_crash.rs`).** It uses `fstp-prop` and the scripted runtime. A run has 1 to 3 workers, 1 to 20 messages and a random schedule. Faults are drawn per step: a crash at any `Step`, a store commit that fails or has an unknown outcome, and sink faults (drop, 421, 451, 550, a lost final reply, a stall past the lease). Crashed workers restart from the store. The store is an in-memory model with the same constraints as `ops.delivery`. Checks:

- I-26: the sink accepted each `idem` at most once, across every attempt and worker.
- I-25: every accepted message has a COMMITTING row with the same body digest, an `EventFired` that lists it, and a recorded template version.
- No message is accepted for an event cancelled before it fired.
- Liveness, not an invariant: once faults stop, every message reaches a terminal phase.

**T2, model check (`fstp-celltest/src/mc/dispatch_model.rs`).** Two workers, one message, a crash at every step, exhaustive. The property is "at most one end of DATA".

**T3, PostgreSQL (`fstp-dispatch/tests/pg_crash.rs`, `fstp-pgtest`).** Two dispatcher instances against the real schema and a loopback TLS sink. Faults drop the pgwire connection at each step, following the `store_faults.rs` pattern. It also checks the partial unique index and the no-update trigger.

**T4, process kill (`e2e` CI job `m6-crash`).** Start the cell with its dispatcher and the sink, fire events for 60 seconds, send SIGKILL at random moments and restart. Then compare the sink with `ops.delivery` under the T1 checks. It runs one binary at a time (machine load cap).

**T5, I-27 canaries (`fstp-dispatch/tests/i27_canary.rs`).** Seed proposals, team names, identities, IRC concerns and copy addresses with `fstp-celltest` canaries. Fire every event kind with every template. Scan each raw SMTP transcript, each decoded MIME part (QP and base64) and each opened outbox body. A hit fails the test. A second test enumerates the placeholder enum.

Further rows:

- I-40: no `NoticeIssued` fires before the sealed PDF and its audit hash exist, under T1 crashes.
- I-53: a tightening yields corrigendum n and one message per affected account.
- R-NT-01 AC: an amended due date cancels and reschedules. R-NT-03 reruns T1. TH-21 checks the rate limit.
- Fuzz targets `smtp_reply` and `smtp_sink_command`.

---

## 8. Demo cell additions

The rule is the click-through check: each person reaches their work by clicking from sign-in.

- **Real path, fake server.** The e2e cell runs the real timeline task, dispatcher and SMTP client. They send to an in-process SMTP sink on loopback, with implicit TLS from the `fstp-tls` test CA and a demo credential. The sink lives in `fstp-api-testkit` and never ships.
- **Sent mail on `/demo`.** The existing message list reads the sink. Each row shows time, recipient, subject, template version, event id and delivery phase. `/demo/mail/{n}` shows the raw message as escaped text, PDF part named but not inlined.
- **Fault buttons.** "Refuse the next message (451)" and "Drop the connection after DATA". The audience then sees a retry, and an IN_DOUBT entry on the tenant admin's delivery list.
- **Clock links.** "Advance to milestone minus 14 days", "to due date", "to plus 7 days", so reminders and the escalation appear.
- **Scenes.** The M5 speedrun gains mail at each step: copy request at submission, NOT_SELECTED notice, a P-05 tightening with its corrigendum to every applicant, contract notice emails with the sealed PDF, and milestone reminders.
- **Playwright `e2e/mail/`.** From sign-in links only: the applicant requests a copy and the demo page lists it; the programme manager tightens P-05 and each applicant's corrigendum mail appears; the tenant admin opens the delivery list.

---

## 9. ADRs and dependencies

| Item | Status | Effect |
| --- | --- | --- |
| ADR-018, mail submission egress and DKIM keys (amends ADR-009) | To write in L6-EGR | Gates the production connector (Q2). Tests and the demo use the duplex and loopback |
| aws-lc-rs (SHA-256, RSA for DKIM), rustls through `fstp-tls` | ADR-001 Tier A, already used | No new crate |
| SMTP, MIME, base64, QP and DKIM canonicalisation | In-house | Fuzz targets for every parser |

No new crate or npm package.

---

## 10. Lanes

At most three lanes run at once. A lane starts when its dependencies have merged into `main`.

| Lane | Builds | Owns | Needs |
| --- | --- | --- | --- |
| L6-REC | Section 3: `Timeline` envelope and codec, idem function, `ops.delivery` migration and store API, `pg.rs` filling `outbox` from the batch. T1 store model and the I-26 property skeleton, red | `crates/fstp-cell-core/src/{lib,timeline}.rs`, `crates/fstp-pgstore/{migrations/app/<next>_delivery.sql,src/delivery.rs}`, `crates/fstp-cell/src/engine/pg.rs`, `crates/fstp-dispatch/src/store.rs` | None |
| L6-SMTP | Section 5.2: client, reply parser, fuzz target `smtp_reply`, the test sink with fuzz target `smtp_sink_command` | `crates/fstp-smtp/**`, `crates/fstp-api-testkit/src/smtp_sink.rs` | None |
| L6-MAIL | Section 5.3: MIME builder, default templates, placeholder enum, I-27 enum test, DKIM behind a flag | `crates/fstp-mail/**` | None |
| L6-TL | Section 4: `derive`, schedule and cancel diff, firing, sweep shim, R-NT-01 and I-40 tests | `crates/fstp-timeline/**`, `crates/fstp-engine/src/sweep.rs`, `crates/fstp-cell/src/tasks/timeline.rs` | L6-REC, L6-MAIL |
| L6-DISP | Section 5.1: worker, leases, recovery, alerts; T1, T2, T3, T5 | `crates/fstp-dispatch/**` (except `store.rs` until L6-REC merges), `crates/fstp-cell/src/tasks/dispatch.rs`, `crates/fstp-celltest/src/mc/dispatch_model.rs` | L6-REC, L6-SMTP, L6-MAIL |
| L6-EGR | Section 5.4, ADR-018, tenant mail configuration, cell secrets for the credential | `docs/adr/ADR-018-*`, `crates/fstp-cell/src/{egress,config}.rs` | L6-SMTP. Production use waits on Q1 and Q2 |
| L6-API | Section 6, `CopyRequested`, corrigendum and notice events, sign-in mails onto the dispatcher | `crates/fstp-access/src/{registry,reads}.rs`, `crates/fstp-api-core/src/{port,views}.rs`, `crates/fstp-domain/src/record.rs` (`OutboxEvent` only), `web/src/notices/**` | L6-TL, L6-DISP |
| L6-DEMO | Section 8 and T4 | `crates/fstp-api-testkit/src/bin/fstp-e2e-cell/**`, `e2e/mail/**`, `docs/handoff/m6-demo.md` | L6-API |
| L6-EXIT | Reruns, CI job `m6-crash`, exit audit with R-IDs and I-IDs | `docs/handoff/m6-exit-audit.md`, `.github/workflows/` M6 job | All above |

Waves: L6-REC, L6-SMTP and L6-MAIL first. Then L6-TL, L6-DISP and L6-EGR. Then L6-API and L6-DEMO. L6-EXIT closes. The demo shows mail after the second wave on the duplex sink. The notice events in L6-API need M5 lane L-CON; until it merges, `NoticeIssued` has no source and its test stays pending, not skipped.

Claims at exit: I-25, I-26, I-27, I-40, I-53, R-NT-01 to R-NT-04, R-SB-04, R-EV-04 (P-08 timing), R-IR-02 (email), R-GA-03. R-NT-05 is trivially met with email only and is claimed again in M8.

---

## 11. Questions for Daniel

Only questions that block a lane are listed.

**Q1. Trust roots for the production submission server (blocks production sending, not the exit or the demo).** `fstp-tls` takes roots as PEM, and no allowlisted crate ships a public root store (`egress.rs` notes the same gap for the service hosts).

- A: Each tenant names one submission relay and supplies its CA certificate as PEM, stored as a cell secret. The client trusts only that CA.
- B: An ADR adds a public root store crate to the allowlist.
- Recommendation: A. It adds no crate, pins the relay and matches a tenant-run or contracted relay.

**Q2. New egress destination (blocks L6-EGR merge, ADR-required).** ADR-009 closes the destination enum, and sending mail needs one more variant.

- A: Accept ADR-018: `MailSubmission { host }`, port 465 only, the host from tenant configuration, refused for CrabNebula hosts (I-38).
- B: Route mail through a CrabNebula-run relay as part of the control plane.
- Recommendation: A. It keeps mail inside the cell boundary and keeps the control plane free of message content.
