# M6 demo: mail through the real timeline and dispatcher

Lane L6-DEMO, branch `m5/demo`, written 2026-11-12. Read it with `docs/handoff/m6-design.md` sections 7 and 8 and `docs/handoff/m5-demo.md`. Every address and text is synthetic.

## What runs

`crates/fstp-api-testkit/src/bin/fstp-e2e-cell/maildemo.rs` runs the real parts of M6 against the test sink, every 700 ms:

1. A mirror folds the engine ledger into a `fstp_cell_core::CellState`, one entry at a time. The fake engine folds a few entries that the cell's fold refuses, such as a Guide published from an out-of-band spec. The mirror skips those and counts them on the demo page.
2. `fstp_timeline::plan` and `firing` schedule and fire the due events. The mirror folds each firing, so an event fires once. The sweep System commands run in `pump.rs` on the real engine.
3. `fstp_timeline::message::MessageSpec::compose` builds each message with `fstp_mail`. A message holds ids, times and a link only (I-27).
4. `fstp_dispatch::Worker` sends it through `SmtpTransport` over implicit TLS to the sink (`fstp_api_testkit::smtp_sink`), with the attempt protocol of I-25 and I-26 over an in-memory delivery log. The worker keeps the cell clock, so a retry comes with the clock links.

## What the demo page shows

- Under "Mail through the dispatcher": every message with its subject, recipient, template version, event id, delivery phase and sink time, and a link to the raw message (`/demo/mail/{n}`, escaped text).
- Under each person: the messages sent to that person.
- Fault buttons: "Refuse the next message (451)", "Drop the connection after DATA" and "Accept, then lose the reply". Each applies once. A 451 shows TRANSIENT, then SENT after "+60 minutes". A lost reply shows COMMITTING, then IN_DOUBT after "+60 minutes", and the message is never sent again (I-26).
- Click path: choose the applicant scene `DEFERRED_AFTER_CONCERN`, refresh the demo page, open "raw message" under the lead. The concern notice mail names the proposal and links `/app/notices`. The concern text stays on the platform (R-IR-02, I-27). Choose `STAGE2`, sign in as the lead, request a copy on the proposal page, refresh the demo page: the copy mail to the given address appears (R-SB-04).

## Playwright

`e2e/mail/mail.spec.ts`, four tests, all passing: the concern mail holds ids and a link only; a copy request is listed with its mail; a 451 refusal is retried and sent once; a lost reply ends IN_DOUBT and is never resent. The people sign in from the demo page.

## Covered

R-SB-04, R-IR-02 (email), R-NT-03, I-25, I-26, I-27. T4 of the design (process kill with random SIGKILL) is not run: it is the CI job `m6-crash` of lane L6-EXIT.

## Decisions and open questions for Daniel

1. **Duplex versus loopback.** The sink listens on loopback with TLS from the `fstp-tls` test CA, the form the design names for the demo cell. No duplex pipe is used.
2. **Per-cell mirror.** Only cell `a` runs the mail loop. A scene change starts a new mirror and a new delivery log.
3. **Copy address.** The ledger holds only the digest of the sealed address, so the demo mails the copy to `requested-copy@e2e.invalid`. Open: resolve the sealed text through the text store, as the production dispatcher will.
4. **Corrigendum on a P-05 tightening is not in the spec.** It needs a studio edit of P-05 on an active programme with an applicant bound to a proposal. No seed has that pair, and the studio has no wire-level helper. Open for a later pass.
5. **Milestone reminders and contract notice mails.** The timeline has no source for them yet (`kind::MILESTONE_REMINDER`, `NOTICE_ISSUED`), so the demo cannot send them. The clock links "due minus 14 days", "due" and "due plus 7 days" exist and will show them once the sources land.
6. **Delivery list for the tenant admin.** The demo page carries the phases. The `/app` delivery list of the tenant admin reads the fake cell's `deliveries` read, which is empty. Open: fill `FakeOutbox::deliveries` from the demo delivery log.
