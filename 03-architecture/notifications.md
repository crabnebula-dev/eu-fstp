# Timeline engine and notifications

## Timeline engine

Timeline events are derived from four sources:

- calls: submission deadline, stage 2 window (P-07), non-selection notices (P-08),
- contracts: milestone due dates and deliverable promises,
- payment requests: review and approval service levels,
- policy reminders: reminder offsets (P-31) and escalation rules (P-33),
- funder profile: reporting period ends and periodic report deadlines,
- complaints: response and escalation deadlines (P-61 to P-64),
- payments: target release time (P-59).

Events are stored in PostgreSQL with a reference to their source record and version. When a source changes, for example a contract amendment, affected events are recomputed. Superseded events are cancelled, not deleted.

All times are stored in UTC. Each deadline records the time zone it was set in. Deadlines in working days use the tenant calendar (P-40). Messages render times in the recipient's time zone and the deadline's own zone.

## Reminder pattern (default, configurable via P-31 and P-33)

| Offset | Recipient | Purpose |
| --- | --- | --- |
| Due minus 14 days | Grantee | Upcoming deliverable |
| Due minus 3 days | Grantee | Final reminder |
| Due date | Grantee | Due today, with payment request link |
| Due plus 7 days | Grantee and programme manager | Overdue notice and escalation |

## Dispatcher

- A transactional outbox in PostgreSQL holds every message to send.
- Each message has an idempotency key of event, recipient and channel (I-26).
- Workers retry transient failures and stop on permanent ones.
- Delivery status and bounces are recorded.
- Every send is logged with event identifier and template version (I-25).

## Channels

Email is the primary channel and the durable record for contractual notices. Matrix and WhatsApp are opt-in per user (`messaging.md`).

## Content rules

- Messages contain the minimum needed plus a link to the authenticated platform.
- No proposal content, scores, deliberation or other people's identity attributes leave the platform through any channel (I-27).
- Reviewer references use pseudonymous handles when P-11 is anonymous.
- No message ever asks for bank details or links to a bank detail change. Every message states that bank details change only inside the platform.

## Email

- SMTP submission client written in-house, with TLS.
- DKIM signing per tenant sending domain. SPF and DMARC alignment are checked at tenant setup.
- Templates are tenant-owned, versioned and localisable.
