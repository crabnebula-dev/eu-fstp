# ADR-020: Per-account read marks for mailbox notices

Status: Proposed, pending Daniel's acceptance. Drafted 2026-11-13 by lane `product/decisions-1113`.

The number is the next free one after ADR-019. `docs/handoff/mailbox-design.md` section 2 kept ADR-020 free for this case.

## Context

- Daniel decided MB-Q1 on 2026-11-13 (`docs/handoff/mailbox-design.md`, "Decided by Daniel on 2026-11-13"): notices carry a per-account "read" mark. It needs a small store, so an ADR comes first.
- The mailbox of lane `m6/mailbox` is a pure read model (MB-D1). Work messages close themselves once their work is done (MB-D2). Notices never close, so without a mark a notice stays "to read" for ever.
- **I-27** A channel holds only ids, states, times and a link. **I-86** No reply names another account, an identity attribute, a bank detail or vault content.
- **I-24** Every call leaves one audit entry.
- The negotiation acknowledgement of R-NG-06 already lives in memory in the API core, until its ledger or outbox record exists (`fstp-api-core/src/content.rs`, lane W6).

## Decision

| Topic | Decision | Basis |
| --- | --- | --- |
| What is marked | A notice of the caller's own mailbox, by its stable message id, such as `notice.outcome:41`. Work messages are not marked: they close themselves | MB-D2 |
| Who marks | The account itself, through the web. One new operation, `me.mailbox.mark_read` (`POST /me/mailbox/read`, body `{"message": "<id>"}`), class Personal, no MCP tool | I-86, MB-Q4 waits |
| Check | The id must be a notice of the caller's mailbox at the call's instant, derived as `me.mailbox` derives it. Anything else is refused with `not_found` and rule `Input`, so the call reveals no other account's notices | R-AC-01, I-86 |
| What is stored | Per account, the set of marked message ids. A message id holds only a kind and decimal ids, so the store holds no text, name, email or score | I-27, I-86 |
| Bound | At most 4096 marks per account and 1 000 000 in all. Past either bound the mark is refused as unavailable, and nothing is evicted | Bounded memory, as the other API core stores |
| Reply | Each notice in `me.mailbox` carries `read: true` or `read: false`. Work messages carry no `read` member. `open` still counts work messages only | MB-D2 |
| Undo | None in this cut. A mark is idempotent | Smallest change |
| Audit | The call leaves its audit entry like any other call. The mark is not a domain fact, so no ledger record is written | I-24 |
| Durability | Interim: in memory in the API core, as the negotiation acknowledgement is. A restarted cell shows every notice as unread again. The durable home is one cell table, `mailbox_read_marks (account, message, marked_at)`, behind a port of the API core, once lane W6 wires the API core's own stores | `content.rs` precedent |

## Consequences

- A notice can be marked read, and the mailbox shows read and unread notices apart.
- No email changes. No pinned template moves (I-25).
- The mark adds no new data class. Erasure (I-24, R-AU-02) of an account removes its marks with the account's other personal rows once the table exists.

## Open points for Daniel

1. Accept the operation name, route and bounds above.
2. Whether a mark survives a restart before lane W6. Interim reading: it does not.
3. Whether a person may mark a notice unread again. Interim reading: no.
