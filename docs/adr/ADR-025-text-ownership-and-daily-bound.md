# ADR-025: Text ownership and a daily size bound

Status: Proposed. Every value and rule below is interim, pending Daniel's acceptance. Drafted 2026-11-19 for issue 6 M9 (fast-pass security review of 2026-11-12), as ADR-024 was for the rate limits.

The number is the next free one after ADR-024.

## Context

- Issue 6 M9 (H-01): any session holder can append text records to the ledger through `PutText` (`crates/fstp-cell-core/src/decide.rs`).
- ADR-024 records the rule "Only an account that may write the text's owning object may put a text. Puts are limited per account and bounded in size per account per day". On 2026-11-18 Daniel accepted the per-account rate limit as the whole fix for then. The owning-object rule and the daily size bound stayed a design item.
- `PutText` carries only a text reference. It names no owning object and no size. No route takes text bytes yet: a test seals a text into the cell's text store in process, then records `PutText` over HTTP (`crates/fstp-celltest/src/cycle.rs`).
- A text in the ledger is personal data under ADR-007. Its erasure needs the erasure log, which a tenant admin requests (Daniel, 2026-11-15).

## Decision

| Topic | Decision |
| --- | --- |
| New command | `PutOwnedText { id, owner, len }` puts a text with an owner and a declared length in UTF-8 bytes. Its record is `OwnedTextPut { id, owner, by, len }`, where `by` is the account that put it |
| Owner forms | One form for now: `Account(account)`. A text of a proposal, a call or another object waits for the route that stores text bytes, and gets its form by amendment |
| Ownership rule | The caller may write the owner. For `Account(a)` that is `a` itself or a current tenant admin, who manages the tenant's accounts. Anyone else is refused as the wrong actor |
| Declared length | From 1 to `MAX_TEXT_LEN` bytes. A text store that takes the bytes later must refuse a body longer than the declared length |
| Daily bound | The declared lengths of the texts one account puts in one UTC day sum to at most `DAILY_TEXT_BYTES`. The putter is charged, not the owner, so a tenant admin cannot fill another account's day. The fold keeps the current day per account only |
| Session route | `POST` of a cell command by a session holder refuses `PutText` with 403. It takes `PutOwnedText`, under the per-account rate limit of ADR-024 |
| `PutText` itself | It stays for the cell's own tasks and the existing ledgers. Records `TextPut` already stored keep folding as before and count against no bound |

### Values

Interim, pending Daniel's acceptance. Each is one named constant in `crates/fstp-cell-core/src/text.rs`, so a later change is one line and its test.

| Limit | Value |
| --- | --- |
| `MAX_TEXT_LEN`, the longest declared text | 64 KiB (65 536 bytes) |
| `DAILY_TEXT_BYTES`, per putting account per UTC day | 1 MiB (1 048 576 bytes) |

## Consequences

- A session holder can no longer register a text with no owner, and one account cannot grow the ledger's text records without bound.
- The declared length binds nothing until a route stores text bytes. That route must check the body against it.
- A refused put over the daily bound is a guard refusal (`GuardFailed`). It is not a rate refusal, so the audit rule of ADR-024 for rate refusals does not apply.
- `PutText` is a cell command, not an operation of the `fstp-access` registry. The reference policy of the authorisation matrix does not change.

## Open points

- The owner forms for proposal, call and other object texts, with the write rule of each.
- Whether the daily bound should also charge the owner.
- Whether a tenant admin should put texts for other accounts at all, or only through a named operation.
