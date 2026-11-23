# Funder visibility elements of the Horizon Europe profile

Status: the `acknowledgement` element is approved by Daniel, 2026-11-22, and wired into the product (ADR-036). The `emblem` element shows the logo Daniel supplied (ADR-034); its wording status stays pending.

Legal party: CrabNebula Ltd. Data Protection Officer (DPO): Daniel Thompson-Yvetot.

Code sites:

- `crates/fstp-report/profiles/horizon-europe/profile.v1.json`, `visibility_elements`: two keys, `acknowledgement` and `emblem`, each with a wording ref and the status `TODO(legal)`. Version 1 never changes (P-53).
- `crates/fstp-report/profiles/horizon-europe/profile.v2.json`: the same, but `acknowledgement` has the status `approved`.
- `crates/fstp-report/wording/horizon-europe/visibility/acknowledgement.txt`: the approved text, read by `fstp_report::wording`.
- `crates/fstp-report/src/profile/mod.rs`: `WordingStatus` has `PendingLegal` and `Approved`. The parser (`profile/parse.rs`) accepts `approved` only for a ref whose text the store holds.
- The funding card shows the sentence: `crates/fstp-brand/src/funding.rs`, `crates/fstp-api-core/src/funding.rs`, `crates/fstp-public/src/html.rs`, `web/src/shell/funding.ts` and `web/src/auth/funding.ts`. PDFs and emails take it from the card's text lines.
- Request items L-08 and L-09.

---

## Element `acknowledgement`

Shown as the last line of the funding card: in the footer of each page, in contract PDFs and in programme emails.

Approved by Daniel, 2026-11-22, with no disclaimer:

> {{programme.name}} is funded by the European Union under the Horizon Europe grant agreement {{action.number}}, {{action.acronym}}.

The slots read the programme's `identity.name`, `funder.action_number` and `funder.action_acronym`. A programme that lacks any of them shows no sentence. The branding page says which value is missing.

## Element `emblem`

Shown next to the acknowledgement.

The "Funded by the European Union" logo Daniel supplied on 2026-11-22, with the text alternative "Funded by the European Union" (ADR-034 section 1). Its size, clear space, colours and placement follow the European Commission's operational guidelines, cited in ADR-034 section 1a.

TODO(legal): L-08, whether the `emblem` element needs any wording beyond the statement the logo itself shows. Until Daniel says so, its status stays `TODO(legal)` in both profile versions.
