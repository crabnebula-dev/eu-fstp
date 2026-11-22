# ADR-036: Approved wording store, funder profile v2 and outcome email templates

Status: Proposed. Drafted 2026-11-22 by lane L35 (`prod/legal-wording`) before its code, as CLAUDE.md asks. Rows marked "Interim, pending Daniel" wait for his answer.

The number is the next free one. ADR-035 is lane L30's.

## Context

Daniel decided on 2026-11-22:

- `legal/README.md` Q7: build the wording store behind each funder profile wording ref, a second wording status `Approved`, and a new profile version `horizon-europe` v2. Version 1 never changes (P-53).
- L-08: the funding acknowledgement is approved, with no disclaimer, as drafted in `legal/funder-profiles/horizon-europe/visibility-elements.md`:
  "{{programme.name}} is funded by the European Union under the Horizon Europe grant agreement {{action.number}}, {{action.acronym}}."
  It shows in the funding card of ADR-034: web footers, public pages, contract PDFs and programme emails. A programme that lacks a slot value shows no sentence rather than a broken one.
- L-08: apply the official emblem usage rules to the funding card (ADR-034 section 1a).
- `legal/README.md` Q5: one email template per proposal outcome, wired to drafts A1 to A4 of `legal/09-emails.md`. The drafts stay "draft, pending Daniel's approval".

Before this record:

- `crates/fstp-report/profiles/horizon-europe/profile.v1.json` names two visibility elements, `acknowledgement` and `emblem`. Each holds a wording ref and the status `TODO(legal)`. The parser accepts no other status.
- The funding card showed the placeholder "EU funding acknowledgement: the approved wording is pending." on pages, and nothing in PDFs and emails.
- One template, `proposal-outcome` version 1, served every outcome through the `{state}` slot.

Binding rules: P-53 (a programme pins a profile version, which never changes), I-25 (a template version never changes), I-27 (emails carry slots only), I-68 (values are text, never markup), I-69 (branding cannot remove a mandatory element), R-RP-01 (reports pin their profile).

## Decision

### 1. The wording store

| Topic | Decision |
| --- | --- |
| Where | `crates/fstp-report/wording/<ref>.txt`, one file per approved wording ref, compiled in with `include_str!`. The first is `wording/horizon-europe/visibility/acknowledgement.txt` |
| Module | `fstp_report::wording`. A const table names each ref, its text file, who approved it and the date. Nothing else adds a text |
| Content | The text exactly as approved, with slots written `{{name}}`. No markup. A trailing newline of the file is not part of the text |
| Slots | A closed list: `{{programme.name}}`, `{{action.number}}`, `{{action.acronym}}`. They read the programme's `identity.name`, `funder.action_number` and `funder.action_acronym`. The names match the Guide's placeholders |
| Parser | An in-house parser splits a text into fixed parts and slots. An unknown slot, an unclosed `{{` or a stray `}}` is refused. Fuzz target `wording_text_parse` from the first commit |
| Rendering | Each slot value is trimmed. If any slot has no value, or only white space, the text renders to nothing. A value is inserted as text. Pages write the result as a text node (I-68), emails and PDFs as plain text |
| Who changes it | Only a code change, reviewed like any other. A new approval adds a file and a row |

### 2. The wording status and the parser rule

| Topic | Decision |
| --- | --- |
| New value | `WordingStatus::Approved`, stored as `"approved"` |
| Rule | The parser accepts `"approved"` only when the store holds a text for that exact ref. A profile cannot claim approval for text that does not exist. `TODO(legal)` stays `PendingLegal` |
| Tenant profiles | A tenant-owned profile parses with the same rule. Its refs start with its own id, so it can never claim a shipped approval. Interim, pending Daniel |

### 3. Profile version 2

| Topic | Decision |
| --- | --- |
| File | `crates/fstp-report/profiles/horizon-europe/profile.v2.json`. The outputs, fields and periods equal v1. The `acknowledgement` element is `approved`. The `emblem` element stays `TODO(legal)`, since Daniel approved no emblem wording |
| v1 | Unchanged byte for byte. A test pins its SHA-256 (`4b0f1269...5e06`) |
| Shipped list | v1 and v2. `for_p53` resolves both. Reports keep the version their programme pins (R-RP-01) |
| Pinning v2 in P-53 | Out of scope. The programme compiler and the Guide know v1 only. Interim, pending Daniel |

### 4. Which version the funding card reads

The acknowledgement on a card comes from the newest shipped version of the programme's P-53 profile id whose `acknowledgement` element is `Approved`.

Reason: every programme today pins v1, and v1 never changes. Reading only the pinned version would keep the sentence away from every programme, including the pilot. The card is presentation, not a report output, so it pins nothing. Reports still pin their version.

A programme whose P-53 names a tenant-owned profile, or no profile, shows no sentence. Interim, pending Daniel.

### 5. Where the sentence shows

| Surface | Decision |
| --- | --- |
| Public pages, `/app/` pages, sign-in pages | The last line of the card, as a text paragraph. The placeholder "EU funding acknowledgement: the approved wording is pending." is gone. A footer with no programme card shows the logo only |
| `GET /brand/funding` | Each card gains `acknowledgement` (the rendered sentence or `null`) and `acknowledgement_missing`, a list of the values that keep it from showing: `programme_name`, `action_number`, `action_acronym` or `profile` |
| Contract PDFs and programme emails | The last of the card's text lines (`FundingCard::text_lines`) |
| The branding page | Under "Funding card", one plain line per active programme without the sentence. It names the programme, each missing value and the editor step that holds it. Example: "SuperSAFE: the funding sentence is not shown. Missing: the acronym (step 1, Funder and instrument). The programme editor asks for these values before activation, so ask your technical administrator to fill them in." |

Interim, pending Daniel: an active programme cannot edit its artefact fields in the creator today (only P-09). A gap found after activation therefore needs a new programme version or an operator fix. The branding page says what is missing, so the gap is visible.

### 6. Emblem usage rules (L-08)

The rules come from the official source recorded in ADR-034 section 1a, with its URL and title. This lane read the document and applied only what it states. Details and the interim readings are there.

### 7. One outcome email template per outcome (Q5)

| Topic | Decision |
| --- | --- |
| Outcomes in the code | The domain enqueues an outcome notice (`OutboxEvent::ProposalOutcome`) only for INELIGIBLE today (`fstp-domain/src/decision.rs`). The state tags that are outcomes are NEGOTIATION (selected), NOT_SELECTED, INELIGIBLE and DECLINED. The code has no reserve list. DEFERRED is a carry-over to the next call |
| New template ids | `outcome-selected` (A1, NEGOTIATION), `outcome-not-selected` (A2, NOT_SELECTED), `outcome-ineligible` (A3, INELIGIBLE), `outcome-declined` (A4, DECLINED). Each is version 1. They are appended to `TemplateId::ALL`, so the ledger codes of the older ids stay |
| Any other state | `proposal-outcome` version 1, unchanged (I-25) |
| Slots | A1 to A4 use `{proposal}`, `{when}` and `{link}` only. No `{state}` |
| Where it is chosen | `fstp_timeline`: the immediate firing of the outbox record and the delivery log read (`event_template`) both call `outcome_template(state)` |
| Status | Draft wording, pending Daniel's approval. Each template carries `TODO(legal)`. A2 and A3 do not name the complaint deadline: TODO(legal) in `legal/09-emails.md` |

## Consequences

- New: one module and one text file in `fstp-report`, one profile file, one fuzz target, four template versions. No new crate and no new dependency.
- `FundingCard` gains the acronym and the rendered acknowledgement. Its JSON gains two members.
- `fstp_brand::emblem::FUNDING_ACKNOWLEDGEMENT` is removed: the sentence is per programme now.
- The demo cell's review and applicant scenes save the SuperSAFE programme name, grant agreement number 101342989 and acronym before activation, so their cards show the sentence. The test kit's seeder holds saved creator values again after a setup step replays the ledger (`FakeEngine::rehold`), as a production shell does from its value store.

## Open questions for Daniel

1. Interim, pending Daniel: cards read the newest approved version of the programme's profile, not the pinned one (section 4).
2. Interim, pending Daniel: P-53 cannot pin v2 yet. The programme compiler and the Guide know v1 only (section 3).
3. Interim, pending Daniel: tenant-owned profiles never show a shipped approved sentence (section 2).
4. TODO(legal): approve the outcome drafts A1 to A4 (`legal/09-emails.md`), and say whether A2 and A3 must name the complaint deadline.
5. Interim, pending Daniel: the code enqueues an outcome notice only for INELIGIBLE. Notices for NOT_SELECTED, NEGOTIATION and DECLINED need the domain to enqueue them. That is a domain change outside this lane. The templates and their selection are ready.
6. The demo seeds only SuperSAFE. No ELFA programme is seeded, so ELFA 101298715 does not show in the demo.
