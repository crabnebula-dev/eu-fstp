# ADR-036: Approved wording store, funder profile v2 and outcome email templates

Status: Proposed. Drafted 2026-11-22 by lane L35 (`prod/legal-wording`) before its code, as CLAUDE.md asks. Rows marked "Interim, pending Daniel" wait for his answer. Updated 2026-11-23 by lane L38 (`prod/outcomes-funding`) with Daniel's decisions of that day: every outcome sends its email (section 7), everything moves to profile v2 (section 8), and the demo seeds ELFA (section 9).

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
| Pinning v2 in P-53 | Decided by Daniel, 2026-11-23: everything moves to v2. Section 8 |

### 4. Which version the funding card reads

Decided 2026-11-23 (section 8): the acknowledgement on a card comes from the version the programme's P-53 pins, moved to its current version through the successor table (`fstp_report::profile::approved_acknowledgement_at`). Every new programme pins v2, and a v1 programme moves to v2 (section 8), so the card reads v2. A version with no approved acknowledgement shows no sentence.

Until 2026-11-23 the card read the newest approved version of the profile id, since every programme pinned v1.

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
| Outcomes in the code | Decided by Daniel, 2026-11-23: all four outcome emails are sent. The domain enqueues an outcome notice (`OutboxEvent::ProposalOutcome`) in the batch of each move into an outcome: NEGOTIATION (selected) from the completing IRC validation, NOT_SELECTED from the stage 1 close and from the cut-off, INELIGIBLE from the failed knock-out, and DECLINED from the decline after a concern and from the decline of a negotiation (`crate::decision::outcome_notice`). The lifecycle and money references expect the same notice. The code has no reserve list. DEFERRED is a carry-over to the next call and sends no outcome email. Tests: `i27_every_outcome_enqueues_its_notice` |
| I-27 | The notice names the proposal and the state only. The email carries ids, time and a link, never a reason, a score or a criterion |
| Calibration consent | A notice that is not INELIGIBLE opens calibration consent (I-37 reading of 2026-11-13), so a selected, not selected or declined proposal can be asked once its notice is committed. Interim, pending Daniel: the selected notice opens consent too |
| New template ids | `outcome-selected` (A1, NEGOTIATION), `outcome-not-selected` (A2, NOT_SELECTED), `outcome-ineligible` (A3, INELIGIBLE), `outcome-declined` (A4, DECLINED). Each is version 1. They are appended to `TemplateId::ALL`, so the ledger codes of the older ids stay |
| Any other state | `proposal-outcome` version 1, unchanged (I-25) |
| Slots | A1 to A4 use `{proposal}`, `{when}` and `{link}` only. No `{state}` |
| Where it is chosen | `fstp_timeline`: the immediate firing of the outbox record and the delivery log read (`event_template`) both call `outcome_template(state)` |
| Status | Draft wording, pending Daniel's approval. Each template carries `TODO(legal)`. A2 and A3 do not name the complaint deadline: TODO(legal) in `legal/09-emails.md` |

### 8. Everything on profile v2 (Daniel, 2026-11-23)

Daniel chose "everything v2": programmes pin horizon-europe profile v2, not only the card.

| Topic | Decision |
| --- | --- |
| New programmes | `fstp_programme::FunderProfile::horizon_europe()` is version 2. The API core opens every new draft on v2 (`creator::default_profile`). The blank spec, the shipped templates and the SuperSAFE fixture pin v2. Activation records the policy with P-53 v2 |
| v1 | Never changes, byte for byte. Its SHA-256 test stays. `FunderProfile::horizon_europe_v1()` still exists so that an older draft can be read |
| The successor table | `fstp_report::profile::SUCCESSORS` and `fstp_programme::FunderProfile::current` name horizon-europe v1 as replaced by v2. A successor is declared only when its outputs, fields and reporting periods equal the older version's, so the move changes no report content. Test: `adr036_q2_successor_keeps_outputs_fields_and_periods` |
| The compiler | `FunderProfile::for_policy_ref` reads a v1 or v2 reference and returns the current version, v2. `compile` accepts a spec whose P-53 names an older shipped version of the profile it compiles under, and writes that profile's own P-53. Any other version is refused, as before (`ProfileMismatch`) |
| How a v1 programme moves | Automatic and recorded, with no operator step (usability rule). The next policy version the creator composes for the programme pins v2: a step save, a start, or the P-09 save of an active programme. The core `EditPolicy` records it in the ledger as any other value. Nobody chooses, confirms or schedules the move |
| Until it moves | The funding card reads the programme's pin moved through the successor table, so it shows the v2 sentence at once (section 4). Reports and the public footer read the pin the ledger holds, so an output always names the recorded version (R-RP-01) |
| Published calls | A call published under v1 keeps v1, since P-53 is frozen at publication (I-12). Its reports pin v1. v1 and v2 give the same outputs, fields and periods |
| Clone start | A clone between programmes on v1 and v2 of the same profile is allowed. Both move to v2 |
| The Guide | `fstp_guide::SHIPPED_VERSIONS` names the versions of each shipped profile: horizon-europe 1 and 2. Both use the shipped Guide template `guide.v1.md`, since v2 changes only the acknowledgement's wording status, not the Guide. `ShippedProfiles::profile_at(name, version)` refuses an unknown version, and the creator reads the Guide for the draft's P-53 name and version. Test: `adr036_q2_guide_knows_v1_and_v2` |

Interim, pending Daniel: a v1 programme that never gets another policy version keeps v1 in its ledger. Its card still shows the v2 sentence. A move with no save at all would need a System policy command, which this lane did not add.

### 9. ELFA in the demo (Daniel, 2026-11-23)

| Topic | Decision |
| --- | --- |
| Programme | The demo cell seeds ELFA (grant agreement 101298715, acronym "ELFA") as a second active programme of the same CrabNebula tenant, beside SuperSAFE, in every scene that seeds SuperSAFE |
| Funding card | Saved before activation through `creator.save_fields`: the name "ELFA", the grant agreement number 101298715, the acronym "ELFA", the coordinator "CrabNebula Ltd" and the contact "privacy@crabnebula.dev". Its card shows the acknowledgement |
| Public slug | `elfa`, so its public pages sit beside `/p/supersafe/` |
| Call | One published call, "ELFA open call 2026", on the SuperSAFE call's dates |
| Staff | Two staff accounts of its own: an ELFA programme manager and an ELFA call drafter. The demo personas keep only their SuperSAFE roles, so each still reaches their work by clicking from sign-in as before |
| Data | Synthetic text only. A grant agreement number is a public fact of the action, not personal data |

## Consequences

- New: one module and one text file in `fstp-report`, one profile file, one fuzz target, four template versions. No new crate and no new dependency.
- `FundingCard` gains the acronym and the rendered acknowledgement. Its JSON gains two members.
- `fstp_brand::emblem::FUNDING_ACKNOWLEDGEMENT` is removed: the sentence is per programme now.
- The demo cell's review and applicant scenes save the SuperSAFE programme name, grant agreement number 101342989 and acronym before activation, so their cards show the sentence. Since 2026-11-23 they also seed ELFA (section 9). The test kit's seeder holds saved creator values again after a setup step replays the ledger (`FakeEngine::rehold`), as a production shell does from its value store.

## Open questions for Daniel

1. Decided 2026-11-23: cards read the programme's own pin, moved to v2 through the successor table (sections 4 and 8).
2. Decided by Daniel, 2026-11-23: everything on v2. New programmes pin v2, and a v1 programme moves at its next policy version, recorded in the ledger with no operator step (section 8). Interim, pending Daniel: a v1 programme with no further policy version keeps v1 in its ledger.
3. Interim, pending Daniel: tenant-owned profiles never show a shipped approved sentence (section 2).
4. TODO(legal): approve the outcome drafts A1 to A4 (`legal/09-emails.md`), and say whether A2 and A3 must name the complaint deadline.
5. Decided by Daniel, 2026-11-23: all four outcome emails are sent. The domain enqueues the notice for NEGOTIATION, NOT_SELECTED, INELIGIBLE and DECLINED (section 7). Interim, pending Daniel: the selected notice opens calibration consent like the others.
6. Decided by Daniel, 2026-11-23: the demo seeds ELFA (101298715) beside SuperSAFE, with its own funding card and one call (section 9). Interim, pending Daniel: ELFA has staff accounts of its own and no demo persona.
