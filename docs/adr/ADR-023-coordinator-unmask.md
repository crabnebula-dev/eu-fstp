# ADR-023: The FSTP coordinator unmasks parties of their own programme

Status: Accepted 2026-11-15 (Daniel Thompson-Yvetot), option "Amend I-17: coordinator unmasks, logged". Drafted 2026-11-15 by lane `m4/coordinator-unmask`. Every reading marked "Interim, pending Daniel" below is the lane's.

## Context

- Daniel wrote on 2026-11-15: "coordinators (as data controllers) should be able to unmask all parties on the platform".
- Asked how, he chose **"Amend I-17: coordinator unmasks, logged"**. The option he picked read:

  > "The FSTP coordinator may unmask any party of their own programme at any stage. Each unmask asks for a purpose, needs a passkey confirmation and is a ledger record shown in the audit log. I-17 is amended (ADR-023) to exempt the coordinator; other Judging roles stay masked."

- He chose these parties:
  - applicants and team members: the identity attributes the vault holds, such as legal name, contact, organisation and verification status;
  - guardians of minors: the guardian's identity and the consent record (I-18);
  - reviewers and IRC members: the person behind each anonymous reviewer handle (P-11). Applicants still see only handles;
  - staff of the programme: programme managers, drafters, finance and the other operations roles of the programme.
- I-17 before this ADR: "Judging roles cannot read identity attributes of an applicant before the proposal enters negotiation." The FSTP coordinator is a Judging role (`roles-and-sod.md`), so I-17 bound the coordinator too.
- Identity attributes live only in the vault. The vault shows released attributes on its own origin, after a signed single-use ticket from the cell (ADR-009 "Vault origin" and "Releases", `overview.md`). The application never receives an attribute.
- These stay unchanged, and this ADR keeps them:
  - **I-20** The platform stores no link between tenant accounts in different tenants. The unmask reaches the coordinator's own programme only.
  - **I-27** No message on any channel contains another person's identity attributes.
  - **I-83** Identity vault databases never share a cluster with application databases.
  - **I-86** Identity attributes, bank details and vault contents are never returned through MCP.
  - **I-89** Calls to external MCP servers send no identity attribute outside an approved finance hand-over.
  - The vault-origin release of I-17 and ADR-008: the vault releases identity on its own origin. Nothing is copied into the cell.

## Decision

### The amended invariant

**I-17** Judging roles cannot read identity attributes of an applicant before the proposal enters negotiation. The FSTP coordinator is exempt for the parties of their own programme: each unmask names a purpose, needs a fresh step-up and leaves its own ledger record, and the vault shows the identity on its own origin only.

So every Judging role other than the FSTP coordinator stays masked as before. Committee members, committee chairs, assigned reviewers and IRC members read no identity attribute before NEGOTIATION.

### Interim readings, pending Daniel

1. **Who may unmask.** Only an account with an active FSTP coordinator binding in the programme the request names. A tenant admin, a programme manager, an auditor, a committee member, a chair, a reviewer, an IRC member and every Receiving role are refused as actors. A coordinator of another programme is refused too, since the binding must be in the named programme.
2. **Which parties.** A party is named by an id the coordinator's pages already show, never by an identity attribute:
   - a role binding of the programme, held or ended: the lead (`applicant`), a team member (`team_member`), a guardian (`guardian`), a committee member or chair (`reviewer`), an IRC member (`irc`), or a Drafting or Operations role or another coordinator (`staff`);
   - a reviewer or IRC assignment of a proposal of the programme. The assignment is the anonymous handle of P-11, so this unmasks the person behind one handle (`reviewer` or `irc`).
   The server derives the party kind from the binding's role or the assignment's kind. A binding or assignment of another programme is refused as unknown input. Tenant-wide roles, such as the Financial and Legal signatories, are not of the programme, so they cannot be named.
3. **At any stage.** No proposal state is required. An ended binding can still be named, so a withdrawn applicant or a former member of staff stays reachable.
4. **Purpose.** The request carries a purpose. It must hold a character other than white space, and it is at most 500 characters. The API core stores it as a confidential text of the programme, and the ledger holds its `TextRef` only (ADR-007).
5. **Step-up.** The unmask is high-risk. It needs a passkey step-up younger than P-71 and bound to its own request digest (I-78). A stale or foreign proof asks for a step-up again and records nothing.
6. **One ledger record per unmask.** The core command `UnmaskParty { programme, subject, purpose }` appends `PartyUnmasked { programme, party_kind, subject, purpose, by }`. The ledger entry carries the instant. The record names the subject by its binding or assignment id only. It holds no name, contact, organisation, verification state or other identity attribute.
7. **Release on the vault origin.** After the record is appended, the cell asks the vault for an unmask ticket for the subject's account and answers with the vault origin's release page. The browser opens it there, as every identity release opens today. The released attributes never pass through the application's origin, the API core, a log or a message.
8. **The vault's second guard.** A release ticket needs the vault's negotiation fact (ADR-009 "Releases"). An unmask ticket is its own ticket kind, `unmask`, on the release route. The vault admits it without a negotiation fact, since the cell decided the coordinator's right and recorded the unmask first. Every other ticket check holds: signature, cell, route, validity window, lifetime bound and single use.
9. **The vault logs it too.** The vault journals the use of every release ticket, and the vault chain records it as an identity release row (ADR-010, m3-finish Q-C). So an unmask is logged twice: in the cell's ledger with its purpose, and in the vault's own chain.
10. **What the vault shows.** For a person: the account, the party kind the ticket names, whether a verified identity exists, and the identity attributes the vault holds. For a guardian, the consent record of the proposal (I-18). The M3 vault holds no name or document attribute yet (ADR-009 reading, M4 brings verification methods). So the production page shows what the vault holds today, and the demo vault shows synthetic attributes.
11. **The audit read.** The auditor of the programme and every tenant admin read the unmask records through `audit.unmasks` (`GET /programmes/{programme}/audit/unmasks`): the party kind, the subject id, the coordinator's account id, the purpose and the instant. The read holds no identity attribute. The general `audit.entries` read is not built yet. Each unmask call also leaves its API audit entry, with its operation name, outcome and step-up reference (I-24).
12. **Web only.** The unmask and the parties read have no MCP tool, so MCP refuses them as not exposed (I-85, I-86). No message names an unmask or its subject (I-27).
13. **The pages.** The coordinator's board lists an "Unmask" control on each proposal, which opens the proposal's parties page. The coordinator's assignment page has an "Unmask" control per assigned reviewer, and a link to the parties page. Each control opens a short form: "As FSTP coordinator you can see who this is. Your purpose is recorded." It has a purpose field and a "Confirm with passkey and unmask" button. The released identity opens on the vault origin.
14. **The production cell route.** The M3 cell's `POST /api/v1/vault-tickets` still stops after the gate for every ticket kind until it can sign tickets (design section 6.5). The unmask follows that state: the API core path above is complete, and the M3 route gains no new kind in this lane.

## Consequences

- A coordinator can see who any party of their programme is, at any stage, with a recorded purpose. Each unmask is visible to the auditor and the tenant admins.
- Applicants still see only reviewer handles. No other Judging role gains any identity read.
- The I-17 canary tests now exempt the coordinator's unmask path, and only that path. The canary crawls of the Judging pages still find no identity attribute on the application's origin, since the unmask opens the vault origin.
- The authorisation matrix reference gains `identity.unmask`, `identity.parties` and `audit.unmasks`.
- The vault gains one ticket kind, `unmask`, on its release route.

## SPEC lines this ADR amends

- `SPEC/02-domain/invariants.md` I-17, with a NOTE.
- `SPEC/02-domain/roles-and-sod.md`, the FSTP coordinator row, the reviewer note that cites I-17 and the anonymous reviewer handles section.
- `SPEC/03-architecture/overview.md`, the negotiation facts line and the vault origin paragraph.
- `SPEC/01-requirements/functional.md`, R-NG-01 NOTE on the guardian exception.
- `SPEC/06-threat-model/threat-model.md` TH-07.
- `SPEC/07-test-plan/test-plan.md`, the I-17 and I-21 row.
- `docs/design/spec-amendments.md` SA-07 records the amendment.

## Tests

- API core, on the matrix worlds (`crates/fstp-api-testkit/src/harness_unmask.rs`): the coordinator unmasks each party kind with a purpose and a step-up, and exactly one `PartyUnmasked` is appended; no purpose, a blank purpose and an over-long purpose are refused; a stale step-up is refused; every other Judging role, staff role and Receiving role is refused; a coordinator acting on another programme is refused; MCP refuses the unmask and the parties read; the audit read shows the record to the auditor and tenant admins and to nobody else; no message is enqueued.
- Domain (`crates/fstp-domain-testkit/tests/i17_adr023_*`): production `decide` admits only the programme's coordinator, refuses a subject of another programme, and the record holds ids only. Teeth: a decide that admits a committee member, or one that copies an identity attribute into the record, is caught.
- Vault (`crates/fstp-vault`): an unmask ticket releases without a negotiation fact, a release ticket still needs one, and the use is journalled.
- Web and demo: the coordinator pages offer the control, and a demo Playwright spec has coordinator C1 unmask an applicant and a reviewer handle while a committee member cannot.

## Open points for Daniel

1. **Telling the unmasked person.** Whether the person is told that the coordinator saw who they are, and when. `TODO(legal)`: the GDPR transparency duties for this processing need Daniel's legal review. Interim: nobody is told, and no message is sent.
2. **A conflicted coordinator.** A coordinator with a declared or detected conflict on a proposal can still unmask its parties. I-03 covers content and reviewer acts, not identity. Whether a conflict should bar the unmask is open.
3. **The purpose bound.** 500 characters is the lane's choice.
4. **The legal basis and retention of the purpose text.** `TODO(legal)`: the purpose is personal data of the coordinator and may name the subject's case. Its retention follows the programme's confidential texts until Daniel decides.
5. **Staff of the programme.** Whether another FSTP coordinator of the same programme counts as staff that may be unmasked. Interim: yes.
