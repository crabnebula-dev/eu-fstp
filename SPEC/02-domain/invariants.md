# Invariants

Invariants hold in every reachable state. Each one has at least one property-based test and, where state transitions are involved, a model-checking property (`07-test-plan/test-plan.md`).

## Separation of duties and conflicts

- **I-01** Within a programme, no person holds roles from more than one of the Drafting, Judging and Receiving groups, counting past bindings within the cooling-off period (P-12).
- **I-02** No IRC member holds any other Judging role in the same programme.
- **I-03** No person with a declared or detected conflict on a proposal can read its content or act on it as a reviewer.
- **I-04** No person in an excluded affiliation class (P-13) holds a Receiving role in that programme.
- **I-05** For any payment, the person who accepted the milestone is not the person who released the payment.
- **I-06** No two tenant accounts with the same verified identity hold bindings that together violate I-01 in the same programme.

## Evaluation

- **I-07** Every scored proposal has scores from at least P-03 assigned reviewers before it can leave stage 1.
- **I-08** A proposal passes stage 1 only if its weighted score is strictly above P-02.
- **I-09** After stage 2, the effective score follows P-24 and references exactly one plan version.
- **I-10** LLM findings never cause a state transition, score or decision.
- **I-11** All findings within one call reference the same pinned model, prompt and rubric configuration.
- **I-12** Policy parameters marked frozen are immutable for a call once it is published.

## Money

- **I-13** Every granted amount lies within P-04 after deduction of ineligible costs.
- **I-14** The sum of amounts granted to one recipient within a programme never exceeds P-05.
- **I-15** A repeat grant or amendment to the same applicant exists only if prior deliverables are recorded as publicly available under a licence in P-26.
- **I-16** The platform never holds or controls funds.

## Data protection and isolation

- **I-17** Judging roles cannot read identity attributes of an applicant before the proposal enters negotiation.
- **I-18** A proposal flagged as from a minor cannot enter negotiation without a verified guardian consent record.
- **I-19** No tenant data crosses a cell boundary except through a tenant export, a user-held profile bundle or a template the tenant published (I-73).
- **I-20** The platform stores no link between tenant accounts in different tenants.
- **I-21** Pre-submission check runs and drafts are not readable by operator or Judging roles.
- **I-22** Exporting a tenant and importing it into an empty cell yields an equivalent tenant state.

## Audit

- **I-23** Role bindings, conflict declarations, policy versions, scores and decisions are append-only. Corrections are new records.
- **I-24** The audit log is tamper-evident. Any modification or deletion of a past entry is detectable.

## Notifications and messaging

- **I-25** Every automated message traces to a timeline event and a template version.
- **I-26** Each combination of event, recipient and channel is delivered at most once.
- **I-27** No message on any channel contains proposal content, scores, deliberation or another person's identity attributes.
- **I-28** No shared group contains an applicant before NEGOTIATION. No shared group mixes Receiving and Judging roles unless P-11 is named and the proposal is GRANTED or later.
- **I-29** Group membership matches current role bindings and opt-ins. Ending a binding enqueues the membership removal in the same transaction, and removal executes within P-35 subject to channel availability.

## Contracts and payment requests

- **I-30** A signed contract version is immutable. Any change is a new version signed by all parties.
- **I-31** Total released payments under a contract, including hardship contributions, never exceed the contract amount.
- **I-32** A payment request is accepted only after automated checks pass and evidence snapshots are recorded.
- **I-33** After a bank detail change, no payment is released until re-verification completes and P-36 elapses.

## Reviewer assignment

- **I-34** The assigned reviewers of a proposal belong to at least P-39 distinct organisations.
- **I-35** No reviewer is assigned to a proposal declaring an affiliation on the proximity list of the reviewer's organisation.

## Former reviewers

- **I-36** A person who reviewed a proposal cannot hold a Receiving role in any call where that proposal is still under evaluation, including after deferral, regardless of P-12.

## Calibration

- **I-37** No proposal enters a calibration set without a recorded, unrevoked consent, and consent is never requested before the outcome notice.

## Self-hosted services

- **I-38** Calls from a self-hosted cell to CrabNebula-hosted services carry no tenant data (`03-architecture/self-hosted-services.md`).
- **I-39** Unavailability of the update or licence service never blocks evaluation, payments, notifications or export.

## Contractual notices

- **I-40** A contractual notice email is sent only after its sealed PDF exists and its hash is recorded in the audit chain.

## Public transparency and funder reporting

- **I-41** No public page shows anything about a proposal that never reached GRANTED.
- **I-42** No public page names a minor, at any visibility level.
- **I-43** A grant is published at the lower of the programme maximum and the grantee's current choice, and is hidden when no choice exists.
- **I-44** Every figure in a funder document reconciles with recorded contracts, payment requests and payments at its data snapshot.

## Horizon Europe alignment

- **I-45** Total amounts committed under contracts across all calls never exceed the action's FSTP budget (P-56).
- **I-46** No milestone due date or payment release falls after the action end date (P-57).
- **I-47** Every milestone references an activity type from the call's closed list (P-55).
- **I-48** An open call package is generated only when it states the maximum per recipient, the criteria for the exact amount, the closed list of activity types, the persons supported, and the award criteria and procedure.
- **I-49** Under the Horizon Europe profile, a contract is generated only with the full flow-down clause set (`02-domain/contracts.md`).
- **I-50** P-05 never exceeds the funder's per-recipient ceiling (P-58).

## Guide for Applicants

- **I-51** Every parameter value in a Guide for Applicants equals the frozen call policy.
- **I-52** A Guide is generated only when every required section is present, including the MGA 6.2.D.1 elements and the flow-down obligations.
- **I-53** A published Guide version is immutable. Corrections are numbered corrigenda notified to every account with a proposal in the call.

## Support programme

- **I-54** Every mentoring assignment is recorded as a relationship in the identity vault and is part of conflict detection in all later calls of the programme.
- **I-55** No consortium partner makes commercial offers to grantees through the platform, and grantee contact data is never used for commercial purposes.

## Complaints

- **I-56** Every complaint receives a reasoned, recorded response within the applicable deadline (P-62, P-64).
- **I-57** Filing a complaint never changes the complainant's evaluation, scores or payment status, except through a recorded remedy.

## Payment request lines

- **I-58** For every milestone, paid plus pending never exceeds the milestone amount.
- **I-59** Every payment request line references a milestone of the same grant in its effective contract version.
- **I-60** An approved line amount never exceeds the requested amount, and a lower approval carries a recorded reason.
- **I-61** An amendment never sets a milestone amount below its paid plus pending amount.
- **I-62** The line that brings a milestone to fully claimed always carries public deliverables under a licence in P-26.
- **I-63** A reallocation never changes a task's total, never moves money between tasks, and never leaves a source milestone below its paid plus pending amount.
- **I-64** At grant closure, committed amounts for the grant drop to its paid total.

## Programme creator and white-labelling

- **I-65** Every value proposed by document import is confirmed or edited by a named programme manager before it takes effect.
- **I-66** A programme cannot be activated while its validation report shows any failure.
- **I-67** Activating a programme needs approval by a second person who did not build it.
- **I-68** Branding is data only. No tenant-supplied script, style rule or markup executes.
- **I-69** Branding cannot remove mandatory elements required by the funder profile, the AI disclosure, the privacy notice, the accessibility statement, the Data Act tenant information or the platform attribution.
- **I-70** Every colour pair used for text meets WCAG 2.2 level AA contrast in light and dark themes.
- **I-71** A custom domain serves traffic only after verified ownership, and only for its own tenant cell.
- **I-72** Terminology overrides apply to interface labels only. Contracts, notices, the Guide for Applicants, funder documents and emails keep their approved wording.
- **I-73** A template reaches other tenants only when published by a tenant admin and a programme manager together, after a personal data scan, under a licence the publisher chose.

## Cryptography

- **I-74** No release ships a Tier B crate whose exact version lacks a recorded Mythos-tier confirmation (ADR-001).
- **I-75** moduletto is always used in a hybrid with a classical primitive: ML-KEM with X25519, ML-DSA with Ed25519. Nothing relies on a moduletto primitive alone.

## Authentication and keys

- **I-77** Accounts holding any Drafting, Judging, Operations or tenant admin role log in with a phishing-resistant method only.
- **I-78** No high-risk action completes without a phishing-resistant step-up within P-71.
- **I-79** An account holding any role outside the Receiving group is never recovered by email alone.
- **I-80** No root key exists in plaintext outside its custody backend.
- **I-81** Destroying a root or data key makes the protected data unrecoverable, including from backups.
  NOTE: Assurance levels. Decided by Daniel on 2026-11-01: "i want this to be able to run on anyone's hardware, not just linux. so, if they are running on windows or mac, we just tell them that the ultimate degree of security isn't met, but we should let them continue. in all cases, do not fail on development mode". File custody meets I-81 in full only on a Linux key volume of ext4 or XFS that is never backed up, snapshotted or copied. On any other host or filesystem, such as APFS, HFS+, NTFS or an unknown type, the platform still starts, and reports that it runs at reduced assurance for I-81 with the reason. It never reports full assurance there. In development mode, host and platform checks warn and never stop a start. Authorisation, step-up and the domain invariants are enforced in every mode.
- **I-82** No database role can read across databases of different cells.
- **I-83** Identity vault databases never share a cluster with application databases.

## MCP server

- **I-84** Every MCP call passes the same policy engine, separation of duties checks and audit logging as the web interface.
- **I-85** High-risk actions cannot complete through MCP. The user confirms them in the platform with a step-up.
- **I-86** Identity attributes, bank details and vault contents are never returned through MCP.
- **I-87** Public MCP tools return exactly the data of the public pages and feed, under the same filters.
- **I-88** Calls to external MCP servers initiated by platform components use read-only tools only, unless a named human approved the specific action.
- **I-89** Calls to external MCP servers send only the fields declared for that integration. Identity attributes and bank details go only to an approved finance hand-over.
- **I-90** A composite signature verifies only when both the Ed25519 and the ML-DSA-65 halves verify.
- **I-91** Self-hosted cells and desktop clients install only updates whose release metadata carries a valid composite signature by a release signing key that the release root currently certifies.
  NOTE: The desktop client is deferred by Daniel on 2026-11-04 (B-04). Until it returns, I-91 binds self-hosted cells.

## Journey UI layer (`12-journey-ui.md`, decided 2026-11-01)

- **I-92** The journey layer holds no authority. Every state change still goes through the domain core. Deleting all journey tables and replaying the ledger rebuilds identical output.
- **I-93** Every diary entry shown to a viewer passes the visibility function for that viewer's role and programme (section 7). No entry is stored once and filtered in the browser.
- **I-94** Journey vocabulary appears in interface labels only. Contracts, contractual notices, the Guide, funder documents, emails and messaging keep approved wording (extends I-72).
- **I-95** The journey graph must equal the state machine. A build fails when a node or edge differs from the domain core's transition table (drift test, section 13).
- **I-96** Every metaphor label is shown with the formal status name beside it, in text, so the legal state is never ambiguous.
- **I-97** A journey row or API response never holds free text from a ledger record. It holds a `TextRef`, resolved at read time under the viewer's rights. After erasure, a `TextRef` resolves to the erasure-log placeholder, never to text (ADR-007, I-81).
