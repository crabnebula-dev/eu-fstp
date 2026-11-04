# Functional requirements

Each requirement states an outcome and an acceptance criterion (AC). NOTEs carry explanation only.

## Programmes and calls

- **R-PC-01** A tenant can run several programmes, each with its own policy parameters.
  AC: two programmes with different P-01 weights produce different weighted scores for identical reviewer inputs.
- **R-PC-02** A published call carries a frozen policy version.
  AC: a parameter edit after publication does not change any outcome in that call (I-12).
  NOTE: The AC covers the parameters marked frozen, as I-12 does. Programme-level parameters such as P-05 and P-13 keep their live values, because I-04 and I-14 hold against them. Adding a P-13 class therefore affects existing Receiving roles.
  NOTE: For P-05 and P-13, a published call enforces the stricter of its publication snapshot and the live programme value (decided 2026-10-25, `02-domain/policy-parameters.md`). A live edit can tighten a published call's limits but never loosen them.
- **R-PC-03** Publishing a call requires approval by a person other than its drafter.
  AC: publication by the drafter alone is rejected.
  AC: approval by an author of the call, or by the last author of P-01 or P-09 in the policy the call freezes, is rejected.
  NOTE: The drafters of a call are its authors plus the last authors of P-01 and P-09 (decided 2026-10-25). A person here means a tenant account (`00-scope.md`).

## Submission

- **R-SB-01** Before negotiation, applicants provide only data needed for evaluation.
  AC: no submission form contains identity document, date of birth or payment fields.
- **R-SB-02** Minors can submit without guardian consent.
  AC: a minor-flagged submission reaches SUBMITTED without a guardian record.
- **R-SB-03** Applicants can withdraw at any point before contract signature.
  AC: a withdrawal from any non-terminal state before GRANTED succeeds, including after signature while the contract is not yet EFFECTIVE.
  NOTE: The state machine permits withdrawal until GRANTED (`02-domain/state-machine.md`), which covers every point before signature. Terminal states, INELIGIBLE among them, have no exits.
- **R-SB-04** Applicants can obtain a copy of their application at an email address they provide.

## Evaluation

- **R-EV-01** Proposals failing any knock-out criterion receive no further review.
- **R-EV-02** Each eligible proposal is scored by at least P-03 assigned reviewers without conflict (I-03, I-07).
- **R-EV-03** Stage 1 outcome follows the weighted score and P-02 (I-08).
  AC: with P-01 weights 30, 40 and 30, a criterion scale of 0 to 4 and every score 3, the weighted score is exactly 75.00% and the proposal does not pass a P-02 of 75%.
  NOTE: Each reviewer scores every P-01 criterion on an integer scale from 0 to the P-01 maximum. The weighted score is the mean of the reviewers' weighted sums, as a fraction of the maximum. P-02 is a percentage with two decimals, compared exactly (decided 2026-10-25, `02-domain/policy-parameters.md`).
  NOTE: P-01 weights are positive integers with no required total. Only valid scores count: scores of released or conflicted reviewers never do. Scores seal when the proposal leaves stage 1, and only a recorded complaint remedy reopens them (decided 2026-10-25).
- **R-EV-04** Non-selected applicants are notified within P-08.
- **R-EV-05** In stage 2, assigned reviewers can ask questions and suggest changes, and applicants can submit a revised plan including budget changes.
  AC: when the assigned reviewers record that they have no questions, the proposal reaches RANKED without waiting for P-07.
  NOTE: Assigned reviewers rescore each revised plan, and at least P-03 valid stage 2 scores are needed. A "no questions" record closes the stage 2 window at once, with answers deemed complete (decided 2026-10-25, `02-domain/state-machine.md`). Every active assigned reviewer must make that record (decided 2026-10-25, O-50).
- **R-EV-06** The effective score after stage 2 follows P-24 (I-09).
  AC: under "higher of original and revised", equal original and revised scores give an effective score that references the original plan version.
  NOTE: When several revisions exist, the latest scored revision is the revised plan. On a P-24 tie, the original plan carries forward (decided 2026-10-25, `02-domain/state-machine.md` NOTE 4).
- **R-EV-07** A proposal without stage 2 answers within P-07 moves to the next call.
  NOTE: A "no questions" record under R-EV-05 counts as complete answers, so this requirement does not apply to it.
  NOTE: The move from STAGE2 to DEFERRED has no guard that a future call exists. The proposal waits in DEFERRED until the next call opens (decided 2026-10-25, `02-domain/state-machine.md`).
  NOTE: The original call's frozen policy keeps governing a deferred proposal, matching what the applicant was told. The new call makes new assignments and handles. Findings stay with the call that produced them, and the new call may produce its own (decided 2026-10-25).
- **R-EV-08** The committee sets a cut-off from the ranking view (`02-domain/roles-and-sod.md`) with remaining budget visible, and the rationale is recorded.
  AC: a cut-off that leaves a tie at the cut-off position without a recorded P-17 tie-break is rejected.
  NOTE: The cut-off is a rank position over a total order. The committee breaks ties under P-17 and records the tie-break. Each cut-off covers the proposals currently RANKED (decided 2026-10-25).
  NOTE: Before NEGOTIATION, the P-17 country priority uses a boolean answer from the identity vault, never a self-declared field (decided 2026-10-25).
  NOTE: The call budget is fixed at publication and shown for information. It is not a hard limit on nominations (decided 2026-10-25).
- **R-EV-09** Committee decisions follow P-16.
  NOTE: Committee members with a conflict on a ranked proposal recuse from that call's cut-off vote (R-CF-02).
  NOTE: P-16 counts a majority of the votes cast by members who are not recused, needs a quorum of more than half of them, lets a member hold at most one delegated vote, and gives the chair a casting vote on a tie (decided 2026-10-25, `02-domain/policy-parameters.md` NOTE 8).
- **R-EV-10** Reviewers can record external verification of claims without disclosing applicant identity unless the applicant consented to sharing.

## Independent review

- **R-IR-01** At least P-15 IRC members review each nominated proposal for eligibility and frugality.
- **R-IR-02** An IRC concern is sent to the applicant, and the proposal is deferred or declined per the state machine.
- **R-IR-03** IRC members see the nominated proposal and outcome, not committee deliberation.
- **R-IR-04** Amendments meeting P-14 skip IRC review.

## Negotiation and grant

- **R-NG-01** Identity attributes are collected only in NEGOTIATION (I-17), except the applicant's country of residence or establishment for P-17, which is collected at submission and held only in the identity vault. Two further exceptions are collected and held only in the identity vault (decided 2026-10-28). An over-18 attestation of the applicant lead may be collected from submission until NEGOTIATION. A guardian's identity and consent are collected at the IRC_REVIEW to NEGOTIATION gate.
  NOTE: Judging roles see only the vault's yes or no answer to the P-17 country condition. The country is verified in NEGOTIATION (decided 2026-10-25, O-48). TODO(legal): confirm this early collection under GDPR.
  NOTE: Guardian exception (decided 2026-10-28). Collection opens once every reviewing IRC member has validated a minor-flagged proposal (R-ID-04). The guardian verifies and consents on the vault origin (`03-architecture/overview.md`), so only the vault receives the guardian's attributes. The proposal stays in IRC_REVIEW until the consent record is effective. Judging roles never read the guardian's attributes, so I-17 holds. TODO(legal): L-02, the legal basis for collecting a guardian's data before NEGOTIATION.
  NOTE: Over-18 attestation exception (decided 2026-10-28). The lead provides the attestation on the vault origin, and only the vault receives it. It is optional: without it, the proposal stays minor-flagged (R-ID-04) and needs a verified guardian consent. Judging roles never see the attestation or the vault's answer about it. TODO(legal): L-02, the legal basis for collecting the attestation before NEGOTIATION, and whether Article 8 GDPR applies to it.
- **R-NG-02** A minor's proposal enters NEGOTIATION only with verified guardian consent (I-18).
  NOTE: The guardian's identity and consent are collected at the IRC_REVIEW to NEGOTIATION gate, in the identity vault only (R-NG-01, decided 2026-10-28). The gate admits a proposal whose lead has an effective verified over-18 attestation at the deadline, or that has a verified guardian consent record (`02-domain/state-machine.md` NOTE 14, decided 2026-10-28).
- **R-NG-03** The grant amount is set by the assigned reviewers, adjusted for ineligible costs, within P-04 and P-05.
  AC: a granted amount that differs from the effective plan total minus the recorded deductions is rejected. An amount equal to either P-04 bound is accepted.
  NOTE: The granted amount equals the effective plan total minus recorded deductions, and each deduction carries a reason. P-04 bounds are inclusive at both ends (decided 2026-10-25, `02-domain/contracts.md`).
  NOTE: P-05 applies per verified identity of the applicant lead. It counts granted amounts plus open reservations from amount determination, amended totals included. At COMPLETED or TERMINATED, committed amounts drop to the paid total (I-64) (decided 2026-10-25).
  NOTE: An edit that lowers P-05 below a recipient's committed sum is refused (decided 2026-10-25).
- **R-NG-04** The contract records amount, milestones and licence obligations (`02-domain/contracts.md`). The applicant can decline before signature.
- **R-NG-05** Repeat grants and amendments require prior deliverables recorded as public under P-26 (I-15). Reviewers see prior outcomes.
  AC: a grant to a lead whose earlier grant in another programme of the same tenant has an accepted deliverable without a public record under its call's P-26 is rejected.
  NOTE: The same applicant means the verified identity of the applicant lead, across the whole tenant. Prior deliverables are every deliverable accepted so far. Each must be public under a licence in the P-26 of the prior call (decided 2026-10-25).
  NOTE: An amendment also needs this grant's own accepted deliverables recorded. A partial claim under P-65 without public deliverables leaves the record incomplete until the final claim on that milestone (decided 2026-10-25).

## Execution and payment

- **R-EX-01** Payment follows an accepted payment request for a milestone, in full or in part.
- **R-EX-02** A hardship contribution proportional to delivered work can be granted on verified evidence.
- **R-EX-03** Each tenant selects record-only or execution payment mode (P-20).
- **R-EX-04** Milestone acceptance and payment release are done by different persons (I-05).

## Conflicts and separation of duties

- **R-CF-01** SoD-01 to SoD-09 are enforced at every enforcement point.
- **R-CF-02** Reviewers declare conflicts before accessing full content. A declared conflict triggers reassignment.
  AC: the FSTP coordinator cannot read a submission for the knock-out check before declaring conflicts on it.
  NOTE: I-03 covers content reads by anyone and every act on the proposal or its grant. These acts are assigned-reviewer acts, IRC review, the knock-out check and committee votes on the cut-off (decided 2026-10-25, `02-domain/roles-and-sod.md`).
  NOTE: The FSTP coordinator declares before the knock-out read. Under the P-10 option "all committee members", every committee member declares before reading (decided 2026-10-25).
  NOTE: A committee member with a conflict on a ranked proposal recuses from that call's cut-off vote. No vote is delegated to or from them (decided 2026-10-25).
- **R-CF-03** Conflict and cap checks return boolean outcomes without disclosing identity to Judging roles.

## Identity

- **R-ID-01** Each tenant selects verification methods from P-18.
- **R-ID-02** The vault stores verification outcome, method, document type, checks performed, time and verifier. It stores no identity document numbers or document images.
- **R-ID-03** Uploaded identity documents are deleted within P-19 after verification, including from backups.
  AC: after verification, no backup or replica can reproduce the document.
  NOTE: Encrypting each document under its own key and destroying the key on verification reaches backups without rewriting them.
- **R-ID-04** Minor status is stored as a derived flag relative to the call deadline.
  NOTE: Derivation (decided 2026-10-28). A proposal is minor-flagged unless its lead has an effective verified over-18 attestation at the call deadline. No field of an applicant's request sets or clears the flag. Only the vault's answer about a verified attestation clears it. The vault answers through a one-bit query (`03-architecture/overview.md` NOTE 7).
  NOTE: Interim, pending Daniel. Which call's deadline applies to a deferred proposal, how an attestation verified after the deadline counts, and whether a later verification showing the lead under 18 overrides an attestation are not decided. ADR-008 (Minor flag details) holds the proposed readings.

## Profile sync

- **R-PS-01** A user can export a profile bundle from one tenant and import it into another.
- **R-PS-02** The user selects which profile fields the bundle contains. Proposals, reviews, scores and role bindings are never included.
- **R-PS-03** The receiving tenant treats imported fields as self-declared, unless carried as verifiable attestations.

NOTE: R-PS-03 means bundle forgery gains nothing beyond what a user could type in.

## Tenant data and switching

- **R-TD-01** A tenant can export all its exportable data and digital assets in the documented schema (`schemas/`).
- **R-TD-02** Importing an export restores the tenant on SaaS or self-hosted without loss (I-22).
- **R-TD-03** Export and import tooling is available under EUPL-1.2 as a separate executable, independent of the platform licence.
  AC: the platform binary contains no EUPL-licensed code; it invokes the tool through its process and file interface.
- **R-TD-04** Export and switching carry no charge.

## LLM assessment

- **R-LA-01** Every submission receives findings on completeness, quality and accuracy of representation.
- **R-LA-02** Every finding carries evidence pointers.
- **R-LA-03** A named human records every decision. Findings are advisory (I-10).
  AC: a stage 1 close recorded with an outcome other than the computed one is rejected.
  NOTE: Computed outcomes are decisions under this requirement. The FSTP coordinator records the stage 1 close and cannot choose its outcome (decided 2026-10-25, `02-domain/state-machine.md`).
  NOTE: Stage 1 closes when every active assignee has a valid score and at least P-03 valid scores exist (decided 2026-10-25).
- **R-LA-04** Each tenant selects its inference provider. Self-hosted cells can use a local endpoint.
- **R-LA-05** Model, prompt and rubric are pinned per call (I-11).
  NOTE: The pin is the full assessor configuration (`config_id` in `04-llm-assessment/assessment.md`). P-21 names only the provider and model, so the pin covers more than P-21.
  NOTE: The frozen P-21 value is a primary model plus an ordered fallback list, pinned at publication. A switch to a fallback regenerates all of the call's findings in one atomic step, so I-11 and I-12 keep holding (decided 2026-10-25, `02-domain/policy-parameters.md`).
- **R-LA-06** Applicants can run a pre-submission check with the same rubric. It returns findings, never scores.
- **R-LA-07** Traces of submission assessments are retained in the tenant cell for P-22, then deleted.
  NOTE: Pre-check traces follow the draft lifecycle in `04-llm-assessment/pre-check.md`, not P-22.
- **R-LA-08** Applicants are informed that AI assessment is used, in the call text and at the pre-check.

## Visibility

- **R-AC-01** Proposal read access in stages 1 and 2 follows P-10.
- **R-AN-01** Reviewer identity towards applicants follows P-11. Anonymous mode uses pseudonymous handles.

## Reporting and audit

- **R-RP-01** Funder documents are generated per funder profile (P-53) from a data snapshot (`03-architecture/funder-reporting.md`).
  AC: regenerating from the same snapshot and template yields an identical document.
- **R-RP-02** Every figure in a funder document reconciles with the payment records (I-44).
- **R-RP-03** Funder documents require approval by a named Operations role before release.
- **R-RP-04** The Horizon Europe profile generates all five outputs in `03-architecture/funder-reporting.md`: call publication record, open call package, periodic reporting data, audit file per call and deliverable drafts.
- **R-AU-01** Every state transition, role binding, policy change and read of proposal content or identity attributes is logged (I-23, I-24).

## Contracts

- **R-CT-01** Contracts are generated from the frozen template (P-29) and the agreed plan version.
  AC: regenerating from the same inputs yields a byte-identical document and hash.
- **R-CT-02** Signature follows P-30, with any fallback approved and recorded. A minor's contract includes the guardian as a signing party.
- **R-CT-03** Signed versions are immutable and amendments are new signed versions (I-30).
- **R-CT-04** Negotiated clause changes are recorded as a diff against the template.

## Payment requests

- **R-PR-01** Grantees request payment per milestone with deliverable evidence per P-34.
- **R-PR-02** Automated checks run before human review, and failures return to the grantee with reasons.
- **R-PR-03** Evidence snapshots are recorded at submission and acceptance (I-32).
- **R-PR-04** Hardship contributions use the payment request flow with vault-held evidence.
- **R-PR-05** Bank detail changes trigger re-verification and the P-36 hold (I-33).

## Notifications and timelines

- **R-NT-01** Timeline events are derived from calls, contracts, payment requests and reminder policy.
  AC: amending a milestone due date reschedules its reminders and cancels the superseded ones.
- **R-NT-02** Reminders and escalations follow P-31 and P-33.
- **R-NT-03** Each event reaches each recipient on each channel at most once (I-26).
- **R-NT-04** Contractual notices are sealed PDFs stored in the platform, announced by email (`02-domain/contractual-notices.md`, I-40).
- **R-NT-05** Users choose which opt-in channels they receive on.

## Group messaging

- **R-MG-01** Tenants can enable the Matrix adapter per P-32. The WhatsApp adapter is deferred by Daniel on 2026-11-04 (B-03).
- **R-MG-02** Group types and membership follow `03-architecture/messaging.md` (I-28, I-29).
- **R-MG-03** Announcements reach recipients without exposing other recipients.

## Calibration with consented proposals

- **R-LA-09** After the outcome notice, applicants can consent to pseudonymised use of their proposal for assessor calibration within the tenant (P-42).
  NOTE: Asking after the outcome prevents consent from appearing to influence evaluation.
- **R-LA-10** Consent is revocable. Revocation removes the proposal from future calibration runs.
- **R-LA-11** Use beyond the tenant, including research, needs both tenant agreement and a separate applicant consent.

## Switching

- **R-SW-01** A tenant can start switching at any time without notice.
- **R-SW-02** After the retrieval period (P-46), the tenant cell is fully erased and the tenant receives an erasure confirmation.
  AC: after erasure, no backup or replica can restore the cell.

## WhatsApp

NOTE: R-WA-01 and R-WA-02 are deferred by Daniel on 2026-11-04 (B-03). Their identifiers stay reserved.

- **R-WA-01** WhatsApp is enabled in v1 for individual notifications, after the assessment in `05-compliance/messaging.md` is complete for the tenant.
- **R-WA-02** Recipients opt in explicitly per programme. Opt-out takes effect immediately.

## Public transparency

- **R-PB-01** Each programme publishes open calls, funded subgrants and finished subgrants (`02-domain/public-transparency.md`).
- **R-PB-02** Each grantee opts in to a visibility level up to P-50 and P-51, and can change it at any time (I-43).
  AC: withdrawing removes the grant from pages and the feed on the next request.
- **R-PB-05** Public aggregates appear only when they cover at least P-54 grants.
- **R-PB-03** Public summaries come from the grantee, never from proposal text.
- **R-PB-04** Public pages work without scripts, carry no tracking and meet R-NF-03.

## Horizon Europe alignment

- **R-SB-05** Submissions include an ethics self-declaration. Declared ethics issues are flagged to the assigned reviewers.
- **R-CF-04** A conflict that could compromise impartial implementation is recorded as notifiable and produces a notification draft for the coordinator to send to the granting authority.
- **R-NG-06** Applicants receive a data protection notice at submission and at negotiation, covering transfer of recipient data to the granting authority and referencing the Portal Privacy Statement.
- **R-EX-05** Grantees can notify events or circumstances affecting their subgrant. Notifications are logged and reach the programme manager.
- **R-HE-01** Under the Horizon Europe profile, I-45 to I-50 are enforced (`05-compliance/horizon-europe-mga.md`).

## Guide for Applicants

- **R-GA-01** Every open call publishes a Guide for Applicants generated from the frozen call policy (`02-domain/guide-for-applicants.md`).
  AC: changing a frozen parameter in a draft programme changes every place it appears in the Guide.
- **R-GA-02** The Guide is available as accessible HTML on the public call page and as a PDF.
- **R-GA-03** Corrigenda are versioned, published with the call and notified to affected applicants (I-53).

## Support programme

- **R-SP-01** Grants can have a mentor assigned, accepted by both mentor and grantee, and ended by the grantee at any time.
- **R-SP-02** Grantees can book presentation slots with the consortium through the timeline engine.
- **R-SP-03** Promotion of a grant stays within the grantee's publication choice (I-43).
- **R-SP-04** Support is free, unconditional and separate from payment decisions (SoD-12, I-55).

## Complaints

- **R-CP-01** Applicants and grantees can file a complaint about a procedural decision within P-61 of its notice (`02-domain/complaints.md`).
- **R-CP-02** The coordinator responds within P-62, and the complainant can escalate to the IRC within P-63.
- **R-CP-03** Reviewers of a complaint did not take part in the contested decision (SoD-13).
- **R-CP-04** Every response is reasoned and recorded (I-56).

## Payment timing

- **R-EX-06** Approved payments are released within P-59. A release that would miss P-59 escalates to the programme manager.

## Payment request lines

- **R-PR-06** A payment request can claim partial amounts on several milestones across tasks (`02-domain/payment-requests.md`).
  AC: a request with lines on three milestones in two tasks, each below the milestone amount, is accepted by the form and the server.
- **R-PR-07** The request form shows amount, paid, pending and available per milestone and per task, and locks fully paid milestones.
- **R-PR-08** Reviewers approve, reduce or reject each line, with a reason for any reduction or rejection (I-60).
- **R-PR-09** Requested amounts above a milestone's available balance are rejected (I-58).
  AC: two concurrent requests that together exceed a milestone's available balance cannot both be submitted.
- **R-PR-10** Evidence for partial claims follows P-65. The final claim on a milestone always carries public deliverables (I-62).
- **R-PR-11** Grantees can request reallocation between milestones of the same task, approved by an assigned reviewer (P-66, I-63).
  AC: a reallocation that would change a task total or lower a milestone below paid plus pending is rejected.
- **R-PR-12** Unclaimed balances at grant end follow P-67, and committed amounts drop to the paid total (I-64).

## Tenant onboarding and programme creator

- **R-TN-01** New tenants are set up through a guided onboarding flow (`02-domain/programme-creator.md`).
- **R-PG-01** Programmes are built in a guided programme creator with per-step validation, previews and a final validation report.
  AC: a programme with P-05 above P-58 cannot be activated, and the report names both values.
- **R-PG-02** Programmes can start from blank, a clone, a template or an imported funding document (I-65).
- **R-PG-03** Activation needs a clean validation report and a second approver (I-66, I-67).
- **R-PG-04** After activation, the creator shows which calls each change affects.

## White-labelling

- **R-WL-01** Each tenant can apply a white-label package covering every interface, public page, document, email and messaging identity (`03-architecture/white-labelling.md`).
- **R-WL-02** Custom domains get automatic certificates after verified ownership (I-71).
- **R-WL-03** Branding cannot execute code, break contrast or remove mandatory elements (I-68 to I-70).
- **R-PG-05** Tenants can save templates for their own use and publish them to other tenants (I-73).
  AC: publishing a template that contains a personal name or email address is blocked with the matches listed.
- **R-WL-04** Every interface and public page shows the platform attribution in the footer (P-68).
- **R-WL-05** Terminology overrides change interface labels only (I-72).

## Desktop client

NOTE: R-DC-01 is deferred by Daniel on 2026-11-04 (B-04). Its identifier stays reserved.

- **R-DC-01** A white-labelled desktop client gives access to the tenant's interfaces (`03-architecture/desktop-client.md`).

## Cryptography

- **R-CR-01** Data at rest that leaves the running system, such as backups and exports, is protected by hybrid post-quantum key encapsulation (ADR-001).
- **R-CR-02** Release builds fail when a Tier B crate lacks a matching Mythos confirmation (I-74).

## Authentication

- **R-LG-01** Users log in with passkeys, and where the tenant enables them, the EUDI Wallet, OPAQUE passwords, or magic links for applicants and grantees (`03-architecture/authentication.md`).
- **R-LG-02** Management roles use phishing-resistant login only (I-77).
- **R-LG-03** High-risk actions need a fresh phishing-resistant step-up (I-78).
  AC: granting a committee role, exporting the tenant or adding a passkey fails without a step-up in the last P-71.
- **R-LG-04** Users can see and end their sessions and linked devices.

## Keys and hosting

- **R-KY-01** Cell root keys are held in an EU-operated KMS or HSM, or a CrabNebula-operated HSM, chosen per cell (ADR-004).
- **R-KY-02** Erasure and crypto-shredding work by key destruction (I-81).
- **R-HS-01** The SaaS runs on an EU-owned provider (ADR-005).
- **R-HS-02** Cells share a database cluster by default, with a dedicated cluster on request (P-73, I-82, I-83).

## MCP server

- **R-MC-01** Each cell exposes an MCP server with OAuth 2.1 authorisation, scoped per user and client (`03-architecture/mcp-server.md`).
- **R-MC-02** MCP actions follow the user's roles exactly (I-84), and high-risk actions need confirmation in the platform (I-85).
- **R-MC-03** Users can list and revoke connected agents.
- **R-MC-04** Agents without an account can research open calls and published subgrants through public MCP tools (I-87), and programmes can opt in to a platform-wide directory (P-76).
- **R-MC-05** Each programme chooses whether agents complete binding actions or only draft them (P-77).
- **R-MC-06** Tenants can connect external MCP servers for checks and hand-offs (`03-architecture/mcp-client.md`, I-88, I-89).
  AC: an integration declared without bank fields cannot send bank details, and a write tool cannot run without a named approval.
- **R-CR-03** Release metadata, update bundles, audit chain anchors and export manifests carry composite Ed25519 plus ML-DSA-65 signatures (ADR-001, I-90).
- **R-CR-04** Contractual notices carry a composite companion signature next to the eIDAS seal.

## Journey UI (`12-journey-ui.md`)

- **R-JV-01** Every proposal and grant shows its current position on the route and the formal state name.
  AC: the route response for each of the 16 states contains the state name and a label.
- **R-JV-02** The journey graph equals the state machine.
  AC: the drift test fails if an edge or node is added, removed or renamed on one side only (I-95).
- **R-JV-03** Diary entries respect the role visibility matrix.
  AC: for each role in 7.2 and each kind, the visible set equals the matrix (I-93).
- **R-JV-04** Submission produces a receipt with ledger sequence, time, audit-log anchor, and can email a copy.
  AC: receipt matches ledger sequence, time, and audit anchor (I-24, O-56). Before the anchor is witnessed, the receipt says "anchor pending" and shows no anchor value. Email carries no extra content (R-SB-04).
- **R-JV-05** Route map has a full text alternative and keyboard operation.
  AC: automated WCAG 2.2 AA checks pass in light and dark themes.
- **R-JV-06** Public route graphic works without script.
  AC: the public page loads with scripts disabled and the SVG is present.
- **R-JV-07** Overlay is computed from policy and original-call policy for deferred proposals.
  AC: a deferred proposal shows the original call's P-07 after a later edit.
- **R-JV-08** Planner can preview the voyager route for a draft programme.
  AC: changing P-07 in the creator changes the previewed window text.
- **R-JV-09** Journey vocabulary never reaches contracts, notices, Guide, funder documents or emails.
  AC: a search of those templates for every Voyage-pack label finds none (I-94).
- **R-JV-10** Stage 1 close shows the computed outcome only.
  AC: UI offers no alternative outcome, and the server rejects one (R-LA-03).
- **R-JV-11** Journey rows and responses hold no free text from ledger records.
  AC: property test over random ledgers finds only `TextRef` values in rows. An erased text yields the placeholder (I-97).
- **R-JV-12** Amounts in journey output are canonical ADR-006 strings.
  AC: every amount field matches the canonical form. The frontend has no `Number` conversion of an amount.
