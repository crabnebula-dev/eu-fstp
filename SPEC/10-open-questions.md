# Open questions

## Resolved

| ID | Resolution |
| --- | --- |
| O-05 | PostgreSQL, one database per cell. Shared or separate clusters remains ADR-required. |
| O-17 | Signal dropped. |
| O-19 | SuperSAFE enables all four group types. |
| O-01 | SuperSAFE P-10 is assigned reviewers only. Non-assigned committee members use the ranking view. |
| O-04 | TypeScript is accepted. |
| O-06 | In-house frontend, no framework. |
| O-16 | Crypto (ADR-001, two tiers with Mythos release gate), tokio and smol (ADR-002), tsc, libFuzzer and Playwright (ADR-003). |
| O-22 | Staff of any partner may be assigned reviewers, subject to SoD-10 and SoD-11. |
| O-15 | All SuperSAFE parameter values set, except P-41 which comes from the grant agreement. |
| O-09 | Synthetic corpus at launch; consented real proposals added after the pilot (R-LA-09 to R-LA-11, M12). |
| O-10 | EUPL-1.2 for the export schema and tooling. |
| O-18 | Qualified signature by default, with recorded fallback to advanced. |
| O-24 | Allowlisted parsing crates under ADR-001; validation procedure in-house. |
| O-25 | DCO sign-off for contributions; tooling kept as a separate EUPL executable. |
| O-12 | Legal nature follows each funder's instrument (P-44). |
| O-14 | Self-hosted cells call update and licence services, treated as within CRA scope. |
| O-27 | Noncommercial installs use the same licence check with a free, automatically issued token. |
| O-28 | P-43 set to 30 days. |
| O-02 | Not Annex III; reassessment triggers recorded in `05-compliance/ai-act.md`. |
| O-03 | Build is self-funded by CrabNebula Ltd. |
| O-07 | CrabNebula Ltd operates the SaaS; NIS2 scope re-checked annually. |
| O-08 | Both relying party modes supported (P-45); self-hosted uses tenant registration. |
| O-13 | No notice period; 30-day retrieval; erasure with confirmation. |
| O-21 | WhatsApp enabled in v1 for individual notifications after per-tenant assessment. Superseded: WhatsApp is deferred by Daniel on 2026-11-04 (B-03). |
| O-29 | Each tenant uses its own WhatsApp Business account. Kept for when WhatsApp returns (B-03). |
| O-20 | Sealed PDF notice in the platform plus email (I-40). |
| O-26 | Signature cascade: wallet QES, then QTSP remote QES, then approved advanced. |
| O-11 | v1 thresholds adopted; revised after the first M7 run. |
| O-30 | Public visibility is grantee opt-in up to a programme maximum (P-50, P-51), hidden by default. |
| O-31 | Horizon Europe profile generates all five outputs. |
| O-32 | Complaints: coordinator review first, then escalation to the IRC (`02-domain/complaints.md`). |
| O-33 | SuperSAFE support programme set (P-60); payment target 15 days after approval (P-59). |
| O-34 | Platform attribution required in interface footers (P-68); documents and emails carry none. |
| O-36 | Passkeys, EUDI Wallet, OPAQUE and applicant magic links; phishing-resistant step-up for high-risk actions (`03-architecture/authentication.md`). |
| O-37 | Root keys in an EU-operated KMS or HSM, or a CrabNebula-operated HSM, per cell (ADR-004). |
| O-40 | MCP server for all roles plus public research tools; reviewer content access off by default (P-75); binding actions per programme (P-77); MCP client in v1. |
| O-41 | SuperSAFE: agents may not complete binding actions; they draft, and the user confirms in the platform (P-77). |
| O-35 | Composite Ed25519 (aws-lc-rs) plus ML-DSA-65 (moduletto) for release metadata, updates, audit anchors, export manifests, and as companion signature on notices (ADR-001). |
| O-47 | A tenant admin grants Drafting, Judging and Operations roles in a programme. SoD-07 applies to self-grants. Receiving bindings arise from the proposal (`02-domain/roles-and-sod.md`, decided 2026-10-25). |
| O-43 | Under the P-10 option "operator staff only", the FSTP coordinator reads proposals in stages 1 and 2 (`02-domain/policy-parameters.md` NOTE 1, decided 2026-10-25). |
| O-48 | The applicant states a country of residence or establishment at submission, held only in the identity vault and verified in NEGOTIATION; R-NG-01 carries the exception. A legal check is pending (`03-architecture/overview.md` NOTE 6, decided 2026-10-25). |
| O-51 | The programme manager closes each milestone with a reason; PAID, REJECTED, WITHDRAWN and CLOSED are terminal, and the programme manager can close a request waiting in CHECKS_FAILED or CHANGES_REQUESTED (`02-domain/payment-requests.md`, decided 2026-10-25). |
| O-44 | P-16: a majority of votes cast by members who are not recused, a quorum of more than half of them, at most one delegated vote per member, and the chair's casting vote on a tie (`02-domain/policy-parameters.md` NOTE 8, decided 2026-10-25). |
| O-46 | The SuperSAFE criterion scale is 0 to 5 (`02-domain/policy-parameters.md` NOTE 6, decided 2026-10-25). |
| O-49 | The FSTP coordinator records the stage 1 rows; the programme manager records IRC_REVIEW to DECLINED and NEGOTIATION to DECLINED; timer and date rows are not decisions (`02-domain/state-machine.md` NOTE 13, decided 2026-10-25). |
| O-50 | Every active assigned reviewer records "no questions" before the stage 2 window closes that way (`02-domain/state-machine.md` NOTE 4, decided 2026-10-25). |
| O-53 | The other account's Drafting binding stays at identity discovery, as its Judging binding does (`02-domain/roles-and-sod.md`, decided 2026-10-25). |
| O-54 | Applicant score and comment visibility: Yes to both scores and reviewer comments, but only after a final decision: NOT_SELECTED, DECLINED or GRANTED. GRANTED is a decision, not a terminal state. An INELIGIBLE proposal has no scores and shows the recorded knock-out reason. A WITHDRAWN proposal had no final decision and shows no scores or comments. Anonymous reviewer rules under P-11 still apply. (`12-journey-ui.md`, decided 2026-11-01) |
| O-55 | Vocabulary pack default: Plain grant language is the platform default vocabulary pack. Voyage is an optional pack a tenant can switch on. Tenants can also edit labels via terminology overrides. Amended by Daniel on 2026-11-01: "I want plain-first / voyage optional". (`12-journey-ui.md`) |
| O-56 | Submission receipt contents: Receipts carry the audit-log anchor (I-24, I-90) in addition to ledger sequence and timestamp. (`12-journey-ui.md`, decided 2026-11-01) |
| O-57 | Coordinator counts before conflict declaration: Permitted. Coordinators may see aggregate per-state counts before conflict declaration, with no titles or applicant data. (`12-journey-ui.md`, decided 2026-11-01) |
| O-58 | IRC route strip: No. IRC members do not get a route strip. They see the nominated proposal and outcome only (R-IR-03). (`12-journey-ui.md`, decided 2026-11-01) |
| O-59 | Chronicle PDF generation: Self-service export by the grantee or auditor. It is not a funder report and needs no approval. (`12-journey-ui.md`, decided 2026-11-01) |
| O-60 | Minor guardian steps visibility: Guardian consent steps appear only to the guardian, never to the rest of the team. (`12-journey-ui.md`, decided 2026-11-01) |
| O-42 | Two-tier release signing: an offline root used about yearly to certify time-limited signing keys, and an isolated automated signing service with moduletto, optional two-maintainer approval (`../docs/adr/ADR-004-key-custody.md`, decided 2026-10-25). |
| O-45 | Per-text data keys; erased texts resolve to an erasure-log entry linked into the audit chain; salted digests; Auditors and tenant admins read the log; erasure requests deferred only for P-41 records; a pseudonymous ledger skeleton remains after P-41. Two legal checks pending (`../docs/adr/ADR-007-domain-ledger.md`, decided 2026-10-25). |
| O-52 | A published call keeps a record of its effective P-05 and P-13 limits, the publication values plus every later tightening. Corrigenda come from that record, and the Guide with its corrigenda equals it under I-51 (`02-domain/policy-parameters.md` NOTE 7, decided 2026-10-25). |

## Open

| ID | Question | Blocks |
| --- | --- | --- |

## Backlogged

O-38 and O-39 moved to `11-backlog.md` with realtime sessions.

## Tracked, important, non-blocking

O-23 is a consortium document change. L-01 to L-17 are legal checks for Daniel.

| ID | Topic | Why it matters |
| --- | --- | --- |
| O-23 | Align the SuperSAFE DoA with the design: section 7 should not limit proposal access to CrabNebula staff; 8.a should state that partners take part in review and extend the no-benefit guarantee to every partner; the activity list in section 3 should be closed, since its last open-ended item conflicts with the closed list MGA 6.2.D.1 requires | The platform implements the resolved reading. An unaligned annex leaves a gap an auditor or reviewer could point to. |
| L-01 | DPIA for LLM assessment of all submissions (`05-compliance/gdpr.md`) | Needed before the first live call that uses findings. |
| L-02 | Legal basis for a minor's data before guardian consent, and whether Article 8 GDPR applies | Determines what the submission flow may collect from minors. |
| L-03 | CRA category reading for the self-hosted product, given the identity vault component | Confirms Module A as the assessment route. |
| L-04 | Data Act Article 25 periods marked TODO(legal) in `05-compliance/data-act.md` | Sets the SaaS contract switching terms. |
| L-05 | eIDAS intermediary obligations marked TODO(legal) in `03-architecture/eudi-wallet.md` | Confirms the stateless intermediary design. |
| L-06 | Confirm the record-keeping and confidentiality periods in the signed SuperSAFE Data Sheet for P-41 | The HE MGA Data Sheet sets standard periods counted from final payment. |
| L-07 | Confirm grantee opt-in as the legal basis for publication, including for natural persons | Publication now rests on the grantee's own choice; confirm the consent wording. |
| L-08 | EU funding acknowledgement obligations passed on to FSTP recipients under the grant agreement | Affects contract templates and public pages. |
| L-09 | Current Funding & Tenders Portal forms for third-party call publication and FSTP reporting | Sets the field mappings in the Horizon Europe profile. |
| L-10 | The Annexe allows up to 400k EUR per recipient over the programme, while MGA 6.2.D.1 caps support per recipient at the Data Sheet amount unless agreed with the granting authority. Confirm the SuperSAFE Data Sheet ceiling | If the Data Sheet ceiling is per recipient and below 400k EUR, the Annexe figure cannot apply. I-50 enforces whichever is lower. |
| L-11 | Confirm hardship contributions are eligible FSTP costs as described in Annex 1 | Determines how hardship payments are reported. |
| L-12 | Check MGA Articles 17.2, 20 and 21 and the AGA annotations and guidance on FSTP against the spec | These parts were not retrieved during the alignment check. |
| L-13 | Confirm the support programme activities are described as action tasks in Annex 1 | Partner effort on mentoring, presentations, promotion and CRA guidance is eligible only if Annex 1 covers it. |
| L-14 | Governing law and any external redress for subgrant contracts, and confirmation of the proposed complaint deadlines P-61 to P-64 | Recipients are not parties to the grant agreement; the subgrant contract sets their remedies. |
| L-15 | Hosting provider due diligence: ownership, sub-processor terms, data centre locations and certifications (ADR-005) | Names the sub-processor in every tenant DPA and supports the Data Act Article 32 assessment. |
| L-16 | CrabNebula Ltd size category under Recommendation 2003/361/EC, including linked enterprises in the group (DSA Articles 15(2) and 19) | Decides online platform duties and transparency reports. |
| L-17 | Whether tenants' programme portals are information society services, making tenants DSA providers towards applicants | Decides tenant tooling scope (G-21). |

### Legal checks awaiting an L- number

Raised on 2026-10-28 by the M3 ADR drafts. Daniel assigns each an L- number, and the `TODO(legal)` markers then name it.

| Topic | Raised in | Why it matters |
| --- | --- | --- |
| Legal basis for short-lived in-memory rate limiting on client IP addresses at the edge and in the cell | `docs/adr/ADR-009-cell-boundary.md` Edge and tunnel (design Q19) | Decides whether client addresses may be held in memory for rate limits at all. |
| Legal basis for storing reviewers' relatives, and the minimum attributes that conflict matching needs | `docs/adr/ADR-009-cell-boundary.md` Write kinds, `ReviewerDeclaration` (design Q31) | The platform would hold third parties' data that they did not declare themselves. |
