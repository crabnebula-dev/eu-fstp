# Contracts

## Instrument

Each programme selects its contract instrument and template version (P-29). The SuperSAFE default is a memorandum of understanding (Annexe 6). The template version is frozen at call publication, so applicants know the terms before submitting.

## Generation

A contract is generated from the template and the agreed plan version. Generated content includes parties, amount, tasks with their milestones, milestone amounts, deliverables, start dates and due dates, licence obligations (P-26), the hardship clause (P-27) and the payment mode (P-20).

Negotiated changes to template clauses are recorded as a diff against the template, with the person who proposed each change.

NOTE: Each milestone carries a start date as well as a due date (decided 2026-10-25).

## Amount and recipient cap (I-13, I-14)

These rules were decided on 2026-10-25.

- The granted amount equals the effective plan total minus recorded deductions for ineligible costs. Each deduction carries a recorded reason.
- The granted amount lies within P-04, inclusive at both ends.
- The recipient for P-05 is the verified identity of the applicant lead.
- The sum counted against P-05 is the granted amounts plus open reservations. A reservation opens when the amount is determined. Amended totals count.
- At grant closure, the counted amount for the grant drops to its paid total (I-64).
- An edit that lowers P-05 below any recipient's counted sum is refused.

NOTE: P-05 is not frozen. For a published call, the stricter of the publication snapshot and the live value applies (`02-domain/policy-parameters.md` NOTE 7).

## Repeat grants and amendments (I-15)

These rules were decided on 2026-10-25.

- The same applicant means the same verified identity of the applicant lead, across every programme of the tenant.
- Prior deliverables are every deliverable accepted so far under that identity's earlier grants.
- Each prior deliverable is checked against the P-26 of the call that funded it.
- An amendment also needs this grant's accepted deliverables to be recorded as publicly available.
- Under the P-65 option "progress report", a partial claim without public deliverables leaves the record incomplete until the final claim (`02-domain/payment-requests.md`).

## Parties

- Tenant operator signatory: the Contract signatory, an Operations role (`02-domain/roles-and-sod.md`, decided 2026-10-25).
- Applicant lead and, where the programme requires, each team member.
- Guardian, for a minor applicant.

## Signature

The signature level follows P-30. SuperSAFE defaults to qualified electronic signatures, produced through the EUDI Wallet or a qualified trust service provider.

Signers follow a fixed cascade (O-26):

1. Qualified signature through the EUDI Wallet.
2. Remote qualified signature through the tenant's qualified trust service provider (P-49).
3. Advanced signature, approved by the programme manager with the reason recorded on the contract.

The third step exists for signers who cannot use either qualified route, for example some applicants outside the EU, which the Annexe permits in section 4.

Signature validation covers the certificate chain against the EU trusted lists and revocation status at signing time. Parsing uses allowlisted crates and the validation procedure is in-house (ADR-001). Signatures are created in the signer's wallet or at a qualified trust service provider, never by the platform.

## States

| State | Meaning |
| --- | --- |
| DRAFTED | Generated, under negotiation |
| SENT | Final version sent for signature |
| SIGNED_BY_GRANTEE | All grantee-side parties signed |
| EFFECTIVE | Countersigned. Proposal moves to GRANTED |
| AMENDMENT_PENDING | New version drafted, not yet signed by all parties |
| SUPERSEDED | Replaced by a signed amendment |
| TERMINATED | Ended early, reason recorded |

## Rules

- A signed version is immutable. Its content hash is in the audit log (I-30).
- An amendment is a new version signed by all parties. IRC review follows P-14.
- Amendments run as a separate workflow. The proposal state does not change while an amendment is pending (decided 2026-10-25).
- The programme manager decides whether a P-14 exemption applies. A total named in P-14 means the amended contract total (decided 2026-10-25).
- An amended total counts against P-05, as set out in "Amount and recipient cap".
- Contract terms are the source for timeline events (`03-architecture/notifications.md`). An amendment recomputes the affected events.
- The grantee can decline at any point before signature (R-NG-04).

## Horizon Europe flow-down clauses (I-49)

Under the Horizon Europe profile, every contract includes clauses that pass on to the recipient the obligations of the grant agreement on:

- conflict of interests (Article 12),
- confidentiality and security (Article 13),
- ethics and values (Article 14),
- visibility of EU funding (Article 17.2),
- specific rules for carrying out the action (Article 18),
- information obligations (Article 19),
- record-keeping (Article 20),
- access rights for the granting authority, OLAF, the European Court of Auditors and other Article 25 bodies.

Clause wording comes from the signed grant agreement and legal review, never from the platform's defaults. Milestones must fall within the action duration (I-46) and reference the closed activity list (I-47).

## Reallocation clause

Where P-66 is enabled, the contract permits moving amounts between milestones of the same task with approval, without amending the contract (`payment-requests.md`).
