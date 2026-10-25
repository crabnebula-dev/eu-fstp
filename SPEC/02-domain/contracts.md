# Contracts

## Instrument

Each programme selects its contract instrument and template version (P-29). The SuperSAFE default is a memorandum of understanding (Annexe 6). The template version is frozen at call publication, so applicants know the terms before submitting.

## Generation

A contract is generated from the template and the agreed plan version. Generated content includes parties, amount, tasks with their milestones, milestone amounts, deliverables and due dates, licence obligations (P-26), the hardship clause (P-27) and the payment mode (P-20).

Negotiated changes to template clauses are recorded as a diff against the template, with the person who proposed each change.

## Parties

- Tenant operator signatory (Operations role with signing authority).
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
