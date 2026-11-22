# Data processing agreement (CrabNebula Ltd and a tenant organisation)

Status: draft outline for Daniel's review, 2026-11-21. Not approved. Not wired into the product.

Legal party: CrabNebula Ltd. Data Protection Officer (DPO): Daniel Thompson-Yvetot.

Replaces: `agreements.text.dpa` in `crates/fstp-signup/src/render.rs` ("TODO(legal): the text of the data processing agreement is pending."). Request item P2.

Basis: Daniel's answer to Q1 (2026-11-21), as in `SPEC/05-compliance/gdpr.md`. On a funder tenant, the funder is controller of programme data and CrabNebula Ltd is its processor. This agreement is written for that case.

TODO(legal): check this outline against the content the GDPR requires of a processor contract. Nothing here quotes or cites the Regulation.

CrabNebula Ltd also coordinates two grant programmes of its own (SuperSAFE, grant agreement 101342989, and ELFA, grant agreement 101298715). For those it is the controller, and no processor agreement exists for that tenant (`SPEC/05-compliance/other.md`).

---

## 1. Parties and roles

- The Customer, as controller of the personal data of its programmes.
- CrabNebula Ltd, 27 Triq it-Tramuntana, Birgu BRG1160, Malta, Company Registration Number C 103590, as processor.
- The Data Protection Officer of CrabNebula Ltd is Daniel Thompson-Yvetot, privacy@crabnebula.dev, 27 Triq it-Tramuntana, Birgu BRG1160, Malta.

## 2. Subject and duration

CrabNebula processes personal data to provide the FSTP platform to the Customer, for the term of the SaaS terms and the exit period after it.

## 3. Nature and purpose

Hosting, storage, backup, display, transmission and erasure of programme data, as the Customer's use of the platform directs. AI assessment runs through the provider the Customer chooses.

## 4. Data subjects

Applicants, team members, guardians of applicants under 18, reviewers and committee members, the Customer's staff, grant recipients, and relatives that reviewers declare.

## 5. Categories of personal data

- Account data: email address, passkey public keys, sign-in records, display name.
- Proposal, review, contract, payment request and complaint data.
- Identity vault data: legal name, date of birth, country, affiliations, verification records, identity documents, guardian identity and consent, bank details, hardship evidence.
- Audit records of reads of proposal content and identity data.
- AI findings and assessment records.

Special categories: hardship evidence may contain health data. TODO(legal): the basis and the extra measures.

## 6. CrabNebula's duties

- Process only on the Customer's documented instructions. The Customer's use of the platform and its settings are those instructions.
- Bind every person with access to confidentiality.
- Keep the security measures of annex 2.
- Use sub-processors only as section 7 allows.
- Help the Customer answer requests from data subjects.
- Help the Customer with security, breach notification, impact assessments and prior consultation.
- Tell the Customer of a personal data breach without undue delay. TODO(legal): the time limit to state.
- At the end of the service, return the data through export, then erase it, unless law requires storage. [NOT BUILT: the export tool is deferred (B-07).]
- Give the Customer the information it needs to show compliance, and allow audits. TODO(legal): audit frequency, notice and cost.
- Tell the Customer if an instruction seems to breach data protection law.

## 7. Sub-processors

- The Customer gives general authorisation for the sub-processors in `sub-processors.md`.
- CrabNebula tells the Customer of any intended change. The Customer can object within TODO(legal): the period. TODO(legal): the consequence of an objection.
- CrabNebula imposes the same data protection duties on each sub-processor.

The Customer's own mail relay and AI provider are chosen and contracted by the Customer. They are not CrabNebula's sub-processors. TODO(legal): confirm this reading (ADR-018, ADR-019).

## 8. Transfers outside the European Union

CrabNebula hosts in the European Union. CrabNebula does not transfer programme data outside it. The Customer may choose an AI provider outside the European Union. That transfer is the Customer's choice and responsibility. TODO(legal): confirm.

## 9. Operator access

CrabNebula staff hold no roles in the Customer's cell. Access to content needs the Customer's break-glass approval and is logged (SoD-08, TH-18). TODO(legal): whether the agreement must say more about operator access. [Daniel to verify: the break-glass flow is a SPEC rule; its build status was not checked for this draft.]

## 10. Backups

Backups are encrypted before they leave the cell, and stored with OVHcloud Object Storage in the European Union. Erasure destroys keys, so erased data cannot be read from backups. TODO(legal): L-15, whether this agreement must state the backup retention period and provider (ADR-005). The retention period is not decided yet (ADR-012).

## 11. Governing law

This agreement is governed by Maltese law.

TODO(legal): the competent courts.

## Annex 1: Details of processing

Sections 2 to 5 above.

## Annex 2: Technical and organisational measures

- Passkey sign-in, always enabled. Magic links per tenant (P-70). Password sign-in (OPAQUE) is not built.
- One database cell per tenant. No link between accounts in different tenants (I-20).
- Identity vault on its own database cluster and web address (I-83). The application receives yes or no answers only.
- One encryption key per free text. Erasure by key destruction (R-KY-02, I-81).
- Tamper-evident audit log of state changes, role bindings, policy changes and reads of proposal content or identity data (R-AU-01, I-24).
- Encrypted and mutually authenticated traffic between components (R-NF-09).
- Separation of duties for payments and role grants (SoD rules).
- Personal details replaced with placeholders before AI inference.
- Client addresses held in memory only, for rate limits. Never stored or logged.
- TODO(legal): organisational measures (staff training, access reviews, incident response) that CrabNebula Ltd commits to.

Version: TODO(legal): version and date.
