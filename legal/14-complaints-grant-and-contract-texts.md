# Complaint, negotiation, grant, contract and payment texts

Status: draft for Daniel's review, 2026-11-21. Not approved. Not wired into the product.

Legal party: CrabNebula Ltd. Responsible data officer: Daniel Thompson-Yvetot.

These texts are spoken by the programme operator to applicants and grantees. CrabNebula Ltd only operates the platform. Request items W5, W6 and W9.

---

## A. Complaint screens (W5)

Code site: none yet. No complaint screen is built in `web/src`. `docs/design/10-post-grant-screens.md` holds the prototypes and their `TODO(legal)` comments. Windows come from P-61 to P-64 (proposed: 10, 15, 10 and 20 working days).

### A1. Filing a complaint

> **File a complaint**
>
> You can contest how a decision was reached. Examples are a missed step, a conflict of interest, or a deviation from the Guide for Applicants. Disagreement with the reviewers' expert scores is not grounds for a complaint.
>
> You can file until {deadline}. That is {P-61} after the decision notice.
>
> A member of the coordinator's team who took no part in the decision reviews your complaint. You get a reply within {P-62}.
>
> Filing a complaint never affects your evaluation or your payments.

### A2. Coordinator reply received

> The coordinator's team replied to your complaint on {when}.
>
> If you are not satisfied, you can escalate it to the independent review committee until {deadline}. That is {P-63} after the reply. At least two committee members who took no part in the decision review it. They reply within {P-64}.

### A3. Escalation

> **Escalate to the independent review committee**
>
> Say why the reply does not resolve your complaint. The committee sees your complaint, the reply and the record of the decision.

### A4. Outcome

> Your complaint was upheld. Your proposal will be evaluated again by different reviewers, or will re-enter the next call at the stage where the error happened. The decision explains which.

> Your complaint was not upheld. The decision explains why.

TODO(legal): L-14, the governing law and any external redress after the internal procedure, for applicants and for grant recipients. Add one sentence to A4 once Daniel supplies it. TODO(legal): confirm P-61 to P-64 (L-14).

## B. Negotiation agreement summary (W6)

Code site: `docs/design/03-applicant-screens.md` line 137 ("agreement summary, notice text and complaint window wording"). No catalogue entry exists. The data protection notice of negotiation is in `02-data-protection-summary-and-notices.md`, section D.

> **Before you sign**
>
> Your contract is with {coordinator.name}. You do not become a party to the EU grant agreement of {action.acronym}.
>
> - The amount is set in the contract. It is reduced by any costs that are not eligible.
> - Payment follows delivery of milestones. Each claim needs evidence, and the final claim on a milestone needs public deliverables under an accepted licence.
> - The contract passes on duties from the EU grant agreement, such as keeping records and accepting checks and audits.
> - A change to the plan between tasks needs a signed amendment.
> - You can decline before you sign.
>
> Read the full contract before you sign. TODO(legal): approve against the signed grant agreement (L-12).

## C. Grant acceptance and approval

Code site: `web/src/grant/messages.en.ts`, marker "the wording of the acceptance and approval texts".

- `grant.accept.intro` draft:

> By accepting, you agree to the grant amount of the current determination. This is not the contract. The contract is drafted after the programme approves the grant. A new determination needs a new acceptance.

- `grant.approve.intro` draft:

> You approve the grant at the amount the grantee accepted. A contract can then be drafted. Your approval is recorded with your name.

## D. Signature routes and decline

Code site: `web/src/contract/messages.en.ts`, marker "the wording of the signature routes and of the decline text".

- Route intro draft:

> Choose how to sign. The platform offers a qualified electronic signature with the EUDI Wallet first, then a remote qualified signature through the programme's trust service provider, then an advanced electronic signature. An advanced signature needs the programme manager's approval. The signing service creates the signature, never the platform.

TODO(legal): the legal effect of each signature level, and which levels the SuperSAFE MoU needs (`crates/fstp-sigval/src/lib.rs`, P-30). Do not describe legal effect in this text until Daniel supplies it.

- `contract.decline.intro` draft:

> You can decline the contract before any grantee signature. Declining ends your proposal's route to a grant. The unsigned draft is sealed and kept as a record. You cannot undo this.

TODO(legal): whether a decline can be undone, or a new negotiation opened, and what to say.

## E. Payment review, approval and release

Code site: `web/src/payments/messages.en.ts`, marker "the wording of the review, approval and release texts". These are staff texts. No legal wording is needed if they state facts only. Draft notes:

- Release: "Releasing records that the payment was sent through your organisation's bank. The platform does not move money." (I-16.)
- Approval: "Your approval of each line is recorded with your name and reason. The approver and the releaser of a payment must be different people." (SoD-04.)

TODO(legal): P-44, the legal nature of payments for each funding instrument, if the texts must name it.

## F. Support channel description

Code site: `ops.reports.failure.support_note` in `web/src/operations/messages.en.ts`, and `docs/design/10-post-grant-screens.md` ("Contact support").

> If a report cannot be generated, contact CrabNebula Ltd support at TODO(legal): support email or URL. Give the programme id and the time of the failure. Do not send personal data or proposal content.
