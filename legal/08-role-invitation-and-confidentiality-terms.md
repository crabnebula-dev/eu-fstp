# Role invitation email and confidentiality terms

Status: draft for Daniel's review, 2026-11-21. Not approved. Not wired into the product.

Legal party: CrabNebula Ltd. Data Protection Officer (DPO): Daniel Thompson-Yvetot.

Requirement: J2 (design section 2.2). A person invited to a Drafting or Judging role accepts confidentiality terms before a role is granted. The accepted text and its version are recorded (`TERMS_VERSION` in `crates/fstp-api-core/src/people.rs`). A grant without accepted terms is refused (`crates/fstp-domain/src/roles/commands.rs`).

Constraints from the code:

- The invitation email holds one slot, the link. It names no programme, no role, no inviter and no address (ADR-026, I-27). The landing page shows the role and the terms once the link is opened.
- Every email ends with the fixed sentence `BANK_DETAILS_SENTENCE`, which the template adds. Do not repeat it.
- A wording change is a new template version (I-25). The old version stays.
- The terms of a Judging role state the programme's choices on P-75 and P-77. The existing sentences in `web/src/people/messages.en.ts` (`people.terms.p75_*`, `people.terms.p77_*`) already do so and need no change.
- A new terms wording needs `TERMS_VERSION` raised, so a recorded acceptance always names the text shown.

---

## A. Invitation email (`role-invitation`, version 2)

Replaces: template `RoleInvitation` version 1 in `crates/fstp-mail/src/template.rs`.

Subject:

> You are invited to a role in a funding programme

Body:

> You are invited to take a role in a funding programme that runs on the FSTP platform.
>
> Open this link to see the programme, the role and its confidentiality terms. You can accept or ignore the invitation there. The link works once, and only for you:
>
> {link}
>
> If you did not expect this invitation, you can ignore this message. No account is created unless you accept.
>
> This message was sent by the FSTP platform, operated by CrabNebula Ltd, on behalf of the organisation that runs the programme.

TODO(legal): whether an invitation email must identify the sender organisation by name. The code forbids naming it today (I-27), so the last line names the platform operator only.

## B. Confidentiality terms for Drafting roles (programme staff)

Replaces: `people.terms.body` in `web/src/people/messages.en.ts` for Drafting roles. Wiring needs one entry per group, for example `people.terms.body.drafting` and `people.terms.body.judging`. Placeholders `{role}` and `{version}` stay.

> **Confidentiality terms for the role of {role}, version {version}**
>
> By accepting, you agree to the following for as long as you hold this role and afterwards.
>
> 1. You keep confidential everything you see in this role that is not public. This covers proposals, reviews, scores, deliberations, contracts, payments and personal data.
> 2. You use that information only to carry out this role in this programme.
> 3. You do not copy it out of the platform, except where the role needs it and the programme allows it.
> 4. You do not try to find out who an applicant or reviewer is, beyond what your role shows you.
> 5. You declare any conflict of interest as soon as you know of it.
> 6. You tell the programme at once if you think confidential information was disclosed.
> 7. Your identity is verified before the role is granted. Your actions in the role are recorded in an audit log.
>
> TODO(legal): the duration of the duty after the role ends, the consequences of a breach, and the governing law.

## C. Confidentiality terms for Judging roles (reviewers, committee, independent review committee)

Replaces: `people.terms.body` for Judging roles, as above. The P-75 and P-77 sentences follow it, as the page builds them today.

> **Confidentiality and review terms for the role of {role}, version {version}**
>
> By accepting, you agree to the following for as long as you hold this role and afterwards.
>
> **Confidentiality**
>
> 1. You keep every proposal, review, score and deliberation confidential. You use them only to evaluate proposals in this programme.
> 2. You do not reuse ideas, text or data from a proposal for any other purpose.
> 3. You do not copy proposal content out of the platform.
> 4. You do not try to find out who an applicant is, beyond what the proposal itself shows. The platform shows applicants under a handle, and shows you to applicants under a handle.
>
> **Conflicts of interest**
>
> 5. Before you read a full proposal, you declare any conflict of interest with it. You declare a new conflict as soon as you know of it.
> 6. You do not review a proposal where you have a conflict. The programme reassigns it.
>
> **AI findings and AI agents**
>
> 7. AI findings support you. They can be wrong. Your scores, comments and decisions must be your own judgement.
> 8. You may use an AI agent only through the platform's agent connection, and only as this programme allows. The programme's choices follow.
>
> **Records**
>
> 9. Your identity is verified before the role is granted. Your reads of proposal content and your actions are recorded in an audit log.
>
> TODO(legal): the duration of the duty after the role ends, the consequences of a breach, the governing law, and whether declared relatives need their own notice (ADR-009, Q31).

## D. Wording already in place

These catalogue sentences stay as they are. They state the programme's choices only:

- `people.terms.p75_on`, `people.terms.p75_off`, `people.terms.p75_undecided`
- `people.terms.p77_allowed`, `people.terms.p77_draft_only`, `people.terms.p77_undecided`
