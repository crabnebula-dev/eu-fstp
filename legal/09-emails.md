# Email wording

Status: draft for Daniel's review, 2026-11-21. Not approved. Not wired into the product.

Legal party: CrabNebula Ltd. Responsible data officer: Daniel Thompson-Yvetot.

Request: W10 in `docs/legal/requests/04-product-wording.md`.

Constraints from the code (`crates/fstp-mail/src/template.rs`, `SPEC/03-architecture/notifications.md`):

- A template is fixed text plus slots. The slots are `{proposal}`, `{call}`, `{contract}`, `{milestone}`, `{request}`, `{state}`, `{when}`, `{due}`, `{amount}`, `{link}` and `{count}`. No other value can enter an email.
- Emails hold identifiers and times, never proposal content or identity attributes (I-27).
- Every email ends with the fixed sentence: "We never ask for bank details by email. Bank details change only inside the platform." The renderer adds it. The drafts below do not repeat it.
- A wording change is a new version of the template. The old version stays (I-25). Each draft below is therefore "version 2".
- Negative outcomes use a respectful tone (`SPEC/12-journey-ui.md`).
- The emails are sent through the tenant's own mail relay (ADR-018).

The role invitation email is in `08-role-invitation-and-confidentiality-terms.md`.

---

## A. Proposal outcome (`proposal-outcome`, version 2)

Replaces: `ProposalOutcome` version 1. Today one template serves every state through `{state}`. W10 asks for one wording per outcome. Two wirings are possible, and Daniel chooses:

1. Keep one template with the neutral wording A0.
2. Add one template id per outcome (A1 to A4). That changes `TemplateId::ALL` and the timeline that picks the template.

### A0. Neutral, one template

Subject:

> Proposal {proposal}: a decision is available

Body:

> A decision on proposal {proposal} was recorded on {when}. The proposal is now in the state {state}.
>
> Sign in to read the decision, the reasons and any next steps:
>
> {link}
>
> If you think the decision was reached the wrong way, the platform shows how to file a complaint and by when.

### A1. Selected

Subject:

> Proposal {proposal}: selected for funding

Body:

> Proposal {proposal} was selected for funding on {when}.
>
> The next step is negotiation. Sign in to read the decision and the steps that follow:
>
> {link}
>
> Funding is final only once the contract is signed.

### A2. Not selected

Subject:

> Proposal {proposal}: outcome of the evaluation

Body:

> Thank you for applying. We are sorry to tell you that proposal {proposal} was not selected for funding. The decision was recorded on {when}.
>
> Sign in to read the reviewers' feedback:
>
> {link}
>
> If you think the decision was reached the wrong way, you can file a complaint on the platform. The Guide for Applicants gives the deadline.

### A3. Not eligible

Subject:

> Proposal {proposal}: eligibility check

Body:

> Thank you for applying. We are sorry to tell you that proposal {proposal} did not meet the eligibility criteria of the call. It was not evaluated further. The decision was recorded on {when}.
>
> Sign in to see which criterion was not met:
>
> {link}
>
> If you think the check was done the wrong way, you can file a complaint on the platform. The Guide for Applicants gives the deadline.

### A4. Declined

Subject:

> Proposal {proposal}: declined

Body:

> Proposal {proposal} was declined on {when}.
>
> Sign in to read the recorded reason:
>
> {link}

TODO(legal): whether A2 and A3 must name the complaint deadline in the email itself. The email cannot carry it today, since no slot holds a duration.

## B. Contractual notice (`contract-notice`, version 2)

Replaces: `ContractNotice` version 1. The sealed PDF attached to the email is the notice itself (I-40).

Subject:

> Contract {contract}: formal notice

Body:

> A formal notice under contract {contract}, for proposal {proposal}, was issued on {when}.
>
> The attached PDF is the notice. It carries an electronic seal. The same notice is on the platform:
>
> {link}
>
> Please read it. A notice can start a period within which you must act.

TODO(legal): when a notice counts as received, and whether the email or the platform copy governs (`SPEC/02-domain/contractual-notices.md`, O-20).

## C. Copy of a submission (`submission-copy`, version 2)

Replaces: `SubmissionCopy` version 1. R-SB-04: the applicant asks for a copy at an address they give.

Subject:

> Proposal {proposal}: your submission record

Body:

> You asked for a copy of the submission record of proposal {proposal}.
>
> The proposal was submitted on {when}. The platform keeps the full submission and its receipt.
>
> Sign in to read or download the full submission:
>
> {link}
>
> For your privacy, this email holds no proposal content.

## D. Passkey disabled (`passkey-disabled`, version 2)

Replaces: `PasskeyDisabled` version 1 (ADR-008, 2026-11-19). It must hold no time, no credential id, no device name and no address.

Subject:

> A passkey of your account was disabled

Body:

> For your security, a passkey of your account on the platform was disabled.
>
> Sign in with another passkey, or recover your account, to see your passkeys and add a new one:
>
> {link}
>
> If you did not expect this, recover your account and check your passkeys.

The mailbox notice `mailbox.kind.notice.passkey_disabled` in `web/src/mailbox/messages.en.ts` can stay as it is. Its wording matches this email.

## E. Sign-in and account emails (no legal marker)

`crates/fstp-cell/src/mail.rs` (`proof_message`) sends the sign-up, magic link and recovery emails. They carry no `TODO(legal)` marker. `docs/design/03-applicant-screens.md` asks for an email body for the sign-up confirmation. Optional closing line for all four, for Daniel to decide:

> This message was sent by the FSTP platform, operated by CrabNebula Ltd. The privacy notice explains how your email address is used.

## F. Other templates

`irc-concern`, `notifiable-conflict`, `milestone-reminder`, `milestone-overdue` and `corrigendum` carry no legal marker. Their wording states the event only, and no change is proposed.
