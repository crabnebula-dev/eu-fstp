# Identity vault statements and fields

Status: draft for Daniel's review, 2026-11-21. Not approved. Not wired into the product.

Legal party: CrabNebula Ltd. Responsible data officer: Daniel Thompson-Yvetot.

Code sites: `web/src/vault/messages.en.ts` (marker at the top: "the consent and attestation statements below are interim wording"), `web/src/applicant/messages.en.ts` (`submit.dob.*`, marker L-02), `web/src/vault/write.ts` and `web/src/applicant/submit.ts` (marker L-02). Request items W4 and D2.

What the code does:

- The date of birth goes to the identity vault only. The vault answers one bit: whether the lead is under 18 at the call deadline (Q23 B). The application never receives the date.
- Without an effective over-18 attestation, the proposal stays minor-flagged. It then needs a verified guardian consent before negotiation (R-NG-02).
- The guardian gives consent on the vault's own web address. Only the vault receives the guardian's data.
- Bank details hold the account holder name and the IBAN. Every change, the first entry included, waits for verification and the hold period P-36 (default 7 days).
- Hardship evidence is a free-text statement, up to 4000 characters, with a reference the grantee enters in the request.

TODO(legal): L-02, the legal basis for collecting the date of birth and a guardian's data before negotiation, and whether the GDPR rule on children's consent applies. Every statement below waits on that answer.

---

## A. Date of birth at submission (W4)

Replaces: `submit.dob.heading` and `submit.dob.intro` in `web/src/applicant/messages.en.ts`.

Heading:

> Date of birth

Intro:

> We ask for your date of birth to know whether you are under 18 at the call deadline. Applicants under 18 need a parent's or guardian's consent before negotiation. Your date of birth goes only to the identity vault. The programme learns only whether you are under 18 at the deadline. Your identity and age are checked later, in negotiation. A false date is a reason to end your application at that check.

## B. Age confirmation in the vault

Replaces: `adult.legend`, `adult.confirm` in `web/src/vault/messages.en.ts`.

- `adult.legend`: "Age confirmation"
- `adult.confirm`: "I confirm that this date of birth is my own and is correct. I understand that it will be checked in negotiation."

## C. Guardian consent

Replaces: `guardian.legend`, `guardian.consent` in `web/src/vault/messages.en.ts`.

- `guardian.legend`: "Consent of a parent or legal guardian"
- Intro text to add above the box, as a new entry `guardian.intro`:

> You are named as the parent or legal guardian of the lead applicant of this proposal. The applicant is under 18. Before the proposal can go to negotiation and a contract, we need your consent. Your identity is checked here, in the identity vault. Your details stay in the vault. The programme sees only that a verified consent exists. You will also sign the contract as a party if a grant is awarded.

- `guardian.consent`:

> I am the parent or legal guardian of the lead applicant. I consent to their proposal going to negotiation, and to the processing of their data and mine as the privacy notice describes.

TODO(legal): whether the guardian also signs the contract in every case (R-CT-02 says the guardian is a signing party of a minor's contract), what the consent must cover, and how a guardian withdraws it.

- Withdrawal line, a new entry `guardian.withdraw_note`:

> You can withdraw your consent at any time on this page. The proposal then cannot continue to a contract.

[NOT BUILT: the vault accepts a `ConsentWithdrawn` write under the guardian consent ticket, but the vault page offers no withdrawal control yet. Hold this line until it exists.]

## D. Identity details page

`write.intro` can stay: "What you enter here goes only to the identity vault of this tenant. The application does not see it." Proposed addition:

> The privacy notice explains how long it is kept and who can see it.

## E. Bank details

`bank.hold` can stay. Proposed addition to `bank.legend` area, a new entry `bank.intro`:

> Bank details are kept in the identity vault and used only to pay this grant. The finance team checks them against a bank document. We will never ask for bank details by email or chat.

`bank.dispute.confirm` can stay. It states a fact and an action.

## F. Hardship evidence

Proposed new entry `hardship.intro`, above `hardship.statement`:

> Describe what prevents completion, such as a natural disaster or a serious medical crisis. Write only what is needed to assess the request. Health details are sensitive data. They are kept in the identity vault, and only the people who verify hardship evidence can read them.

TODO(legal): the legal basis for health data in hardship evidence, and whether the request needs an explicit consent statement.
