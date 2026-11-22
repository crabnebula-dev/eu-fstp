# ADR-032: Anonymous drafts with a resume link

Status: Accepted in principle by Daniel on 2026-11-22. The readings marked "Interim, pending Daniel" below wait for his answer. Drafted 2026-11-22 by lane L25 `prod/anonymous-drafts`.

The number is the next free one after ADR-031. ADR-030 is taken by lane `prod/branding-theme`.

## Context

Daniel decided on 2026-11-22, verbatim:

> "Let people create a submission anonymously or after logging in, but require simple registration in order to properly submit. This includes email verification, full identity verification will then be required later on."

And on where the anonymous draft lives: "On the server, with a resume link". The draft is saved on the platform under a secret link that the browser keeps. Registering (email, then the code or link from the email) attaches the draft to the new account. Unclaimed drafts are deleted after 30 days. It works across devices if the person saves the link. Full identity verification stays at NEGOTIATION (`state-machine.md`). Lane L24 builds that request flow.

The rules this decision must keep:

- `roles-and-sod.md` "Receiving bindings": "A Receiving binding starts when the draft is created, or when the person is added to the proposal if that is later." Roles bind a tenant account. A proposal in DRAFT therefore always has a lead account with an Applicant binding.
- **I-21** "Pre-submission check runs and drafts are not readable by operator or Judging roles."
- **I-17** and **R-SB-01**: before negotiation, applicants provide only data needed for evaluation. No identity attribute reaches a draft.
- **I-23** and **I-24**: the ledger and the audit log are append-only and tamper-evident.
- **R-NF-02**: logs and metrics hold no proposal content or identity attribute.
- **R-NF-08**: all data at rest in a cell is encrypted with cell-specific keys.
- **R-MC-04**: agents without an account stay on the public tools.
- `pre-check.md`: the pre-check is rate-limited per proposal and per account across drafts in the same call (P-23). Unsubmitted drafts and their pre-check runs are deleted when the call closes. **TH-29**: "Pre-check quota bypass by opening extra drafts", mitigated by the account-level cap.
- `authentication.md` "First passkey", ceremony 2: self-registration of a Receiving account after email proof.

## Invariant check

No invariant forbids the decision, once the anonymous draft is not a proposal.

- An anonymous draft is form text kept under a link. It is not a domain proposal, has no state in the state machine, and writes no ledger record. So no Receiving binding exists without an account, and the binding rule above holds unchanged.
- The proposal, its DRAFT state and the lead's Applicant binding are created when the draft is claimed, by the ordinary `CreateDraft` of the signed-in account. Every guard of `CreateDraft` runs then: the call is open, the programme is active, SoD-01, SoD-03, SoD-05, SoD-06, I-06 and I-36.
- Nothing is appended to the ledger for an anonymous draft, so I-23 and I-24 are untouched. Its deletion is the deletion of an operational row.

## Decision

| Topic | Decision | Basis |
| --- | --- | --- |
| What an anonymous draft is | The three form sections of a workspace (`title`, `summary`, `narrative`) and the call it is for. No account, email, name, address, peer address or other identity data | R-SB-01, I-17 |
| Where it lives | One row of `workspace.anonymous_drafts` in the cell's application database. The sections are sealed under the cell's ledger key generation with the AAD `"fstp-anondraft-v1" \|\| cell \|\| draft id`. Clear columns are the draft id, the token digest, the call id, times and the key generation | R-NF-08, I-21 |
| The resume link | A 32-byte random token, written as 64 lowercase hex characters in the URL fragment: `https://<cell>/auth/draft#<token>`. The fragment never reaches the server. The browser also keeps it in local storage | R-NF-02 |
| Token at rest | Only the SHA-256 digest of the token is stored. A database reader cannot open a draft by its row | Bearer secret |
| Token on the wire | Only in a JSON request body, never in a path or query. So no access log, route log or proxy log holds it | R-NF-02 |
| Routes | Four cell routes, each `POST`, JSON, no session, `Origin` checked: `/auth/drafts` `{call}` starts a draft and answers `{token, expires}`; `/auth/drafts/open` `{token}` answers the call, the sections and the expiry; `/auth/drafts/save` `{token, title, summary, narrative}` replaces the sections; `/auth/drafts/discard` `{token}` deletes the draft. An unknown, expired or claimed token answers 404 with one body for every cause | ADR-008 shared checks |
| Size | The workspace limits: title 300 bytes, summary 1 200 bytes, narrative as `forms::TEXT_LIMIT`. Control and format characters are refused as in every free text | As for normal drafts |
| Rate limits | Per peer: 10 starts per hour, and 120 opens, saves and discards per minute. Per cell: 600 starts per hour and at most 20 000 live anonymous drafts. Over any limit the route answers 429, and nothing is stored. Interim, pending Daniel (values) | ADR-024 |
| Call | A draft starts only for a published call that is open now. Open and save refuse once the call has closed. The claim runs `CreateDraft`, which checks the call again | `CreateDraft` guard |
| Lifetime | An unclaimed draft expires 30 days after it was started, or at the call's deadline if that is earlier. An expired draft is never served, and the cell's draft sweep deletes it within one hour | Daniel 2026-11-22, `pre-check.md` |
| Registration | Submitting needs an account. An applicant account exists only after self-registration with email proof, so every account that can submit has a verified email. Nothing changes at `Submit` | Daniel 2026-11-22 |
| Claim | One new operation, `proposal.claim_draft` (`POST /proposals/{proposal}/claim`, body `{token}`), web only, no MCP tool, acting as the lead of a proposal in DRAFT. The page first runs `proposal.create` for the draft's call. The claim then copies the sections into that proposal's workspace and deletes the anonymous draft. From then on the resume link answers 404 | I-84, R-MC-04 |
| Claim checks | The caller is the active lead; the proposal is in DRAFT; the token names a live draft for the same call as the proposal. Any other case is refused with rule `Input` after the actor check, so the refusal tells nothing more | As `proposal.save_workspace` |
| Signed-in people | A person who is signed in writes in the normal workspace, as before. A person with an anonymous draft who signs in to an existing account claims it the same way | Daniel 2026-11-22 |
| Pre-check | Interim, pending Daniel: the AI pre-check does not run on anonymous drafts. It needs an account first | P-23, TH-02, TH-29 |
| MCP | No tool reads, writes or claims an anonymous draft. Agents without an account stay read-only | R-MC-04 |
| Audit | The claim leaves one audit entry, as every API call does. The anonymous routes write a route log event with the route template and status only, as the other auth routes do | I-24, R-NF-02 |
| Files | An anonymous draft holds no upload, and no pre-check runs on it, so its deletion is the deletion of its row | Daniel 2026-11-22 |

### Why no pre-check on anonymous drafts (Interim, pending Daniel)

- **Cost.** Each pre-check is a model call that the tenant pays for. Without an account, the only limit is the peer limit, and a peer can change.
- **Abuse.** `pre-check.md` names the pre-check as an oracle for probing the assessor (TH-02). Its mitigation is the rate limit per proposal and per account across drafts in the same call (P-23, TH-29). An anonymous draft has no account, so the account cap cannot apply. Anyone could start a fresh draft per check.
- **Small cost to the applicant.** Registration is one email and one link. After the claim, the pre-check runs on the account's draft under P-23.
- **Production today.** A production cell has no pre-check provider yet (Q38), so nothing is lost now.

### Where the person goes

1. The public call page links "Start writing now, no account needed" to `/auth/draft?call=<id>`.
2. The draft page starts the draft and shows the editor, which saves by itself. Beside it the page shows the resume link with a copy button, and says plainly: "Anyone with this link can read and change this draft. Save it to continue on another device. We delete the draft on <date> unless you register."
3. "Register to submit" opens `/auth/signup`. After the account is created, the page sees the draft in local storage and opens `/app/calls/<id>/claim`.
4. "I already have an account" opens `/app/calls/<id>/claim`. Without a session, the shell sends the person to sign in and back.
5. The claim page runs `proposal.create` and `proposal.claim_draft`, removes the link from local storage, and opens the new proposal's workspace. Submission then follows the normal flow.

## Consequences

- People can start writing before they decide to register. Nothing they type reaches the ledger until they register and claim.
- The resume link is a bearer secret. Anyone who has it can read, change or delete the draft until it is claimed. The page says so in plain words.
- The cell holds one more sealed table. Its rows carry no identity data. A database reader sees sealed bytes, digests, call ids and times.
- No email is sent for an anonymous draft, so no address is collected for it.

## Open points for Daniel

1. **Pre-check on anonymous drafts.** Interim: no pre-check until the draft is claimed (reasons above).
2. **Rate limit values.** Interim: 10 starts per peer per hour, 600 starts per cell per hour, 20 000 live drafts per cell, 120 opens, saves and discards per peer per minute.
3. **Lifetime at call close.** Interim: an anonymous draft also ends at its call's deadline, as `pre-check.md` deletes unsubmitted drafts when the call closes. Daniel named 30 days only.
4. **Self-registration without a passkey (ADR-008 open point).** Daniel's words "simple registration" and "email, then the code or link from the email" may answer the ADR-008 question "May self-registration end without a passkey where the tenant enables magic links?" with yes. This lane does not change the signup ceremony: it still enrols a passkey after the email link. The change touches the ledger records of `fstp-cell-core`, so it waits for Daniel's explicit answer.
5. **An emailed code instead of a link.** The signup proof is a link today. A short typed code needs its own attempt limit. Interim: the link only.
6. **SPEC wording.** Proposed additions, not edited until Daniel accepts them:
   - `SPEC/01-requirements/functional.md`, after R-SB-04: "**R-SB-06** A person can start a draft for an open call without an account. The draft is kept under a secret resume link, holds no identity data, and is deleted after 30 days or at the call's deadline unless it is claimed. Submitting needs a registered account with a verified email. AC: an anonymous draft cannot be submitted; after a claim the resume link no longer opens the draft."
   - `SPEC/04-llm-assessment/pre-check.md`, Rules: "The pre-check runs only on drafts of an account. An anonymous draft gets no pre-check until it is claimed (TH-29)."

## Record

| Item | Value | Recorded |
| --- | --- | --- |
| Third-party crates added by this ADR | None | 2026-11-22 |
| New table | `workspace.anonymous_drafts`, app migration `0012_anonymous_drafts.sql` | 2026-11-22 |
| New operation | `proposal.claim_draft`, web only | 2026-11-22 |
| New fuzz target | `anon_draft_body_decode` in `crates/fstp-api-core/fuzz` | 2026-11-22 |
