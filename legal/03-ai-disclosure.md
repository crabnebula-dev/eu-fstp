# AI disclosure

Status: draft for Daniel's review, 2026-11-21. Not approved. Not wired into the product.

Legal party: CrabNebula Ltd. Data Protection Officer (DPO): Daniel Thompson-Yvetot.

Requirement: R-LA-08. Applicants are told that AI assessment is used, in the call text and at the pre-check. `SPEC/05-compliance/ai-act.md` ties it to the AI Act transparency duty.

TODO(legal): name the AI Act provisions this disclosure serves, and confirm the current application dates (`ai-act.md`, "To confirm"). Nothing below cites an article.

What the platform does, from the code and `SPEC/04-llm-assessment/`:

- The pre-check returns findings only, never scores or bands. Only the applicant team sees it. It is rate-limited (P-23).
- The submitted version gets a fresh assessment. Reviewers see the findings.
- Names, email addresses, phone numbers, IBANs, postal addresses and team handles are replaced with placeholders before inference (`crates/fstp-assess/src/strip.rs`).
- Claims may be checked against public sources through a GET-only retrieval proxy (`crates/fstp-retrieve`).
- Findings never decide. A named person records every decision (I-10, R-LA-03).
- Reviewers can mark findings as agreed or disputed, for calibration.
- Indicative rubric bands are hidden from reviewers unless P-28 is on. Default: off.
- The tenant chooses the provider and the model (P-21).

---

## A. Call page block "Use of AI tools"

Replaces: `public.ai.disclosure` in `crates/fstp-public/src/html.rs` (section `#ai-disclosure` of the public call page).

Draft:

> **Use of AI tools**
>
> This call uses an AI system to help review proposals.
>
> - Before you submit, you can ask the AI system to check your draft. It returns findings on completeness, quality and accuracy. It never gives a score. Only your team sees the result.
> - After you submit, the AI system assesses your proposal again. The reviewers see its findings.
> - Before your proposal reaches the AI system, names, contact details, bank details and addresses are replaced with placeholders.
> - The AI system may check claims in your proposal against public web sources.
> - Findings support the reviewers. They never decide. A named person takes every decision.
>
> If you think a decision was reached the wrong way, you can file a complaint. The Guide for Applicants explains how.

Note: the catalogue entry is one message. If it cannot hold a list, join the points as sentences.

## B. Guide for Applicants

The Guide already states the AI use in section 5 step 3 and section 6 "About reviews". No new section is needed. See `funder-profiles/horizon-europe/guide.v1.md`.

`crates/fstp-guide/src/render.rs` holds a separate line, now "TODO(legal): approve the wording of this AI interaction disclosure before first use." Draft replacement:

> You are about to use an AI system. It checks your draft against the call criteria and returns findings, never a score. A person takes every decision about your proposal.

## C. Pre-check panel (applicant)

Replaces: `ai.disclosure` in `web/src/findings/messages.en.ts`, where the panel shows pre-check findings.

Draft:

> These findings come from an AI system, not from a person. They can be wrong. They never score your proposal and never decide. Use them to improve your draft if you find them useful.

## D. Findings panel (reviewers and staff)

Same catalogue entry in `web/src/findings/messages.en.ts` when staff read findings. If one entry must serve both, use draft C. A separate entry would read:

> These findings come from an AI system. They can be wrong. They support your judgement and never replace it. Mark each finding as agreed or disputed. Your scores and decisions must be your own.

TODO(legal): whether reviewers need an AI literacy statement here or elsewhere (`ai-act.md`, Article 4 is named in the spec; Daniel verifies).

## E. Footer element

Replaces: `public.footer.ai` in `crates/fstp-public/src/html.rs` and `footer.ai_disclosure` in `web/src/creator/messages.en.ts`. It shows where findings appear.

Draft:

> AI findings on this page come from an AI system. A person takes every decision.

## F. Agent connection page

`web/src/connect/messages.en.ts` already states the agent's limits. No legal marker sits there. Draft addition, for Daniel to decide:

> The agent is run by a provider you choose. What the agent reads is processed by that provider under your agreement with it.
