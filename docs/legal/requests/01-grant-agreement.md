# Request 01: the SuperSAFE grant agreement and the Guide for Applicants

Attach before sending:
- The signed SuperSAFE Model Grant Agreement, including the Data Sheet and Annex 1 (Daniel supplies these).
- The SuperSAFE Annexe FSTP for call HORIZON-CL4-2026-04-DATA-02 (Daniel supplies it).
- `SPEC/05-compliance/horizon-europe-mga.md`
- `SPEC/profiles/horizon-europe/guide-for-applicants.md`
- `SPEC/02-domain/policy-parameters.md`
- `SPEC/02-domain/contracts.md` and `SPEC/02-domain/payment-requests.md`
- `docs/adr/ADR-006-money-representation.md`

---

## Prompt

You are an expert in EU research funding law. You know the Horizon Europe Model Grant Agreement (MGA), its Annotated Grant Agreement (AGA), and financial support to third parties (FSTP). Please review the attached documents and answer the numbered items below.

**Context.** CrabNebula Ltd ([seat of CrabNebula Ltd]) builds a multi-tenant software platform that runs FSTP programmes for Horizon Europe beneficiaries. The platform runs open calls, staged evaluation, independent review, subgrant contracts and milestone payments. The reference programme is the SuperSAFE Annexe FSTP. The platform's rules are written as numbered policy parameters (P-xx) and invariants (I-xx), defined in the attached specification files. The platform generates a "Guide for Applicants" from a template, filling in values from the programme's parameters.

**Rules for your answer.**
- Base each answer on the attached signed agreement and annexes where they speak to it. Quote the clause number you rely on.
- Cite other law or guidance only where you are sure of the instrument and article. If you are unsure, say so instead of guessing.
- Where an item asks for wording, give a draft for review by counsel. Mark any value you could not find in the documents as `[to confirm: ...]`.
- Keep each item's ID exactly as written, so the answers can be matched to the code.

**Items.**

G1 (L-06). What record-keeping and confidentiality periods does the signed Data Sheet set, counted from the final payment? The platform's parameter P-41 holds the retention period. State the value to configure and the clause it comes from.

G2 (L-08). Which EU funding acknowledgement and visibility obligations (for example under MGA Article 17.2) must the beneficiary pass on to FSTP recipients? Draft the acknowledgement text and emblem rules that the subgrant contract and the platform's public pages should carry.

G3 (L-09). Which Funding & Tenders Portal forms or templates apply to publishing a third-party call and to reporting FSTP? List the fields the platform must produce for each, as precisely as the documents allow.

G4 (L-10). The Annexe allows up to 400,000 EUR per recipient over the programme. MGA 6.2.D.1 caps support per recipient at the Data Sheet amount unless the granting authority agrees otherwise. What per-recipient ceiling does the signed Data Sheet set? The platform enforces the lower of the two (invariant I-50).

G5 (L-11). Are hardship contributions eligible FSTP costs as Annex 1 describes them? The platform models a hardship contribution as payment lines that claim milestones of partly delivered work. Is that reading compatible with Annex 1, and how must hardship payments be reported?

G6 (L-12). Check MGA Articles 17.2, 20 and 21, and the AGA annotations and guidance on FSTP, against the attached specification. List every place where the specification conflicts with them or misses a duty.

G7 (L-13). Does Annex 1 describe the support programme activities (mentoring, presentations, promotion and CRA guidance) as action tasks? Partner effort on them is eligible only if it does. Quote the task, or say it is missing.

G8 (ADR-006). Does the grant agreement or a funder rule fix how a calculated amount is rounded to the cent, for example a percentage share of eligible costs? If yes, state the rule. If no, recommend one.

G9. The Guide for Applicants template has sections marked as needing wording approved against the signed grant agreement. For each such section in `guide-for-applicants.md`, draft the text, or list the facts from the agreement that the text must state.

G10. What electronic signature level does the subgrant contract need for each party (simple, advanced or qualified, under eIDAS)? And does the beneficiary need an electronic seal? Answer from the agreement and the MoU if attached; otherwise give the general position and what to check.

**Answer format.** For each item:

```
## <ID>
Answer:
Basis (clause or article):
Confidence: high | medium | low
Draft text (if asked):
To confirm:
Decision for the platform (one line):
```
