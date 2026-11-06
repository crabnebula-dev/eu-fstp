# Request 02: data protection

Attach before sending:
- `SPEC/05-compliance/gdpr.md` and `SPEC/05-compliance/ai-act.md`
- `SPEC/04-llm-assessment/assessment.md` and `pre-check.md`
- `SPEC/02-domain/roles-and-sod.md` and `SPEC/02-domain/public-transparency.md`
- `SPEC/02-domain/policy-parameters.md` (NOTE 9, the country)
- `SPEC/01-requirements/functional.md` (R-ID-04, R-NG-01, R-SB-01, R-SB-02)
- `SPEC/12-journey-ui.md` section 7.3
- `docs/adr/ADR-007-domain-ledger.md` and `docs/adr/ADR-009-cell-boundary.md`
- `docs/handoff/m4-design.md` section 15.0 (Daniel's answers, including Q23)

---

## Prompt

You are an expert in EU data protection law (GDPR) and in the EU AI Act. Please review the attached documents and answer the numbered items below.

**Context.** CrabNebula Ltd ([seat of CrabNebula Ltd]) operates a multi-tenant platform that runs FSTP grant programmes for Horizon Europe beneficiaries. Each tenant (a funder or consortium) is the controller for its programme's applicant data, and CrabNebula Ltd is its processor. OVHcloud hosts the service in the EU. An "identity vault" holds identity attributes (date of birth, country, affiliations, bank details) apart from the main ledger, and answers only one-bit questions to the rest of the system. An AI assessor produces findings on each submitted proposal. Human reviewers score and decide; the findings never decide alone. Applicants may be minors, in which case a guardian must consent.

**Rules for your answer.**
- Cite only provisions you are sure of, by instrument and article. If you are unsure, say so.
- Where an item asks for wording, give a draft for review by counsel, in plain English for applicants.
- Keep each item's ID exactly as written.

**Items.**

D1 (L-01). The platform has an AI assessor produce findings on every submitted proposal. Outline the data protection impact assessment this needs: the risks, the measures already in the attached design, and what is missing. Also say whether the AI Act classes this use as high-risk.

D2 (L-02). Daniel decided that the applicant states a date of birth at submission. It goes to the identity vault only, and the vault answers one bit: is the applicant a minor at the call deadline. Identity, and age, are verified later, in negotiation. What is the legal basis for collecting the date of birth at submission? Does GDPR Article 8 apply? What is the legal basis for collecting a guardian's data before negotiation, for a nominated minor's proposal? Which attributes are the minimum?

D3. The applicant states a country before negotiation, also to the vault only (NOTE 9). Does this meet data minimisation and purpose limitation?

D4 (L-07). Funded grants appear on public pages only with the grantee's own opt-in, at the level the grantee chooses. Is opt-in a valid basis for publication, including for natural persons? Draft the opt-in wording.

D5 (I-37). After the outcome notice, the platform may ask applicants for consent to use their proposal, pseudonymised, to calibrate the AI assessor. Is consent the right basis? What must the request say? Draft the consent and withdrawal wording. Can the platform keep calibration results after a withdrawal?

D6 (ADR-007). After the retention period, the ledger keeps a pseudonymous skeleton of each record (state changes and amounts, with no personal data). Does that skeleton count as anonymised data? Which records does the retention obligation cover, and is deferring erasure for them lawful?

D7. The service holds client IP addresses in memory, briefly, to rate-limit requests at the edge and in the cell. What is the legal basis, and what retention limit applies?

D8. To detect conflicts of interest, reviewers declare their relatives, and the platform stores those declarations. What is the legal basis for holding third parties' data that they did not provide? What is the minimum set of attributes conflict matching needs?

D9. Draft the platform-default data protection summary shown in the Guide for Applicants, and say what the privacy statement it links to must contain. A tenant may replace both. Also draft the data protection notice shown to a grantee before negotiation (R-NG-06).

D10. The vault holds bank details for payments and hardship evidence. Every bank-detail change triggers re-verification and a waiting period before any payment. Are there further minimisation or retention duties for these attributes?

**Answer format.** For each item:

```
## <ID>
Answer:
Basis (instrument and article):
Confidence: high | medium | low
Draft text (if asked):
To confirm:
Decision for the platform (one line):
```
