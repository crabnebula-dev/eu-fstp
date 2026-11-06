# Request 04: wording shown in the product

Attach before sending:
- `SPEC/04-llm-assessment/assessment.md` (R-LA-08) and `SPEC/05-compliance/ai-act.md`
- `SPEC/03-architecture/mcp-server.md` (P-75 and P-77)
- `SPEC/02-domain/roles-and-sod.md`
- `SPEC/02-domain/complaints.md` and `contractual-notices.md`
- `SPEC/02-domain/contracts.md`
- `SPEC/02-domain/policy-parameters.md` (P-61 to P-64, P-68)
- `docs/design/03-applicant-screens.md` and `docs/design/10-post-grant-screens.md`
- `docs/handoff/m4-design.md` section 15.0

---

## Prompt

You are an expert in EU law who drafts clear, plain-English text for public-facing digital services: the AI Act, GDPR, consumer-facing terms, and grant contracts. Please draft or review the texts listed below.

**Context.** CrabNebula Ltd ([seat of CrabNebula Ltd]) operates a platform that runs FSTP grant programmes for Horizon Europe beneficiaries (tenants). Applicants submit proposals. An AI assessor produces findings that human reviewers see; humans score and decide. Programme staff and reviewers are invited by email and must accept confidentiality terms before they get a role. Each text appears in the product as approved wording that tenants cannot edit, unless an item says otherwise.

**Rules for your answer.**
- Write for applicants and staff in plain English: short sentences, no legal jargon where a plain word works.
- Cite only provisions you are sure of. If a text needs a fact you do not have, insert `[to confirm: ...]`.
- Give each text as a draft for review by counsel, and say which obligation it serves.
- Keep each item's ID exactly as written.

**Items.**

W1 (R-LA-08). The AI disclosure shown on each call page and in the Guide for Applicants. It must say that an AI system produces findings on proposals, what the findings are used for, that humans decide, and how to contest an outcome. Which AI Act provisions does it serve?

W2. The confidentiality terms an invited person accepts before getting a programme role. Draft one version for drafting roles (programme staff) and one for judging roles (reviewers, committee, independent review). The judging version must state the programme's choices on P-75 and P-77, inserted as values: whether reviewers may read proposal content through an AI agent, and whether agents may only draft. The accepted text and version are recorded.

W3. The terms a reviewer accepts before reading proposals: conflict-of-interest declaration, confidentiality, no reuse of proposal content, and the handling of AI findings.

W4 (L-02). The label and helper text for the date-of-birth field at submission. It must say the date goes to the identity vault only, why it is needed, and that a false statement is grounds to decline at verification.

W5 (L-14). Complaint screens: the text on filing a complaint, the coordinator review, and the escalation to independent review. Include the complaint deadlines (P-61 to P-64), and state which governing law and external redress apply to subgrant recipients.

W6. The negotiation stage: the agreement summary shown before signing, and the data protection notice the grantee acknowledges (R-NG-06).

W7. The accessibility statement template for a tenant portal, with placeholders for the tenant.

W8 (P-68). The platform attribution and the mandatory footer elements on every page: privacy notice link, accessibility statement link, platform attribution, AI disclosure where findings appear, and the Data Act information for tenant admins.

W9. An outline of the subgrant contract template: parties, the funded project and milestones, payments and record-only release, deliverables and evidence, hardship contributions (see L-11), the EU funding acknowledgement (see L-08), amendments as new signed versions, termination, governing law and complaints.

W10. The emails the platform sends: the contractual notice emails (formal notices under the subgrant contract), the outcome emails (selected, not selected, ineligible, declined), and the copy of a submission sent at the applicant's request. Each email holds identifiers and times, not proposal content. Draft the subject line and body of each, with `[to confirm: ...]` for facts you do not have.

W11 (I-37). The request, sent after the outcome notice, asking the applicant to consent to the pseudonymised use of their proposal to calibrate the AI assessor, and the confirmation of a withdrawal. Request 02, item D5, covers the legal basis; this item covers the wording only.

**Answer format.** For each item:

```
## <ID>
Draft text:
Obligation it serves (instrument and article):
Confidence: high | medium | low
To confirm:
```
