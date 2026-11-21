# Privacy notice (platform default)

Status: draft for Daniel's review, 2026-11-21. Not approved. Not wired into the product.

Legal party: CrabNebula Ltd. Data Protection Officer (DPO): Daniel Thompson-Yvetot.

Used where: the page behind the footer element "Privacy notice" on every interface and public page, when the tenant has set no privacy notice of its own. See `README.md` for the code sites.

Drafting notes for Daniel (not part of the notice):

- Section 1 names the controller through the per-tenant value `{{controller.*}}` (`README.md`, Q1, answered). For a funder tenant it names that tenant. For the two programmes CrabNebula Ltd coordinates itself, it names CrabNebula Ltd. Section 1 shows the rendered text for each case.
- Every legal basis, every right and every authority stays `TODO(legal)`. Nothing here cites an article.
- Lines marked `[NOT BUILT: ...]` describe a rule of the specification that the code does not carry out yet. Remove the line or wait for the build before approval.
- `{{controller.*}}` and `{{tenant.*}}` name values the tenant supplies. The platform has no such placeholder yet (see `README.md`, wiring).

---

## 1. Who is responsible for your data

This service runs funding programmes. An organisation that runs a programme on the service is called the "programme operator" in this notice. CrabNebula Ltd builds and operates the service.

The programme operator decides why and how your data is used for its programme. It is the controller of that data. This covers your account in its programme space, your proposals, reviews, contracts, payments and identity checks.

The controller of this programme is: {{controller.legal_name}}, {{controller.address}}.

### When a funder runs the programme

The programme operator is a funder or a consortium. It is the controller. CrabNebula Ltd processes your data for it, as its processor, under a data processing agreement and only on its instructions.

Rendered example: "The controller of this programme is {{tenant.legal_name}}, {{tenant.address}}. CrabNebula Ltd processes your data on its behalf."

### When CrabNebula Ltd runs the programme

CrabNebula Ltd coordinates two grant programmes of its own on this service:

- TODO(legal): name of the first programme coordinated by CrabNebula Ltd.
- TODO(legal): name of the second programme coordinated by CrabNebula Ltd.

For these programmes, CrabNebula Ltd is the controller. No other organisation processes your data as its processor on the platform side.

Rendered example: "The controller of this programme is CrabNebula Ltd, TODO(legal): registered address."

### Data CrabNebula Ltd controls for every tenant

CrabNebula Ltd is also the controller of the data an organisation gives when it signs up for the service: its legal name, billing address, contracting signatory and the agreements it accepts. The same holds for licence registration data of self-hosted installations.

### CrabNebula Ltd

- Name: CrabNebula Ltd.
- Registered address: TODO(legal): registered address of CrabNebula Ltd.
- Company number: TODO(legal): company registration number and register.
- Email: TODO(legal): general contact email address.

## 2. Data Protection Officer

CrabNebula Ltd has designated Daniel Thompson-Yvetot as its Data Protection Officer (DPO).

- DPO contact: TODO(legal): the dedicated DPO email address.
- DPO postal address: TODO(legal): the DPO postal address.

For a programme a funder runs, contact the funder first: {{controller.privacy_contact}}. The funder's own DPO, if it has one: {{controller.dpo_contact}}. You can also write to the DPO of CrabNebula Ltd, who passes your request to the funder.

## 3. What this notice covers

This notice covers the service at {{platform.url}} and every programme portal on it. It covers the identity vault, which is a separate part of the service on its own web address. A tenant can replace this notice with its own. If it does, the tenant's notice applies to its programmes.

## 4. What data we process

| Data | Examples | When we collect it | Where it is kept |
| --- | --- | --- | --- |
| Account data | Email address, passkey public keys, sign-in records, optional display name | When you create an account or sign in | The tenant's own database cell |
| Session data | A session cookie that keeps you signed in | While you are signed in | Your browser and the tenant's cell |
| Proposal data | Your proposal, plan, budget, answers, attachments, team invitations by email | When you draft and submit | The tenant's cell |
| Country | The country of residence or establishment you state | At submission | The identity vault only |
| Age | Your date of birth, or a guardian's consent | At submission or before negotiation | The identity vault only |
| Identity data | Legal name, verification method and result, identity document for a manual check | At negotiation, or when you take a staff or reviewer role | The identity vault only |
| Guardian data | A guardian's identity and consent, for an applicant under 18 | Before negotiation | The identity vault only |
| Affiliations and declarations | Affiliations, partner staff status, a reviewer's declared relatives | When you declare them | The identity vault only |
| Bank details | Account holder name, IBAN, the bank document checked | When a grant is paid | The identity vault only |
| Hardship evidence | Your description of the hardship | When you ask for a hardship contribution | The identity vault only |
| Review data | Scores, comments, conflict declarations, decisions | During evaluation | The tenant's cell |
| AI findings | Findings on completeness, quality, accuracy and integrity, and the record of how they were made | When a proposal is checked or assessed | The tenant's cell |
| Contract and payment data | Contract versions, signatures, payment requests, evidence, payment records | After selection | The tenant's cell |
| Complaints | Your complaint and the replies | When you file one | The tenant's cell |
| Messages | Notices in your platform mailbox, and the emails we send | When an event concerns you | The tenant's cell and the tenant's mail provider |
| Audit records | Who read proposal content or identity data, and when | Every time such a read happens | The tenant's cell |
| Public grant data | The details of your grant that you choose to publish | Only if you opt in | The programme's public pages |
| Network address | Your IP address | On each request | In memory only, for rate limits. It is never stored or logged |

Notes for Daniel:

- The application never receives identity attributes. The vault answers it with yes or no only, for example "is the lead under 18 at the deadline".
- The coordinator of a programme can reveal who stands behind a handle in its own programme. Each reveal needs a stated purpose and a passkey, and it is recorded. Nobody is told. TODO(legal): the transparency duty for this reveal (ADR-023). This notice must say it, in wording Daniel approves.
- [NOT BUILT: no route of the vault registers identities with their attribute tuples yet (ADR-004, lane L11). Document upload for a manual check is designed but not served.]

## 5. Why we process your data, and the legal basis

| Purpose | Data used | Legal basis |
| --- | --- | --- |
| Give you an account and keep it secure | Account and session data, network address | TODO(legal) |
| Receive and evaluate proposals | Proposal, review and AI finding data | TODO(legal) |
| Check eligibility, including country and age | Country, age, affiliations | TODO(legal): L-02 for age, D3 of request 02 for country |
| Detect conflicts of interest | Declarations, including relatives a reviewer declares | TODO(legal): the basis for holding relatives' data (ADR-009, Q31) |
| Verify identity before a contract | Identity data | TODO(legal) |
| Get a guardian's consent for an applicant under 18 | Guardian data | TODO(legal): L-02 |
| Prepare, sign and manage the contract | Contract data | TODO(legal) |
| Pay the grant and prevent payment fraud | Bank details, payment data | TODO(legal) |
| Report to the granting authority of the EU programme | Grant, payment and recipient data | TODO(legal): the duty to report and its source in the grant agreement (L-09) |
| Handle complaints | Complaint data | TODO(legal) |
| Keep records for audits | All records under the funder retention period | TODO(legal): L-06 |
| Publish funded grants | Public grant data | Your opt-in. TODO(legal): L-07 |
| Improve the AI assessor within the tenant | Your proposal, pseudonymised | Your consent. TODO(legal): D5 of request 02 |
| Show your display name to team admins | Display name | TODO(legal): SA-11 |
| Limit abusive request rates | Network address, in memory only | TODO(legal): the basis for short-lived in-memory rate limits (ADR-009, Q19) |

## 6. Use of AI

An AI system reviews proposals. It produces findings on completeness, quality, accuracy and integrity. Findings support human reviewers. They never decide, and they never score.

- Before you submit, you can run a pre-submission check. It shows you findings on your draft. Only your team sees them.
- After you submit, the AI system assesses your proposal again. Reviewers see the findings.
- Before your proposal goes to the AI system, the platform replaces names, email addresses, phone numbers, IBANs, postal addresses and team handles with placeholders. The map back to the real values never leaves the tenant's cell.
- The AI system may check claims in your proposal against public web sources.
- The tenant chooses the AI provider and the model for each call. See section 9.

Full details are in the AI disclosure (`03-ai-disclosure.md`).

## 7. No decision by automated means alone

A named person takes every decision about your proposal, your contract and your payments. The platform refuses a decision that no person records. AI findings are advice to that person.

TODO(legal): confirm that this statement meets the information duty on automated decisions, and whether any further information is owed.

## 8. Who receives your data

- **Programme staff of the tenant**, as their role needs. Reviewers see your proposal under a handle, not your identity. Reviewers are anonymous to you unless the programme sets otherwise.
- **The independent review committee**, for selected proposals and for complaints.
- **The granting authority of the EU programme**, for reporting. TODO(legal): name the authority and the Funding & Tenders Portal Privacy Statement address (L-09).
- **The public**, only for the grant details you choose to publish.
- **An AI agent you connect yourself.** If you connect an AI agent to your account, it can read what your roles allow. It never receives identity or bank details. Its provider then processes that data under your own agreement with it.
- **Service providers** listed in section 9.

We do not sell your data. We do not use your data for advertising. Public pages carry no tracking.

## 9. Service providers

| Provider | What it does | Where | Status |
| --- | --- | --- | --- |
| OVHcloud | Hosting of the service and the databases | European Union | TODO(legal): L-15, the contracting entity and its terms |
| OVHcloud Object Storage | Encrypted backups | European Union | TODO(legal): L-15, and the backup retention period (ADR-012) |
| Second backup provider | Encrypted backups | European Union | TODO(legal): not chosen yet (ADR-012, Q25) |
| The tenant's mail provider | Sends the emails of the tenant's programmes | Chosen by the tenant | The tenant's provider, not CrabNebula Ltd's (ADR-018). TODO(legal): how this notice names it |
| The tenant's AI provider | Runs the AI assessment | Chosen by the tenant. The default protocol is Anthropic's, which may be outside the EU | TODO(legal): ADR-019, the DPIA and the transfer basis |

Backups are encrypted before they leave the service. Erasing your data destroys its keys, so erased data cannot be read from backups.

## 10. Transfers outside the European Union

The service is hosted in the European Union. A tenant may choose an AI provider outside the European Union. Your proposal then reaches that provider, after the replacement of personal details described in section 6.

TODO(legal): the transfer mechanism for a non-EU AI provider, and the wording of this section (ADR-019, TH-13).

## 11. How long we keep your data

| Data | How long |
| --- | --- |
| Identity documents uploaded for a manual check | Deleted when the check is complete, including from backups, unless the programme sets a period (P-19). [NOT BUILT: document upload is not served yet.] |
| Drafts and pre-check results that were never submitted | Until the call closes or you withdraw. [NOT BUILT: no deletion job for drafts was found in the code.] |
| AI assessment records | Until the funder retention period ends (P-22, P-41). [NOT BUILT: no deletion job for traces was found in the code.] |
| Records of a grant | Until the funder retention period ends. It starts when the grant's last payment is confirmed and lasts {{P-41}}. TODO(legal): L-06, the period and which records it covers |
| After the retention period | The tenant admins are reminded, and they erase the texts of the grant. A skeleton of ids, amounts, scores and decisions stays, with no text and no identity data. TODO(legal): whether this skeleton is anonymous data (ADR-007) |
| Display name | Until you change or remove it. A removed name is erased at once |
| Session | Ends after {{P-72.idle}} without activity, and after {{P-72.absolute}} at most |
| Network address | Not stored. Held in memory only for the time a rate limit needs |
| Backups | TODO(legal): L-15, the backup retention period |

If you ask us to erase your data, we erase it at once, except data that the funder retention period covers. That data is erased when the period ends.

TODO(legal): confirm that deferring erasure for records under the funder retention period is lawful (ADR-007).

## 12. How we protect your data

- You sign in with a passkey, or with a sign-in link sent by email if the programme operator enables it. [Daniel: update if OPAQUE or EUDI Wallet sign-in is built.]
- Identity data and bank details are kept in a separate identity vault, on its own database cluster and web address. The application only receives yes or no answers.
- Each tenant's data sits in its own database cell. No link exists between your accounts in different tenants.
- Each free text has its own encryption key. Erasure destroys the key.
- Every read of proposal content or identity data is logged in a tamper-evident audit log.

## 13. Your rights

You can ask for:

- a copy of your data,
- the correction of wrong data,
- the erasure of your data,
- the restriction of its use,
- a copy of data you gave us, in a machine-readable form,
- an end to processing you object to.

Where we rely on your consent, you can withdraw it at any time. A withdrawal does not affect what happened before it.

To use a right, write to the controller of the programme or to the DPO in section 2. The controller answers your request. Where a funder is the controller, CrabNebula Ltd helps it answer. Where CrabNebula Ltd is the controller, the DPO answers.

TODO(legal): confirm the list of rights, which rights apply to each legal basis, and the response time to state.

## 14. Complaints to a supervisory authority

You can complain to a data protection supervisory authority. TODO(legal): name the lead supervisory authority for CrabNebula Ltd and its contact details, and state the right to complain where you live or work.

## 15. Applicants under 18

Applicants under 18 may apply where the programme allows it. A parent or legal guardian gives consent in the identity vault before the proposal can enter negotiation. A grant whose team includes a person under 18 is never shown on public pages.

TODO(legal): L-02, the basis for collecting the date of birth at submission, and whether the GDPR rule on children's consent applies.

## 16. Cookies and browser storage

The service uses one cookie, which keeps you signed in. See `05-cookies-and-storage.md`.

## 17. Changes to this notice

We will publish any change on this page with a new version number and date. Where a change affects you, we will tell you on the platform.

Version: TODO(legal): version and date of the approved notice.
