# Tenant onboarding and programme creator

New tenants are set up through a guided onboarding flow. Programmes are then built in a programme creator: a guided, step-by-step builder that produces a validated programme, not a page of settings.

## Tenant onboarding

| Step | Captures |
| --- | --- |
| Organisation | Legal entity, address, signatories, contact for data protection |
| Agreements | SaaS terms, data processing agreement, sub-processor list (skipped for self-hosted) |
| Branding | White-label package (`03-architecture/white-labelling.md`) |
| Domains and email | Custom domains, sending domain with SPF, DKIM and DMARC checks |
| Identity | EUDI Wallet relying party mode (P-45), verification methods (P-18). P-18 covers identity verification only. Advanced signature is a signing fallback in the contract signature cascade (step 7), not a verification method (decided by Daniel 2026-11-01) |
| Inference | Inference provider and model (P-21) |
| Payments | Payment mode (P-20), bank interface where execution mode is used |
| Channels | Email only. The Matrix homeserver is deferred by Daniel on 2026-11-04 (B-05) and the WhatsApp Business account deferred by Daniel on 2026-11-04 (B-03) |
| Administrators | At least two tenant admins (SoD-07), and at least one Financial signatory and one Legal signatory (SoD-14, SoD-15) |

Each step validates before the next opens. The tenant can save and return at any point. Activation is requested by one tenant admin and approved by another (SoD-18).

## Programme creator

The creator walks a programme manager through these steps:

| Step | Captures | Bounded by |
| --- | --- | --- |
| 1. Funder and instrument | Funder profile, action number, action dates, FSTP budget, per-recipient ceiling, retention periods | P-53, P-56, P-57, P-58, P-41 |
| 2. Programme identity | Name, narrative, scope, language, public URL | P-25, white-label package |
| 3. Eligibility | Persons and categories supported, exclusions, tie-break priority, minors | P-13, P-17 |
| 4. What we fund | Closed list of activity types, accepted licences | P-55, P-26 |
| 5. Evaluation | Knock-out criteria, criteria and weights, threshold, reviewers per proposal, stages, anonymity, read access | P-01 to P-03, P-09 to P-11, P-15, P-16, P-24 |
| 6. Money | Grant range, per-recipient cap, payment mode, partial claim evidence, reallocation, unclaimed balances, payment target | P-04, P-05, P-59, P-65 to P-67 |
| 7. Contract | Instrument, template, signature cascade, flow-down clauses | P-29, P-30, I-49 |
| 8. Support and complaints | Support programme, complaint deadlines | P-60, P-61 to P-64 |
| 9. People | Invitations for programme managers, drafters, committee, IRC, finance roles, with live separation of duties checks | SoD-01 to SoD-13 |
| 10. Communications | Channels, group types, reminder offsets, message templates | P-31 to P-33 |
| 11. Review | Validation report, previews of the Guide for Applicants, public pages and contract, approval request | I-48, I-50, I-52 |

## Starting points

A programme can start from:

- a blank programme with funder profile defaults,
- a clone of an existing programme in the same tenant,
- a programme template shipped with the platform or created by the tenant,
- a source document, such as an FSTP annex (`Document import` below).

## Document import

The programme manager can upload the funding document that describes the programme, such as an Annexe FSTP. The assessor proposes parameter values, each with an evidence pointer into the document.

- **I-65** Every imported value is confirmed or edited by a named programme manager before it enters the programme. Unconfirmed proposals never take effect.
- Proposals that conflict with the funder profile are flagged, never silently adjusted. The SuperSAFE per-recipient cap against the Data Sheet ceiling (L-10) is an example.
- The uploaded document is treated as untrusted data, under the same rules as submissions (`04-llm-assessment/assessment.md`).

## Validation

The creator runs every check that can be decided before a call opens:

- funder profile bounds, such as P-05 against P-58 (I-50),
- completeness of the call package and Guide (I-48, I-52),
- presence of flow-down clauses (I-49),
- separation of duties across invited people,
- reachability of channels and email sending domain,
- contrast and mandatory elements of the white-label package (I-68, I-69).
- **I-66** A programme cannot be activated while its validation report shows any failure. Warnings need a recorded acknowledgement.
- **I-67** Activating a programme needs approval by a second person who did not build it.

## After activation

The creator stays the editing interface for the programme. Frozen parameters follow I-12: edits apply to the next call only, and the creator shows which calls each change affects. Every change creates a policy version (I-23).

## Template library

Programme templates come from three sources: templates shipped with the platform, templates a tenant keeps for itself, and templates a tenant publishes for other tenants.

A template holds policy parameter values, narrative sections, the activity list, contract template references and message templates. It never holds people, proposals, scores, identity data or programme history.

- **I-73** A template is published to other tenants only by a tenant admin and a programme manager together, after an automated scan finds no personal data. The publisher chooses its licence (P-69).
- Published templates live in a library in the control plane. This is the only shared content the control plane holds, and it contains no tenant data beyond what the publisher released.
- Templates are versioned and carry their provenance: publisher, version, funder profile and licence.
- Using a template creates a draft in the creator. Every step still validates, and activation still needs a clean report and a second approver (I-66, I-67).
- Template narrative and links are shown in the creator as editable text, never applied silently.
- A publisher can withdraw a template from the library. Programmes already built from it are unaffected.
- Self-hosted cells can import and export templates as files.

NOTE: I-19 is extended so published templates are a third route across cell boundaries, next to tenant export and profile bundles.
