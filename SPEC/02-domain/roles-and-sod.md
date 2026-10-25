# Roles and separation of duties

Roles bind a tenant account to a programme with a start date and an optional end date. Roles never bind globally across programmes.

## Roles

| Role | Group | Notes |
| --- | --- | --- |
| Programme manager | Drafting | Sets policy parameters, approves call publication. |
| Call drafter | Drafting | Writes call text and knock-out criteria. |
| FSTP coordinator | Judging | Runs the knock-out check (Annexe 5.b). |
| Committee member | Judging | Votes on committee decisions. |
| Committee chair | Judging | Casting vote on ties (Annexe 5.a). |
| Assigned reviewer | Judging | Committee member assigned to a proposal for one call. |
| IRC member | Judging | Independent reviewer (Annexe 5.d). |
| Applicant | Receiving | Lead of a proposal. |
| Applicant team member | Receiving | Contributor on a proposal. |
| Guardian | Receiving | Consents on behalf of a minor applicant. |
| Tenant admin | Operations | Tenant configuration. No proposal content access by default. |
| Finance approver | Operations | Accepts milestones for payment. |
| Payment releaser | Operations | Releases approved payments. |
| Auditor | Operations | Read-only access to audit log and aggregates. |

## Rules

- **SoD-01** Within a programme, a person holds roles from at most one of Drafting, Judging and Receiving.
- **SoD-02** An IRC member holds no other Judging role in the programme.
- **SoD-03** Operations roles cannot combine with Receiving in the same programme.
- **SoD-04** Finance approver and payment releaser are different persons for any single payment.
- **SoD-05** After a Drafting or Judging binding ends, a Receiving binding in the same programme requires the cooling-off period P-12 to elapse.
- **SoD-06** Persons in excluded affiliation classes (P-13) cannot hold Receiving roles.
- **SoD-07** A tenant admin granting a role to their own account requires approval by a second tenant admin.
- **SoD-08** Platform operator staff hold no roles in SaaS cells. Content access requires break-glass approval by the tenant and is logged.
- **SoD-09** Drafting and Judging bindings require a verified identity at binding time. At negotiation, the vault checks the applicant's verified identity against those bindings.

NOTE 1: SoD-09 closes the gap where one person opens a second tenant account to sit on both sides. Applicants stay pseudonymous until negotiation, so the check runs at that point.

NOTE 2: Excluded affiliation classes for SuperSAFE are: staff of consortium partners (Annexe 8.a, 8.e), and IRC members, their employers, co-workers and relatives (Annexe 8.c).

## Enforcement points

Rules are evaluated at three points:

1. At role binding.
2. At every action that reads proposal content or changes state.
3. When a declared affiliation or relationship changes. A new violation suspends the affected bindings pending resolution.

## Conflict declarations

Assigned reviewers declare conflicts per proposal before reading full content. They see only the title and a neutral summary at that point. A declared conflict triggers reassignment. Conflict detection also runs in the identity vault against declared affiliations and returns only a boolean outcome to the platform.

## Committee ranking view

Under P-10 "assigned reviewers only", committee members who are not assigned to a proposal see a ranking view, never the full proposal. The view contains:

- title and neutral summary written by the assigned reviewers,
- weighted scores per criterion,
- requested amount and remaining call budget,
- the assigned reviewers' rationale.

LLM findings are not part of the ranking view, since they quote submission content.

NOTE: Assigned reviewers write summaries and rationale without identifying the applicant. The privacy canary tests cover these fields (I-17).

## Reviewer assignment

Staff of any consortium partner may be assigned reviewers (O-22). Two rules limit organisational bias:

- **SoD-10** The assigned reviewers of a proposal come from at least P-39 distinct organisations.
- **SoD-11** A reviewer is not assigned to a proposal that declares an affiliation on the proximity list of the reviewer's organisation (P-38).

NOTE: Annexe 8.e allows proposals from the non-commercial constituencies around partners. SoD-11 keeps a partner's reviewers away from its own constituencies, which is the personal conflict risk 8.b addresses.

## Anonymous reviewer handles

With P-11 anonymous, each reviewer gets a separate handle per proposal. Handles are never reused across proposals or calls, so applicants cannot correlate reviewers between submissions. Stage 2 messages travel through the platform under these handles.

## Confidentiality on binding

Every Drafting and Judging binding includes acceptance of confidentiality terms covering proposals seen in that role. The terms survive the end of the binding, at least for the funder's confidentiality period after final payment. This matters once a former reviewer becomes eligible to apply under P-12.

## Mentors

Mentors are staff of consortium partners assigned to a grant under the support programme (`02-domain/support-programme.md`). They are already excluded from Receiving roles as partner staff (P-13). SoD-12 in that file limits their Judging roles towards grantees they mentor.

## Complaint reviewers

Complaint handling is described in `02-domain/complaints.md`. SoD-13 there bars anyone who took part in the contested decision from reviewing the complaint.
