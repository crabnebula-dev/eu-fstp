# Roles and separation of duties

Roles bind a tenant account to a programme with a start date and an optional end date. Roles never bind globally across programmes. Receiving bindings are further scoped to one proposal and its call (see Receiving bindings).

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
| Contract signatory | Operations | Signs contracts for the funder side, with signing authority (`02-domain/contracts.md`). |
| Auditor | Operations | Read-only access to audit log and aggregates. |

NOTE: The Contract signatory is the tenant operator signatory that `02-domain/contracts.md` lists as a party, and it holds signing authority (decided 2026-10-25). SoD-03 keeps it apart from Receiving roles.

NOTE: For R-PC-03, the drafters of a call are its authors plus the last authors of P-01 and P-09 in that call's policy (decided 2026-10-25). The last author of P-01 or P-09 changes only when its value changes (confirmed 2026-10-25). None of them may approve the call's publication.

## Granting roles

A tenant admin grants Drafting, Judging and Operations roles in a programme (decided 2026-10-25, O-47). The tenant admin role is tenant-wide, not bound to a programme, and the shell attests it to the domain core (confirmed 2026-10-25). SoD-07 applies when the grant is to the admin's own account.

Receiving bindings are not granted by an admin. They arise from the proposal itself (see Receiving bindings, decided 2026-10-25).

## Manual identity checks

In M3, a tenant admin records the outcome of a manual identity check (P-18, R-ID-02), and the vault records that admin as the verifier (decided 2026-10-28). Two rules bind the recorder in M3 (decided 2026-10-28):

- No recorder verifies their own account.
- No recorder verifies an account that shares their identity.

A later Operations role, "identity verifier", replaces the tenant admin as recorder (decided 2026-10-28). Whether the same two rules bind it is not decided. ADR-008 (Manual identity checks) proposes that they do.

## Rules

- **SoD-01** Within a programme, a person holds roles from at most one of Drafting, Judging and Receiving.
- **SoD-02** An IRC member holds no other Judging role in the programme.
- **SoD-03** Operations roles cannot combine with Receiving in the same programme.
- **SoD-04** Finance approver and payment releaser are different persons for any single payment.
- **SoD-05** After a Drafting or Judging binding ends, a Receiving binding in the same programme requires the cooling-off period P-12 to elapse. The same applies to every other switch among Drafting, Judging and Receiving (decided 2026-10-25).
- **SoD-06** Persons in excluded affiliation classes (P-13) cannot hold Receiving roles.
- **SoD-07** A tenant admin granting a role to their own account requires approval by a second tenant admin.
- **SoD-08** Platform operator staff hold no roles in SaaS cells. Content access requires break-glass approval by the tenant and is logged.
- **SoD-09** Drafting and Judging bindings require a verified identity at binding time. At negotiation, the vault checks the applicant's verified identity against those bindings.

NOTE 1: SoD-09 closes the gap where one person opens a second tenant account to sit on both sides. Applicants stay pseudonymous until negotiation, so the check runs at that point.

NOTE 2: Excluded affiliation classes for SuperSAFE are: staff of consortium partners (Annexe 8.a, 8.e), and IRC members, their employers, co-workers and relatives (Annexe 8.c).

NOTE 3: A person means a tenant account (`00-scope.md`). The exception is I-06, which lifts I-01 to the verified identity behind the accounts. I-02, I-03, I-05, SoD-03 and SoD-07 therefore apply per account.

NOTE 4: SoD-02 and I-02 concern roles held now. A past Judging binding never bars an IRC binding, and the reverse. Cooling-off windows apply only across the Drafting, Judging and Receiving groups.

## Cooling-off

Cooling-off is one comparison, used for every switch among Drafting, Judging and Receiving (decided 2026-10-25).

When a binding in one of these groups ends, the platform pins a bar for that account, programme and group. The bar is the sequence number of the latest call of the programme published at the end, plus the P-12 value at the end. Calls are numbered in publication order within the programme.

A binding of that account in another of these groups is refused when:

- for a Receiving binding, its call's sequence number is at most the bar;
- for a Drafting or Judging binding, the latest published call's sequence number is at most the bar.

NOTE: The bar covers every call published up to the end of the binding, including calls published before it started, and the next P-12 calls. With P-12 = 0, only the calls published up to the end are barred. P-12 = 0 is allowed.

NOTE: P-12 is pinned when each binding ends. A later P-12 edit changes only the bars of bindings that end after the edit.

NOTE: An end may be scheduled for a later instant, when the role is granted or afterwards (decided 2026-10-25). The binding stays held until that instant. Its bar is pinned then, from the calls published by that instant and the P-12 value in force at it. A scheduled end can be brought forward, never moved earlier than the current time.

NOTE: Cooling-off counts call publications, never a wall-clock duration (`02-domain/policy-parameters.md` NOTE 4). I-36 adds a further bar for calls holding a proposal the person reviewed.

NOTE: Through I-06, a bar also binds every other account with the same verified identity. SoD-09 enforces this: an account with an unexpired bar joins the candidate set of the identity query (`03-architecture/overview.md` NOTE 1).

## Receiving bindings

A Receiving binding starts when the draft is created, or when the person is added to the proposal if that is later. It ends when the proposal reaches a terminal state. It is scoped to the proposal and its call. This holds equally for applicants, team members and guardians (decided 2026-10-25).

NOTE: A grantee therefore stays bound until the proposal is COMPLETED or TERMINATED.

## Identity discovery

When the vault verifies an applicant at negotiation, it can find either of two things. The applicant shares a verified identity with an account whose bindings, together with the applicant's, break I-01 (I-06). Or the applicant falls in an excluded affiliation class (I-04). In the same step, the platform voids the discovered account's Receiving bindings (decided 2026-10-25).

- Voided bindings never count as held, including as past bindings within the cooling-off period. They pin no cooling-off bar.
- The other account's Judging binding stays, since it was verified at grant time.
- A Drafting binding of the other account stays too, since SoD-09 also verified it at grant time (decided 2026-10-25, O-53).
- Scores already given by a matching Judging account get a notifiable conflict (R-CF-04).
- The notifiable conflict is recorded even when the discovered Receiving binding was already voided for another reason, such as I-04 (decided 2026-10-25).
- Re-evaluation of those scores happens only through complaint remedies (`02-domain/complaints.md`).

The same voiding applies, in the same step, when a P-13 class is added (decided 2026-10-25). The vault then re-checks every Receiving holder of the programme, and each account now in an excluded class loses its Receiving bindings. It applies equally when the vault reports a new affiliation that puts a Receiving holder in an excluded class, under the verification commit protocol (`03-architecture/overview.md` NOTE 4).

The vault can also find that accounts holding Drafting and Judging bindings share one verified identity. SoD-09 refuses this at binding time, so only a later identity merge reaches it. In the same step, the platform suspends the Judging binding as a conflict of interest (decided 2026-10-25).

- A conflict-of-interest suspension restores I-06. The suspended Judging binding never counts as held, including as a past binding within the cooling-off period, and it pins no cooling-off bar.
- Its reinstatement is refused while the identity clash lasts.
- The suspended account's open assignments are released, and scores it already gave get a notifiable conflict (R-CF-04).
- The Drafting binding stays.

NOTE: The I-04 check is evaluated over the identity vault's knowledge. The platform holds no other source for affiliation classes.

## Enforcement points

Rules are evaluated at three points:

1. At role binding.
2. At every action that reads proposal content or changes state.
3. When a declared affiliation or relationship changes, or a P-13 class is added. A Receiving binding that would break I-04 or I-06 is voided, and a Judging binding that breaks I-06 together with a Drafting binding is suspended as a conflict of interest, as described under Identity discovery. Any other new violation suspends the affected bindings pending resolution.

NOTE: A suspended binding is inactive for every action. Only a conflict-of-interest suspension restores I-06. Every other suspended binding, Receiving bindings included, still counts as held for I-04 and I-06.

## Conflict declarations

Assigned reviewers declare conflicts per proposal before reading full content. They see only the title and a neutral summary at that point. A declared conflict triggers reassignment. Conflict detection also runs in the identity vault against declared affiliations and returns only a boolean outcome to the platform.

The acts that a declared or detected conflict bars on a proposal or its grant are (decided 2026-10-25):

- reading its content, by anyone,
- every assigned-reviewer act,
- IRC review,
- the knock-out check,
- the committee vote on the cut-off, through the recusal rule below.

Two further groups declare before reading full content (decided 2026-10-25):

- The FSTP coordinator declares per proposal before the knock-out read.
- Under P-10 "all committee members", every committee member declares per proposal.

A committee member with a declared or detected conflict on any ranked proposal of a call recuses from that call's cut-off vote. No vote is delegated to or from a recused member (decided 2026-10-25).

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

NOTE: Data placement for SoD-10, SoD-11 and I-36 (decided 2026-10-25).

- Each committee binding records the reviewer's organisation. SoD-10 and I-34 count distinct organisations from that field.
- A reviewer has one organisation per programme. A committee binding that records a different organisation from the account's active committee binding in the programme is refused (SoD-10, decided 2026-10-28).
- SoD-10 and I-34 hold at every step where the assigned reviewers decide: the stage 1 close, the stage 2 ranking and the amount determination in NEGOTIATION (R-NG-03, decided 2026-10-28).
- Affiliations a proposal declares are held only in the identity vault. SoD-11 and I-35 are checked through the proximity-list query (`03-architecture/overview.md`).
- For I-36, a DEFERRED proposal is under evaluation in the next call.
- A person who reviewed a proposal cannot take a Receiving role in any later call of the programme until every proposal they reviewed is decided: terminal, or GRANTED or later. This holds regardless of P-12, and it keeps a later deferral from putting a former reviewer's own proposal in the same call as one they reviewed (I-36, decided 2026-10-25).

NOTE: Annexe 8.e allows proposals from the non-commercial constituencies around partners. SoD-11 keeps a partner's reviewers away from its own constituencies, which is the personal conflict risk 8.b addresses.

## Anonymous reviewer handles

With P-11 anonymous, each reviewer gets a separate handle per proposal. Handles are never reused across proposals or calls, so applicants cannot correlate reviewers between submissions. Stage 2 messages travel through the platform under these handles.

## Confidentiality on binding

Every Drafting and Judging binding includes acceptance of confidentiality terms covering proposals seen in that role. The terms survive the end of the binding, at least for the funder's confidentiality period after final payment. This matters once a former reviewer becomes eligible to apply under P-12.

## Mentors

Mentors are staff of consortium partners assigned to a grant under the support programme (`02-domain/support-programme.md`). They are already excluded from Receiving roles as partner staff (P-13). SoD-12 in that file limits their Judging roles towards grantees they mentor.

## Complaint reviewers

Complaint handling is described in `02-domain/complaints.md`. SoD-13 there bars anyone who took part in the contested decision from reviewing the complaint.
