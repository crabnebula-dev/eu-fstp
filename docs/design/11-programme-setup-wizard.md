# 11. Programme set-up wizard and set-up progress

Status: Daniel answered section 14 on 2026-11-15, and lane m4/setup-wizard-build built the wizard. Section 15 records the build. The spec wins over this document.

Sources: `SPEC/02-domain/programme-creator.md`, `SPEC/02-domain/roles-and-sod.md`, `SPEC/12-journey-ui.md` §8.2, `docs/handoff/m4-design.md` §2.2 (J1, J2), §3.2 and §15.0, ADR-021, and the design docs 01, 02, 05 and 09.

## 1. The request

Daniel, 2026-11-15: "I would like to have a wizard for setting up a grant programme and inviting people (already registered in the platform) to join organizational units and take on roles. This should be similar in approach to the way that applicants can see their growth / progress. Like a travel booking."

His answers to the follow-up questions:

- **Units.** "Programme is the unit." There is no new concept. Joining a unit means a role binding in one programme: role, programme, start date and optional end date (`roles-and-sod.md`). The team is grouped by role group: Drafting, Judging, Operations.
- **Invitees.** "This organisation's accounts." The search covers the accounts in this organisation's cell. Anyone else gets an email invitation. Other organisations' accounts are never searched or shown (I-19, I-20).
- **First step.** "Clickable prototype first." This note and the prototypes come before any build.

## 2. What the wizard is

The wizard is a presentation layer over the existing programme creator. It adds no domain concept and no rule.

- The 11 creator steps stay the source of truth and keep their spec order (`12-journey-ui.md` §8.2). The wizard only groups them into seven plain stages.
- The full step editor (`planning-studio.html`, doc 05) stays. The wizard is the guided first pass. The editor remains the place for later changes, as with onboarding and the admin screens (Q24).
- Every check the wizard shows is a projection. The server checks every rule again at each command (I-92).

The travel booking model gives three patterns:

1. A **stage bar** across the top. Done stages carry a check and link back. The current stage is filled and numbered. Upcoming stages are dashed circles and are not links.
2. A **summary panel**, "Your set-up so far", beside the stage. It fills in as stages complete, and each done stage has a "Change" link. This mirrors a booking's running itinerary.
3. A **confirmation and progress page** after the last stage. It echoes the applicant progress map (doc 02): what happened, what is current, what comes next, and who acts.

## 3. Precondition: the organisation is active (ADR-021)

Programme work starts only after the organisation is activated.

- Before activation, the cell refuses `creator.open_draft`, `creator.invite` and `roles.grant` under rule `ADR-021`. The entry to the wizard is then not shown. The tenant admin home keeps only the onboarding links.
- The start page states the activation as a fact: date, and approval by a second tenant admin (SoD-18).
- A refusal under ADR-021 on any wizard page shows the ADR-021 notice in words, never the rule id.

## 4. Who does what

| Actor | In the wizard | Spec |
| --- | --- | --- |
| Tenant admin who opens the draft (A. Chen) | Stage 1: names the programme, picks the funder profile, chooses the programme manager, opens the draft with a step-up. Grants the programme manager role once that person has accepted the terms and verified identity | `creator.open_draft` (high-risk), `creator.invite`, `roles.grant` (high-risk); O-47, SoD-09, I-78 |
| Programme manager (S. Okafor) | Stages 2 to 7: starting point, creator steps 1 to 11, the team, and the activation request | `creator.apply_start`, `creator.save_fields`, `creator.invite`, `creator.request_activation` (programme manager only) |
| Second tenant admin, outside the builders (M. Diop) | Approves activation from the approval inbox, with a step-up. Is never chosen by the builder | `creator.approve_activation`; I-66, I-67, I-78 |
| Each invitee | Accepts the terms, verifies identity for a Drafting or Judging role | `people.accept_invitation`, `people.begin_verification`; SoD-09, J2 |
| Tenant admin, after activation | Grants each invited role whose holder is ready | `roles.grant`; D3 admits only the programme manager on a draft |

The builder rule shapes the flow. Every account that opens the draft, saves, invites, acknowledges or grants on it joins the builder set (m4-design §3.2, Q1). A builder cannot approve activation. The wizard therefore says, on the start and team pages, how many tenant admins remain outside the builders.

## 5. Stages

| Stage | Creator steps | Prototype | Key content |
| --- | --- | --- | --- |
| 1. Start | none; opens the draft | `setup-wizard-start.html` | ADR-021 status, programme name, funder profile, programme manager search, role dates, SoD-07 and I-67 notes, step-up |
| 2. Programme | 1 Funder and instrument, 2 Programme identity | `setup-wizard-programme.html` | Starting point (template, clone, document import with I-65, blank), action number, budget, P-57 dates, P-58 ceiling, name, description, P-25 language, public address |
| 3. Applicants | 3 Eligibility, 4 What we fund | `setup-wizard-applicants.html` | Persons supported, minors, P-13 excluded classes, P-17 tie-break, P-55 activity list, P-26 licences |
| 4. Evaluation and money | 5 Evaluation, 6 Money, 7 Contract, 8 Support and complaints | `setup-wizard-evaluation.html` | P-01 criteria and weights, P-02, P-03, P-39, P-15, P-04, P-05 within P-58 (I-50), P-59, contract template (P-30, I-49), P-60, P-61 to P-64 |
| 5. Team | 9 People | `setup-wizard-team.html` | Section 6 below |
| 6. Communications | 10 Communications | `setup-wizard-communications.html` | P-32 email only (B-03, B-05), P-31 reminders, P-33 escalation, message templates |
| 7. Review and confirm | 11 Review | `setup-wizard-review.html` | Validation report, acknowledgements, stage summary with Change links, previews, what happens next, Request activation |

Each stage validates before the next opens. A stage can be saved and resumed. The step editor link stays on stage 2 for anyone who wants every field at once.

## 6. The Team stage

### 6.1 Find a person

- A search form (`role="search"`, GET) takes a name or an email.
- Results list only accounts of this organisation. Columns: name and email, roles held now in this organisation's programmes, identity status, and a "Choose" link.
- A note states the scope: "Accounts of other organisations on the platform are never searched or shown (I-19, I-20)."

### 6.2 Invite by email

The person fieldset offers a second choice: "Someone without an account: invite by email". The invitee gets a link to create an account in this organisation. Their checks run once they have an account. Until then the review shows the `InviteeWithoutAccount` warning.

### 6.3 Role and dates

- One radio group "Role", split into three fieldsets by role group, in Daniel's order:
  - Drafting: Programme manager, Call drafter.
  - Judging: FSTP coordinator, Committee member, Committee chair, IRC member.
  - Operations: Finance approver, Payment releaser, Contract signatory, Auditor.
- Assigned reviewer is not offered. Reviewers are assigned per call from the committee later.
- Home organisation of a committee member, for the P-39 spread across organisations. This is the creator's `organisation` field, not a tenant.
- "Role starts on" and "Role ends on (optional)". The role never starts before it is granted.

### 6.4 Live separation of duties checks

The check list sits under the role choice in a polite live region. It changes with the chosen role group, using CSS `:has()` in the prototype, so it works with no script. Each rule shows a badge with a glyph and a word: Passed, Not affected, Waiting or Refused.

| Rule | What the line says | When it can fail in set-up |
| --- | --- | --- |
| SoD-01 | The person holds no role from another of Drafting, Judging and Receiving in this programme | Adding a committee member who is already the call drafter |
| SoD-02 | An IRC member holds no other Judging role here | The refused example: H. Haddad as IRC member while FSTP coordinator |
| SoD-03 | An Operations role does not combine with a Receiving role here | Rare before the first call, since no proposal exists yet |
| SoD-04 | Finance approver and payment releaser stay two people for each payment | One person in both roles with nobody else in either |
| SoD-05 | No cooling-off bar applies (P-12) | A person whose Drafting or Judging role in this programme ended |
| SoD-07 | Not your account, or a second tenant admin must approve | A tenant admin who adds themselves |
| SoD-09 | Identity verified, checked again at the grant | A Drafting or Judging invitee who has not verified yet: Waiting, not Refused |

Display rules:

- A refusal that comes from roles in this programme names the rule and the role that blocks it.
- A refusal that comes from the identity vault names the rule only, for example "Refused under SoD-09". It never names another account (R-CF-03, as the built People step already does).
- A refused choice disables "Add to team". The reason sits beside the button.

### 6.5 Team so far

Three tables, one per role group, with person, role, dates, status and checks. Status uses the invitation states the build already has: Invited, Terms accepted, Identity verified, Role granted, plus Planned for Operations roles.

Two hints sit under the tables:

- **Short roster** (`RosterShort` warning): fewer IRC members than P-15, fewer committee members than P-03, or fewer organisations than P-39.
- **Call approval**: the programme manager who set P-01 or P-09 counts as a drafter of each call. A second programme manager is needed to approve calls (R-PC-03).

## 7. Review and confirm

- **Validation report.** "No failures" or the failure list with links to the field. Each warning has an "Acknowledged" checkbox. Passed checks fold into a `details` list. A report with any failure keeps Request activation unavailable (I-66).
- **Your programme.** One card per stage with its key values and a Change link, like the booking review before payment.
- **Previews.** Progress map preview (R-JV-08), Guide for Applicants (R-GA-01), public page and contract.
- **What happens next.** Approval by a tenant admin outside the builders with a step-up (I-67, I-78), with no approver select. Then the role grants (SoD-09), the call (R-PC-03) and publication (I-52, I-12).
- **Changes after the request.** Any change withdraws the request, reruns the report and voids the acknowledgements (`StaleRevision`).
- **Request activation** ends the wizard and opens the progress page. Only a programme manager can request it.

## 8. Set-up progress

`setup-progress.html` is the post-booking page. It is the programme team's counterpart of the applicant progress map.

- A compact strip of nine milestones at the top (`.strip`), then the same nine as a vertical journey list. Each item has a glyph and a word for its status, so colour is never the only signal.
- A callout first states the viewer's own next action.

| # | Milestone | Next action shown | Who acts |
| --- | --- | --- | --- |
| 1 | Programme drafted | None | Programme manager |
| 2 | Validation report clean | None. A change reruns the report | Programme manager |
| 3 | Team invited | Invitees accept the terms and verify identity | Each invitee |
| 4 | Activation requested | None | Programme manager |
| 5 | Activation approved | A tenant admin approves with a step-up. A draft change withdraws the request | Tenant admin outside the builders |
| 6 | Team roles granted | Grant in Members and roles | Tenant admin |
| 7 | Call drafted | The call drafter drafts the call | Call drafter |
| 8 | Call approved | Invite a second programme manager if none is outside the drafters | Programme manager who did not draft the call |
| 9 | Call published | Publish with a step-up | Programme manager |

The **team status** table follows. It is grouped by Drafting, Judging and Operations, with one row per person. Columns: Invited, Terms accepted, Identity verified, Role granted, Next action. Operations rows read "Not needed" for terms and identity, since those roles need neither (NOTE 5, J2). A disabled "Send a reminder" button marks where the reminder action goes.

The prototype state: activation requested on 15 Nov 2026, approval pending, 9 people, 1 role granted.

## 9. Synthetic data

Horizon Bridges and its `horizon-bridges.example` accounts, as in doc 09. The programme is OpenTech Fund, the draft that doc 09 lists with a pending Call drafter invitation for `r.gomez@example.org`. New synthetic people: S. Okafor, H. Haddad, E. Rossi, L. Farrugia, D. Ahmed (`horizon-bridges.example`), J. Moreau (`lakeside.example`) and T. Lindqvist (`northgate.example`). A Playwright test keeps every address in those domains.

## 10. Prototypes

| File | Signed in as | State |
| --- | --- | --- |
| `setup-wizard-start.html` | Tenant admin | Stage 1 current; S. Okafor chosen |
| `setup-wizard-programme.html` | Programme manager | Stage 2; template start; steps 1 and 2 validated |
| `setup-wizard-applicants.html` | Programme manager | Stage 3; steps 3 and 4 validated |
| `setup-wizard-evaluation.html` | Programme manager | Stage 4; P-05 within P-58 |
| `setup-wizard-team.html` | Programme manager | Stage 5; search "k", P. Novak chosen, Committee member selected, 9 people on the team |
| `setup-wizard-communications.html` | Programme manager | Stage 6; email only |
| `setup-wizard-review.html` | Programme manager | Stage 7; 0 failures, 2 warnings acknowledged |
| `setup-progress.html` | Programme manager | Activation approval current |

The flow is clickable: Administration, "Set up a new programme", each "Save and continue", "Request activation", then the progress page. `home-admin.html` gains the entry link and a link to the progress page. Each prototype shows the shell of doc 01: skip link, top bar, sidebar with role chip, one `main` and the shared footer.

## 11. Accessibility

- The stage bar is a `nav` named "Set-up stages" with an ordered list. The current item has `aria-current="step"`. Each item carries a hidden status word: complete, current stage or not started.
- The summary panel is an `aside` named "Your set-up so far", so it is a landmark a screen reader can jump to.
- The checks region is `aria-live="polite"`, so a changed result is announced once.
- Disabled buttons carry a `TODO(js)` comment and an `aria-describedby` reason. No TODO renders inside `main`.
- At 375px the stage bar becomes a vertical list and the summary panel moves below the stage.
- Every field of every stage has an "i" button beside its label, with its help hidden under the label until opened (SA-13). It is the shared field help of doc 05, "Field help". The stage 1 and Team stage fields use it too: programme name, email, role, home organisation and the role dates.

## 12. Spec IDs per screen element

| Element | IDs |
| --- | --- |
| Entry shown only once active; ADR-021 notice | ADR-021, SoD-18, R-TN-01 |
| Step-up on open draft, grant and approval | I-77, I-78 |
| Stage grouping of the 11 creator steps | R-PG-01, `12-journey-ui.md` §8.2 |
| Starting points, imported values confirmed | R-PG-02, I-65 |
| Cap within ceiling | I-50, P-05, P-58 |
| Account search scoped to this organisation | I-19, I-20 |
| Role binding with dates, granted by a tenant admin | O-47, I-23 |
| Live checks | SoD-01 to SoD-05, SoD-07, SoD-09, P-12, R-CF-03 |
| Roster hints | P-03, P-15, P-39, R-PC-03 |
| Validation report and acknowledgements | I-48, I-49, I-52, I-66, I-69, I-70 |
| Activation by a second person outside the builders, no approver choice | I-67 |
| Previews | R-JV-08, R-GA-01 |
| Progress milestones for the call | R-PC-03, I-12, I-52 |
| Team status columns | SoD-09, J2 terms acceptance |

## 13. What a build would need

These are gaps between the prototype and the current API. They are listed for planning, not decided here.

1. An account directory read for the search. Today the login email is sealed and found only by an exact keyed lookup (ADR-008, Q22). Accounts hold no display name.
2. Start and end dates on an invitation. `CreatorCommand::Invite` carries none, so the grant must ask for them again.
3. Operations roles in `creator.invite`. The built People step offers the six Drafting and Judging roles only.
4. A progress read that joins the programme status, the activation request and each invitation's state into one reply.

## 14. Open questions for Daniel

1. **Name search.** Accounts have no name, and the login email is sealed behind an exact lookup. Should the platform add a display name and a directory read for tenant admins and the draft's programme managers? The alternative is exact email match only. Recommendation: the directory read, limited to those two roles and to this cell.
2. **Operations roles in the wizard.** Should the Team stage plan Finance approver, Payment releaser, Contract signatory and Auditor, to be granted at activation? Recommendation: yes, as "Planned" rows with no terms and no identity step.
3. **Dates on invitations.** Should an invitation carry the start and optional end date, so the grant reuses them? Recommendation: yes.
4. **Builders and the approver.** Inviting or granting on a draft makes an account a builder. With two tenant admins, one careless grant can leave nobody to approve activation. Should the wizard block a tenant admin's action that would leave no eligible approver, or only warn? Recommendation: warn on every such action, and block the last one.
5. **Wizard and step editor.** Is the wizard the first-time path, with the step editor kept for later changes? Recommendation: yes, as with onboarding and the admin screens.

## 15. Daniel's answers and the build (2026-11-15)

Daniel's answers to section 14:

1. **Name search.** Exact email only. No directory and no display name.
2. **Operations roles.** Yes, as planned rows. A tenant admin grants them after activation, and the progress page tracks them.
3. **Dates on invitations.** Yes. The grant after acceptance reuses them.
4. **Builders and the approver.** Lane m4/i67-override adds a tenant admin override of I-67, with a reason and a ledger record. The wizard keeps the notice on who approves, and leaves a named place for the override form.
5. **Wizard and step editor.** The wizard is the first-time path. The creator step editor stays for later changes.

### 15.1 What lane m4/setup-wizard-build built

- **Pages.** `web/src/setup/`: `/app/setup/new` (stage 1), `/app/programmes/{p}/setup/{stage}` (stages 2 to 7) and `/app/programmes/{p}/setup/progress`. They use the app shell, the creator's field editors, the draft and report reads, and the creator review's report, previews and request (`creator/pages/review.ts` `reviewParts`, shared with the creator review page).
- **Entry.** The tenant admin home and navigation link "Set up a new programme with the wizard". The programme manager home links the wizard and the progress page of each draft. Before activation the home lists onboarding alone, so the wizard is not offered (ADR-021). A refusal under ADR-021 shows the creator's ADR-021 text.
- **Stage 1.** A tenant admin names the programme, opens the draft (`creator.open_draft`, step-up) and invites the programme manager with `creator.invite`. The progress page of the new draft follows. `creator.open_draft` takes an optional `name`, saved in the opening entry as a manual edit of `identity.name` by the opener (lane m3/finish-gaps). The roles table is unchanged: `creator.save_fields` stays programme manager only, and the programme manager can rename in stage 2. Decided by Daniel on 2026-11-15: that save names draft revision 0, since it is decided before the draft exists.
- **Starting point.** Stage 2 links the creator start page with `?then=setup`. After a start, that page returns to the wizard.

### 15.2 Exact email (answer 1)

The Team stage and stage 1 take a full email address and call `creator.invite`. M3 binds the address to the account that already has exactly this address, or to a new account (`fstp-e2e-cell` `people.rs`, the existing flow). The page shows the same invitation either way, so it never says whether an address has an account. No other organisation's accounts are read (I-19, I-20).

### 15.3 Planned Operations rows (answer 2)

Least invasive design: **no new record.** A planned row is an invitation of an Operations role, recorded as today by `CreatorRecord::InvitationRecorded`. `creator.invite` already admits the four Operations roles (`fstp_access::invitable`).

- The wizard shows an Operations invitation as "Planned, granted after activation" until its role is granted.
- The invitee accepts the invitation, which binds their account and records the role-only terms, as for every role (J2). No identity check runs, since SoD-09 names Drafting and Judging only.
- After activation the people admin page offers the grant once the invitee has accepted (`people/model.ts` `grantOffered`). The server composes `GrantRole` as before, with no confidentiality text for Operations.
- The progress page reads "Not needed" for identity on these rows.

Decided by Daniel on 2026-11-15: the invitee of a planned row gets the invitation email when the row is added, since accepting it is what binds the account. Operations invitees accept the role-only terms, as above. A row that sends nothing until activation would need the grant to name an account by exact email, which no read gives.

### 15.4 Dates on invitations (answer 3)

- `CreatorCommand::Invite` and `CreatorRecord::InvitationRecorded` carry `start` and `end: Option`, instants in microseconds. The codec names both members, `end` as `null` when open.
- `creator.invite` takes `start` and `end` as canonical decimal strings, as the `roles.grant` form does. Without `start`, the role starts at the invitation. An end that does not lie after the start is refused under `Input` (`CreatorRefusal::InvitationDates`).
- The wizard sends a role start date as its UTC midnight, and an end date as the midnight after it, so the role holds through that day.
- `creator.invitations` lists `start` and `end` (`fstp_access::REPLIES`, `web/src/gen/api.ts`).
- The grant by invitation starts at the later of the invitation start and the grant, since a grant is never backdated (design 2.6), and ends at the invitation end.

Interim, pending Daniel: the record codec stays strict, so a stored `InvitationRecorded` written before this change no longer decodes. The demo cells rebuild their ledger at each seed, and no production ledger holds one yet.

### 15.5 Live checks

The SoD lines of the Team stage are projections of the team the invitation list shows. A refusal names the rule and the role on this team that blocks it, never an account (R-CF-03). SoD-09 waits for the invitee and SoD-07 for the grant. After the invitation, the team table shows the server's live check of each row. The server checks every rule again at each command.

### 15.6 Progress without a new read

The progress page reads `creator.get_draft`, `creator.get_report`, `creator.invitations` and, once the programme is active, `call.list`. No combined read was needed, so the registry and the authorisation reference gain no operation.

### 15.7 The approver (answer 4)

Review and confirm and the progress page keep the notice on who approves activation (I-67). Each holds an empty, hidden `section#setup-approver-override[data-slot="i67-override"]` where lane m4/i67-override puts its form.

### 15.8 The approver count (lane m3/finish-gaps)

`creator.get_draft` carries `approvers`: how many attested tenant admins are not builders of the draft. It is a count and names no account (R-CF-03). The approver notice on Review and confirm and on the progress page says how many remain, or that none does. The count does not check verified identity or the vault's identity answers, which the approval still checks (I-67).
