# Spec amendments and backend notes

Design decisions that require changes to the spec or backend. Each item has a status: Spec amendment pending, Backend work pending, or both.

This record is not normative. It is input for Daniel's engineering work. The spec wins until each amendment is made.

## SA-01: Financial signatory and Legal signatory roles

**Source.** Daniel's decision, 2026-11-01. Q31.
**Status.** Spec amendment applied on 2026-11-04. Backend work pending.

### Spec amendment required

Add the following to `SPEC/02-domain/roles-and-sod.md`, in the Roles table:

| Role | Group | Notes |
|---|---|---|
| Financial signatory | Operations | Approves payment instructions and financial commitments at the organisation level. Tenant-wide; not programme-bound. |
| Legal signatory | Operations | Approves contracts, terms and legal commitments at the organisation level. Tenant-wide; not programme-bound. |

Add rules:
- **SA-01a** At least one account must hold Financial signatory before the organisation can be activated.
- **SA-01b** At least one account must hold Legal signatory before the organisation can be activated.
- **SA-01c** One account may hold both Financial signatory and Legal signatory.
- **SA-01d** Removing the last holder of either role is refused while the organisation is active.
- **SA-01e** These roles are distinct from the programme-bound Contract signatory (Operations). The Contract signatory signs individual grant contracts. The Financial and Legal signatories act at the organisation level.

Note: SoD-07 applies when a tenant admin grants either role to their own account.

### Backend work required

1. **Role storage.** Add Financial signatory and Legal signatory as valid tenant-wide role kinds in the domain model. Unlike programme-bound roles, these bind an account to the tenant (not to a programme). Store start date and optional end date, as with all bindings.

2. **Activation gate.** At organisation activation, enforce SA-01a and SA-01b. Block activation if either role has no holder. Return the missing roles in the error response so the shell can display them.

3. **Removal guard.** At role removal, check SA-01d. If removing the binding would leave the role with no holder, refuse with a clear error. This check runs at the point of removal, not only at activation.

4. **Audit log.** Record every grant and removal of these roles in the audit log, as with other role changes. Include the granting account, the target account, the role and the timestamp.

5. **SoD-07 enforcement.** Apply the existing SoD-07 check (self-grant requires a second tenant admin) to Financial signatory and Legal signatory, as it applies to Tenant admin grants.

6. **Identity vault.** These roles do not require verified identity at binding time (SoD-09 covers Drafting and Judging only). No vault query is needed at grant time. If this assumption is wrong, a spec decision is needed.

7. **API.** Expose these roles on the tenant member list endpoint, the role grant endpoint and the role removal endpoint. The shell reads them for the admin-members screen and the onboarding activation check.

8. **Profile bundle.** If the profile bundle (R-PS-03) exports role bindings, include Financial signatory and Legal signatory in the export.

---

## SA-02: Onboarding activation second-admin rule

**Source.** Daniel's decision, 2026-11-01. Q29.
**Status.** Spec amendment applied on 2026-11-04. Backend work pending.

### Spec amendment required

Add the following rule to `SPEC/02-domain/programme-creator.md`, under Validation:

- **SA-02a** Organisation activation requires approval by a tenant admin who did not complete the final step of the onboarding setup. This is by analogy with I-67 (programme activation). The platform records which account submitted the activation request and refuses approval from the same account.

### Backend work required

1. **Activation request.** Record the account that submits the activation request on the onboarding wizard (step 9, "Activate organisation" action).

2. **Approval gate.** Require a separate approval action from a different tenant admin. Refuse if the approving account matches the requesting account.

3. **Audit log.** Record both the activation request and the approval, with account identifiers and timestamps.

4. **Shell flow.** The onboarding step 9 screen already shows the requesting admin and the awaiting approver (synthetic: a.chen requests, m.diop approves). The backend must expose the activation state so the shell can render this.

---

## SA-03: Terminated-before-signature contract record

**Source.** Daniel's decision, 2026-11-01. Q28.
**Status.** Spec amendment applied on 2026-11-04. Backend work pending.

### Spec amendment required

Add the following to `SPEC/02-domain/contracts.md`, under Rules:

- **SA-03a** A contract terminated before any party signs it has its generated draft PDF sealed with the tenant's electronic seal and stored at the point of termination. The termination reason is recorded. The sealed PDF and its hash are included in the audit log (I-30). This satisfies the audit trail requirement even where no signatures exist.

### Backend work required

1. **Termination flow.** When a contract transitions to TERMINATED and no signatures have been collected, trigger the draft PDF seal and store it, recording the hash in the audit log.

2. **Seal.** Apply the same seal as a normal contractual notice PDF (P-47, ADR-001 crates, tenant key). The seal is applied to the draft, not to a signed version.

3. **Audit record.** Write an audit entry: contract reference, state transition to TERMINATED, termination reason, draft PDF hash, seal timestamp.

4. **Download.** Expose the sealed draft for download, labelled as a sealed draft (not a signed contract), for the same retention period as signed contracts (P-41).

---

## SA-04: Advanced signature removed from verification methods

**Source.** Daniel's decision, 2026-11-01. Q30.
**Status.** Spec amendment applied on 2026-11-04.

### Spec amendment required

Clarify in `SPEC/02-domain/programme-creator.md` step 5 (Identity) and in `SPEC/03-architecture/authentication.md` that P-18 (verification methods) covers identity verification only: EUDI Wallet and remote qualified routes. Advanced signature (P-30 step 3) is a fallback signing route, not a verification method, and is not configured in step 5.

### Backend work required

None. The backend already separates verification (P-18, identity vault) from signing (P-30, contract flow). This is a spec clarification only.

---

## Applied IDs

Applied by the implementing agent on 2026-11-04, after Daniel confirmed all four. SA-01a to SA-01d became SoD-14 to SoD-17, and SA-01e became NOTE 5 of `roles-and-sod.md`. SA-02a became SoD-18. SA-03a is a rule in `contracts.md`. SA-04 is a note in `authentication.md` and the Identity row of `programme-creator.md`.

## SA-05: Masquerade is a synthetic role preview

**Source.** Daniel's decision, 2026-11-01. **Status.** Spec amendment applied on 2026-11-04 as `SPEC/12-journey-ui.md` section 8.6.

The preview shows synthetic sample data only, never real records, and changes no access rule. Real content still needs SoD-08 break-glass approval.

## SA-06: Tenant admin override of I-67

**Source.** Daniel's decision, 2026-11-15, option "Override I-67 itself". **Status.** Spec amendment applied on 2026-11-15 under ADR-022. Backend work applied by lane `m4/i67-override`.

The option read: "A tenant admin may approve activation of a programme they built, as an override. This changes invariant I-67 in SPEC, so it needs a spec amendment and an ADR recording that you chose it, plus an audit record on every override."

### Spec amendment applied

- I-67 in `SPEC/02-domain/invariants.md` and `SPEC/02-domain/programme-creator.md` now reads: "Activating a programme needs approval by a second person who did not build it, or an override by a tenant admin who built it. Every override is a separate step with a fresh step-up and a written reason, and it leaves its own ledger record." A NOTE cites ADR-022.
- R-PG-03, the Template library line of `programme-creator.md`, the seal ceremony lines of `12-journey-ui.md` and the I-65 to I-67 row of the test plan restate the override.
- A NOTE under SoD-18 says the override does not apply to organisation activation.

### Backend work

1. A distinct operation, `creator.override_activation`, high-risk with step-up, for a tenant admin of the builder set only.
2. A written reason, not blank, within the free-text limit, stored as a `TextRef` (ADR-007).
3. The creator record `ActivationOverridden` and the core `ProgrammeActivated` with its `override_reason`, paired in one entry by the engine fold.
4. I-66 unchanged. The normal approval unchanged.

## SA-07: The FSTP coordinator unmasks parties of their own programme

**Source.** Daniel's decision, 2026-11-15, option "Amend I-17: coordinator unmasks, logged". **Status.** Spec amendment applied on 2026-11-15 under ADR-023. Backend work applied by lane `m4/coordinator-unmask`.

The option read: "The FSTP coordinator may unmask any party of their own programme at any stage. Each unmask asks for a purpose, needs a passkey confirmation and is a ledger record shown in the audit log. I-17 is amended (ADR-023) to exempt the coordinator; other Judging roles stay masked."

### Spec amendment applied

- I-17 in `SPEC/02-domain/invariants.md` now reads: "Judging roles cannot read identity attributes of an applicant before the proposal enters negotiation. The FSTP coordinator is exempt for the parties of their own programme: each unmask names a purpose, needs a fresh step-up and leaves its own ledger record, and the vault shows the identity on its own origin only." A NOTE cites ADR-023.
- `roles-and-sod.md` restates it in the FSTP coordinator row, the reviewer note and the anonymous reviewer handles section.
- `overview.md` names the unmask ticket as the one release without a negotiation fact.
- R-NG-01 NOTE, TH-07 and the I-17 and I-21 test plan row restate the exemption.
- `authentication.md` lists the unmask in its high-risk table (I-78).
- I-20, I-27, I-83, I-86 and I-89 are unchanged.

### Backend work

1. The core command `UnmaskParty` and its record `PartyUnmasked { programme, party_kind, subject, purpose, by }`, for an active FSTP coordinator of the named programme only. The subject is a binding or assignment id.
2. The operation `identity.unmask`, high-risk with step-up, web only, with a purpose of 1 to 500 characters stored as a `TextRef`.
3. The vault ticket kind `unmask` on the release route, admitted without a negotiation fact.
4. The reads `identity.parties` for the coordinator and `audit.unmasks` for the auditor and tenant admins.

## SA-08: Tenant admins and the FSTP coordinator read the audit log

**Source.** Daniel's decision, 2026-11-15: "tenant admins and coordinators can all 'read-only' the audit log." **Status.** Spec amendment applied on 2026-11-15. Backend and web work applied by lane `m4/audit-readers`.

### Spec amendment applied

- `roles-and-sod.md`: the FSTP coordinator, Tenant admin and Auditor rows carry a NOTE. Tenant admins and the FSTP coordinator of a programme read its audit log read-only. The entries show text references only (ADR-007), so no proposal content is exposed.
- R-AU-01 and I-24 are unchanged. The tenant admin row's "No proposal content access by default" still holds.

### Backend work

1. `audit.entries` and `audit.vault_outcomes` share the read rule `ReadRule::AUDIT_READER`: the auditor of the programme, every tenant admin, and an FSTP coordinator of the programme. The reference names it `Rule::AuditReader`.
2. I-86 exposure is unchanged. `audit.entries` keeps its MCP tool `fstp_audit_list_entries` for every reader. `audit.vault_outcomes` stays web only.
3. `audit.unmasks` is unchanged: the auditor and the tenant admins.

### Web work

1. The audit page shows the entries to all three readers.
2. A tenant admin's home links to the audit log of each programme of the tenant, from `creator.list_programmes`. A coordinator's home links to the audit log of each programme it coordinates.

## SA-09: A page the viewer may not open is never shown

**Source.** Daniel's decision, 2026-11-15: "I should never be able to see a route that my user (or a non-logged in user) does not have permissions to see." His examples: `/app/grants` and `/app/proposals` showed "The platform refused this request (unauthenticated): actor". **Status.** Decided. Built by lane `m4/page-gate` on 2026-11-15, with a line in `SPEC/12-journey-ui.md` section 8. The page table is `fstp_access::PAGES`.

### Rule

1. The server decides before it serves any `/app/` page. Today both cells serve the shell for every `/app/` path and leave the refusal to the page.
2. **No session.** The server redirects (303) to sign-in with the page as the return path. After sign-in the gate runs again. A mailbox link therefore still reaches its page.
3. **A session that may not open the page.** The server answers the same "Page not found" page, status 404, as for a path that does not exist. This covers a missing role, a resource outside the viewer's scope and an ADR-021 gate before activation. The answer never says that the page exists or why it is closed. ADR-021's "still being set up" notice stays on the home page only.
4. **Login too weak** (a magic-link session on a page that needs a passkey). The server sends the viewer to sign in with a passkey, then runs the gate again.
5. **One rule decides.** Each page row names the read the page cannot render without. The page is served only when the authorisation reference (`fstp-access`) admits that read for the session's principal and, on a page with an id, for that resource. So a page and its API never disagree.
6. **Links.** Navigation, home pages and mailbox items list only pages the viewer may open.
7. **No raw refusal text for a page.** If a page's own read is refused after it loaded, for example because the session ended, the page shows sign-in or "Page not found", never the refusal code.

### Unchanged

- A refused action inside a page the viewer may open still names the rule, never an account (R-CF-03, `overview.md`).
- The API keeps its refusal classes. The gate concerns page routes only.

## SA-10: I-21 and the coordinator's parties read on a draft

**Source.** Daniel's decision, 2026-11-15 (late), confirming the reading of lane m4/evening-answers. **Status.** Spec amendment applied. Code built in 8efed4b8.

- `invariants.md` I-21 carries a NOTE. The FSTP coordinator's parties read and unmask (ADR-023 decision 4) work on a draft and show who the parties are, never draft content or pre-submission check runs. I-21 is otherwise unchanged.

### SA-09 amendment, Daniel 2026-11-15 (night)

Daniel: "if i go to route that does not exist, i want to go to home, not see a JSON response". The cell answered `{"code":"not_found","rule":"route"}` for an unknown path outside `/app/`.

- **Browser page requests** (GET or HEAD that a browser navigates to, outside `/api/`) for a path that does not exist redirect (303) to home, `/app/`. The gate then sends a signed-out visitor to sign-in. This holds on every path of the cell's origin, inside and outside `/app/`. An unknown path under `/p/{slug}/` goes to that organisation's public home `/p/{slug}` when the organisation exists.
- **Rule 3 changes accordingly.** A page the viewer may not open gets the same answer as an unknown path: the same 303 to home. The two stay indistinguishable, so the answer still never says that a page exists.
- **API requests keep their JSON answers.** `/api/` and every other machine route answer as before.
- The shell's link check must not follow the redirect. A redirect counts as "may not open".

**Built** by lane `m4/page-gate-2` on 2026-11-15. Readings, pending Daniel:

- A browser page request is a `GET` or `HEAD` with `Sec-Fetch-Mode: navigate`. With no Fetch metadata, it is one whose `Accept` names `text/html`. A script cannot set `Sec-Fetch-Mode`, so a fetch, a script or a stylesheet keeps its answer (`fstp_http::is_page_navigation`).
- Inside `/app/` the gate answers 303 to home for every `GET` and `HEAD`, browser or not, so the shell's link check sees the redirect.
- The public home of a programme is served at `/p/{slug}/`, with the slash. The redirect goes there, and `/p/{slug}` without the slash goes there too.
- The machine routes are `/api/`, `/mcp`, `/oauth` and the OAuth `/.well-known` documents. `fstp-cell`'s front does not serve `/app/` yet, so there `/app/` itself keeps its 404 and never redirects to itself.

## SA-11: Team and member pages, with display names

**Source.** Daniel's decision, 2026-11-15 (night): "I need to have a page where I as an admin / or programme manager can see who is a member of the team." Answers: both views; add a display name; overview with actions. **Status.** Decided. Built by lane `m4/team-pages` on 2026-11-15.

### Display name (new personal data)

- Each account may set its own display name on its account page, and clear it. It is plain text, at most 100 characters, with no markup.
- It is stored as a confidential text of the account (ADR-007), so account erasure erases it.
- It is shown only on the team and member pages below. It never appears to applicants or Judging roles in place of a handle (I-17, P-11), in a message (I-27), or in a log.
- `TODO(legal)`: the privacy notice needs a line for this processing. Daniel supplies the wording.

### Programme team page: `/app/programmes/{programme}/team`

- **Readers.** Tenant admins and the programme's manager.
- **Rows.** Every Drafting, Judging and Operations role of the programme, including open invitations. Each row shows:
  - the display name (or "no name set") and the invitation or login email;
  - the role and its status: invited, accepted, verified, active, suspended or ended;
  - the role dates.
- **Actions.** The page offers the actions the viewer may take, each decided again by the server: grant, end and reinstate, each with a step-up, plus inviting a person. Applicants and their teams are not listed.

### Organisation member page: `/app/admin/members`

- **Readers.** Tenant admins only.
- **Rows.** Every member account of the organisation, with its display name, its email, and its roles across programmes with their status.
- **Actions.** The same actions per role, each with a step-up.

### Built by lane m4/team-pages

- Operations: `team.list` (`GET /programmes/{programme}/team`, the programme's manager and the tenant admins), `admin.members` (`GET /admin/members`, tenant admins), `me.display_name` and `me.set_display_name` (`GET` and `POST /me/display-name`, the caller's own). All four are web only, with no tool (I-86). None needs a step-up. The role actions keep their own step-up.
- Join: the roster gives the bindings, the creator draft gives the open invitations and their invitation email, and the accounts port gives the login email (`Accounts::login_email`). The text store keeps the display name as a confidential text owned by the account (`TextOwner::Account`). It releases the name only to the team, member and own reads.
- Pages: `/app/programmes/{programme}/team` and `/app/admin/members`, both in `fstp_access::PAGES`. The account page `/auth/account` has a display name section.
- Links: the tenant admin's home links the member page and the team page of each programme, and its navigation the member page. The programme manager's home links the team page of each programme it manages. The people page links the team page.

Readings, pending Daniel:

- The navigation links no team page. R-NF-03 and its web test say the navigation links only pages without an id, and the team page needs a programme. The home page and the people page link it instead.
- A display name changes no domain fact, so no ledger record names it. The text store alone knows which text of an account is its display name. A replaced or cleared name is erased at once, logged as a person's erasure request (cause 2).
- A voided binding shows as ended, with its rule. The roster keeps no ended Operations binding, so an ended Operations role is no longer listed.
- The tenant-wide Financial and Legal signatories appear on the member page with no programme, and on no team page.
- The team page offers the invitation while the programme has a creator draft. The member page offers the per-role actions only.
- The page titles use the plain names "Team" and "Members" from the page catalogue. The vocabulary pack key `vocab.team` names the applicant team, so it is not reused.
- `TODO(legal)`: the privacy notice line for this processing is still open.

## SA-12: Tenant admins help set up programmes

**Source.** Daniel, 2026-11-15 (night), on a refused creator start page ("refused under rule actor. Signed in as Tenant admin"): "I want the admin to be able to help set up everything." **Status.** Decided. To be built by lane `m4/admin-setup`.

### Rule

- A tenant admin may take every programme set-up action of the programme manager and the call drafter on any programme of the own tenant, without a Drafting binding. This covers:
  - the creator start and steps, field and narrative saves, policy edits, imports, knock-out criteria and the Guide preview;
  - the wizard stages, invitations and the activation request;
  - drafting calls.
- Each act names the admin as its actor, as for any editor.
- **I-67 still holds.** An admin who edits a programme counts as one of its builders. Activation then needs a normal approval by a tenant admin who is not a builder, or the builder admin's override under ADR-022.
- **Unchanged:**
  - The tenant admin row's "No proposal content access by default" still holds, since set-up is no proposal content.
  - SoD-07 and SoD-18.
  - The approval and publication rules of calls (R-PC-03).
- `SPEC/02-domain/roles-and-sod.md` gains a NOTE on the tenant admin row.

## SA-13: Field help in the wizard and the Programme editor

**Source.** Daniel, 2026-11-15 (night): "provide information about every field that the administrator / programme manager can fill out. Leave the text hidden by default, but if the user clicks an 'i' icon, then the information is shown. In the wizard and the editor, it is helpful because unless you have done this before you might not know what is intended." **Status.** Decided. Built by lane `m4/field-help` on 2026-11-15.

- Every field a tenant admin or programme manager can fill in has a help text. This covers the "Create a programme" wizard, the Programme editor and creator steps, knock-out criteria, imports and invitations.
- The help text is hidden by default. An "i" button beside the field's label shows it and hides it again. The button follows the disclosure pattern: a real button, `aria-expanded`, `aria-controls`, keyboard operable, and an accessible name "About <field label>".
- The text is plain language (docs/design/10). It says what the field means, what a typical value looks like, and what it affects, such as which check, which document or which applicants. Content comes from the SPEC descriptions (`policy-parameters.md`, `programme-creator.md`, the profile and Guide sections) with the P- id. It never invents legal claims; where a legal explanation would be needed it says `TODO(legal)`.
- A completeness test fails when a field has no help text, as the label check already does.

### Built by lane m4/field-help

- Component: `web/src/help/help.ts`, with its style in `web/src/site/ui.css` (`.fstp-info`, `.fstp-help`). Design docs 05 ("Field help") and 11 (section 11) describe it.
- Texts: `web/src/help/messages.en.ts`. It holds 84 creator field texts, 7 wizard texts, 3 invitation texts and 3 import texts.
- Where: the creator field editors (`creator/editor.ts` `fieldEditor`), so every creator step, the Knock-out criteria page and the import review; the wizard's stage 1 and Team stage; the People step's invitation form and the team page's; the creator start page's clone and import choices; the conflict acknowledgement of the import review.
- Tests: `web/test/sa13_field_help.test.ts` (completeness, ARIA state, toggling, placement) and `e2e/studio/field_help.spec.ts` (a programme manager on a Programme editor step and a tenant admin on wizard stage 1, with the suite's structure and contrast checks).

Readings, pending Daniel:

- The help is per field. The members and list items of a structured field, such as the criteria of P-01, share the field's text.
- The call number on Approval and publication is outside SA-13's list, so it has no help yet.
- These texts say `TODO(legal)` in place of a legal explanation: P-41, P-46, P-19, the statement on minors, P-77, P-30, P-44, P-47 and the flow-down obligations.
- The P-61 to P-64 texts give the policy table's proposed values as "Proposed value".

### SA-11 amendment, Daniel 2026-11-15 (night): unique display names

Daniel: "Display names should be unique."

- A display name is unique within the organisation (the tenant). It is never compared across tenants (I-20).
- Names are compared after normalisation: Unicode NFC, surrounding white space trimmed, inner white space collapsed to one space, and case folded. "Anna Berg" and "anna  berg" are the same name.
- Setting a name that another account of the tenant holds is refused with "This name is already used in your organisation". Setting your own current name again is not a conflict.
- Names are stored sealed (ADR-007), so uniqueness uses a keyed fingerprint of the normalised name, made through `fstp-crypto`, kept per tenant and erased with the name. The check and the write are one atomic step, so two accounts cannot take the same name at once.
- **Normalisation, Daniel 2026-11-15 (night):** "Simpler comparison". No workspace code does NFC or full case folding (also open in `fstp-import` text and `fstp-assess` extraction). Names are compared after trimming, collapsing inner white space to one space, and `to_lowercase`, with no NFC. Two names that differ only in how an accent is encoded may both be accepted. This replaces the NFC and case-folding sentence above.
