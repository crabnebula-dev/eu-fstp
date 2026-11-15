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
