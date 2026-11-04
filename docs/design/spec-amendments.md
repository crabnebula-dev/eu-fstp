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
