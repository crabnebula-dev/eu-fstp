# ADR-022: Tenant admin override of I-67 at programme activation

Status: Accepted 2026-11-15 (Daniel Thompson-Yvetot), option "Override I-67 itself". Drafted 2026-11-15 by lane `m4/i67-override`. Every reading marked "Interim, pending Daniel" below is the lane's.

## Context

- Daniel was asked whether "superadmin override powers" for tenant admins should keep I-67 or override it. On 2026-11-15 he chose **"Override I-67 itself"**.
- The option he picked read: "A tenant admin may approve activation of a programme they built, as an override. This changes invariant I-67 in SPEC, so it needs a spec amendment and an ADR recording that you chose it, plus an audit record on every override."
- I-67 before this ADR: "Activating a programme needs approval by a second person who did not build it." R-PG-03 restates it, and so do `programme-creator.md` (Validation, Template library), `12-journey-ui.md` and the test plan.
- The creator approves through `creator.approve_activation`. Only a tenant admin outside the builder set may approve, with a fresh step-up (I-78). The core guard of `ActivateProgramme` refuses a builder again (M4 change D2).
- I-66 is a separate invariant. It needs a clean validation report and an acknowledgement for each warning.

## Decision

### The amended invariant

**I-67** Activating a programme needs approval by a second person who did not build it, or an override by a tenant admin who built it. Every override is a separate step with a fresh step-up and a written reason, and it leaves its own ledger record.

So every activation is either approved by a tenant admin outside the builder set, or carries an override record by a tenant admin of the builder set with a reason.

### Interim readings, pending Daniel

1. **Who may override.** Only a tenant admin may override, and only one in the programme's builder set. A programme manager or any other builder never may. A tenant admin outside the builder set uses the normal approval, so the override refuses them.
2. **A distinct command.** The override is its own operation, `creator.override_activation` (`POST /programmes/{programme}/activation-override`). It is separate from `creator.approve_activation`, which stays the default path and is unchanged.
3. **Step-up.** The override is high-risk, as approval is (I-78). It needs a fresh passkey step-up bound to its own request digest.
4. **Reason.** The request carries a written reason. It must hold a character other than white space, and it is bounded by the free-text limit of the API core (`forms::TEXT_LIMIT`, 64 KiB). The text is stored as a confidential text of the programme, and the ledger holds its `TextRef` only (ADR-007).
5. **Ledger records.** The entry holds the probe results, the creator record `ActivationOverridden { programme, revision, report, decision, by, builders, reason, at }` and the core `ProgrammeActivated`. The core record carries the same `override_reason`. The engine fold refuses an overriding `ProgrammeActivated` without its `ActivationOverridden` in the same entry, and the reverse, as it already pairs `ActivationApproved` (D2e).
6. **Audit.** The call leaves its audit entry like every admin act, with its operation name, outcome and step-up reference (I-24). The ledger record above is the durable record of the override and its reason.
7. **What the override lifts.** It lifts only the "second person who did not build it" part of I-67. So the builder check and the Sybil check `SameIdentityAsAny(approver, builders)` are not asked for an override. Everything else still holds:
   - I-66 is unchanged. The recomputed report must be clean, with every warning acknowledged at a live revision.
   - The draft must be open, the command must name the head revision, and an activation request must be live.
   - The vault must verify the overriding admin. Every builder must be verified, as the report already requires (`BuilderUnverified`).
8. **Defence in depth.** The core guard admits an approver in the builder set only for a command that carries an override reason, from a tenant admin, and only when the approver is in the builder set. Without an override reason the core guard refuses a builder, as before.
9. **The page.** On the approval inbox (`/app/admin/approvals`), a tenant admin who built the programme sees an "Approve as override" form with a reason field. It says: "You built this programme. As a tenant admin you can approve it anyway. Your reason is recorded." The normal approve button is never offered to a builder.

## Consequences

- A tenant with one active builder admin can activate without waiting for a second person. Each such activation is visible in the ledger as an override with its reason.
- The I-67 properties change to the amended invariant. The M-ACTIVATE model and the activation machine gain the override command. The Sybil configuration now expects no normal approval to activate, while an override by the building admin may.
- The authorisation matrix reference gains `creator.override_activation`: a tenant admin of the builder set may act, every other principal is refused as an actor.
- SoD-18 (organisation activation) is unchanged. It refers to I-67 only by analogy.

## SPEC lines this ADR amends

- `SPEC/02-domain/invariants.md` I-67.
- `SPEC/02-domain/programme-creator.md` I-67 under Validation, and the Template library line that restates it.
- `SPEC/01-requirements/functional.md` R-PG-03.
- `SPEC/12-journey-ui.md`, the seal ceremony lines that restate I-67.
- `SPEC/07-test-plan/test-plan.md`, the I-65 to I-67 row.
- `SPEC/02-domain/roles-and-sod.md`, a NOTE under SoD-18 that the override does not apply there.
- `docs/design/spec-amendments.md` SA-06 records the amendment.

## Decided by Daniel, 2026-11-15 (evening)

1. **Readings accepted.** Only a tenant admin of the builder set may override. A non-builder admin uses the normal approval and is refused on the override path. The Sybil check is not asked for an override.
2. **Mailbox item.** A tenant admin of the builder set gets one mailbox item when activation is requested. It says an override is available and links to the approval inbox, where the "Approve as override" form is.

## Open points for Daniel

1. The audit read `audit.entries` is not built yet. Until it is, the override shows in the audit port's entries and in the ledger.
