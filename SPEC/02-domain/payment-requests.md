# Payment requests

## Plan structure

A grant plan is a list of tasks. Each task holds milestones, and each milestone has an amount. A task's amount is the sum of its milestones. The contract total is the sum of its tasks (`02-domain/contracts.md`).

## Balances

For every milestone the platform keeps:

| Figure | Meaning |
| --- | --- |
| Amount | Milestone amount in the effective contract version |
| Paid | Sum of released lines |
| Pending | Sum of requested lines in requests not yet released, rejected or withdrawn |
| Available | Amount minus paid minus pending |

Tasks show the same figures as sums over their milestones.

Amounts follow `../docs/adr/ADR-006-money-representation.md`. In records and exports they are decimal strings in the currency's fixed scale, for example EUR `"1234.50"`. PostgreSQL stores them as `numeric` at that scale. The domain holds them as integer minor units, which is cents for EUR.

## Flow

A payment request has one or more lines. Each line references one milestone of the grant and carries:

- the requested amount, above zero and at most the milestone's available balance,
- deliverable evidence: public location, release or commit identifier, licence identifier (SPDX),
- a short progress or delivery report for that milestone.

One request can cover milestones across several tasks. A milestone can be claimed over several requests until its amount is used up.

Hardship contributions use the same flow with request type "hardship" and evidence held in the vault.

## Request form

- Tasks are listed in plan order, each with its available and total amount.
- Each milestone row shows its available amount and an input for the requested amount.
- A control on each row fills the input with the full available amount.
- Fully paid milestones stay visible with their original amount, and their input is disabled.
- Milestones with pending lines show the pending amount, so grantees can see what is already in review.
- The form shows the running request total before submission.
- Inputs above the available amount are rejected in the form and again on the server.

## Line review

Assigned reviewers decide per line. They can approve the requested amount, approve a lower amount with a recorded reason, or reject the line with a reason. The released amount of a request is the sum of its approved lines.

The difference between a requested and an approved amount returns to the milestone's available balance.

## Automated checks

Before human review, the platform checks:

- each deliverable location is publicly reachable without authentication,
- the detected licence is in P-26,
- each line is at most its milestone's available balance (I-58), and the request fits the contract total (I-31),
- the evidence requirements in P-34 are met.

On submission and again on acceptance, the platform records an evidence snapshot: identifiers, content hashes and retrieval time. A later licence change or deletion upstream does not alter the recorded evidence (TH-24).

LLM findings may compare deliverables with the promised scope. They are advisory (I-10).

## States

| State | Actor | Meaning |
| --- | --- | --- |
| DRAFT | Grantee | Being prepared |
| SUBMITTED | Grantee | Submitted for checks |
| CHECKS_FAILED | System | Returned with failed checks listed |
| UNDER_REVIEW | Assigned reviewer | Technical acceptance in progress |
| CHANGES_REQUESTED | Assigned reviewer | Returned with requested changes |
| ACCEPTED | Assigned reviewer | Every line approved in full or in part, or rejected, with at least one approved line |
| PAYMENT_APPROVED | Finance approver | Approved for payment |
| RELEASED | Payment releaser | Exported (record-only) or instructed (execution) |
| PAID | System or finance | Payment confirmed |
| REJECTED | Assigned reviewer | Every line rejected, with reasons |
| WITHDRAWN | Grantee | Withdrawn before release; pending amounts return to available |

## Rules

- Acceptance requires passed checks and recorded snapshots (I-32).
- Approver and releaser are different persons (I-05).
- Released totals never exceed the contract amount (I-31).
- A change of bank details blocks release until re-verification completes and P-36 elapses (I-33).
- The change is notified to the previously verified email address and contact channels, with a way to dispute it during the hold. A dispute freezes payments and alerts the finance approver.
- Accepted deliverables feed the I-15 record used for repeat grants and amendments (`02-domain/contracts.md`).

NOTE: For I-05, the payment releaser is a different person from every assigned reviewer who approved a line of the request, and from the finance approver (SoD-04). This satisfies R-EX-04, SoD-04 and the roles table at once (decided 2026-10-25).

## Milestone closure

COMPLETED needs every milestone closed and every payment request in a terminal state (`02-domain/state-machine.md` NOTE 12). M5 sets both rules (O-51). TODO(Daniel): confirm them in M5.

- PAID, REJECTED and WITHDRAWN end a request, so they are read as terminal until M5 decides.
- Whether CHECKS_FAILED and CHANGES_REQUESTED become terminal, for example when the grant ends, is part of O-51.
- A milestone can close without being fully paid, since P-67 releases unclaimed balances at grant end.

## Legal nature

Payment records, contract templates, messages and exports use the legal nature set by the funder's instrument (P-44). The platform holds no default terminology of its own. For SuperSAFE, the Annexe "donation" wording in section 5 should be aligned with the grant wording elsewhere (O-23).

## Rules for lines

- **I-58** For every milestone, paid plus pending never exceeds the milestone amount.
- **I-59** Every line references a milestone of the same grant in its effective contract version.
- **I-60** An approved line amount never exceeds the requested amount. A lower approval carries a recorded reason.
- **I-61** An amendment never sets a milestone amount below its paid plus pending amount.

## Evidence for partial claims (P-65)

Each programme chooses one of two options:

- **Public deliverables:** every line, partial or final, carries public deliverables under an accepted licence.
- **Progress report:** partial lines carry a progress report, and public deliverables are required on the line that brings the milestone to fully claimed.
- **I-62** The line that brings a milestone to fully claimed always carries public deliverables under a licence in P-26, whatever P-65 says.

NOTE: SuperSAFE uses public deliverables, which matches payment upon delivery in Annexe section 5 and keeps the I-15 record complete for repeat grants.

NOTE: Under the progress report option, a partial claim without public deliverables leaves the public deliverable record incomplete until the final claim on that milestone (decided 2026-10-25).

## Reallocation within a task (P-66)

A grantee can ask to move an amount from one milestone to another in the same task.

- An assigned reviewer approves or refuses, with a reason. The grantee cannot approve their own reallocation.
- **I-63** A reallocation never changes a task's total, never moves money between tasks, and never leaves a source milestone below its paid plus pending amount.
- Approved reallocations are recorded against the signed contract version. The effective plan is the signed contract plus approved reallocations, and balances follow the effective plan.
- A reallocation is not a contract amendment and needs no IRC review. Moves between tasks, and changes to the contract total, remain amendments (P-14).
- The contract template carries a clause permitting reallocation within a task, so the signed text covers it.
- Reallocations appear in the audit file per call.

## Unclaimed balances at grant end (P-67)

When a grant reaches COMPLETED or TERMINATED, each milestone's unclaimed balance is released.

- Under "return to FSTP budget", the balance returns to the action's FSTP budget and can fund later calls, within the action duration (I-46).
- Under "lapse", the balance is recorded as unspent and reported as such.
- **I-64** At grant closure, committed amounts for the grant drop to its paid total, so I-45 counts only what was actually paid.

NOTE: Returning balances to the FSTP budget keeps them within the FSTP cost category. Moving them to any other cost category normally needs an amendment of the grant agreement (AGA Article 5.5).
