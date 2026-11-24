# M10 hardening report

This report records the hardening milestone M10 of `SPEC/09-milestones.md`. It follows `SPEC/08-hardening/hardening-plan.md`. It is written as evidence for the CRA technical documentation.

## 1. Run record

| Item | Value |
| --- | --- |
| Model | Claude Mythos 5.2 (`claude-mythos-5-2`). The hardening plan names 5.1. 5.2 is the model actually used |
| Reviewers | One lead session and its review lanes, all on that model. Fix lanes ran on Claude Opus and were reviewed by the lead |
| Review dates | 2026-11-23 to 2026-11-24 |
| Commit reviewed | `268e5079a172a5ef6fe00cd7a8e0577b26415f68` on `main` (PR #63) |
| Commit after the fixes | `6c7fa592` on `main` |
| Decisions | Daniel Thompson-Yvetot decided every scope and design question named in this report |

## 2. Entry criteria

| Criterion | Evidence |
| --- | --- |
| M1 to M6 closed | `README.md`, status table |
| Threat model updated against the implemented system | TH-69 to TH-93 added, and each mapped to its activity in the hardening plan (PR #64, commit `5b94069b`) |
| Invariant, authorisation and privacy tests green | Full CI run 45157691201 on `ba993a36`, whose tree equals the tree of the reviewed commit. A second full run on the reviewed commit itself (45221593195) failed one end-to-end test of 483. Section 6 records its cause and fix. Daniel accepted run 45157691201 for this criterion on 2026-11-23 |

## 3. Method

- Each activity was reviewed by reading the code of the frozen commit against the threats the plan maps to it.
- Where a reviewer suspected a defect, it wrote a proof-of-concept test that fails on the frozen commit.
- Each finding got an identifier, a severity and a row in the findings register.
- A finding closes only when its fix and its regression test are merged and a full CI run is green.
- No fuzz campaign was part of the review. The fuzz targets run in CI as before.
- No test ran against a production host. No real personal data was used. Fixtures come from the synthetic corpus.

Severity scale used by the run:

| Severity | Meaning |
| --- | --- |
| Critical | An invariant breaks for an outside party without special access |
| High | An invariant breaks for a party with an ordinary role, or secret or personal data leaks |
| Medium | A defence layer fails but another holds |
| Low | A hardening gap |
| Info | A note |

## 4. Coverage

| Activity | Subject | Review |
| --- | --- | --- |
| H-01 | Authorisation bypass across roles, states and programmes | Done, two passes |
| H-02 | Cross-cell and control plane isolation | Done |
| H-03 | Assessor red-team | Done, two passes |
| H-04 | Pre-check oracle probing | Done |
| H-05 | In-house parsers and protocol implementations | Done in three passes, with the gap named below |
| H-06 | Payment flow tampering | Done |
| H-07 | Identity vault query surface and side channels | Done, two passes |
| H-08 | Reviewer de-anonymisation | Done |
| H-09 | Audit log integrity | Done |
| H-10 | Supply chain and build pipeline | Done |
| H-11 | Self-hosted default configuration, the operator tool and the demo-only flags | Done |
| H-12 | Messaging adapters and group membership | Not reviewed. The adapters are out of scope (B-03, B-05) |
| H-13 | Timeline engine and dispatcher abuse | Done |
| H-14 | Contract integrity, payment requests and bank detail paths | Done |
| H-15 | Qualified signature validation, trusted lists and PDF signatures | Done |
| H-16 | Update and licence services | Done |
| H-17 | White-label packages, brand logos, the funding card and the legal pages | Done |
| H-18 | Tier B crate versions | Done. See section 7 |
| H-19 | Hybrid constructions | Done |
| H-20 | Desktop client | Not reviewed. Deferred (B-04) |
| H-21 | Authentication, step-up, recovery and sessions | Done |
| H-22 | Key custody, rotation, shredding and database isolation | Done |
| H-23 | MCP server and client, and the Claude plugin path | Done |

Limits of the coverage:

- H-05: 18 of the 72 fuzz projects were not read as parsers. The largest unread part is `fstp-oauth` beyond its form and URL decoders. Daniel decided on 2026-11-23 not to add a fourth pass in M10.
- H-12 and H-20 wait until their subjects return to scope.
- The review read one frozen commit. Code merged later was reviewed only as part of the fixes in section 5.

## 5. Findings fixed in M10

The run found no critical finding. It found four high findings. All four are fixed, with the related findings Daniel placed in scope.

| Id | Activity | Severity | Finding | Fix | Regression tests |
| --- | --- | --- | --- | --- | --- |
| F-005 | H-07 | High | A team member could use the content read of the MCP server to make the vault mask answer for a verified teammate. The answer worked as an oracle for that person's names and birth date (TH-07, I-86, I-17) | The applicant-side content read through MCP no longer asks the vault mask. Draft reads there are refused | `m10_h07_i86_team_content_read_through_mcp_never_asks_the_vault_mask` |
| F-006 | H-07 | High | An applicant team without verified identities got no name mask before AI input (I-17, TH-13, TH-62) | The cell masks the display names it holds itself, as handles, before any AI input (ADR-033 as amended) | `m10_h07_i17_an_unverified_team_is_masked_by_cell_held_names` |
| F-017 | H-22 | High | Draft text in the workspace was sealed under a key that no erasure destroys, so it had no erase path (TH-30) | Each proposal's workspace has its own key, and erasure destroys it. Migration `0015_workspace_erasure.sql` (ADR-026, ADR-007) | `m10_f017_th30_an_erased_draft_text_has_no_live_key_at_any_crash_point` |
| F-039 | H-01 | High | The raw command route `POST /api/v1/commands` asked no step-up for high-risk operations. A stolen tenant admin session could grant itself tenant admin (TH-56, TH-05, I-78) | In production the route serves break-glass approval only. A wider route exists only under a test feature that cannot compile into a release build (ADR-026 D8 as amended) | `m10_f039_f040_raw_route_refuses_every_command_but_break_glass_approval`, `m10_f039_raw_route_stepup` |
| F-040 | H-01 | Medium | The same route skipped controls of the API core, such as the setup gate, reply validation and rate limits (TH-36, I-10) | Closed by the fix of F-039 | `m10_f039_f040_raw_route_refuses_every_command_but_break_glass_approval` |
| F-058 | H-01 | Low | A production unmask wrote its audit record and then failed, so the log listed unmasks that showed nothing (TH-07, ADR-023) | The unmask leaves no record when the vault page cannot open, and it runs through the API port | `m10_f058_i17_unmask_leaves_no_record_when_the_vault_page_cannot_open` |
| F-079 | H-07 | Medium | A lead could bind any account to a team without that person's consent. The refusal text showed whether the account was a reviewer, an admin or excluded (TH-07, TH-08, TH-03) | Team membership needs an invitation by email and the person's acceptance. The old binding commands are retired (ADR-038) | `m10_f079_th07_*`, `m10_f079_th08_the_lead_learns_nothing_about_the_invited_account`, `m10_f079_th07_raw_route_refuses_the_retired_team_binding_commands` |
| F-083 | H-05 | Low | The cell front decided on the raw request path while the router matched the percent-decoded path. An encoded spelling reached routes that the front treats differently (TH-26, R-PB-04) | One spelling: the front and the router decide on the same path | `m10_f083_one_spelling` |
| F-018 | H-22 | Medium | An old off-host key copy together with an old backup could open data that was erased later (TH-30, TH-59, I-81) | A guard key held by a required second custodian. Each erasure rotates the guard and destroys the old one, so an old copy no longer opens. The custodian receives a fresh guarded copy after each rotation. Production refuses copies made before the guard existed (ADR-004, ADR-012, ADR-028) | `m10_f018_*` in `crates/fstp-keyd/tests/guard.rs`, `adr028_guard_*` in `fstp-admin` |

Merges: F-005, F-006, F-017, F-039, F-040, F-058, F-079 and F-083 through PR #65 (`6b1c7f07`). F-018 through PR #66 (`6c7fa592`).

Changes of behaviour that follow from the fixes:

- A lead no longer adds a team member directly. The person receives an invitation and accepts it after sign-in.
- AI input can show team names as handles.
- Migration 15 deletes existing workspace draft rows. No production cell existed at the time.
- A production host needs a paired second custodian for its key custody. `fstp-admin pair-custodian` and `fstp-admin custodian` set it up, and `fstp-admin restore-keys` restores the keys after a host loss.

Limits of the F-018 fix as merged: `restore-keys`, the key release inside `restore` and the custodian copy fetch have not run end to end on a systemd host with real PostgreSQL. The timed retry of an owed copy has no test. The first pilot installation exercises both.

## 6. Test infrastructure faults found during the run

| Id | Fault | Outcome |
| --- | --- | --- |
| F-068 | The end-to-end test `speedrun_negotiation_to_paid_and_closed` failed once with an I-32 refusal (run 45221593195). The test acted once the request was under review, before the acceptance checks were recorded. The I-32 guard was right to refuse | The test waits for the acceptance checks, and the demo checks runner repeats its passes until no request waits. The fault was reproduced with an added delay and no longer occurs with the fix (PR #67, `8b5f0cbf`). The guard is unchanged |
| F-092 | The test `g12_vault_binary_answers_the_cell_binary` failed once in CI, with the production cell exiting before it was ready and printing no error. It passed in every later run | Not explained. The harness now prints the cell's error output (`93a7669b`). Daniel decided on 2026-11-23 to watch and record |

## 7. Tier B crate confirmations (H-18, I-74)

`der` 0.7.10, `spki` 0.7.3, `x509-cert` 0.2.5 and `cms` 0.2.3 are confirmed, with conditions C1 to C3. The record is `docs/hardening/m10-tier-b-review.md`, `deps/tier-b-confirmations.txt` and the release gate table of ADR-001 (PR #64, `526d2800`). moduletto 0.1.0 at `ded73e57` was confirmed on 2026-11-20, and its pin did not move.

Condition C1 binds later work. No path may carry outside bytes to `fstp-pki::cms` or `fstp-sigval` until the two bounded-work items of that review (F-014 and F-015) are closed with their regression tests. The production cell meets this today, because it refuses every signature. Both items close before a production signature port or trusted list lands.

## 8. Findings not fixed in M10

- No critical or high finding is open.
- Findings of medium severity and below that are not listed in section 5 remain open. Daniel decided on 2026-11-23 that M10 fixes the high findings and the related ones in section 5.
- The open findings, their proof-of-concept tests and the lane reports are held in a private register, not in this public repository. Each enters a later version of this report once its fix and regression test are merged.
- The injection samples that H-03 proposes for `corpus/injection-v1` are held with that register for the same reason. They enter the corpus with the fixes of their findings.
- The open findings are handled under the vulnerability handling process. No production deployment exists at the date of this report.

## 9. Exit criteria

| Criterion | State | Evidence |
| --- | --- | --- |
| No open critical or high findings | Met | Section 5 |
| Every Tier B crate version in the release has a recorded confirmation in ADR-001 (I-74) | Met | Section 7 |
| All regression tests merged and green | Met | Full CI run 45446562822 on `main` at `6c7fa592` |
| Hardening report available | Met | This document |

## 10. Requirements, invariants and threats covered by the fixes

- Invariants: I-10, I-17, I-32, I-74, I-78, I-80, I-81, I-86.
- Requirements: R-AC-01, R-PB-04.
- Threats: TH-03, TH-05, TH-07, TH-08, TH-13, TH-26, TH-30, TH-36, TH-56, TH-59, TH-62.
- ADRs written or amended: ADR-001, ADR-002, ADR-004, ADR-007, ADR-012, ADR-026, ADR-028, ADR-033, ADR-038.

## 11. Open questions

- Whether `fstp-admin backup-keys` should write the custody passphrases beside the key copies, to spare the operator typing them at `restore-keys`. Decided by Daniel on 2026-11-24: yes (ADR-028, record of lane `m10/guard-key`, part 3).
- The cause of F-092.
- When the remaining H-05 parsers, H-12 and H-20 are reviewed.
