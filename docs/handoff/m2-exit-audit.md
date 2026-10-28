# M2 exit audit (step W6, lane w6-audit)

Written on 2026-10-26 against branch `m2/w6-audit`, based on `0f7bfe9`, and updated in the W7 review on 2026-10-28. It checks the M2 exit checklist of `docs/handoff/m2-design.md` section 11. It covers I-01 to I-15, I-23, and I-34 to I-36, which `SPEC/09-milestones.md` NOTE 1 adds to the exit.

## Method

- Every test named in design section 11 was looked up by function name across `crates/`.
- Every fstp-mc model was run on the production backend with a temporary probe in `check_exhaustive`. The probe printed the stored state count and whether the run was exhaustive. The probe is removed.
- Each shared `max_states` constant now holds the production count. Where the reference twin stores fewer states, it runs under its own `*_REFERENCE_STATES` constant. `tripwire` doubles the constant, so every run stops at twice its own count (design 6.1).
- Every teeth test was read to confirm that it asserts a failure: `expect_violation`, `expect_prop_failure` or `expect_unreachable` on the target id.
- Test names and doc comments of the M2 crates were scanned for a requirement or invariant id.

All results below are local runs on an Apple M5 with 10 cores, macOS, PostgreSQL 16 from Homebrew. CI has not run this branch yet.

## Exit checklist

"Prod" and "ref" are the states stored by the production run and by the reference twin. Every listed model run is exhaustive.

| Invariant | Property and pure tests | Model checks (prod / ref states) | Teeth | Status |
| --- | --- | --- | --- | --- |
| I-01 | `i01_sod01_sod05_bindings_match_reference` | `i01_m_sod_p12_0` (1,370 / 1,300), `i01_m_sod_p12_1` (1,225 / 1,155), `i01_m_sod_p12_2` (1,174 / 1,104), `i01_m_sod_two_programmes` (713 / 713) | `i01_teeth_binding_inside_window_is_caught` | Green |
| I-02 | `i02_sod02_irc_member_holds_no_other_judging_role`, `i02_assignment_irc_member_holds_no_other_judging_assignment` | `i02_m_sod_irc_exclusive` (252 / 227) | `i02_teeth_irc_with_assignment_is_caught` | Green |
| I-03 | `i03_rcf02_conflicted_person_cannot_read_or_act`, `i03_p11_handles_never_repeat_across_proposals_and_calls` | `i03_m_conflict_truthful` (23,364 / 23,364), `i03_m_conflict_havoc` (16,724 / 16,724), `i03_m_conflict_two_proposals` (2,702 / 2,702), `i03_m_conflict_staged` (10,230 / 9,618) | `i03_teeth_read_after_conflict_is_caught` | Green |
| I-04 | `i04_sod06_excluded_account_holds_no_receiving_role` | `i04_m_excl` (470 / 470) | `i04_teeth_excluded_receiving_is_caught` | Green |
| I-05 | `i05_sod04_releaser_is_never_acceptor_or_approver`; compile-fail twins in `fstp-domain-testkit/src/reference/payment.rs` (4 pairs) | `i05_m_pay` (162 / 162) | `i05_teeth_releaser_equals_approver_is_caught` | Green |
| I-06 | `i06_sod09_verified_identity_never_spans_groups` | `i06_m_sod_sybil` (149,961 / 98,387), `i06_m_race_with_protocol` (19 / 19), `i06_m_race_without_protocol_reaches_violation` (12 / 12) | `i06_teeth_sybil_left_bound_is_caught`, `i06_teeth_conflict_suspension_counted_as_held_is_caught` | Green |
| I-07 | `i07_quorum_counts_valid_scores_once`, `i07_stage1_exit_requires_p03_valid_scores` | `i07_i08_m_life_s1` (6,766 / 5,698), `i07_i08_m_life_s1_weighted` (6,202 / 5,260) | `i07_teeth_superseded_score_counted_is_caught` (pure and model) | Green |
| I-08 | `i08_weighted_score_matches_exact_reference`, `i08_equality_is_not_a_pass`, `r_pc_01_weights_change_scores_for_discriminating_inputs` | `i07_i08_m_life_s1`, `i07_i08_m_life_s1_weighted` | `i08_teeth_ge_instead_of_gt_is_caught` (pure and model) | Green |
| I-09 | `i09_effective_score_follows_p24_and_names_one_plan` | `i09_m_life_s2` (34,824 / 25,870), `i09_m_life_s2_after_ranking_on_the_revised_plan` (192 / 192), `i09_m_life_s2_after_ranking_on_the_original_plan` (192 / 192) | `i09_teeth_effective_cleared_is_caught` | Green |
| I-10 | `i10_domain_crates_cannot_reach_findings`, `i10_findings_never_alter_core_state` | `i10_m_life_s1_findings` (27,064 / 22,792), the I-10 properties of M-LIFE-S1 | `i10_teeth_finding_driven_transition_is_caught`, `i10_teeth_core_decider_reading_findings_is_caught` | Green |
| I-11 | `i11_call_findings_share_pinned_config` | `i11_m_find` (110 / 74) | `i11_teeth_foreign_config_is_caught` | Green |
| I-12 | `i12_every_frozen_parameter_is_in_the_snapshot`, `i12_frozen_edits_leave_call_outcomes_unchanged` (twin machine) and its four witnesses in the same file | `i12_m_policy` (353, production only, equal to the hand count) | `i12_teeth_head_instead_of_snapshot_is_caught`, `i12_teeth_frozen_edit_changes_outcome_is_caught` | Green |
| I-13 | `i13_i14_grant_sequences_respect_range_and_cap` | `i13_i14_m_money` (594 / 840) | `i13_teeth_out_of_range_grant_is_caught` | Green |
| I-14 | `i13_i14_grant_sequences_respect_range_and_cap`, `i14_p05_edit_below_committed_is_refused` | `i13_i14_m_money`, `i14_m_race_reservation` (1,566 / 1,682) | `i14_teeth_grant_above_cap_is_caught`, `i14_teeth_reservation_race_is_caught` | Green |
| I-15 | `i15_repeat_grant_requires_public_deliverables`, `i15_amendment_requires_public_deliverables` | `i15_m_money_repeat` (234 / 256) | `i15_teeth_repeat_without_records_is_caught` | Green |
| I-23 | `i23_ledger_is_prefix_monotone_and_replays` (its scripted path now runs the amount, the grant facts, execution, an amendment, a payment and the termination), the ledger checks of the I-12 twin machine, `i23_verifier_flags_every_mutation` (`fstp-ledger`), `i23_store_api_has_no_mutation` as 11 compile-fail pairs in `fstp-ledger/src/twins.rs` | `i23_m_ledger` (1,422, production only, equal to the measured count) | `i23_teeth_changed_past_entry_is_caught` | Green |
| I-34, I-35 | `i34_i35_assignment_respects_orgs_and_proximity` (machine), plus four example tests in the same file; the W7 reproducers in `review_w7.rs` | none in the design | `i34_teeth_same_organisation_below_p39_is_caught`, `i35_teeth_reviewer_on_the_proximity_list_is_caught` | Green, per step, plus a re-check at the stage 1 close and the ranking (W7, Q-W6-4) |
| I-36 | `i36_former_reviewer_never_receives_in_call_under_evaluation`, `i36_former_reviewer_waits_until_every_reviewed_proposal_is_decided`, `i36_decision_closes_the_deferral_race`, `i36_deferred_proposal_bars_its_former_reviewer_in_the_next_call`, `i36_unreviewed_and_other_programme_calls_are_unaffected` | none in the design | `i36_teeth_current_call_only_check_is_caught`, `i36_teeth_race_under_the_current_call_check_is_caught` | Green |

Notes on the rows:

- `i23_store_api_has_no_mutation` exists only as the module doc of `fstp-ledger/src/twins.rs`. Rustdoc runs each pair under `cargo test -p fstp-ledger`. No test function carries the name.
- The I-05 twins live in the testkit, not in `fstp-domain`. They compile against the public `fstp_domain::payment` API, so they still prove the property.
- The I-34 and I-35 rows had no teeth test, which design 6.1 requires for every machine. This lane adds them.
- I-34 and I-35 are checked per step, on the records each step appends. `ReviewMachine::invariant` has no state-level check of either. The I-34 and I-35 teeth forge the `Assigned` record in the step output only, not in the system ledger or the model. So they prove that the per-step record check catches a forged assignment. They do not prove that a forged assignment held in the ledger is caught on replay. A ledger injection alone would add nothing today, since the run stops at the forged step.

## Tripwires

Each shared constant now holds the production count, and its tripwire is twice that count. Where the reference twin stores a different count, it runs under its own `*_REFERENCE_STATES` constant, with a tripwire at twice the reference count. Before fix round 1 the twins shared the production constant. They then stopped at up to three times their own count, so their growth did not fail visibly. "same" means the twin runs under the shared constant, because both backends store the same count.

| Constant | Before | Production | Production tripwire | Reference constant | Reference | Reference tripwire |
| --- | --- | --- | --- | --- | --- | --- |
| `M_SOD_I01_P12_0_STATES` | 1,300 | 1,370 | 2,740 | `M_SOD_I01_P12_0_REFERENCE_STATES` | 1,300 | 2,600 |
| `M_SOD_I01_P12_1_STATES` | 1,155 | 1,225 | 2,450 | `M_SOD_I01_P12_1_REFERENCE_STATES` | 1,155 | 2,310 |
| `M_SOD_I01_P12_2_STATES` | 1,104 | 1,174 | 2,348 | `M_SOD_I01_P12_2_REFERENCE_STATES` | 1,104 | 2,208 |
| `M_SOD_TWO_PROGRAMMES_STATES` | 713 | 713 | 1,426 | same | 713 | 1,426 |
| `M_SOD_I02_STATES` | 227 | 252 | 504 | `M_SOD_I02_REFERENCE_STATES` | 227 | 454 |
| `M_SOD_I06_STATES` | 98,387 | 149,961 | 299,922 | `M_SOD_I06_REFERENCE_STATES` | 98,387 | 196,774 |
| `M_CONFLICT_TRUTHFUL_STATES` | 23,364 | 23,364 | 46,728 | same | 23,364 | 46,728 |
| `M_CONFLICT_HAVOC_STATES` | 16,724 | 16,724 | 33,448 | same | 16,724 | 33,448 |
| `M_CONFLICT_TWO_PROPOSAL_STATES` | 2,702 | 2,702 | 5,404 | same | 2,702 | 5,404 |
| `M_CONFLICT_STAGED_STATES` | 10,230 | 10,230 | 20,460 | `M_CONFLICT_STAGED_REFERENCE_STATES` | 9,618 | 19,236 |
| `M_EXCL_STATES` | 470 | 470 | 940 | same | 470 | 940 |
| `M_PAY_STATES` | 162 | 162 | 324 | same | 162 | 324 |
| `M_RACE_PROTOCOL_STATES` | 19 | 19 | 38 | same | 19 | 38 |
| `M_RACE_NO_PROTOCOL_STATES` | 12 | 12 | 24 | same | 12 | 24 |
| `M_LIFE_S1_EVEN_STATES` | 5,698 | 6,766 | 13,532 | `M_LIFE_S1_EVEN_REFERENCE_STATES` | 5,698 | 11,396 |
| `M_LIFE_S1_WEIGHTED_STATES` | 5,260 | 6,202 | 12,404 | `M_LIFE_S1_WEIGHTED_REFERENCE_STATES` | 5,260 | 10,520 |
| `M_LIFE_S2_STATES` | 19,220 | 34,824 | 69,648 | `M_LIFE_S2_REFERENCE_STATES` | 25,870 | 51,740 |
| `M_LIFE_S2_AFTER_STATES` | 192 | 192 | 384 | same | 192 | 384 |
| `M_LIFE_S1_FINDINGS_STATES` | 22,792 | 27,064 | 54,128 | `M_LIFE_S1_FINDINGS_REFERENCE_STATES` | 22,792 | 45,584 |
| `M_FIND_STATES` | 74 | 110 | 220 | `M_FIND_REFERENCE_STATES` | 74 | 148 |
| `M_POLICY_STATES` | 353 | 353 | 706 | none | none | none |
| `M_LEDGER_STATES` | 1,422 | 1,422 | 2,844 | none | none | none |
| `M_MONEY_STATES` | 864 | 594 | 1,188 | `M_MONEY_REFERENCE_STATES` | 840 | 1,680 |
| `M_RACE_RESERVATION_STATES` | 1,682 | 1,566 | 3,132 | `M_RACE_RESERVATION_REFERENCE_STATES` | 1,682 | 3,364 |
| `M_MONEY_REPEAT_STATES` | 256 | 234 | 468 | `M_MONEY_REPEAT_REFERENCE_STATES` | 256 | 512 |
| `M_AFTER_STATES` | 203 | 111 | 222 | `M_AFTER_REFERENCE_STATES` | 203 | 406 |
| `M_LIFECYCLE_STATES` | 4,734 | 4,287 | 8,574 | `M_LIFECYCLE_REFERENCE_STATES` | 4,022 | 8,044 |

`M_LIFECYCLE_REFERENCE_STATES` serves the five M-LIFECYCLE reference twins: `lifecycle_states_reachable_up_to_negotiation_reference`, `lifecycle_m_lifecycle_terminal_states_have_no_exit_reference`, `r_ev_01_ineligible_has_no_successor_reference`, `r_ev_07_stage2_deferral_needs_no_future_call_reference` and `r_ir_02_concern_defers_or_declines_reference`. The old constant of 4,476 no longer matched the reference, which stores 4,488 on this base.

The teeth runs keep their multiples of the shared constant (two, four or eight times). They stop once the target verdict is decided, so their bound is a search budget, not a tripwire.

Every count above was measured again after fix round 1. The reference-mode call approval fix below left every count unchanged.

The W7 review measured every model again with the same probe. M-LIFE-S2 and M-LIFECYCLE changed, since I-34 is now checked again at the stage 1 close and the ranking. M-LIFE-S2 also gained a spare reviewer after a release, so its O-50 witness stays reachable. M-RACE reservation, the I-15 repeat model and the after-negotiation model had kept their old counts after the NOTE 9 decline change. Their production runs store fewer states than the references, as M-MONEY does, so each twin now runs under its own `*_REFERENCE_STATES` constant. `review_w7_money_tripwires.rs` asserts the stored counts of those three models on both backends. Every other count was unchanged.

No bound was relaxed to pass a test. Every production run was already exhaustive under the old bound. The largest ratio is 1.52 for M-SOD I-06, which stayed under the old tripwire of twice the reference count.

`review_w6audit_reference_tripwires.rs` checks the M-FIND and M-SOD I-02 twins: each must run under a tripwire of at most twice the count it stores.

### Why production stores more states

In production mode a model state holds the production projection beside the reference views. In reference mode the projection stays at genesis. Two command orders can reach the same reference views but different production projections.

The money models are the exception: M-MONEY, M-RACE reservation, the I-15 repeat model and the after-negotiation model store fewer states on production. The money reference leaves some grant-fact steps `Either`, and in reference mode the model takes such a step as accepted. Production refuses some of them, so its run has no successor there. This reason is read from the M-MONEY constant doc and was not probed state by state.

A temporary probe explored the models on both backends. It then set the backend field to production and removed the production projection, and the finding store where one exists, from every state. The first seven rows were measured after fix round 1. Fix round 2 added the last five.

| Model | Production | Reference | Production with the projection removed | Sets equal |
| --- | --- | --- | --- | --- |
| M-SOD I-06 | 149,961 | 98,387 | 98,387 | yes |
| M-LIFE-S1 (1, 1) | 6,766 | 5,698 | 5,698 | yes |
| M-LIFE-S1 (3, 1) | 6,202 | 5,260 | 5,260 | yes |
| M-LIFE-S1 with findings | 27,064 | 22,792 | 22,792 | yes |
| M-LIFE-S2 | 19,220 | 14,722 | 14,722 | yes (W6 counts, not measured again in W7) |
| M-FIND | 110 | 74 | 74 | yes |
| M-LIFECYCLE | 4,734 | 4,488 | 4,488 | yes (W6 counts, not measured again in W7) |
| M-SOD I-01 (P-12 = 0) | 1,370 | 1,300 | 1,300 | yes |
| M-SOD I-01 (P-12 = 1) | 1,225 | 1,155 | 1,155 | yes |
| M-SOD I-01 (P-12 = 2) | 1,174 | 1,104 | 1,104 | yes |
| M-SOD I-02 | 252 | 227 | 227 | yes |
| M-CONFLICT staged | 10,230 | 9,618 | 7,884 | no, a strict subset |

Before fix round 1 the life model sets differed although their counts matched. The cause was `world.life.decisions`, the decision ids of the lifecycle reference. Production held the setup's call-approval decisions, and the references did not. In reference mode the setup builder took `ApproveCallPublication` as accepted with no records. Production emits `CallApproved`, whose decision id the lifecycle reference folds. The builder now emits the same `CallApproved` record, as `reference::policy` already expected. `review_w6audit_reference_call_approval.rs` holds the reproducers. No verdict changed: no current model reuses a setup decision id.

So for the eleven models whose sets are equal, production refines the reference states by its projection only.

M-CONFLICT staged is the exception. With the projection removed, its 7,884 production states are a strict subset of the 9,618 reference states. Every path into the 1,734 reference-only states enters through a `Read` that the review reference leaves unjudged. In reference mode the model takes an unjudged step as accepted (`ReviewWorld::synthesize`). Production refuses each of these reads, so the production run has no successor there.

The probe checked every reference edge from a shared state into a reference-only state. There are 3,940 such edges, all `Read` steps, and production refuses every one. Of these, 2,504 are coordinator reads in STAGE1 or STAGE2. The instance runs under P-10 "assigned reviewers only". `policy-parameters.md` NOTE 1 gives the coordinator stage reads only under "operator staff only". The other 1,436 are reads in RANKED, by the coordinator or a committee member. The module doc of `reference::review` names both cases M4 visibility and unjudged. No verdict depends on them, since an unjudged step passes either way.

The production count is still the larger one. Its 10,230 states collapse to 7,884 once the projection is removed. So 2,346 production states differ from another production state in the projection alone.

The `two-way` property passes in every state of every run. So production and the references agree on every decision the references judge.

## Test identifiers

The scan covered every `#[test]` function in the six M2 crates. A test counted as identified when its name or the doc comment above it held a spec id. Ids include I-, R-, SoD-, P-, O-, TH-, T-, NOTE n, Q-n and ADR ids.

Fixed in this lane:

- `r_ng_grant_completing_fact_is_retried_after_verification`: SoD-09, NOTE 9.
- `r_ng_grant_preconditions_seam_matches_the_completing_fact`: R-NG-03, SoD-09.
- `r_ng_grant_completes_on_the_acceptance`, `r_ng_grant_completes_on_the_approval`, `r_ng_grant_completes_on_the_contract_fact`: I-13.
- `r_ng_grant_stories_pass_on_the_reference`: I-13, SoD-09, NOTE 9.

The `r_ng_grant_*` tests verify the state-machine row NEGOTIATION to GRANTED and the contract EFFECTIVE fact (design 3.2, `contracts.md` States). That row has no requirement id of its own (Q-W6-2). Fix round 1 removed R-NG-04 from these six doc comments. R-NG-04 covers the contract contents and the decline before signature, which these tests do not check. Each test now cites the guard ids it asserts.
- `r_ex_terminate_from_in_execution_by_programme_manager`, `r_ex_terminate_stories_pass_on_the_reference`: Q18.
- `lifecycle_states_reachable_up_to_negotiation_reference`: R-AU-01.
- `lifecycle_after_negotiation_states_reachable_reference`: R-AU-01, I-64.

Left without an id, because they verify no requirement or invariant:

- Harness self-tests: `harness_*.rs`, `testkit_smoke.rs`, `review_harness.rs`, and the codec generator self-tests in `codec_round_trip.rs`.
- Interface and driver mechanics: `interface_*` in `fstp-domain`, `driver_*` in `fstp-engine`.
- Spec table checks: `spec_rule_refs_exist`, `spec_transitions_match_state_machine`.
- Review regressions that cite only a design section, such as `review_finding_entry_raises_the_time_floor` and the `review_api_sufficiency.rs` tests.

The ledger time floor in `review_findings.rs` and `review_w5_find.rs` is a design 2.2 rule with no spec id. Daniel may want to give it one.

## Timing

All test runs reused built test binaries. Building every test target from a warm cache took 46.6 s wall and 273 s of CPU. A cold build of every workspace test target (`cargo test --workspace --locked --no-run`, empty target directory) took 73.6 s wall and 417.5 s of CPU (338.6 s user, 78.9 s system). The CI job's release build of the `fstp-tls` test took 32.4 s wall and 91.4 s of CPU, cold.

| Run | Wall | User CPU | System CPU |
| --- | --- | --- | --- |
| `cargo test --workspace --locked --offline` | 402.6 s | 491.1 s | 42.8 s |
| The M2 gate (`-p fstp-domain -p fstp-domain-testkit -p fstp-engine -p fstp-findings -p fstp-ledger -p fstp-money`) | 375.7 s | 534.5 s | 65.9 s |

The ten slowest test binaries of the workspace run, by the time each reported:

| Binary | Time |
| --- | --- |
| `i07_i08_m_life_s1` | 51.5 s |
| `i06_teeth_conflict_suspension_counted_as_held_is_caught` | 41.6 s |
| `i06_m_sod_sybil` | 30.9 s |
| `i06_teeth_sybil_left_bound_is_caught` | 26.8 s |
| `i03_m_conflict` | 25.8 s |
| `i09_m_life_s2` | 24.0 s |
| `review_w5ledger_strength` | 7.4 s |
| `i23_ledger_is_prefix_monotone_and_replays` | 7.3 s |
| `r_ev_07_stage2_deferral_needs_no_future_call` | 3.6 s |
| `wire` (`fstp-pgwire`) | 3.4 s |

The slowest single model runs, timed inside the parallel run:

| Test | Time |
| --- | --- |
| `i10_m_life_s1_findings` | 48.3 s |
| `i10_m_life_s1_findings_reference` | 25.9 s |
| `i06_m_sod_sybil` | 25.2 s |
| `i03_m_conflict_truthful` | 23.7 s |
| `i09_m_life_s2` | 23.4 s |
| `i03_m_conflict_havoc` | 19.9 s |

The binary times add up to 282 s. The rest of the wall time is doctest compilation and process start for about 260 binaries.

### CI risk

The test job runs `cargo test --workspace --locked` on `ubuntu-24.04` with a 60-minute timeout. Cargo runs test binaries one after another. So the wall time is the sum of the binaries, each bounded by its slowest test.

The CI job builds from an empty target directory, since it keeps no cache. The estimate below assumes each CI core runs at half the speed of a local core. That ratio is an assumption, since CI has not run this branch yet.

- Tests: the local sequential wall time of 402.6 s, scaled by the per-core speed ratio, gives about 805 s, or 13.4 minutes. Fewer cores than locally can serialise tests inside one binary. A full serialisation is bounded by the 533.9 s of test CPU, doubled: 1,068 s, or 17.8 minutes.
- Build: the cold-build CPU time, doubled and spread over the runner's cores. That gives 417.5 s times 2 over 4 cores, about 3.5 minutes, or over 2 cores about 7 minutes. The release `fstp-tls` build adds 91.4 s times 2 over the cores: under 1.5 minutes on 2 cores.

On a 2-core runner the worst case is about 17.8 + 7 + 1.5, or 26.3 minutes, before checkout and the PostgreSQL install. On a 4-core runner the expected case is about 13.4 + 3.5 + 0.8, or 17.7 minutes. Both are well under the 60-minute timeout, so the job is not at risk today.

Proposals, none applied:

- `i10_m_life_s1_findings` dominates the slowest binary. Its two finding offers multiply the M-LIFE-S1 space. It could become two instances, one per offer, each with its own tripwire. Splitting it into its own file alone saves nothing, since binaries run in sequence.
- The two I-06 teeth tests explore the whole mutant space without `stop_when_decided(true)`. Stopping once the I-06 verdict is decided would likely shorten them. That needs a check that their other assertions still hold.
- If the job ever nears its limit, M-SOD I-06 can be split by the merge action: with and without the identity merge of c.

## Open questions

- Q-W6-1, answered in fix round 1: the field was `world.life.decisions`. The reference-mode setup emitted no `CallApproved` record, so the lifecycle reference lacked the setup's call-approval decisions. The builder now emits it. Every life model state set now equals production with the projection removed.
- Q-W6-2: two rules that tests verify have no spec id. One is the ledger time floor of design 2.2. The other is the state-machine row NEGOTIATION to GRANTED, completed by the last of acceptance, approval and the contract EFFECTIVE fact (design 3.2, `contracts.md` States). Should either get one?
- Q-W6-3, closed in W7: `i12_frozen_edits_leave_call_outcomes_unchanged` landed with the W6 twin lane, and I-12 is green.
- Q-W6-4: should `ReviewMachine::invariant` gain a state-level I-34 and I-35 check over the system ledger? The teeth would then also forge the record in the ledger, so a forged assignment held there would be caught on replay. Today both invariants are checked per step on appended records. Since W7, the stage 1 close and the ranking also re-check I-34 over the active reviewers.
