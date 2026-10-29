# M2 exit audit (step W6, lane w6-audit)

Written on 2026-10-26 against branch `m2/w6-audit`, based on `0f7bfe9`. It was updated in the W7 review on 2026-10-28, and again in the W7 close-out and its fix rounds 1 and 2 on branch `m2/w7-fix` the same day. Close-out round 2 updated it for Daniel's answers of 2026-10-28. It checks the M2 exit checklist of `docs/handoff/m2-design.md` section 11. It covers I-01 to I-15, I-23, and I-34 to I-36, which `SPEC/09-milestones.md` NOTE 1 adds to the exit.

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
| I-01 | `i01_sod01_sod05_bindings_match_reference`; scheduled ends (W7 close-out and fix round 1): the 16 tests of `i01_sod05_scheduled_role_ends.rs`, the 3 of `i01_end_scheduled_role_is_the_systems_at_the_instant.rs`, the 2 of `i01_scheduled_end_codec_round_trips.rs`, and the reproducers of `review_w7fid_scheduled_end.rs` and `review_w7rev_scheduled_and_sod10.rs` | `i01_m_sod_p12_0` (1,370 / 1,300), `i01_m_sod_p12_1` (1,225 / 1,155), `i01_m_sod_p12_2` (1,174 / 1,104), `i01_m_sod_two_programmes` (713 / 713), `i01_m_sod_scheduled_end` (12,468 / 11,829) | `i01_teeth_binding_inside_window_is_caught`, `i01_teeth_grant_inside_the_scheduled_end_window_is_caught` | Green |
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
| I-13 | `i13_i14_grant_sequences_respect_range_and_cap`; no amount lock (W7 close-out): `r_ng_03_new_amount_supersedes_acceptance_and_approval.rs`, `r_ng_decline_after_acceptance_and_approval_reads_the_p04_minimum` and its twin, `review_w7_decline_after_acceptance_reads_the_p04_minimum`, `review_m_money_reaches_a_determination_after_acceptance`; close-out round 2 (Q-W7-7, Q-W7-4): the 5 tests of `review_w7fix_stale_acceptance.rs`, the 8 of `review_w7fix_contract_cleared.rs`, `review_w7fixrev_stale_contract_fact_after_new_amount_is_refused`, `r_ng_03_production_names_the_current_determination`, and the 6 of `codec_grant_facts_name_their_determination.rs` (`fstp-domain`, TH-26) | `i13_i14_m_money` (32,310 / 35,544), `lifecycle_all_sixteen_states_reachable` (21,711, production only) | `i13_teeth_out_of_range_grant_is_caught` | Green |
| I-14 | `i13_i14_grant_sequences_respect_range_and_cap`, `i14_p05_edit_below_committed_is_refused`, the release before the reservation in `r_ng_03_new_amount_after_acceptance_and_approval_supersedes_the_old_one` | `i13_i14_m_money`, `i14_m_race_reservation` (1,566 / 1,682) | `i14_teeth_grant_above_cap_is_caught`, `i14_teeth_reservation_race_is_caught` | Green |
| I-15 | `i15_repeat_grant_requires_public_deliverables`, `i15_amendment_requires_public_deliverables` | `i15_m_money_repeat` (234 / 256) | `i15_teeth_repeat_without_records_is_caught` | Green |
| I-23 | `i23_ledger_is_prefix_monotone_and_replays` (its scripted path now runs the amount, the grant facts, execution, an amendment, a payment and the termination), the ledger checks of the I-12 twin machine, `i23_verifier_flags_every_mutation` (`fstp-ledger`), `i23_store_api_has_no_mutation` as 11 compile-fail pairs in `fstp-ledger/src/twins.rs` | `i23_m_ledger` (1,422, production only, equal to the measured count) | `i23_teeth_changed_past_entry_is_caught` | Green |
| I-34, I-35 | `i34_i35_assignment_respects_orgs_and_proximity` (machine), plus four example tests in the same file; the W7 reproducers in `review_w7.rs` and `review_w7check.rs`; W7 close-out: `i34_assignment_order_no_longer_matters.rs`, `i34_amount_determination_needs_p39_organisations.rs`, `i34_sod10_one_organisation_per_reviewer_per_programme.rs`; fix round 1: `review_w7fid_determination_dead_end.rs`, the SoD-10 reinstatement reproducer of `review_w7rev_scheduled_and_sod10.rs`; fix round 2: `review_w7v2_sod10_switch.rs` | none in the design | `i34_teeth_same_organisation_below_p39_is_caught`, `i34_teeth_assignment_out_of_reach_is_caught`, `sod10_teeth_two_organisations_of_one_reviewer_are_caught`, `i35_teeth_reviewer_on_the_proximity_list_is_caught` | Green. I-34 holds at admission, the stage 1 close, the ranking and the amount determination. An `Assign` is refused only once P-39 organisations are out of reach (W7 close-out, Q-W6-4). A reviewer assignment is open in NEGOTIATION too (fix round 1, Q-W7-6) |
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
| `M_MONEY_STATES` | 20,304 | 32,310 | 64,620 | `M_MONEY_REFERENCE_STATES` | 35,544 | 71,088 |
| `M_RACE_RESERVATION_STATES` | 1,682 | 1,566 | 3,132 | `M_RACE_RESERVATION_REFERENCE_STATES` | 1,682 | 3,364 |
| `M_MONEY_REPEAT_STATES` | 256 | 234 | 468 | `M_MONEY_REPEAT_REFERENCE_STATES` | 256 | 512 |
| `M_AFTER_STATES` | 203 | 111 | 222 | `M_AFTER_REFERENCE_STATES` | 203 | 406 |
| `M_LIFECYCLE_STATES` | 4,734 | 4,287 | 8,574 | `M_LIFECYCLE_REFERENCE_STATES` | 4,022 | 8,044 |
| `M_CONFORMANCE_STATES` | 19,929 | 21,711 | 43,422 | none | none | none |
| `M_CONFORMANCE_NO_WITHDRAW_STATES` | 14,470 | 15,658 | 31,316 | none | none | none |
| `M_SOD_SCHEDULED_STATES` | 1,511 | 12,468 | 24,936 | `M_SOD_SCHEDULED_REFERENCE_STATES` | 11,829 | 23,658 |

`M_LIFECYCLE_REFERENCE_STATES` serves the five M-LIFECYCLE reference twins: `lifecycle_states_reachable_up_to_negotiation_reference`, `lifecycle_m_lifecycle_terminal_states_have_no_exit_reference`, `r_ev_01_ineligible_has_no_successor_reference`, `r_ev_07_stage2_deferral_needs_no_future_call_reference` and `r_ir_02_concern_defers_or_declines_reference`. The old constant of 4,476 no longer matched the reference, which stores 4,488 on this base.

The teeth runs keep their multiples of the shared constant (two, four or eight times). They stop once the target verdict is decided, so their bound is a search budget, not a tripwire.

Every count above was measured again after fix round 1. The reference-mode call approval fix below left every count unchanged.

The W7 review measured every model again with the same probe. M-LIFE-S2 and M-LIFECYCLE changed, since I-34 is now checked again at the stage 1 close and the ranking. M-LIFE-S2 also gained a spare reviewer after a release, so its O-50 witness stays reachable. M-RACE reservation, the I-15 repeat model and the after-negotiation model had kept their old counts after the NOTE 9 decline change. Their production runs store fewer states than the references, as M-MONEY does, so each twin now runs under its own `*_REFERENCE_STATES` constant. `review_w7_money_tripwires.rs` asserts the stored counts of those three models on both backends. Every other count was unchanged.

The W7 close-out measured every model again with the same probe, on both backends, and removed the probe. Two constants changed and two are new. Every other count was unchanged.

- `M_CONFORMANCE_STATES` and `M_CONFORMANCE_NO_WITHDRAW_STATES` grew. The amount is never locked now, so a new determination is open after acceptance and approval (NOTE 9, decided 2026-10-28). A new amount clears both, so an unbounded `Determine` would cycle with fresh decision ids. M-CONFORMANCE now draws it after acceptance or approval only while fewer than two exist, as M-MONEY does. Before acceptance and approval it is drawn as before, so the old space is kept. The no-withdraw count serves `stalls`, which is not a `check_exhaustive` run.
- `M_SOD_SCHEDULED_STATES` and its reference constant are new. The test author set a provisional 20,000. Each now holds its measured count.
- `M_CONFLICT_TWO_PROPOSAL_STATES` keeps 2,702 on both backends after its setup change, which keeps R2 of O2 as an unassigned committee member.

W7 fix round 1 measured every model again with the same probe, on both backends, and removed the probe. Two pairs of constants changed. Every other stored count equals its constant. In the table above, the "Before" column of these two rows holds the W7 close-out count.

- `M_MONEY_STATES` and `M_MONEY_REFERENCE_STATES` grew from 594 and 840 to 20,304 and 22,332. M-MONEY now offers the grant facts one by one as well as the composite grant. So a new amount reaches a NEGOTIATION that holds a given acceptance or approval, and a ghost flag marks the step that superseded it (NOTE 9, decided 2026-10-28). Before, the three facts went together and no such state was reached.
- `M_SOD_SCHEDULED_STATES` and its reference constant grew from 1,511 and 1,451 to 12,468 and 11,829. The instance now has two instants, the bring-forward and the refused move later. Time moves as a step of its own, apart from the System end, so every step between an instant and its System end is checked.

In the debug test run, `i13_i14_m_money` now takes 83.5 s for both twins, and `review_w7rev_m_money_redetermine` takes 77.0 s. They are the two slowest binaries of the workspace now, so the CI estimate under Timing grows by about 5 minutes on 2 cores. It stays well under the 60-minute timeout. The Timing tables below predate this round. No bound was relaxed: both instances were made larger on purpose, and each constant holds the measured count.

No bound was relaxed to pass a test. Every production run was already exhaustive under the old bound, with one exception in the W7 close-out. M-CONFORMANCE was not exhaustive under twice 11,019 once the lock was gone. It became finite again only through the `Determine` bound above, and its constant was then set to the measured count. The largest ratio is 1.52 for M-SOD I-06, which stayed under the old tripwire of twice the reference count.

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

## W7 close-out (branch `m2/w7-fix`)

Five items, each decided in the spec on 2026-10-25 or 2026-10-28.

- No amount lock (NOTE 9, R-NG-03). `DetermineAmount` stays open in NEGOTIATION after acceptance and approval. The new amount supersedes the old one, and its fold clears the acceptance, the approval and the approver. The batch releases the old reservation before it reserves the new amount. The decline reads the P-04 minimum against the room under P-05 at every point of NEGOTIATION.
- One organisation per reviewer per programme (SoD-10). A committee member grant is refused when the account holds a committee binding in the programme that records another organisation. Every held binding counts, an ordinarily suspended one too. Fix round 1 counted only the bindings active beside the new one. Fix round 2 went back to every held binding, whatever its period.
- I-34 at the amount determination. `DetermineAmount` is refused while the active reviewer assignees of the current call span fewer than P-39 organisations.
- Scheduled role ends (Cooling-off NOTE). `GrantRole` carries an optional `end`, after `start`. `EndRole` at a later instant records `BindingEndScheduled`, or brings a scheduled end forward. Moving it later, scheduling the same instant again, or an instant before now is refused. `EndRole` at now ends the binding at once. The System command `EndScheduledRole`, which `due` lists from the instant on, records `BindingEnded` at the scheduled instant. A committee binding's assignments are released in that batch as for any end.
- Low items. The assign-time I-34 check refuses only once P-39 organisations are out of reach, counting the proposal's reviewers, the new one and every other active committee member of the programme. The layering gate rejects any third-party crate as a normal or build dependency of the five M2 production crates (`layering-third-party`). It keeps the named I/O roots, since that rule also covers dev edges. The production source scan catches grouped `use` items over several lines and `std::time::Instant`.

Tests updated because they encoded a reading Daniel overturned on 2026-10-28:

- `review_i34_committee_organisation_reaches_assign` (`review_w4rev_spec.rs`) expected a second O1 reviewer to be refused below P-39. It now assigns R1 and R2 of O1 while O2 and O3 are in reach, and expects a refusal under I-34 once both have ended.
- `review_i02_assignment_bar_is_per_programme` (`review_w4rev.rs`) had one committee member, of O1, so P-39 = 2 was out of reach at its first assignment. Its setup now adds R2 of O2. Its I-02 assertions are unchanged.

Other test-side changes of the implementer:

- `interface_no_command_kind_reaches_not_implemented.rs` covers the new kind `EndScheduledRole` in a roles world, since the money world's review references treat every `EndRole` as an end at once.
- `fstp-domain` codec tests: the generators of `codec_support/mod.rs`, the samples of `interface_stubs.rs` and two round-trip cases in `codec_round_trip.rs` cover the new command, record and member.
- Three testkit literals and one pattern gained `end` (`gen/roster.rs`, `gen/policy.rs`, `reference/sod.rs`).
- `mc/conformance.rs` bounds `Determine` after acceptance or approval, as described under Tripwires.
- A fuzz seed `command_decode/end_scheduled_role` was added.
- New file `i01_end_scheduled_role_is_the_systems_at_the_instant.rs`: a tenant admin cannot issue `EndScheduledRole` (I-84), the System cannot issue it before the instant, and a binding without a scheduled end has none to record.

## W7 fix round 1 (branch `m2/w7-fix`)

The independent review reported 17 findings, 10 of them with a reproducer. Each reproducer failed before its fix and passes now.

- Scheduled ends after the instant (Cooling-off NOTE). From a scheduled instant until the System records the end, the engine refuses every command but `EndScheduledRole` and `VaultChanged` under SoD-05 (`roles::end_overdue`, shared check 1 of `engine.rs`). So no decision reads the binding as held after its instant. No call is published and no P-12 is edited in between, so the System end pins the calls and the P-12 of the instant. An `EndRole` at now can no longer move an overdue end later. `VaultChanged` stays open, since every command first processes a newer vault epoch, the System end included. A reaction only voids and suspends. This is a reading for Daniel (Q-W7-2).
- A scheduled end at or before the binding's start is refused, as at the grant.
- SoD-10 counts only committee bindings active beside the new one: from its start to its scheduled end, if any. Fix round 2 overturned this reading, see below. The reinstatement of a suspended committee binding is refused under SoD-10 when another committee binding of the account, active beside it, records another organisation. The references and `check_one_organisation` follow both.
- The I-34 refusal at the amount determination no longer leaves NEGOTIATION without a way forward. A reviewer assignment is open in NEGOTIATION, so the coordinator can restore P-39 organisations (R-CF-02, R-NG-03). This is a reading for Daniel (Q-W7-6).
- In reference mode, `SodWorld::exec` now returns a refusal that names the rule the reference gives, through `reference::sod::rule_of`. So the two reference twins of Q-W7-1 pass with their assertions unchanged.
- M-MONEY reaches a new amount that supersedes a given acceptance or approval, with a NOTE 9 witness. M-SOD with scheduled ends gained a second instant, the bring-forward, a time step apart from the System end, `transition("Cooling-off window")`, two witnesses and a teeth test.
- The third-party layering rule treats every package that is not a workspace member as third-party, a vendored path crate too.

New tests of this round: `i01_scheduled_end_window_admits_only_the_system_end` and its twin, `i01_scheduled_end_at_or_before_the_start_is_refused`, `sod10_another_organisation_after_a_scheduled_end_is_accepted`, `sod10_reinstatement_beside_another_organisation_is_refused`, `i34_reviewer_assigned_in_negotiation_restores_p39_organisations` and its twin, `i01_teeth_grant_inside_the_scheduled_end_window_is_caught` and its twin, and `review_w7_vendored_path_crate_outside_the_workspace_is_rejected` in `tools/deps-check`.

Not changed in this round, for Daniel: a contract fact recorded before a new amount (Q-W7-4), and an `AcceptGrant` or `ApproveGrant` composed against a superseded amount (Q-W7-7). Both were changed in close-out round 2, below.

## W7 fix round 2 (branch `m2/w7-fix`)

The review reported two findings, one with a reproducer. The reproducer failed before its fix and passes now.

- SoD-10 and I-35 across a scheduled end (`review_w7v2_sod10_switch.rs`). Under the round 1 overlap reading, an O1 committee binding could be granted to start at the scheduled end of the account's O2 binding. At the System end, `binding_releases` kept the reviewer's assignments, since the account still held a committee binding. The reviewer then served under O1, which no I-35 check had seen. The fix takes the literal SPEC reading (`roles-and-sod.md`, Reviewer assignment NOTE: "one organisation per programme"; "a different organisation from the account's active committee binding"). A committee member grant, or a reinstatement, is refused when any held committee binding of the account in the programme records another organisation, whatever its period. A binding with an end scheduled but not yet recorded is held and active, so it counts. `roles::commands::other_organisation`, `reference::sod::other_organisation` and `reference::review::check_one_organisation` drop the period test. So every held committee binding of an account in a programme records one organisation, and the organisation of a kept assignment never changes. Option (b) of the finding, a release rule that reads the organisation at the end instant, is not needed under this reading.
- The production source scan (`review_w7_production_sources.rs`) now strips any visibility before it tests for `use ` or `mod `: `pub`, and `pub(...)` with a balanced path inside, such as `pub(super)` or `pub(in crate::x)`. So a grouped import over several lines behind such a visibility is joined and caught. `IO_MODULES` gained `io`, since the five crates name no `std::io` today. The new test `review_w7_production_scan_catches_imports_behind_any_visibility` failed before the change.

Test updated because it encoded the round 1 reading that this round overturned:

- `sod10_another_organisation_after_a_scheduled_end_is_accepted` (`i34_sod10_one_organisation_per_reviewer_per_programme.rs`) accepted an O2 binding from the scheduled end of c's O1 binding, before the System end. It now expects SoD-10 refusals for O2 grants from `t(9)` and `t(10)` while the O1 binding is held, and acceptance of an O2 grant once the System has recorded the end at `t(10)`.

Tripwires: no model grants two organisations to one account, since the generators derive the organisation from the account. So no model's verdicts or stored counts change, and every tripwire run passes under its constant. No bound was changed.

## W7 close-out round 2 (branch `m2/w7-fix`)

Daniel answered four open readings on 2026-10-28. A test author wrote the reproducers and tests first, and each was red for its intended reason. The implementer then changed production.

- Q-W7-7, yes. `AcceptGrant` and `ApproveGrant` carry a `determination` member: the decision id of the amount determination they accept. The codec spells it as every decision id. `grant::check_fact` refuses either command under R-NG-03 unless it names the current determination. So an acceptance or approval composed against a superseded amount and decided after the new one is refused, and its decision id stays unspent. One naming a determination never recorded is refused too. The records `GrantAccepted` and `GrantApproved` are unchanged.
- Q-W7-4, clear it. The `AmountDetermined` fold now clears the contract fact as well as the acceptance, the approval and the approver. So the contract always matches the current amount. NEGOTIATION to GRANTED needs the acceptance, the approval and the contract fact all given after the current determination. The contract port reports the contract of the new amount again.
- Q-W7-6, the reading stands. A reviewer assignment is open in NEGOTIATION, so a proposal refused under I-34 at the amount determination can recover (`roles-and-sod.md`, Reviewer assignment NOTE).
- Q-W7-2, the reading stands. From a scheduled instant until the System records the end, every command but `EndScheduledRole` and `VaultChanged` is refused under SoD-05 (`roles-and-sod.md`, Cooling-off NOTE). No production change.
- SPEC notes, each marked decided 2026-10-28: NOTE 9 of `state-machine.md` for Q-W7-7 and Q-W7-4, and the two notes of `roles-and-sod.md` for Q-W7-6 and Q-W7-2. `invariants.md` is unchanged.
- References and models (test author): `reference::money` refuses an acceptance or approval that names a determination other than the current one, and clears the contract fact on a new amount. M-MONEY gained a `Stale` action that both sides refuse, a contract id per determination, the `contract_cleared` ghost and two Q-W7-4 witnesses. MoneyMachine draws stale acceptances and approvals.
- Fuzz: two seeds, `command_decode/accept_grant` and `command_decode/approve_grant`, hold the new member. The `decide_sequence` target of `fstp-engine` draws the member from its id pool, so it can name the current determination or another.

New tests of this round:

- `review_w7fix_stale_acceptance.rs`: `r_ng_03_acceptance_of_a_superseded_determination_is_refused` (the Q-W7-7 reproducer) and `r_ng_03_grant_fact_naming_an_unknown_determination_is_refused`, each with an `_on_the_reference` twin, and `r_ng_03_grant_fact_steps_name_their_determination`.
- `review_w7fix_contract_cleared.rs`: `r_ng_03_new_amount_clears_the_contract_fact` (the Q-W7-4 reproducer) and `r_ng_03_contract_fact_is_given_again_after_a_new_amount`, each with an `_on_the_reference` twin.
- `codec_grant_facts_name_their_determination.rs` (`fstp-domain`): four TH-26 tests that the member round-trips and that its absence is refused, `th26_r_ng_03_grant_fact_determination_has_one_spelling` and `th26_codec_seeds_hold_grant_facts_naming_their_determination`.

Tests updated because they encoded a reading Daniel overturned on 2026-10-28:

- `review_w7rev_m_money_redetermine.rs`: its witness read a contract fact that survived the second determination as proof of a supersede. It now asks for the supersede ghost with all three facts cleared.
- `r_ng_03_new_amount_supersedes_acceptance_and_approval.rs` and `r_ng_decline_only_when_no_p04_amount_fits.rs`: the grant fact steps name their determination. One approval after the second amount now names determination 2.

Test-side changes of the implementer, each a compile fix for the new member: `interface_stubs.rs` and `codec_support/mod.rs` in `fstp-domain`, arms 34 and 35 of `decide_sequence.rs`, and the four grant fact helpers of `gen/money.rs`, whose stand-in for the old interface is gone.

Tripwires, measured again with the same probe on both backends, then removed:

- `M_MONEY_STATES` grew from 20,304 to 32,310, and `M_MONEY_REFERENCE_STATES` from 22,332 to 35,544. A new amount clears the contract fact, so the contract fact is given again, and the `contract_cleared` ghost splits states. The stale acceptances and approvals are refused on both sides and add no state.
- `M_CONFORMANCE_STATES` grew from 19,929 to 21,711, and `M_CONFORMANCE_NO_WITHDRAW_STATES` from 14,470 to 15,658, for the same contract fact reason. The no-withdraw count was read inside `stalls`, which is not a `check_exhaustive` run.
- Every other stored count equals its constant. In the tripwire table, the "Before" column of these rows holds the fix round 2 count. Every production run was exhaustive under its old tripwire, so no bound was relaxed to pass a test.

In the debug workspace run of this round, `i13_i14_m_money` took 148.4 s, `review_w7rev_m_money_redetermine` 133.8 s and `review_w6decline_tripwire` 131.5 s. They were 83.5 s and 77.0 s for the first two in fix round 1. Part of this run shared the machine with the fuzz runs, so the times are an upper bound. Together the three take 413.7 s, about 6.9 minutes of the sequential run, or about 13.8 minutes on a CI core at half speed. The job stays well under its 60-minute timeout.

### Fix round 1 of close-out round 2

Reviewers reported four findings. Each was checked against NOTE 9 and `contracts.md`.

- A redelivered EFFECTIVE fact for the contract of a superseded amount was recorded again, and it granted the new amount on the old contract. Fixed. The `AmountDetermined` fold now remembers each contract whose fact it clears, in `MoneyState::superseded_contracts`. `grant::check_fact` refuses a `ContractFact` that names one of them under R-NG-03. A signed version is immutable (`contracts.md` Rules), so that fact is never a fact for the current amount. `reference::money` mirrors it in `MoneyProposal::superseded_contracts` and `grant_fact`. M-MONEY offers `Stale(p, Contract)`, which redelivers a cleared contract, and treats any `Stale` action both sides accept as a divergence. NOTE 9 now says that such a redelivery is refused. The reproducer is `review_w7fixrev_stale_contract_fact_after_new_amount_is_refused`.
- `ContractFact` names no determination. A contract first reported EFFECTIVE after a new determination still counts for the current amount. This is raised with Daniel as Q-W7-8 below. The domain alone does not bind such a late fact to the current amount.
- No public read of the current determination. Fixed. `MoneyState::determination(proposal)` returns its decision id, for the M4 and M5 shells that compose `AcceptGrant` and `ApproveGrant`.
- The reference refused a redelivered superseded contract only after its repeat check, which may record a repeat. On the reference backend M-MONEY then accepted the stale contract after the contract of the new amount. Both sides now refuse a superseded contract before the repeat check.
- The reference checked a stale acceptance or approval in a different order from production. Fixed. `reference::money::grant_fact` now checks the fresh decision id, then the fact already given, then the current determination, as production does. Verdicts are unchanged.

New tests of this fix round:

- `review_w7fixrev_stale_contract.rs`: `review_w7fixrev_stale_contract_fact_after_new_amount_is_refused` (the reviewers' reproducer).
- `review_w7fix_contract_cleared.rs`: `r_ng_03_contract_of_a_superseded_amount_is_refused_after_a_new_amount` and `r_ng_03_contract_of_a_superseded_amount_is_refused_after_the_new_contract`, each with an `_on_the_reference` twin.
- `r_ng_03_shell_reads_the_current_determination.rs`: `r_ng_03_production_names_the_current_determination`.

Tripwires, measured again: M-MONEY stores 32,310 states on production and 35,544 on the references, as before. The stale contract is refused on both sides and adds no state. The new `superseded_contracts` sets leave both counts unchanged. No constant changed.

### Fix round 2 of close-out round 2

Reviewers reported two low findings, neither with a reproducer.

- The cleared-contract guard reads only the proposal a `ContractFact` names. The domain tracks no contract identity across proposals or amendments. A contract cleared for one proposal, or another proposal's current contract, could complete a second grant. `ActivateAmendment` accepts any contract id as the new version. Both paths need the M5 port to misreport. No spec text binds a contract id to a proposal in the domain, so no production guard was added. The gap is raised with Daniel under Q-W7-8. The module docs of `grant` and `amendment` now say that the M5 contract port alone guarantees contract identity across proposals and amendments until he answers.
- Doc comments still described the stand-in for the old interface. Fixed. The module doc of `gen/money.rs`, the doc of `with_determination`, the `_naming` helpers and `r_ng_03_grant_fact_steps_name_their_determination` now describe the current interface. `reference::money` reads `determination` from the command itself, and `names_current` no longer has a case for a command without the member. Verdicts are unchanged.

No test was added or changed in its assertions. No tripwire changed, since no production behaviour changed.

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
- Q-W7-1, closed in fix round 1: in reference mode `SodWorld::exec` now returns a refusal that names the reference's rule. Both reference twins pass with their assertions unchanged.
- Q-W7-2, answered by Daniel on 2026-10-28: the reading below stands, and `roles-and-sod.md` (Cooling-off NOTE) records it. From a scheduled instant until the System records the end, every command but the System end and `VaultChanged` is refused under SoD-05. So the end pins the calls published by the instant and the P-12 value in force at it, and no step reads the binding as held after the instant. The cost is that the cell waits for the System end, which the M6 timeline issues at the instant. The alternative reads publication and P-12 edit times instead, and checks every guard against the instant.
- Q-W7-3: "remaining reviewer seats" at assignment is read as every other active committee member of the programme with a known organisation. Conflicts are not read, so a seat a conflict would close still counts. The steps that decide then refuse.
- Q-W7-4, answered by Daniel on 2026-10-28: clear it. A new amount determination also clears any contract fact recorded for the earlier amount, so the contract always matches the current amount. NEGOTIATION to GRANTED needs acceptance, approval and the contract fact all for the current determination (NOTE 9). Implemented in close-out round 2.
- Q-W7-5: the review and money references treat `EndRole` as an end at once. A scheduled end through those worlds would need the review reference to release assignments at the System end. Only the roles world drives scheduled ends today.
- Q-W7-6, answered by Daniel on 2026-10-28: the reading stands, and `roles-and-sod.md` (Reviewer assignment NOTE) records it. A reviewer assignment is now open in NEGOTIATION. Without it, I-34 at the amount determination (decided 2026-10-28) left a proposal whose reviewers were released there with no way to GRANTED or DECLINED. The reading rests on R-CF-02 (a declared conflict triggers reassignment) and R-NG-03. The alternative was a NOTE 9 decline ground for an I-34 failure.
- Q-W7-7, answered by Daniel on 2026-10-28: yes. `AcceptGrant` and `ApproveGrant` each name the amount determination they accept, by its decision id. Each is refused unless that determination is the current one for the proposal (NOTE 9, R-NG-03). This changes the command interface of the M4 and M5 lanes. Implemented in close-out round 2. An M4 or M5 shell composes either command from `MoneyState::determination(proposal)`, which returns the decision id of the current determination (fix round 1 of close-out round 2).
- Q-W7-8 (close-out round 2, fix round 1): `ContractFact` names no determination. The domain refuses a redelivered fact for a contract a new amount cleared. It cannot tell whether a contract first reported EFFECTIVE after a new determination was built for that amount. Should `ContractFact` name the determination its contract was built for, refused under R-NG-03 unless current? Or should the M5 seam confirm it at countersignature through `check_grant_preconditions`? Until then, the domain alone does not bind a late contract fact to the current amount, and NOTE 9 relies on the contract port for that case. Fix round 2 adds a related gap. The domain does not tie a contract id to the proposal or the amount it was signed for. A `ContractFact` for one proposal may name a contract cleared for, or current on, another proposal, and `ActivateAmendment` may name any contract id. Should the domain record which proposal and determination each contract id belongs to, and refuse a reuse? Or do the M5 interface notes state that the port alone guarantees contract identity across proposals and amendments? Until then, the port alone guarantees it.
- Q-W6-4: should `ReviewMachine::invariant` gain a state-level I-34 and I-35 check over the system ledger? The teeth would then also forge the record in the ledger, so a forged assignment held there would be caught on replay. Today both invariants are checked per step on appended records. Since W7, the stage 1 close and the ranking also re-check I-34 over the active reviewers.
