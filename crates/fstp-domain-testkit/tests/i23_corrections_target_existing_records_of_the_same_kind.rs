//! I-23: a correction targets an existing record of the same kind (design 5.1, ADR-007).
//!
//! The base is the witness ledger, built from genesis through the engine
//! over a `MemStore`. Each case appends one correction record by hand: a
//! score correction, a policy version, a binding end, suspension, void or
//! reinstatement, a score void, an assignment release or a superseding
//! plan. The correction targets either the right record, a missing one, a
//! record of another kind or, for some kinds, a record of the same kind
//! that is not the current one. A score correction may also name a
//! superseded entry of its own key, and a plan may supersede a plan that
//! was already superseded. A score correction or void may also name a key
//! whose stage sealed when the proposal left it (design 5.1, NOTE 3). A
//! second void of a binding and a second release of an assignment are
//! refused too. Each names a binding or assignment that is no longer held,
//! so both sides must refuse it. A score void may name a key of a real
//! assignment with no current value, or a key that an earlier void in the
//! same case already voided. Both are refused.
//!
//! A reinstatement to the right target needs a suspension still in force.
//! Its base is the witness ledger extended by a vault merge of the IRC
//! member into the staff drafter, which suspends the IRC binding.
//!
//! The property is two-way. The independent reference (`CorrectionView`)
//! and production's public structural fold must both accept exactly the
//! corrections with the right target. A fold that accepts a wrong target
//! breaks I-23 on replay. A fold that refuses the right target could not
//! replay a ledger the engine wrote.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::assignment::ReleaseCause;
use fstp_domain::id::{AssignmentId, BindingId, PlanVersionId, PolicyVersionId};
use fstp_domain::proposal::PlanOrigin;
use fstp_domain::record::{
    AssignmentReleased, BindingEnded, BindingReinstated, BindingSuspended, BindingVoided,
    PlanVersionRecorded, Record, ScoreRecorded, ScoreVoided,
};
use fstp_domain::refusal::RuleRef;
use fstp_domain::roles::CoolingOff;
use fstp_domain::scoring::{ScoreKey, ScoreVector, VoidCause};
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::policy::{next_version, text};
use fstp_domain_testkit::r#gen::review::{
    IRC, PR1, PR2, R1, R3, judge_binding, milestone, plan_of,
};
use fstp_domain_testkit::r#gen::roster::{P1, STAFF_DRAFTER};
use fstp_domain_testkit::harness::teeth::inject_envelope;
use fstp_domain_testkit::mc::ledger_model::{
    CorrectionView, L2_BINDING, LedgerRun, LedgerVaultOp, make_entry, reviewer_assignment,
    stage1_key, stage2_key, witness_run,
};
use fstp_domain_testkit::mc::life_model::revision_of;
use fstp_engine::{EngineState, Record as EngineRecord, replay};
use fstp_ledger::{Entry, Seq};
use fstp_prop::{Config, Gen, check_with};

/// The kinds of correction the property appends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    ScoreCorrection,
    PolicyVersion,
    BindingEnd,
    BindingSuspension,
    BindingVoid,
    Reinstatement,
    ScoreVoid,
    Release,
    PlanSupersede,
}

/// Where a correction points.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Target {
    /// The record it must name.
    Right,
    /// Nothing: no record has that id or sequence number.
    Missing,
    /// A record of another kind.
    OtherKind,
    /// A record of the same kind that is not the one to correct.
    OtherOfKind,
    /// An earlier record of the same target that a later record replaced.
    Stale,
    /// A score key whose stage sealed when the proposal left it (NOTE 3).
    Sealed,
}

/// The kinds with the targets each can take. A kind without `Right` has no
/// record in the base that a correct engine could still target.
const KINDS: [(Kind, &[Target]); 9] = [
    (
        Kind::ScoreCorrection,
        &[
            Target::Right,
            Target::Missing,
            Target::OtherKind,
            Target::OtherOfKind,
            Target::Stale,
            Target::Sealed,
        ],
    ),
    (
        Kind::PolicyVersion,
        &[
            Target::Right,
            Target::Missing,
            Target::OtherKind,
            Target::OtherOfKind,
        ],
    ),
    (
        Kind::BindingEnd,
        &[
            Target::Right,
            Target::Missing,
            Target::OtherKind,
            Target::OtherOfKind,
        ],
    ),
    (
        Kind::BindingSuspension,
        &[
            Target::Right,
            Target::Missing,
            Target::OtherKind,
            Target::OtherOfKind,
        ],
    ),
    (
        Kind::BindingVoid,
        &[
            Target::Right,
            Target::Missing,
            Target::OtherKind,
            Target::OtherOfKind,
        ],
    ),
    (
        Kind::Reinstatement,
        &[
            Target::Right,
            Target::Missing,
            Target::OtherKind,
            Target::OtherOfKind,
        ],
    ),
    (
        Kind::ScoreVoid,
        &[
            Target::Right,
            Target::Missing,
            Target::OtherKind,
            Target::OtherOfKind,
            Target::Stale,
            Target::Sealed,
        ],
    ),
    (
        Kind::Release,
        &[
            Target::Right,
            Target::Missing,
            Target::OtherKind,
            Target::OtherOfKind,
        ],
    ),
    (
        Kind::PlanSupersede,
        &[
            Target::Right,
            Target::Missing,
            Target::OtherKind,
            Target::OtherOfKind,
            Target::Stale,
        ],
    ),
];

/// A raw id that no record of the base uses.
const MISSING: u128 = 777_777_777;

/// The binding of R2, a committee member whose binding is open.
fn r2_binding() -> BindingId {
    judge_binding(2)
}

/// The Receiving binding of the lead of PR1, held in NEGOTIATION.
fn l1_binding() -> BindingId {
    BindingId::from_raw(300)
}

/// The IRC2 binding, ended in the base.
fn ended_binding() -> BindingId {
    BindingId::from_raw(205)
}

/// The Receiving binding of the lead of PR2, voided in the base by a vault exclusion.
fn voided_binding() -> BindingId {
    L2_BINDING
}

/// A raw id of a record of another kind: R1's assignment on PR2.
fn other_kind_raw() -> u128 {
    reviewer_assignment(R1, PR2).raw()
}

/// The base: the witness run, its view and its state.
struct Base {
    run: LedgerRun,
    view: CorrectionView,
    /// A binding under a suspension still in force, if the base holds one.
    suspended: Option<BindingId>,
}

/// The two bases of the property.
struct Bases {
    /// The witness run.
    plain: Base,
    /// The witness run extended by a vault merge that suspends a binding.
    suspended: Base,
}

/// The witness run, extended by a vault merge of [`IRC`] into the staff
/// drafter. The merge suspends the IRC binding, which stays suspended.
fn suspended_base() -> Result<Base, String> {
    let mut run = witness_run()?;
    let now = run.scenario.state().now_floor();
    let applied = run.vault(now, |truth| {
        LedgerVaultOp::Merge(IRC, STAFF_DRAFTER).apply(truth);
    })?;
    let suspended = applied
        .appended
        .iter()
        .find_map(|r| match r {
            Record::BindingSuspended(x) => Some(x.binding),
            _ => None,
        })
        .ok_or("the vault merge of IRC suspended no binding")?;
    let view = CorrectionView::of(&run.ledger)?;
    if view
        .bindings
        .get(&suspended)
        .is_none_or(|f| f.suspensions <= f.reinstatements)
    {
        return Err("the merge left no suspension in force".to_owned());
    }
    Ok(Base {
        run,
        view,
        suspended: Some(suspended),
    })
}

impl Base {
    fn state(&self) -> &EngineState {
        self.run.scenario.state()
    }

    fn entries(&self) -> &[Entry<EngineRecord>] {
        &self.run.ledger
    }

    /// The first entry that holds a record of `name`.
    fn seq_of(&self, name: &str) -> Seq {
        let n = self
            .view
            .kinds
            .iter()
            .find(|(_, k)| **k == name)
            .map_or(1, |(n, _)| *n);
        Seq::from_raw(n)
    }

    /// The entry of the current value of `key`.
    fn live(&self, key: &ScoreKey) -> Seq {
        Seq::from_raw(self.view.live.get(key).copied().unwrap_or(0))
    }

    /// The first score entry of `key`, which a later correction superseded.
    fn first(&self, key: &ScoreKey) -> Seq {
        let n = self
            .view
            .score_entries
            .iter()
            .find(|(_, k)| *k == key)
            .map_or(0, |(n, _)| *n);
        Seq::from_raw(n)
    }
}

/// The correction of `kind` pointing at `target`.
fn correction(base: &Base, kind: Kind, target: Target) -> Record {
    let epoch = base.state().epoch();
    let key = stage1_key(R1, PR2);
    match kind {
        Kind::ScoreCorrection => {
            // The key the record corrects: PR1 left STAGE1, so its stage 1
            // keys are sealed.
            let corrected = if target == Target::Sealed {
                stage1_key(R1, PR1)
            } else {
                key
            };
            let supersedes = match target {
                Target::Right | Target::Sealed => base.live(&corrected),
                Target::Missing => Seq::from_raw(base.view.head.saturating_add(7)),
                Target::OtherKind => base.seq_of("BindingGranted"),
                Target::OtherOfKind => base.live(&stage1_key(R1, PR1)),
                // R1's first score on PR2, which its correction superseded.
                Target::Stale => base.first(&key),
            };
            Record::ScoreRecorded(ScoreRecorded {
                key: corrected,
                values: ScoreVector(vec![2, 0]),
                supersedes: Some(supersedes),
                reason: Some(text(91_000)),
            })
        }
        Kind::PolicyVersion => {
            let head = fstp_domain::policy::head(&base.state().core, P1)
                .cloned()
                .expect("the base has a policy head");
            let mut v = next_version(&head, PolicyVersionId::from_raw(MISSING.saturating_add(1)));
            v.parent = match target {
                Target::Missing => Some(PolicyVersionId::from_raw(MISSING)),
                Target::OtherKind => Some(PolicyVersionId::from_raw(r2_binding().raw())),
                // The first version: no longer the latest one.
                Target::OtherOfKind => Some(PolicyVersionId::from_raw(1)),
                Target::Right | Target::Stale | Target::Sealed => Some(head.id),
            };
            v.live.p12 = CoolingOff(1);
            Record::PolicyVersionRecorded {
                version: Box::new(v),
                author: fstp_domain_testkit::r#gen::roster::STAFF_PM,
            }
        }
        Kind::BindingEnd => Record::BindingEnded(BindingEnded {
            // A binding that already ended.
            binding: binding_for(target, r2_binding(), ended_binding()),
            at: Timestamp::from_micros(base.state().now_floor().micros()),
            barred_through: 1,
            p12: CoolingOff(0),
        }),
        Kind::BindingSuspension => Record::BindingSuspended(BindingSuspended {
            // A binding that was voided.
            binding: binding_for(target, r2_binding(), voided_binding()),
            rule: RuleRef::I01,
            epoch,
        }),
        Kind::BindingVoid => Record::BindingVoided(BindingVoided {
            // A binding that was already voided.
            binding: binding_for(target, l1_binding(), voided_binding()),
            rule: RuleRef::I04,
            epoch,
        }),
        Kind::Reinstatement => Record::BindingReinstated(BindingReinstated {
            // The right target is the binding under a suspension still in
            // force. The same kind is a binding with no suspension in force.
            binding: binding_for(
                target,
                base.suspended.unwrap_or_else(r2_binding),
                r2_binding(),
            ),
            by: fstp_domain_testkit::r#gen::roster::ADMIN,
            reason: text(92_000),
        }),
        Kind::ScoreVoid => {
            let voided = match target {
                Target::Missing => ScoreKey {
                    assignment: AssignmentId::from_raw(MISSING),
                    ..key
                },
                Target::OtherKind => ScoreKey {
                    assignment: AssignmentId::from_raw(r2_binding().raw()),
                    ..key
                },
                // R1's current stage 2 score on PR1, which left STAGE2.
                Target::Sealed => stage2_key(R1, PR1),
                // A stage 1 key of R1's real PR2 assignment on a plan it
                // never scored: PR2 is in STAGE1, but the key has no value.
                Target::OtherOfKind => ScoreKey {
                    plan: revision_of(PR2, 1),
                    ..key
                },
                // The prelude of the case voided this key already.
                Target::Right | Target::Stale => key,
            };
            Record::ScoreVoided(ScoreVoided {
                key: voided,
                cause: VoidCause::Conflict,
            })
        }
        Kind::Release => {
            let assignment = match target {
                Target::Missing => AssignmentId::from_raw(MISSING),
                Target::OtherKind => AssignmentId::from_raw(r2_binding().raw()),
                // R3's assignment on PR2, released by a vault conflict.
                Target::OtherOfKind => reviewer_assignment(R3, PR2),
                Target::Right | Target::Stale | Target::Sealed => key.assignment,
            };
            Record::AssignmentReleased(AssignmentReleased {
                assignment,
                cause: ReleaseCause::Unassigned,
            })
        }
        Kind::PlanSupersede => {
            let (proposal, supersedes) = match target {
                Target::Missing => (PR1, PlanVersionId::from_raw(MISSING)),
                Target::OtherKind => (PR1, PlanVersionId::from_raw(other_kind_raw())),
                // The live plan of another proposal.
                Target::OtherOfKind => (PR2, revision_of(PR1, 1)),
                // PR1's submitted plan, which its revision superseded.
                Target::Stale => (PR1, plan_of(PR1)),
                // PR1's live plan: its first stage 2 revision.
                Target::Right | Target::Sealed => (PR1, revision_of(PR1, 1)),
            };
            let digest = fstp_domain::id::ContentDigest::from_bytes([9u8; 32]);
            Record::PlanVersionRecorded(PlanVersionRecorded {
                plan: PlanVersionId::from_raw(MISSING.saturating_add(2)),
                proposal,
                origin: PlanOrigin::Stage2Revision,
                supersedes: Some(supersedes),
                tasks: vec![fstp_domain::proposal::Task {
                    milestones: vec![
                        milestone(fstp_domain::id::MilestoneId::from_raw(MISSING))
                            .expect("milestone"),
                    ],
                }],
                content: digest,
            })
        }
    }
}

/// The binding a binding correction names under `target`: `right`, or
/// `same_kind` for a binding of the same kind that it must not name.
fn binding_for(target: Target, right: BindingId, same_kind: BindingId) -> BindingId {
    match target {
        Target::Missing => BindingId::from_raw(MISSING),
        Target::OtherKind => BindingId::from_raw(other_kind_raw()),
        Target::OtherOfKind => same_kind,
        Target::Right | Target::Stale | Target::Sealed => right,
    }
}

/// The record a case appends before its correction, if any. A second void
/// of a key follows a first void of that key, which both sides accept.
fn prelude(kind: Kind, target: Target) -> Option<Record> {
    (kind == Kind::ScoreVoid && target == Target::Stale).then(|| {
        Record::ScoreVoided(ScoreVoided {
            key: stage1_key(R1, PR2),
            cause: VoidCause::Conflict,
        })
    })
}

/// One case: the reference and the fold agree with the target.
fn case(bases: &Bases, g: &mut Gen) -> Result<(), String> {
    let (kind, targets) = *g.pick(&KINDS);
    let target = *g.pick(targets);
    g.note("correction", &(kind, target));
    let base = if kind == Kind::Reinstatement && target == Target::Right {
        &bases.suspended
    } else {
        &bases.plain
    };
    let at = base.state().now_floor();
    let mut extended = base.entries().to_vec();
    let mut state = base.state().clone();
    let mut next = base.view.head.saturating_add(1);
    if let Some(first) = prelude(kind, target) {
        let first = EngineRecord::Core(first);
        let seq = Seq::from_raw(next);
        extended.push(make_entry(seq, at, [0xed; 16], first.clone())?);
        CorrectionView::of(&extended)
            .map_err(|e| format!("reference: the prelude {first:?} was refused: {e}"))?;
        inject_envelope(&mut state, seq, at, &first)
            .map_err(|e| format!("I-23: the fold refused the prelude {first:?}: {e:?}"))?;
        next = next.saturating_add(1);
    }
    let record = EngineRecord::Core(correction(base, kind, target));
    let seq = Seq::from_raw(next);
    let entry = make_entry(seq, at, [0xee; 16], record.clone())?;
    extended.push(entry);
    let expected = target == Target::Right;
    let reference = CorrectionView::of(&extended);
    if reference.is_ok() != expected {
        return Err(format!(
            "reference: {kind:?} to the {target:?} target, expected accepted = {expected}, got {reference:?}"
        ));
    }
    let folded = inject_envelope(&mut state, seq, at, &record);
    if folded.is_ok() != expected {
        return Err(format!(
            "I-23: the structural fold of a {kind:?} to the {target:?} target gave {folded:?}, \
             expected accepted = {expected}\n  record: {record:?}"
        ));
    }
    if folded.is_ok() {
        let replayed = replay(&extended).map_err(|e| format!("I-23: the replay failed: {e}"))?;
        if replayed != state {
            return Err("I-23: the replay of the extended ledger differs from the fold".to_owned());
        }
    }
    Ok(())
}

/// I-23: a correction whose target is missing, of another kind, or not the
/// record it must name is refused by the reference and by production's
/// structural fold. A correction to the right target is accepted by both
/// and replays.
#[test]
fn i23_corrections_target_existing_records_of_the_same_kind() {
    let run = witness_run().unwrap_or_else(|e| panic!("{e}"));
    let view = CorrectionView::of(&run.ledger).unwrap_or_else(|e| panic!("{e}"));
    let plain = Base {
        run,
        view,
        suspended: None,
    };
    let suspended = suspended_base().unwrap_or_else(|e| panic!("{e}"));
    let bases = Bases { plain, suspended };
    check_with(
        "i23_corrections_target_existing_records_of_the_same_kind",
        Config::default().with_cases(256),
        |g| case(&bases, g),
    );
}
