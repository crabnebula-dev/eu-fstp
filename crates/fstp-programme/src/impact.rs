//! R-PG-04: which calls a change affects.
//!
//! [`impact`] reads what it needs about each call from the state into
//! [`CallFacts`], and [`impact_on`] decides from those facts alone.
//! [`programme_effects`] names what a change does beyond any call.
//!
//! Interim, pending Daniel, in six points:
//!
//! - The domain has no read that lists a programme's calls, so the caller
//!   passes them (`calls`). A domain read can replace the parameter later.
//! - `AppliesLive` is a fifth effect the design does not list. A live
//!   parameter is read at decision time, so a change governs a published
//!   call from its next decision. P-05 and P-13 never give it.
//! - Q37 is built as recommended (C), with the effective-limits record of
//!   D12. A published call keeps its publication values plus every later
//!   tightening (P-05 and P-13 NOTE 7). So the limit after a change is the
//!   stricter of that record and the new live value. A tightening is
//!   reported with the corrigendum it needs (I-53). A loosening never
//!   reaches a published call, so it is `NextCallOnly`.
//! - Until D12 lands in the domain, [`call_facts`] reads the record through
//!   `effective_p05` and `effective_p13`. They equal the record unless a
//!   loosening followed a tightening.
//! - `Refused` covers what M2 `validate` refuses, such as P-05 above P-58
//!   (I-50). Lowering P-05 below a recipient's counted sum needs a vault
//!   answer, so `EditPolicy` refuses it (I-14), not this function. With no
//!   call, a refused version yields no impact. The creator's
//!   `PolicyInvalid` check reports that refusal (M4 design section 3.2).
//! - Adding a P-13 class voids Receiving bindings across the programme,
//!   whether or not any call is published (NOTE 7, I-04). This is a
//!   [`ProgrammeEffect`], not a call effect.

use std::cmp::Ordering;
use std::collections::BTreeSet;

use fstp_domain::State;
use fstp_domain::id::{CallId, ClassId, ProgrammeId};
use fstp_domain::policy::{
    LiveSnapshot, PolicyVersion, effective_p05, effective_p13, frozen_policy, validate,
};
use fstp_domain::programme::{CallStatus, call};
use fstp_domain::refusal::RuleRef;
use fstp_domain::rules::{Freeze, ParamId};
use fstp_money::NonNegAmount;

use crate::spec::{FieldId, FieldKind};

/// The corrigendum a tightening after publication needs (NOTE 7, I-53).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CorrigendumNeed {
    /// P-05 drops below the cap the call enforces now.
    P05 {
        /// The cap at publication, which the Guide shows.
        published: NonNegAmount,
        /// The cap the call enforces after the change.
        tightened: NonNegAmount,
    },
    /// P-13 gains classes the call does not exclude yet. The same change
    /// voids Receiving bindings across the programme, which
    /// [`programme_effects`] reports.
    P13 {
        /// The classes added to what the call enforces.
        added: BTreeSet<ClassId>,
    },
}

/// What a change does to the programme as a whole, beyond any call.
/// Interim, pending Daniel.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ProgrammeEffect {
    /// P-13 gains classes. Every holder now in one of them loses its
    /// Receiving bindings in the same step (NOTE 7, I-04).
    VoidsReceivingBindings {
        /// The classes the change adds to the live P-13.
        classes: BTreeSet<ClassId>,
    },
}

/// The programme-wide effects of replacing `current` with `next` as the
/// programme's head, in a fixed order.
pub fn programme_effects(current: &PolicyVersion, next: &PolicyVersion) -> Vec<ProgrammeEffect> {
    let classes: BTreeSet<ClassId> = next
        .live
        .p13
        .0
        .difference(&current.live.p13.0)
        .copied()
        .collect();
    if classes.is_empty() {
        Vec::new()
    } else {
        vec![ProgrammeEffect::VoidsReceivingBindings { classes }]
    }
}

/// Why [`call_facts`] could not read a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ImpactError {
    /// The call is published, but its frozen policy or its effective
    /// limits do not read. Leaving it out would under-report the change.
    LimitsUnreadable {
        /// The call.
        call: CallId,
    },
}

impl core::fmt::Display for ImpactError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ImpactError::LimitsUnreadable { call } => {
                write!(f, "the limits of published call {} do not read", call.raw())
            }
        }
    }
}

impl std::error::Error for ImpactError {}

/// How one change affects one call.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ImpactEffect {
    /// The call is published and keeps its frozen value or its published
    /// limit (I-12, NOTE 7). The change applies from the next call.
    NextCallOnly,
    /// The call is not published yet, so it will freeze the new value.
    AppliesToDraftCall,
    /// A live parameter: the published call reads the new value at its next
    /// decision.
    AppliesLive,
    /// P-05 or P-13 tightens a published call. It always needs a numbered
    /// corrigendum (NOTE 7, Q37).
    TightensPublished {
        /// The corrigendum it needs.
        corrigendum: CorrigendumNeed,
    },
    /// The new version is refused, for example P-05 above P-58 (I-50).
    Refused(RuleRef),
}

/// The effect of a change of one field on one call.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CallImpact {
    /// The call.
    pub call: CallId,
    /// The changed field.
    pub field: FieldId,
    /// The effect.
    pub effect: ImpactEffect,
}

/// The limits a published call enforces (NOTE 7). `p05` and `p13` are
/// its effective-limits record: the publication snapshot plus every later
/// tightening (D12).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PublishedLimits {
    /// The P-05 and P-13 snapshot at publication.
    pub snapshot: LiveSnapshot,
    /// The P-05 cap the call enforces now.
    pub p05: NonNegAmount,
    /// The P-13 classes the call enforces now.
    pub p13: BTreeSet<ClassId>,
}

/// What [`impact_on`] needs to know about one call.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CallFacts {
    /// The call.
    pub call: CallId,
    /// Its limits once published, `None` while it is unpublished.
    pub published: Option<PublishedLimits>,
}

/// The facts of each call of `programme` among `calls`, in call order.
/// Unknown calls and calls of other programmes are skipped. A published
/// call whose limits do not read is an error, never skipped.
pub fn call_facts(
    state: &State,
    programme: ProgrammeId,
    calls: &[CallId],
) -> Result<Vec<CallFacts>, ImpactError> {
    let calls: BTreeSet<CallId> = calls.iter().copied().collect();
    let mut out = Vec::new();
    for c in calls {
        let Some(view) = call(state, c).filter(|v| v.programme() == programme) else {
            continue;
        };
        let published = if view.status() == CallStatus::Published {
            Some(published_limits(state, c).ok_or(ImpactError::LimitsUnreadable { call: c })?)
        } else {
            None
        };
        out.push(CallFacts { call: c, published });
    }
    Ok(out)
}

/// The limits published call `c` enforces, or `None` when any part does
/// not read.
fn published_limits(state: &State, c: CallId) -> Option<PublishedLimits> {
    Some(PublishedLimits {
        snapshot: frozen_policy(state, c)?.snapshot().clone(),
        p05: effective_p05(state, c).ok()?,
        p13: effective_p13(state, c).ok()?.0,
    })
}

/// R-PG-04: the effect of each field in `changed` on each call of
/// `programme` among `calls`, when `next` becomes the programme's head.
/// Sorted by call, then field.
pub fn impact(
    state: &State,
    programme: ProgrammeId,
    calls: &[CallId],
    changed: &BTreeSet<FieldId>,
    next: &PolicyVersion,
) -> Result<Vec<CallImpact>, ImpactError> {
    Ok(impact_on(
        &call_facts(state, programme, calls)?,
        changed,
        next,
    ))
}

/// The effect of each field in `changed` on each call of `facts`. A `next`
/// that M2 `validate` refuses gives `Refused` with the refusing rule for
/// every pair.
pub fn impact_on(
    facts: &[CallFacts],
    changed: &BTreeSet<FieldId>,
    next: &PolicyVersion,
) -> Vec<CallImpact> {
    let refused = validate(next).err().map(|r| r.rule);
    let mut out = Vec::new();
    for f in facts {
        for field in changed {
            let effect = match refused {
                Some(rule) => ImpactEffect::Refused(rule),
                None => effect_on(f.published.as_ref(), *field, next),
            };
            out.push(CallImpact {
                call: f.call,
                field: *field,
                effect,
            });
        }
    }
    out
}

impl ImpactEffect {
    /// Whether the change reaches the call: the call freezes the new value
    /// at publication, reads it at its next decision, or needs a
    /// corrigendum. A refused change reaches no call.
    pub fn reaches_call(&self) -> bool {
        matches!(
            self,
            ImpactEffect::AppliesToDraftCall
                | ImpactEffect::AppliesLive
                | ImpactEffect::TightensPublished { .. }
        )
    }
}

/// R-PG-04: the calls among `impacts` that some change reaches, each once,
/// in call order.
pub fn affected(impacts: &[CallImpact]) -> Vec<CallId> {
    impacts
        .iter()
        .filter(|i| i.effect.reaches_call())
        .map(|i| i.call)
        .collect::<BTreeSet<CallId>>()
        .into_iter()
        .collect()
}

/// R-PG-04: the calls of `programme` among `calls` that a change of the
/// fields in `changed` to their values in `next` reaches, in call order.
pub fn affected_calls(
    state: &State,
    programme: ProgrammeId,
    calls: &[CallId],
    changed: &BTreeSet<FieldId>,
    next: &PolicyVersion,
) -> Result<Vec<CallId>, ImpactError> {
    Ok(affected(&impact(state, programme, calls, changed, next)?))
}

/// The effect of a change of `field` to its value in `next` on one call.
fn effect_on(
    published: Option<&PublishedLimits>,
    field: FieldId,
    next: &PolicyVersion,
) -> ImpactEffect {
    let Some(limits) = published else {
        return ImpactEffect::AppliesToDraftCall;
    };
    let spec = match field.spec() {
        Some(s) if s.kind == FieldKind::Policy => s,
        // Artefacts shape the Guide, which publication fixed.
        _ => return ImpactEffect::NextCallOnly,
    };
    let frozen = spec
        .params
        .iter()
        .any(|p| p.spec().is_some_and(|s| s.freeze == Freeze::Frozen));
    if frozen {
        return ImpactEffect::NextCallOnly;
    }
    match field {
        FieldId::P05 => p05_effect(limits, next),
        FieldId::P13 => p13_effect(limits, next),
        _ => ImpactEffect::AppliesLive,
    }
}

/// The lower of two amounts in one currency, or `None` across currencies.
fn lower(a: NonNegAmount, b: NonNegAmount) -> Option<NonNegAmount> {
    match a.amount().cmp_same(b.amount()) {
        Ok(Ordering::Less) => Some(a),
        Ok(_) => Some(b),
        Err(_) => None,
    }
}

/// P-05 on a published call. The call keeps its effective-limits record,
/// so the cap after the change is the lowest of the snapshot, the record
/// and the new live value (NOTE 7, D12). Only a drop below the record
/// reaches the call, and it needs a corrigendum.
fn p05_effect(limits: &PublishedLimits, next: &PolicyVersion) -> ImpactEffect {
    let refused = ImpactEffect::Refused(RuleRef::Param(ParamId::P05));
    let snapshot = limits.snapshot.p05;
    let Some(after) = lower(snapshot, limits.p05).and_then(|r| lower(next.live.p05, r)) else {
        return refused;
    };
    match after.amount().cmp_same(limits.p05.amount()) {
        Ok(Ordering::Less) => ImpactEffect::TightensPublished {
            corrigendum: CorrigendumNeed::P05 {
                published: snapshot,
                tightened: after,
            },
        },
        Ok(_) => ImpactEffect::NextCallOnly,
        Err(_) => refused,
    }
}

/// P-13 on a published call. The call keeps its effective-limits record,
/// so the classes after the change are those of the snapshot, the record
/// and the new live value (NOTE 7, D12). Only a class the record lacks
/// reaches the call, and it needs a corrigendum.
fn p13_effect(limits: &PublishedLimits, next: &PolicyVersion) -> ImpactEffect {
    let added: BTreeSet<ClassId> = limits
        .snapshot
        .p13
        .0
        .union(&next.live.p13.0)
        .filter(|c| !limits.p13.contains(c))
        .copied()
        .collect();
    if added.is_empty() {
        ImpactEffect::NextCallOnly
    } else {
        ImpactEffect::TightensPublished {
            corrigendum: CorrigendumNeed::P13 { added },
        }
    }
}

#[cfg(test)]
mod tests {
    use fstp_domain::id::{PolicyVersionId, ProgrammeId};
    use fstp_domain::policy::ExclusionClasses;
    use fstp_money::{Amount, Currency};

    use super::*;
    use crate::{CompileIds, FunderProfile, compile, supersafe_fixture};

    fn eur(minor: i64) -> NonNegAmount {
        match Amount::from_minor(minor, Currency::Eur).map(NonNegAmount::new) {
            Ok(Ok(a)) => a,
            _ => panic!("bad test amount"),
        }
    }

    /// The SuperSAFE policy, with P-05 400000.00 and P-13 classes 1 and 2.
    fn head() -> PolicyVersion {
        let spec = match supersafe_fixture() {
            Ok(f) => f.spec,
            Err(e) => panic!("{e}"),
        };
        let ids = CompileIds::new(ProgrammeId::from_raw(1), PolicyVersionId::from_raw(2), None);
        match compile(&spec, &FunderProfile::horizon_europe(), ids) {
            Ok(c) => c.policy,
            Err(e) => panic!("{e}"),
        }
    }

    /// A call published under `head`, enforcing its snapshot.
    fn published(v: &PolicyVersion) -> CallFacts {
        CallFacts {
            call: CallId::from_raw(10),
            published: Some(PublishedLimits {
                snapshot: LiveSnapshot {
                    p05: v.live.p05,
                    p13: v.live.p13.clone(),
                },
                p05: v.live.p05,
                p13: v.live.p13.0.clone(),
            }),
        }
    }

    fn one(facts: &CallFacts, field: FieldId, next: &PolicyVersion) -> ImpactEffect {
        let out = impact_on(std::slice::from_ref(facts), &BTreeSet::from([field]), next);
        match out.as_slice() {
            [i] => i.effect.clone(),
            other => panic!("expected one impact, got {other:?}"),
        }
    }

    /// R-PG-04, I-12: a frozen parameter never reaches a published call,
    /// and an unpublished call takes every change.
    #[test]
    fn r_pg_04_frozen_change_is_next_call_only() {
        let v = head();
        let draft = CallFacts {
            call: CallId::from_raw(11),
            published: None,
        };
        assert_eq!(
            one(&published(&v), FieldId::P01, &v),
            ImpactEffect::NextCallOnly
        );
        assert_eq!(
            one(&draft, FieldId::P01, &v),
            ImpactEffect::AppliesToDraftCall
        );
        assert_eq!(
            one(&published(&v), FieldId::ProgrammeName, &v),
            ImpactEffect::NextCallOnly
        );
        assert_eq!(
            one(&published(&v), FieldId::P06, &v),
            ImpactEffect::AppliesLive
        );
    }

    /// R-PG-04, NOTE 7: lowering P-05 below a published call's cap needs a
    /// corrigendum; raising it leaves the published cap in force.
    #[test]
    fn r_pg_04_p05_tightening_needs_a_corrigendum() {
        let v = head();
        let facts = published(&v);
        let mut lower = v.clone();
        lower.live.p05 = eur(30_000_000);
        assert_eq!(
            one(&facts, FieldId::P05, &lower),
            ImpactEffect::TightensPublished {
                corrigendum: CorrigendumNeed::P05 {
                    published: v.live.p05,
                    tightened: eur(30_000_000),
                },
            }
        );
        let mut higher = v.clone();
        higher.live.p05 = eur(40_000_000);
        higher.live.p58 = Some(eur(40_000_000));
        assert_eq!(
            one(&facts, FieldId::P05, &higher),
            ImpactEffect::NextCallOnly
        );
    }

    /// R-PG-04, NOTE 7: adding a P-13 class tightens a published call;
    /// removing one leaves the snapshot in force.
    #[test]
    fn r_pg_04_p13_addition_needs_a_corrigendum() {
        let v = head();
        let facts = published(&v);
        let mut more = v.clone();
        more.live.p13.0.insert(ClassId::from_raw(9));
        assert_eq!(
            one(&facts, FieldId::P13, &more),
            ImpactEffect::TightensPublished {
                corrigendum: CorrigendumNeed::P13 {
                    added: BTreeSet::from([ClassId::from_raw(9)]),
                },
            }
        );
        let mut fewer = v.clone();
        fewer.live.p13 = ExclusionClasses(BTreeSet::new());
        assert_eq!(
            one(&facts, FieldId::P13, &fewer),
            ImpactEffect::NextCallOnly
        );
    }

    /// R-PG-04, I-04, NOTE 7: adding a P-13 class voids Receiving bindings
    /// across the programme; removing one or changing nothing else voids none.
    #[test]
    fn i04_r_pg_04_p13_addition_voids_receiving_bindings() {
        let v = head();
        let mut more = v.clone();
        more.live.p13.0.insert(ClassId::from_raw(9));
        assert_eq!(
            programme_effects(&v, &more),
            vec![ProgrammeEffect::VoidsReceivingBindings {
                classes: BTreeSet::from([ClassId::from_raw(9)]),
            }]
        );
        let mut fewer = v.clone();
        fewer.live.p13 = ExclusionClasses(BTreeSet::new());
        assert_eq!(programme_effects(&v, &fewer), Vec::new());
    }

    /// R-PG-04, NOTE 7, D12: a P-05 drop below a record already tightened
    /// by a corrigendum names the new tightened cap.
    #[test]
    fn r_pg_04_p05_second_tightening_is_against_the_record() {
        let v = head();
        let mut facts = published(&v);
        if let Some(l) = facts.published.as_mut() {
            l.p05 = eur(30_000_000);
        }
        let mut lower = v.clone();
        lower.live.p05 = eur(20_000_000);
        assert_eq!(
            one(&facts, FieldId::P05, &lower),
            ImpactEffect::TightensPublished {
                corrigendum: CorrigendumNeed::P05 {
                    published: v.live.p05,
                    tightened: eur(20_000_000),
                },
            }
        );
    }

    /// R-PG-04: the affected calls are those a change reaches. A frozen
    /// change reaches only a call not yet published (I-12), and a P-05
    /// drop reaches a published call too (NOTE 7).
    #[test]
    fn r_pg_04_affected_calls_are_the_calls_a_change_reaches() {
        let v = head();
        let live = published(&v);
        let draft = CallFacts {
            call: CallId::from_raw(11),
            published: None,
        };
        let facts = [live.clone(), draft];
        let frozen = impact_on(&facts, &BTreeSet::from([FieldId::P01]), &v);
        assert_eq!(affected(&frozen), vec![CallId::from_raw(11)]);
        let mut lower = v.clone();
        lower.live.p05 = eur(30_000_000);
        let cap = impact_on(
            &facts,
            &BTreeSet::from([FieldId::P01, FieldId::P05]),
            &lower,
        );
        assert_eq!(
            affected(&cap),
            vec![CallId::from_raw(10), CallId::from_raw(11)]
        );
        assert_eq!(affected(&[]), Vec::<CallId>::new());
    }
    /// R-PG-04, I-50: a version with P-05 above P-58 is refused for every call.
    #[test]
    fn i50_r_pg_04_cap_above_ceiling_is_refused() {
        let v = head();
        let mut bad = v.clone();
        bad.live.p05 = eur(50_000_000);
        assert_eq!(
            one(&published(&v), FieldId::P05, &bad),
            ImpactEffect::Refused(RuleRef::I50)
        );
    }
}
