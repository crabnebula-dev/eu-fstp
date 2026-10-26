//! Independent reference for findings, written from the spec text (design section 6.1).
//!
//! Owned by lane L-FIND-B (docs/handoff/m2-design.md section 10).
//!
//! Sources:
//! - I-10: findings never cause a state transition, score or decision.
//! - I-11: all findings within one call reference the same pinned model,
//!   prompt and rubric configuration (`config_id`).
//! - `SPEC/04-llm-assessment/assessment.md`: the finding schema, and the
//!   rule that all findings of a call are regenerated with the replacement
//!   configuration when the pinned model becomes unavailable.
//! - `SPEC/02-domain/policy-parameters.md` NOTE 10: the frozen P-21 value
//!   is a primary model plus an ordered fallback list. A replacement takes
//!   the next model on the list and regenerates every finding of the call
//!   in one atomic step.
//! - `SPEC/02-domain/state-machine.md` NOTE 8: findings stay with the call
//!   that produced them.
//! - R-LA-02: every finding carries an evidence pointer.
//! - `SPEC/04-llm-assessment/assessment.md`: reviewers mark findings as
//!   agreed or disputed. `SPEC/02-domain/roles-and-sod.md` Conflict
//!   declarations: a declared or detected conflict bars every
//!   assigned-reviewer act (I-03). Enforcement point 2: every action that
//!   changes state re-checks the actor's binding.
//!
//! The reference shares only id and finding types with production. It
//! keeps its own ghost of each call's pin, taken from the command that
//! published the call, never from the production projection.
//!
//! Readings taken where the sources are silent:
//! - A call without a pin, unpublished or unknown, stores no finding.
//! - A replacement names a configuration the call never held, its pin
//!   included. Every finding of the new set names the call and the new
//!   configuration, and no id repeats an id ever taken.
//! - An empty replacement set still moves the call to the new
//!   configuration.
//! - A mark is an assigned-reviewer act. The marker holds an active
//!   reviewer or IRC assignment on the finding's proposal, made in the
//!   finding's call, over an active binding of its role in the call's
//!   programme. No conflict fact exists, and the vault, at an epoch the
//!   engine has processed, reports no conflict with the applicant team.
//! - The reference does not judge whether the finding's proposal belongs
//!   to the call. The tests only offer findings whose proposal is in the
//!   producing call, or findings of a call with no pin.

use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::Actor;
use fstp_domain::id::{AccountId, CallId, LlmConfigId, ProposalId};
use fstp_domain::policy::ModelRef;
use fstp_domain::time::Timestamp;
use fstp_findings::{Finding, FindingId};

use crate::reference::review::{ConflictFacts, RefStatus, RevView};
use crate::reference::sod::View;

/// The ghost of one published call: its pin and the frozen P-21 fallbacks.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RefCall {
    /// The `config_id` pinned at publication.
    pub pin: LlmConfigId,
    /// The frozen P-21 fallback list, in the order it is taken.
    pub fallbacks: Vec<ModelRef>,
    /// The configuration findings of the call must carry now: the pin, or
    /// the latest replacement.
    pub current: LlmConfigId,
    /// How many replacements the call has had.
    pub replacements: usize,
    /// Every configuration the call has held, the current one included.
    pub held: BTreeSet<LlmConfigId>,
    /// The current findings of the call, by id.
    pub findings: BTreeMap<FindingId, Finding>,
}

/// The reference store: every call's ghost and findings, and every id taken.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct RefFindings {
    /// The published calls.
    pub calls: BTreeMap<CallId, RefCall>,
    /// Every finding id ever stored, current or replaced.
    pub taken: BTreeSet<FindingId>,
}

/// Whether `f` carries at least one evidence pointer and no span ends
/// before it starts (R-LA-02).
pub fn well_formed(f: &Finding) -> bool {
    !f.evidence.is_empty()
        && f.evidence.iter().all(|e| match e {
            fstp_findings::EvidenceRef::Submission { start, end, .. } => start <= end,
            fstp_findings::EvidenceRef::Retrieved { .. } => true,
        })
}

impl RefFindings {
    /// The store before any publication.
    pub fn new() -> RefFindings {
        RefFindings::default()
    }

    /// Records that `call` was published with `pin` under a frozen P-21
    /// whose fallback list is `fallbacks`.
    pub fn publish(&mut self, call: CallId, pin: LlmConfigId, fallbacks: Vec<ModelRef>) {
        self.calls.entry(call).or_insert_with(|| RefCall {
            pin,
            fallbacks,
            current: pin,
            replacements: 0,
            held: [pin].into_iter().collect(),
            findings: BTreeMap::new(),
        });
    }

    /// The configuration a finding of `call` must carry now, or `None`
    /// when the call has no pin.
    pub fn expected(&self, call: CallId) -> Option<LlmConfigId> {
        self.calls.get(&call).map(|c| c.current)
    }

    /// The current findings of `call`, in id order.
    pub fn findings_of(&self, call: CallId) -> Vec<&Finding> {
        self.calls
            .get(&call)
            .map(|c| c.findings.values().collect())
            .unwrap_or_default()
    }

    /// Whether `id` names a current finding.
    pub fn is_current(&self, id: FindingId) -> bool {
        self.calls.values().any(|c| c.findings.contains_key(&id))
    }

    /// The current finding ids, in order.
    pub fn current_ids(&self) -> Vec<FindingId> {
        self.calls
            .values()
            .flat_map(|c| c.findings.keys().copied())
            .collect()
    }

    /// Whether storing `f` is allowed, or why not (I-11, R-LA-02).
    pub fn record_verdict(&self, f: &Finding) -> Result<(), String> {
        let Some(expected) = self.expected(f.call) else {
            return Err(format!("I-11: {:?} has no pinned config_id", f.call));
        };
        if f.config != expected {
            return Err(format!(
                "I-11: {:?} names {:?}, the call requires {expected:?}",
                f.id, f.config
            ));
        }
        if !well_formed(f) {
            return Err(format!("R-LA-02: {:?} has no well-formed evidence", f.id));
        }
        if self.taken.contains(&f.id) {
            return Err(format!("{:?} is already taken", f.id));
        }
        Ok(())
    }

    /// Stores `f` when [`RefFindings::record_verdict`] allows it.
    pub fn record(&mut self, f: Finding) -> Result<(), String> {
        self.record_verdict(&f)?;
        if self.force_insert(f) {
            Ok(())
        } else {
            Err("the call vanished".to_owned())
        }
    }

    /// Stores `f` under its published call without any other check, and
    /// returns whether it did. The ghost pin stays as it was. Only teeth
    /// tests call it, to build the store a broken engine would leave.
    pub fn force_insert(&mut self, f: Finding) -> bool {
        let Some(c) = self.calls.get_mut(&f.call) else {
            return false;
        };
        self.taken.insert(f.id);
        c.findings.insert(f.id, f);
        true
    }

    /// Whether replacing every finding of `call` with `findings` under
    /// `config`, pinned to `config_model`, is allowed, or why not
    /// (P-21 NOTE 10, I-11, R-LA-02).
    pub fn replace_verdict(
        &self,
        call: CallId,
        config: LlmConfigId,
        config_model: &ModelRef,
        findings: &[Finding],
    ) -> Result<(), String> {
        let Some(c) = self.calls.get(&call) else {
            return Err(format!("I-11: {call:?} has no pinned config_id"));
        };
        match c.fallbacks.get(c.replacements) {
            Some(m) if m == config_model => {}
            Some(m) => {
                return Err(format!(
                    "P-21 NOTE 10: the next fallback of {call:?} is {m:?}, not {config_model:?}"
                ));
            }
            None => {
                return Err(format!(
                    "P-21 NOTE 10: {call:?} has used every fallback on its frozen list"
                ));
            }
        }
        if c.held.contains(&config) {
            return Err(format!(
                "I-11: {call:?} already held {config:?}; a replacement is a new configuration"
            ));
        }
        let mut seen = BTreeSet::new();
        for f in findings {
            if f.call != call {
                return Err(format!("{:?} belongs to {:?}, not {call:?}", f.id, f.call));
            }
            if f.config != config {
                return Err(format!(
                    "I-11: {:?} names {:?} inside a replacement under {config:?}",
                    f.id, f.config
                ));
            }
            if !well_formed(f) {
                return Err(format!("R-LA-02: {:?} has no well-formed evidence", f.id));
            }
            if self.taken.contains(&f.id) || !seen.insert(f.id) {
                return Err(format!("{:?} is already taken", f.id));
            }
        }
        Ok(())
    }

    /// Replaces every finding of `call` when [`RefFindings::replace_verdict`]
    /// allows it. The earlier findings leave the call and their ids stay taken.
    pub fn replace(
        &mut self,
        call: CallId,
        config: LlmConfigId,
        config_model: &ModelRef,
        findings: Vec<Finding>,
    ) -> Result<(), String> {
        self.replace_verdict(call, config, config_model, &findings)?;
        for f in &findings {
            self.taken.insert(f.id);
        }
        let c = self
            .calls
            .get_mut(&call)
            .ok_or_else(|| format!("{call:?} vanished"))?;
        c.current = config;
        c.replacements = c.replacements.saturating_add(1);
        c.held.insert(config);
        c.findings = findings.into_iter().map(|f| (f.id, f)).collect();
        Ok(())
    }

    /// The same store with every finding removed and every pin kept: the
    /// `strip` of design 6.2 I-10.
    pub fn stripped(&self) -> RefFindings {
        let mut out = self.clone();
        out.taken.clear();
        for c in out.calls.values_mut() {
            c.current = c.pin;
            c.replacements = 0;
            c.held = [c.pin].into_iter().collect();
            c.findings.clear();
        }
        out
    }
}

/// I-11 over observed findings: for each call of `calls`, every finding
/// `observed` returns names the call and carries the configuration the
/// ghost expects. A call without a pin holds none.
pub fn check_i11<'f>(
    ghost: &RefFindings,
    calls: &[CallId],
    observed: impl Fn(CallId) -> Vec<&'f Finding>,
) -> Result<(), String> {
    for call in calls {
        let held = observed(*call);
        let expected = ghost.expected(*call);
        for f in held {
            if f.call != *call {
                return Err(format!(
                    "I-11: {:?} is stored under {call:?} but names {:?}",
                    f.id, f.call
                ));
            }
            match expected {
                Some(e) if e == f.config => {}
                Some(e) => {
                    return Err(format!(
                        "I-11: {:?} in {call:?} names {:?}, the call's pinned config_id is {e:?}",
                        f.id, f.config
                    ));
                }
                None => {
                    return Err(format!(
                        "I-11: {:?} is stored under {call:?}, which has no pinned config_id",
                        f.id
                    ));
                }
            }
        }
    }
    Ok(())
}

/// The ids of `findings`, in order.
pub fn ids<'f>(findings: impl IntoIterator<Item = &'f Finding>) -> BTreeSet<FindingId> {
    findings.into_iter().map(|f| f.id).collect()
}

/// Whether the observed findings of each call of `calls` are exactly the
/// reference's, compared by id and content.
pub fn same_findings<'f>(
    ghost: &RefFindings,
    calls: &[CallId],
    observed: impl Fn(CallId) -> Vec<&'f Finding>,
) -> Result<(), String> {
    for call in calls {
        let mut got: Vec<&Finding> = observed(*call);
        got.sort_by_key(|f| f.id);
        let want = ghost.findings_of(*call);
        if got != want {
            return Err(format!(
                "two-way: {call:?} holds {:?}, the reference holds {:?}",
                ids(got.iter().copied()),
                ids(want.iter().copied())
            ));
        }
    }
    Ok(())
}

/// What a mark verdict reads: the review and roles references, the vault
/// ground truth, whether the engine has processed the vault's epoch, and
/// the instant of the mark.
pub struct MarkFacts<'a> {
    /// The review reference view.
    pub review: &'a RevView,
    /// The roles reference view.
    pub roles: &'a View,
    /// The vault's conflict answers.
    pub conflicts: &'a dyn ConflictFacts,
    /// Whether the engine has processed the vault's current epoch.
    pub vault_current: bool,
    /// The instant of the mark.
    pub now: Timestamp,
}

/// Whether `actor` may mark a current finding of `call` on `proposal`,
/// or why not (I-03, enforcement point 2, assessment.md). `finding` is
/// `None` for an id that names no current finding.
pub fn mark_verdict(
    finding: Option<(CallId, ProposalId)>,
    actor: Actor,
    facts: &MarkFacts<'_>,
) -> Result<(), String> {
    let Actor::Account(by) = actor else {
        return Err("only an account marks a finding".to_owned());
    };
    let Some((call, proposal)) = finding else {
        return Err("the finding is not current".to_owned());
    };
    let Some(programme) = facts.review.calls.get(&call).map(|c| c.programme) else {
        return Err(format!("{call:?} is unknown"));
    };
    let assigned = facts.review.assignments.values().any(|a| {
        a.reviewer == by
            && a.proposal == proposal
            && a.call == call
            && matches!(a.kind, AssignmentKind::Reviewer | AssignmentKind::Irc)
            && a.status == RefStatus::Active
            && a.role().is_some_and(|role| {
                facts.roles.bindings.values().any(|b| {
                    b.account == by
                        && b.role == role
                        && b.programme == programme
                        && b.active()
                        && b.start <= facts.now
                })
            })
    });
    if !assigned {
        return Err(format!(
            "{by:?} holds no active reviewing assignment on {proposal:?} in {call:?} over an active binding"
        ));
    }
    if facts.review.facts.contains(&(by, proposal)) {
        return Err(format!("I-03: {by:?} has a conflict fact on {proposal:?}"));
    }
    if !facts.vault_current {
        return Err("the vault is ahead of the processed epoch".to_owned());
    }
    let team: std::collections::BTreeSet<AccountId> = facts
        .roles
        .bindings
        .values()
        .filter(|b| b.proposal == Some(proposal) && b.held())
        .map(|b| b.account)
        .collect();
    if facts.conflicts.has_conflict(by, &team) {
        return Err(format!(
            "I-03: the vault reports a conflict of {by:?} on {proposal:?}"
        ));
    }
    Ok(())
}
