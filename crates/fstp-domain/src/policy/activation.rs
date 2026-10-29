//! The core activation guard of a draft programme (M4 design section 3.4, D2, I-66, I-67).
//!
//! Owned by lane L-DOM (M4 design section 13, step W1b).
//!
//! - `CreateProgramme` creates a programme in `Draft` status (D1). The core
//!   `ActivateProgramme` makes it `Active`, once. The engine composes it
//!   only from the creator's approval, over a recomputed clean report
//!   (D2e, I-66). The core keeps the report digest and the revision as
//!   data.
//! - The core builder set of a draft is folded in the projection: the
//!   account that created it, every author of a policy version while it is
//!   a draft, and every grantor of a binding on it while it is a draft
//!   (Q1 A, interim, pending Daniel). The creator adds the builders only it
//!   knows, such as creator record authors, import resolvers and
//!   acknowledgers, through `creator_builders`.
//! - The guard is defence in depth for I-67. It refuses an approver in the
//!   builder set, `RuleRef::I67` with `GuardFailed`. It then asks
//!   `SameIdentityAsAny(approver, builders)` and refuses when it holds,
//!   `RuleRef::I67` with `VaultRefused` (Q2 B, interim, pending Daniel).
//!   The answer is recorded as a `VaultOutcome` (overview NOTE 5). The
//!   creator checks `IsVerified` for the approver and every builder before
//!   it composes the command (M4 design section 3.2). The core does not
//!   repeat that check, as D2 names only the two refusals above.
//! - [`ProgrammeActivated`] has private fields. Only [`decide`] and the
//!   record decoder build it, so no code outside the crate states an
//!   approver or a builder set.

use std::collections::BTreeSet;

use crate::command::{Command, Ctx};
use crate::id::{AccountId, DecisionId, ProgrammeId};
use crate::oracle::{Answers, Query};
use crate::programme::{ProgrammeStatus, programme_status};
use crate::record::{Record, RulesVersion};
use crate::refusal::{Refusal, RefusalReason, RuleRef};
use crate::state::{State, UsedId};

/// The digest of the validation report an activation names (I-66). The
/// creator computes it over the canonical report. The core keeps it as
/// data, and the engine pairs it with the creator's approval (D2e).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReportDigest([u8; 32]);

impl ReportDigest {
    /// The digest with these bytes.
    pub const fn from_bytes(b: [u8; 32]) -> ReportDigest {
        ReportDigest(b)
    }

    /// The bytes of the digest.
    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }
}

/// The activation of a draft programme (I-66, I-67, M4 change D2).
///
/// Its fields are private. The core guard builds it in [`decide`], and the
/// record decoder through `from_decoded`. Code outside the crate reads it
/// through the accessors only.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProgrammeActivated {
    programme: ProgrammeId,
    decision: DecisionId,
    report: ReportDigest,
    revision: u32,
    approver: AccountId,
    builders: BTreeSet<AccountId>,
    rules: RulesVersion,
}

impl ProgrammeActivated {
    /// Every field, for the record decoder in `codec/` only.
    pub(crate) fn from_decoded(
        programme: ProgrammeId,
        decision: DecisionId,
        report: ReportDigest,
        revision: u32,
        approver: AccountId,
        builders: BTreeSet<AccountId>,
        rules: RulesVersion,
    ) -> ProgrammeActivated {
        ProgrammeActivated {
            programme,
            decision,
            report,
            revision,
            approver,
            builders,
            rules,
        }
    }

    /// The activated programme.
    pub fn programme(&self) -> ProgrammeId {
        self.programme
    }

    /// The activation decision.
    pub fn decision(&self) -> DecisionId {
        self.decision
    }

    /// The digest of the report the activation names.
    pub fn report(&self) -> ReportDigest {
        self.report
    }

    /// The draft revision the report covers.
    pub fn revision(&self) -> u32 {
        self.revision
    }

    /// The approving tenant admin, outside the builder set (I-67).
    pub fn approver(&self) -> AccountId {
        self.approver
    }

    /// The builder set the approval was checked against: the core builders
    /// plus the creator's.
    pub fn builders(&self) -> &BTreeSet<AccountId> {
        &self.builders
    }

    /// The rules version that produced the decision.
    pub fn rules(&self) -> RulesVersion {
        self.rules
    }
}

/// The core builders of `programme` (I-67, Q1 A interim reading): the
/// account that created it, every author of a policy version of it while
/// it was a draft, and every account that granted a binding in it while it
/// was a draft. The set stops growing at activation. It is empty for an
/// unknown programme.
pub fn programme_builders(state: &State, programme: ProgrammeId) -> BTreeSet<AccountId> {
    crate::programme::builders(state, programme)
        .cloned()
        .unwrap_or_default()
}

/// A checked `ActivateProgramme`, before the vault answer.
struct Plan {
    record: ProgrammeActivated,
    /// `SameIdentityAsAny(approver, builders)` (Q2 B).
    identity: Query,
}

/// Checks an `ActivateProgramme` against the state: a draft programme, a
/// fresh decision id and an approver outside the builder set.
fn plan(state: &State, cmd: &Command, ctx: &Ctx) -> Result<Plan, Refusal> {
    let Command::ActivateProgramme {
        programme,
        decision,
        report,
        revision,
        creator_builders,
    } = cmd
    else {
        return Err(Refusal::new(RuleRef::Input, RefusalReason::WrongState));
    };
    let approver = crate::policy::actor_account(ctx)?;
    match programme_status(state, *programme) {
        None => {
            return Err(Refusal::new(RuleRef::Input, RefusalReason::UnknownEntity));
        }
        Some(ProgrammeStatus::Active) => {
            // A programme is activated once (D1).
            return Err(Refusal::new(RuleRef::I66, RefusalReason::WrongState));
        }
        Some(ProgrammeStatus::Draft) => {}
    }
    if state.used_ids.contains(UsedId::Decision(*decision)) {
        return Err(Refusal::new(RuleRef::Ledger, RefusalReason::IdReused));
    }
    let mut builders = programme_builders(state, *programme);
    builders.extend(creator_builders.iter().copied());
    if builders.contains(&approver) {
        return Err(Refusal::new(RuleRef::I67, RefusalReason::GuardFailed));
    }
    Ok(Plan {
        identity: Query::SameIdentityAsAny {
            subject: approver,
            others: builders.clone(),
        },
        record: ProgrammeActivated {
            programme: *programme,
            decision: *decision,
            report: *report,
            revision: *revision,
            approver,
            builders,
            rules: RulesVersion::M4,
        },
    })
}

/// The vault question of an `ActivateProgramme`.
pub(crate) fn queries(state: &State, cmd: &Command, ctx: &Ctx) -> Result<Vec<Query>, Refusal> {
    Ok(vec![plan(state, cmd, ctx)?.identity])
}

/// The records of an `ActivateProgramme`: the recorded identity answer and
/// the activation.
pub(crate) fn decide(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    answers: &Answers,
) -> Result<Vec<Record>, Refusal> {
    let plan = plan(state, cmd, ctx)?;
    let a = answers.get(&plan.identity).ok_or(Refusal::new(
        RuleRef::FactsIncomplete,
        RefusalReason::AnswerMissing,
    ))?;
    if a.holds {
        // A second account of a builder is not a second person (Q2 B).
        return Err(Refusal::new(RuleRef::I67, RefusalReason::VaultRefused));
    }
    Ok(vec![
        Record::VaultOutcome {
            kind: plan.identity.kind(),
            digest: a.digest,
            holds: a.holds,
            epoch: a.epoch,
        },
        Record::ProgrammeActivated(plan.record),
    ])
}
