//! The `Contract` envelope of the engine (M5 design sections 3.1 and 4.1,
//! lane L-CON).
//!
//! A contract command goes to `fstp_contract_core::decide` over the contract
//! store, with the actor's account. The engine adds what the contract
//! crate cannot see:
//!
//! - `Send` asks `fstp_domain::grant::grant_preconditions` for the
//!   proposal and refuses unless `check_grant_preconditions` holds;
//! - the signature that completes a version composes the core
//!   `ContractFact { Effective }` as a System command of the contract
//!   port, decided by `fstp_domain::decide` with its own vault answers.
//!   The entry holds the core records first, then `ContractEffective`.
//!
//! The fold refuses a `ContractEffective` whose entry holds no core
//! `ContractFactRecorded` of the same contract (`lib.rs`, entry pairings).
//! Contract refusals map onto existing rule references until the domain
//! gains an I-30 reference: frozen and chain faults are `Row`, actor
//! faults `Actor`, and unknown ids `Input`.

use fstp_contract_core::{ContractCommand, ContractFoldError, ContractRecord, ContractRefusal};
use fstp_domain::command::{Actor, ContractEvent, Ctx, SystemCause};
use fstp_domain::engine::FoldError;
use fstp_domain::id::{AccountId, ContractId, ProposalId};
use fstp_domain::oracle::{Answers, Query};
use fstp_domain::refusal::{Refusal, RefusalReason, RuleRef};

use crate::{EngineState, Record};

pub use fstp_contract_core::ContractStore;

/// The domain refusal of a contract refusal.
#[must_use]
pub fn refusal(r: ContractRefusal) -> Refusal {
    use ContractRefusal as C;
    match r {
        C::UnknownContract | C::UnknownVersion | C::UnknownChange | C::UnknownParty => {
            Refusal::new(RuleRef::Input, RefusalReason::UnknownEntity)
        }
        C::ContractExists | C::RevisionRepeated => {
            Refusal::new(RuleRef::Ledger, RefusalReason::IdReused)
        }
        C::PartiesInvalid | C::BaseMismatch | C::ProposalMismatch | C::SealedDraftRequired => {
            Refusal::new(RuleRef::Input, RefusalReason::InvalidValue)
        }
        C::NotTheParty | C::ActorRequired => {
            Refusal::new(RuleRef::Actor, RefusalReason::WrongActor)
        }
        C::NotLatestVersion
        | C::VersionFrozen
        | C::LatestStillDrafted
        | C::NotOpenForSignature
        | C::OpenChange
        | C::AlreadySigned
        | C::RevisionChain
        | C::AdvancedNotApproved
        | C::AdvancedAlreadyApproved
        | C::CountersignatureNotLast
        | C::Terminated => Refusal::new(RuleRef::Row, RefusalReason::WrongState),
    }
}

fn actor_account(ctx: &Ctx) -> Option<AccountId> {
    match ctx.actor {
        Actor::Account(a) => Some(a),
        Actor::System(_) => None,
    }
}

fn proposal_of(state: &EngineState, contract: ContractId) -> Result<ProposalId, Refusal> {
    state
        .contracts
        .contract(contract)
        .map(fstp_contract_core::Contract::proposal)
        .ok_or_else(|| refusal(ContractRefusal::UnknownContract))
}

/// The core command and context the contract port issues when a version
/// becomes effective.
#[must_use]
pub fn contract_fact(
    proposal: ProposalId,
    contract: ContractId,
    ctx: &Ctx,
) -> (fstp_domain::Command, Ctx) {
    let cmd = fstp_domain::Command::ContractFact {
        proposal,
        contract,
        event: ContractEvent::Effective,
    };
    let system = Ctx {
        actor: Actor::System(SystemCause::ContractPort),
        ..*ctx
    };
    (cmd, system)
}

fn effective_of(records: &[ContractRecord]) -> Option<ContractId> {
    records.iter().find_map(|r| match r {
        ContractRecord::Effective { contract, .. } => Some(*contract),
        _ => None,
    })
}

/// The vault questions of a contract command.
pub(crate) fn contract_queries(
    state: &EngineState,
    cmd: &ContractCommand,
    ctx: &Ctx,
) -> Result<Vec<Query>, Refusal> {
    crate::ledger_clock(state, ctx)?;
    let records =
        fstp_contract_core::decide(&state.contracts, cmd, actor_account(ctx)).map_err(refusal)?;
    match cmd {
        ContractCommand::Send { contract, .. } => {
            fstp_domain::grant::grant_preconditions(&state.core, proposal_of(state, *contract)?)
        }
        _ => match effective_of(&records) {
            Some(contract) => {
                let (core, system) = contract_fact(proposal_of(state, contract)?, contract, ctx);
                fstp_domain::queries(&state.core, &core, &system)
            }
            None => Ok(Vec::new()),
        },
    }
}

/// The records of a contract command, with the composed core records of
/// a version that becomes effective.
pub(crate) fn decide_contract(
    state: &EngineState,
    cmd: &ContractCommand,
    ctx: &Ctx,
    answers: &Answers,
) -> Result<Vec<Record>, Refusal> {
    crate::ledger_clock(state, ctx)?;
    let records =
        fstp_contract_core::decide(&state.contracts, cmd, actor_account(ctx)).map_err(refusal)?;
    if let ContractCommand::Send { contract, .. } = cmd {
        fstp_domain::grant::check_grant_preconditions(
            &state.core,
            proposal_of(state, *contract)?,
            answers,
        )?;
    }
    let Some(contract) = effective_of(&records) else {
        return Ok(records.into_iter().map(Record::Contract).collect());
    };
    let (core, system) = contract_fact(proposal_of(state, contract)?, contract, ctx);
    let core_records = fstp_domain::decide(&state.core, &core, &system, answers)?;
    let mut out = Vec::with_capacity(records.len().saturating_add(core_records.len()));
    let mut contract_records = records.into_iter().peekable();
    // SignatureApplied first, then the core records, then the rest.
    if let Some(first) = contract_records.next() {
        out.push(Record::Contract(first));
    }
    out.extend(core_records.into_iter().map(Record::Core));
    out.extend(contract_records.map(Record::Contract));
    Ok(out)
}

/// The fold error of a contract fold refusal.
fn contract_fold(e: ContractFoldError) -> FoldError {
    match e {
        ContractFoldError::Unknown => FoldError::UnknownEntity,
        ContractFoldError::Inconsistent(_) => FoldError::Inconsistent,
    }
}

/// Folds a contract record. A `ContractEffective` needs a core
/// `ContractFactRecorded` of the same contract earlier in its entry.
pub(crate) fn apply_contract(
    state: &mut EngineState,
    contract_facts: &[ContractId],
    r: &ContractRecord,
) -> Result<(), FoldError> {
    if let ContractRecord::Effective { contract, .. } = r
        && !contract_facts.contains(contract)
    {
        return Err(FoldError::Inconsistent);
    }
    fstp_contract_core::apply(&mut state.contracts, r).map_err(contract_fold)
}
