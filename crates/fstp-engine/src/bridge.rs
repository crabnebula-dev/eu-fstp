//! The import bridge (I-65, M4 design section 3.3). It is the only place
//! where the import store and the creator meet.
//!
//! `resolve_import` checks the programme manager binding, the proposal,
//! the `shown` digest and the field. It then emits the import record and
//! the creator's `SaveFields` with import provenance in one entry.
//!
//! Lane W2b (L-IMPORT) owns this file. The M4 W0 lane added it with its
//! `mod` line.
//!
//! # What is built, and the seam
//!
//! The binding check is built here: [`programme_manager_at`] and
//! [`resolver`]. They read the core alone, so they need no new edge.
//!
//! The rest of the designed bridge names `fstp-import`, `fstp-creator` and
//! `fstp-programme` types. This crate's `Cargo.toml` has no edge to any of
//! them, and the lead owns that manifest and the shared `Cargo.lock`. So
//! [`resolve_import`] still refuses with [`BridgeError::NotImplemented`]
//! and names the seam. Once the lead adds the three edges, its body is the
//! following, in one entry, with nothing appended on any refusal:
//!
//! 1. `resolver(state, programme, ctx)`: the actor holds an active
//!    programme manager binding on the draft at `ctx.now` (I-65).
//! 2. `fstp_import::check_resolution(&state.import, ..)` with the
//!    proposal, `shown`, the `ClientResolution` and
//!    `conflict_acknowledged`. It checks the proposal: it exists, belongs
//!    to the programme and is unresolved. It checks that `shown` is the
//!    salted digest of the stored value's text and that the field is
//!    importable. A confirmation must name the proposal's value and an
//!    edit another value. Both need the value held in the import store.
//!    A flagged conflict must be acknowledged. It yields the
//!    `ProposalResolved` record and, for a confirmation or an edit, the
//!    `AppliedValue`.
//! 3. For a confirmation or an edit: the field's strict decoder,
//!    `fstp_programme::decode_field_value(field, value.as_data())`, then
//!    `fstp_creator::decide_import_save` with `base` and an
//!    `ImportFieldEdit` carrying `Provenance::Import { proposal,
//!    resolution }`. A decoding failure refuses the whole resolution.
//! 4. The entry holds `Record::Import(ProposalResolved)`, the creator
//!    records and the core `EditPolicy` records of that save. A dismissal
//!    holds only the import record.
//!
//! The import records name each value by its text reference only
//! (ADR-007). After the engine appends a `RecordProposals` batch, it
//! passes the batch to `ImportStore::hold_recorded`. After a replay, the
//! shell resolves each reference through the text store and calls
//! `ImportStore::hold`.
//!
//! The engine fold should refuse an entry with a `FieldsSaved` under
//! `Provenance::Import` that has no `ProposalResolved` of the same
//! proposal, kind and account beside it, as D2e pairs activation records.
//! That pairing belongs to lane W2e's fold.

use fstp_domain::command::{Actor, Ctx};
use fstp_domain::id::{AccountId, ProgrammeId};
use fstp_domain::roles::Role;
use fstp_domain::state::State;
use fstp_domain::time::Timestamp;

use crate::{Command, EngineState};

/// Why a bridge command failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BridgeError {
    /// The named part of the bridge is not built yet. The text names the
    /// seam.
    NotImplemented(&'static str),
    /// The actor is the system. Only a person resolves an import proposal.
    NotAnAccount,
    /// The actor holds no active programme manager binding on the
    /// programme at that instant (I-65).
    NotProgrammeManager,
}

/// Whether `account` holds an active programme manager binding on
/// `programme` at `now` (I-65, design 12.1 point 2).
///
/// The binding is held, not suspended or voided, started at or before
/// `now`, and not at or past a scheduled end. An ended binding has left
/// the roster, so it never counts.
pub fn programme_manager_at(
    core: &State,
    programme: ProgrammeId,
    account: AccountId,
    now: Timestamp,
) -> bool {
    core.roster().bindings().any(|(_, b)| {
        b.account == account
            && b.programme == programme
            && b.role == Role::ProgrammeManager
            && b.active_at(now)
            && b.scheduled_end.is_none_or(|end| now < end)
    })
}

/// The resolver of an import command on `programme`: the actor's account,
/// when it holds an active programme manager binding there at `ctx.now`.
///
/// The bridge runs it before any import check, and the engine runs it for
/// an upload (`import.upload`) too, which needs the same binding (interim
/// reading, pending Daniel).
pub fn resolver(
    state: &EngineState,
    programme: ProgrammeId,
    ctx: &Ctx,
) -> Result<AccountId, BridgeError> {
    let Actor::Account(account) = ctx.actor else {
        return Err(BridgeError::NotAnAccount);
    };
    if programme_manager_at(&state.core, programme, account, ctx.now) {
        Ok(account)
    } else {
        Err(BridgeError::NotProgrammeManager)
    }
}

/// Resolves one import proposal of a draft programme.
///
/// It refuses until the lead adds this crate's edges to `fstp-import`,
/// `fstp-creator` and `fstp-programme`. The module documentation gives the
/// body it then runs. A refusal appends nothing, so no proposal reaches a
/// draft through this path in the meantime (I-65).
pub fn resolve_import(
    state: &EngineState,
    programme: ProgrammeId,
) -> Result<Vec<Command>, BridgeError> {
    let _ = (state, programme);
    Err(BridgeError::NotImplemented(
        "fstp_engine::bridge::resolve_import: fstp-engine has no Cargo.toml edge to fstp-import, fstp-creator or fstp-programme yet (lead)",
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use fstp_domain::command::SystemCause;
    use fstp_domain::id::{BindingId, CommandId};
    use fstp_domain::record::{BindingEnded, BindingGranted, BindingSuspended};
    use fstp_domain::refusal::RuleRef;
    use fstp_domain::roles::{BindingScope, CoolingOff};
    use fstp_domain::{Record, Via};
    use fstp_ledger::Seq;
    use fstp_money::Currency;

    use super::*;

    const P: ProgrammeId = ProgrammeId::from_raw(1);
    const OTHER: ProgrammeId = ProgrammeId::from_raw(2);
    const A: AccountId = AccountId::from_raw(10);
    const ADMIN: AccountId = AccountId::from_raw(11);

    fn at(t: i64) -> Timestamp {
        Timestamp::from_micros(t)
    }

    fn grant(binding: u128, programme: ProgrammeId, role: Role, start: i64) -> Record {
        Record::BindingGranted(BindingGranted {
            binding: BindingId::from_raw(binding),
            account: A,
            programme,
            role,
            scope: BindingScope::Programme,
            start: at(start),
            granted_by: ADMIN,
            second_admin: None,
            confidentiality: None,
            organisation: None,
            verified_epoch: None,
        })
    }

    /// The core after `records`, one entry each, at times 1, 2 and so on,
    /// after the two programmes were created.
    fn core(records: &[Record]) -> State {
        let mut s = State::genesis();
        let mut all = vec![
            Record::ProgrammeCreated {
                programme: P,
                currency: Currency::Eur,
                by: ADMIN,
            },
            Record::ProgrammeCreated {
                programme: OTHER,
                currency: Currency::Eur,
                by: ADMIN,
            },
        ];
        all.extend_from_slice(records);
        for (i, r) in all.iter().enumerate() {
            let n = u64::try_from(i).unwrap().saturating_add(1);
            fstp_domain::apply(&mut s, Seq::from_raw(n), at(1), r).unwrap();
        }
        s
    }

    /// I-65: only an active programme manager binding on the same
    /// programme, started by `now`, counts.
    #[test]
    fn i65_programme_manager_at_needs_an_active_binding() {
        let none = core(&[]);
        assert!(!programme_manager_at(&none, P, A, at(5)));
        let bound = core(&[grant(1, P, Role::ProgrammeManager, 3)]);
        assert!(programme_manager_at(&bound, P, A, at(3)));
        assert!(programme_manager_at(&bound, P, A, at(9)));
        assert!(!programme_manager_at(&bound, P, A, at(2)));
        assert!(!programme_manager_at(&bound, OTHER, A, at(5)));
        assert!(!programme_manager_at(&bound, P, ADMIN, at(5)));
        let drafter = core(&[grant(1, P, Role::CallDrafter, 0)]);
        assert!(!programme_manager_at(&drafter, P, A, at(5)));
    }

    /// I-65: an ended, suspended or scheduled-to-end binding does not
    /// count from that instant on.
    #[test]
    fn i65_programme_manager_at_refuses_ended_and_suspended_bindings() {
        let ended = core(&[
            grant(1, P, Role::ProgrammeManager, 0),
            Record::BindingEnded(BindingEnded {
                binding: BindingId::from_raw(1),
                at: at(1),
                barred_through: 1,
                p12: CoolingOff(1),
            }),
        ]);
        assert!(!programme_manager_at(&ended, P, A, at(5)));
        let suspended = core(&[
            grant(1, P, Role::ProgrammeManager, 0),
            Record::BindingSuspended(BindingSuspended {
                binding: BindingId::from_raw(1),
                rule: RuleRef::I01,
                epoch: fstp_domain::id::VaultEpoch::from_raw(1),
            }),
        ]);
        assert!(!programme_manager_at(&suspended, P, A, at(5)));
        let scheduled = core(&[
            grant(1, P, Role::ProgrammeManager, 0),
            Record::BindingEndScheduled {
                binding: BindingId::from_raw(1),
                at: at(7),
            },
        ]);
        assert!(programme_manager_at(&scheduled, P, A, at(6)));
        assert!(!programme_manager_at(&scheduled, P, A, at(7)));
    }

    fn ctx(actor: Actor, now: i64) -> Ctx {
        Ctx {
            now: at(now),
            actor,
            command: CommandId::from_bytes([1; 16]),
            via: Via::Web,
            tenant_admin: false,
            second_tenant_admin: None,
            binds_tenant_admin: false,
        }
    }

    /// I-65: the resolver is the actor's account when it is a programme
    /// manager at that instant. The system and other accounts are refused.
    #[test]
    fn i65_resolver_is_a_named_programme_manager() {
        let state = EngineState::new(
            core(&[grant(1, P, Role::ProgrammeManager, 0)]),
            crate::FindingStore::genesis(),
        );
        assert_eq!(resolver(&state, P, &ctx(Actor::Account(A), 5)), Ok(A));
        assert_eq!(
            resolver(&state, P, &ctx(Actor::Account(ADMIN), 5)),
            Err(BridgeError::NotProgrammeManager)
        );
        assert_eq!(
            resolver(&state, OTHER, &ctx(Actor::Account(A), 5)),
            Err(BridgeError::NotProgrammeManager)
        );
        assert_eq!(
            resolver(&state, P, &ctx(Actor::System(SystemCause::Timeline), 5)),
            Err(BridgeError::NotAnAccount)
        );
    }
}
