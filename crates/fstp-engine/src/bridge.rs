//! The import bridge and the import commands (I-65, M4 design sections
//! 3.3 and 4.2). It is the only place where the import store and the
//! creator meet.
//!
//! # Import commands
//!
//! [`decide_import_command`] routes an `ImportCommand` to
//! `fstp_import::decide_import` over the import store. Both commands need
//! an open draft: a programme with a creator draft that is not active.
//!
//! - `RegisterDocument` (`import.upload`) needs an account with an active
//!   programme manager binding on the draft at that instant
//!   ([`resolver`]), and the account must be the uploader.
//! - `RecordProposals` comes from the system, which ran the proposer. The
//!   engine flags each proposal's profile conflicts against the draft
//!   ([`profile_conflicts`]) and replaces whatever the shell sent. A
//!   conflict is flagged, never adjusted.
//!
//! Neither command's records hold a draft value, so a proposal never
//! alters a draft by itself (I-65). After the driver appends a
//! `RecordProposals` batch, it holds the batch's values in the import
//! store (`ImportStore::hold_recorded`).
//!
//! # Resolution
//!
//! [`resolve_import`] decides a [`BridgeCommand::ResolveImport`] in one
//! entry, with nothing appended on a refusal:
//!
//! 1. [`resolver`]: the actor holds an active programme manager binding on
//!    the draft at `ctx.now` (I-65).
//! 2. `fstp_import::check_resolution`: the proposal exists, belongs to the
//!    programme and is unresolved, `shown` is the stored value's salted
//!    digest, the field is importable, a confirmation names the proposal's
//!    value and an edit another value, and a flagged conflict is
//!    acknowledged.
//! 3. For a confirmation or an edit: the field's strict decoder in the
//!    programme's currency, then `fstp_creator::decide_import_save` with
//!    `base` and `Provenance::Import`. A decoding failure refuses the whole
//!    resolution. The composed core commands are decided in the same
//!    entry, as for a creator save.
//! 4. The entry holds `Import(ProposalResolved)`, then the creator records
//!    and core records of the save. A dismissal holds only the import
//!    record, and its `base` must be the draft's head.
//!
//! The engine fold refuses an entry whose `FieldsSaved` carries import
//! provenance without the matching `ProposalResolved` before it, and an
//! entry whose confirmation or edit saves nothing (crate root).
//!
//! Interim, pending Daniel: an upload needs the same binding as a
//! resolution, and both import commands need an open draft.

use std::cmp::Ordering;

use fstp_creator::{CreatorDecision, DraftRevision, ImportFieldEdit, ValueDigest};
use fstp_domain::command::{Actor, Ctx};
use fstp_domain::id::{AccountId, ContentDigest, ProgrammeId};
use fstp_domain::oracle::{Answers, Query};
use fstp_domain::refusal::{Refusal, RefusalReason, RuleRef};
use fstp_domain::roles::Role;
use fstp_domain::state::State;
use fstp_domain::time::Timestamp;
use fstp_import::{
    AccountRef, ClientResolution, ConflictRule, ImportActor, ImportCommand, ImportProposal,
    ImportProposalId, ImportRefusal, ImportResolution, ProgrammeRef, ResolveRequest, SaltedDigest,
};
use fstp_json::{Object, ToJson, Value};
use fstp_programme::{FieldId, FieldValue};

use crate::{EngineState, Record};

/// A command of the engine bridge (design section 3.3).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum BridgeCommand {
    /// Resolve one import proposal of a draft. One value per resolution:
    /// M4 has no bulk accept (Q30).
    ResolveImport {
        /// The draft programme.
        programme: ProgrammeId,
        /// The proposal.
        proposal: ImportProposalId,
        /// The salted digest of the value the client displayed.
        shown: SaltedDigest,
        /// The client's resolution. Confirm and Edit carry a value,
        /// Dismiss carries none.
        resolution: ClientResolution,
        /// Whether the client acknowledged the flagged profile conflicts.
        conflict_acknowledged: bool,
        /// The draft revision the client saw.
        base: DraftRevision,
    },
}

/// Why a bridge command failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BridgeError {
    /// Kept for the lanes that code against the W0 stub. The bridge of
    /// this crate never returns it.
    NotImplemented(&'static str),
    /// The actor is the system. Only a person resolves an import proposal.
    NotAnAccount,
    /// The actor holds no active programme manager binding on the
    /// programme at that instant (I-65).
    NotProgrammeManager,
}

impl BridgeError {
    /// The engine refusal of this error.
    pub fn refusal(self) -> Refusal {
        match self {
            BridgeError::NotImplemented(_) => {
                Refusal::new(RuleRef::NotImplemented, RefusalReason::NotImplemented)
            }
            BridgeError::NotAnAccount => Refusal::new(RuleRef::Actor, RefusalReason::WrongActor),
            BridgeError::NotProgrammeManager => {
                Refusal::new(RuleRef::I65, RefusalReason::BindingInactive)
            }
        }
    }
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

/// The engine refusal of an import refusal.
pub fn import_refusal(r: ImportRefusal) -> Refusal {
    use ImportRefusal as I;
    use RefusalReason as Why;
    let (rule, why) = match r {
        I::AccountOnly | I::SystemOnly | I::NotTheUploader => (RuleRef::Actor, Why::WrongActor),
        I::DuplicateDocument | I::DuplicateProposal | I::DuplicateText => {
            (RuleRef::Ledger, Why::IdReused)
        }
        I::TextLength
        | I::EmptyBatch
        | I::BatchTooLarge
        | I::ForeignDocument
        | I::NotImportable
        | I::BadEvidence
        | I::BadConflicts => (RuleRef::Input, Why::InvalidValue),
        I::UnknownDocument | I::UnknownProposal => (RuleRef::Input, Why::UnknownEntity),
        I::ForeignProgramme | I::ShownMismatch | I::ConfirmDiffers | I::EditUnchanged => {
            (RuleRef::I65, Why::InvalidValue)
        }
        I::AlreadyResolved | I::ValueUnavailable => (RuleRef::I65, Why::WrongState),
        I::ConflictNotAcknowledged => (RuleRef::I65, Why::GuardFailed),
    };
    Refusal::new(rule, why)
}

/// The domain programme of an import programme reference.
fn programme_of(p: ProgrammeRef) -> ProgrammeId {
    ProgrammeId::from_raw(p.raw())
}

/// The import reference of a domain programme.
fn programme_ref(p: ProgrammeId) -> ProgrammeRef {
    ProgrammeRef::from_raw(p.raw())
}

/// Refuses unless `programme` has a creator draft that is not active.
fn open_draft(state: &EngineState, programme: ProgrammeId) -> Result<(), Refusal> {
    match state.creator.draft(programme) {
        None => Err(Refusal::new(RuleRef::Input, RefusalReason::UnknownEntity)),
        Some(d) if d.active().is_some() => {
            Err(Refusal::new(RuleRef::I65, RefusalReason::WrongState))
        }
        Some(_) => Ok(()),
    }
}

/// Decides one import command over the import store (module
/// documentation). The records hold no draft value (I-65).
pub fn decide_import_command(
    state: &EngineState,
    cmd: &ImportCommand,
    ctx: &Ctx,
) -> Result<Vec<Record>, Refusal> {
    let (cmd, actor) = match cmd {
        ImportCommand::RegisterDocument(doc) => {
            let programme = programme_of(doc.programme);
            open_draft(state, programme)?;
            let account = resolver(state, programme, ctx).map_err(BridgeError::refusal)?;
            (
                cmd.clone(),
                ImportActor::Account(AccountRef::from_raw(account.raw())),
            )
        }
        ImportCommand::RecordProposals {
            document,
            proposals,
        } => {
            if !matches!(ctx.actor, Actor::System(_)) {
                return Err(import_refusal(ImportRefusal::SystemOnly));
            }
            let doc = state
                .import
                .document(*document)
                .ok_or(import_refusal(ImportRefusal::UnknownDocument))?;
            let programme = programme_of(doc.programme);
            open_draft(state, programme)?;
            let flagged = proposals
                .iter()
                .map(|p| ImportProposal {
                    conflicts_with_profile: profile_conflicts(state, programme, p),
                    ..p.clone()
                })
                .collect();
            (
                ImportCommand::RecordProposals {
                    document: *document,
                    proposals: flagged,
                },
                ImportActor::System,
            )
        }
    };
    fstp_import::decide_import(&state.import, &cmd, actor)
        .map(|records| records.into_iter().map(Record::Import).collect())
        .map_err(import_refusal)
}

/// The profile conflicts of `p` against the draft of `programme` at
/// recording (I-50, L-10 shape): a proposed P-05 above the draft's P-58,
/// or a proposed P-58 below the draft's P-05. A draft field counts only
/// once the draft saved it. A value the field's decoder refuses carries
/// no flag, since it can never be confirmed. Amounts in another currency
/// cannot be compared, so they are flagged.
pub fn profile_conflicts(
    state: &EngineState,
    programme: ProgrammeId,
    p: &ImportProposal,
) -> Vec<ConflictRule> {
    let (Some(draft), Some(head)) = (
        state.creator.draft(programme),
        fstp_domain::policy::head(&state.core, programme),
    ) else {
        return Vec::new();
    };
    let decoded =
        fstp_programme::decode_field_value_in(p.field, head.currency, p.value.as_data().as_bytes());
    let saved = |f: FieldId| draft.fields().contains_key(&f);
    let above = |a: fstp_money::NonNegAmount, b: fstp_money::NonNegAmount| {
        a.amount()
            .cmp_same(b.amount())
            .map_or(true, |o| o == Ordering::Greater)
    };
    let conflict = match decoded {
        Ok(FieldValue::P05(v)) => {
            saved(FieldId::P58) && head.live.p58.is_some_and(|ceiling| above(v, ceiling))
        }
        Ok(FieldValue::P58(v)) => saved(FieldId::P05) && above(head.live.p05, v),
        _ => false,
    };
    if conflict {
        vec![ConflictRule::I50]
    } else {
        Vec::new()
    }
}

/// What a resolution decides before the vault answers: the import record
/// and the creator decision of its save, if any.
struct Plan {
    record: fstp_import::ImportRecord,
    save: Option<CreatorDecision>,
}

/// The checks and the save of one resolution, steps 1 to 3 of the module
/// documentation.
fn plan(state: &EngineState, cmd: &BridgeCommand, ctx: &Ctx) -> Result<Plan, Refusal> {
    let BridgeCommand::ResolveImport {
        programme,
        proposal,
        shown,
        resolution,
        conflict_acknowledged,
        base,
    } = cmd;
    let account = resolver(state, *programme, ctx).map_err(BridgeError::refusal)?;
    open_draft(state, *programme)?;
    let checked = fstp_import::check_resolution(
        &state.import,
        &ResolveRequest {
            programme: programme_ref(*programme),
            proposal: *proposal,
            shown: *shown,
            resolution,
            conflict_acknowledged: *conflict_acknowledged,
            by: AccountRef::from_raw(account.raw()),
        },
    )
    .map_err(import_refusal)?;
    let Some(applied) = checked.applied else {
        if state.creator.head(*programme) != Some(*base) {
            return Err(Refusal::new(RuleRef::Input, RefusalReason::WrongState));
        }
        return Ok(Plan {
            record: checked.record,
            save: None,
        });
    };
    let head = fstp_domain::policy::head(&state.core, *programme)
        .ok_or(Refusal::new(RuleRef::Input, RefusalReason::UnknownEntity))?;
    let value = fstp_programme::decode_field_value_in(
        applied.field,
        head.currency,
        applied.value.as_data().as_bytes(),
    )
    .map_err(|_| Refusal::new(RuleRef::I65, RefusalReason::InvalidValue))?;
    let edit = ImportFieldEdit {
        field: applied.field,
        value,
        digest: ValueDigest::new(ContentDigest::from_bytes(applied.digest.bytes())),
        proposal: fstp_creator::ImportProposalId::from_raw(applied.proposal.raw()),
        resolution: match applied.resolution {
            ImportResolution::Confirmed => fstp_creator::ImportResolution::Confirmed,
            ImportResolution::Edited => fstp_creator::ImportResolution::Edited,
            // `check_resolution` applies no value for a dismissal.
            ImportResolution::Dismissed => {
                return Err(Refusal::new(RuleRef::I65, RefusalReason::WrongState));
            }
        },
    };
    let save = fstp_creator::decide_import_save(
        &state.core,
        &state.creator,
        *programme,
        *base,
        &edit,
        ctx,
    )
    .map_err(crate::compose::creator_refusal)?;
    Ok(Plan {
        record: checked.record,
        save: Some(save),
    })
}

/// The vault questions of a bridge command: those of the core commands
/// its save composes. A refusal is left to [`resolve_import`].
pub fn bridge_queries(state: &EngineState, cmd: &BridgeCommand, ctx: &Ctx) -> Vec<Query> {
    let Ok(Plan {
        save: Some(save), ..
    }) = plan(state, cmd, ctx)
    else {
        return Vec::new();
    };
    let mut out: Vec<Query> = Vec::new();
    for c in &save.core {
        if let Ok(qs) = fstp_domain::queries(&state.core, c, ctx) {
            for q in qs {
                if !out.contains(&q) {
                    out.push(q);
                }
            }
        }
    }
    out
}

/// Resolves one import proposal of a draft programme in one entry
/// (module documentation). A refusal appends nothing, so no proposal
/// reaches a draft through another path (I-65).
pub fn resolve_import(
    state: &EngineState,
    cmd: &BridgeCommand,
    ctx: &Ctx,
    answers: &Answers,
) -> Result<Vec<Record>, Refusal> {
    let Plan { record, save } = plan(state, cmd, ctx)?;
    let mut out = vec![Record::Import(record)];
    if let Some(CreatorDecision { records, core }) = save {
        out.extend(records.into_iter().map(Record::Creator));
        let mut scratch = state.core.clone();
        for c in &core {
            if matches!(c, fstp_domain::Command::ActivateProgramme { .. }) {
                return Err(Refusal::new(RuleRef::I66, RefusalReason::WrongActor));
            }
            let records = crate::compose::decide_core(&mut scratch, c, ctx, answers)?;
            out.extend(records.into_iter().map(Record::Core));
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Command forms
// ---------------------------------------------------------------------------

/// Lowercase hexadecimal of a digest.
fn hex(bytes: [u8; 32]) -> Value {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in bytes {
        for nibble in [b >> 4, b & 0x0f] {
            if let Some(d) = DIGITS.get(usize::from(nibble)) {
                s.push(char::from(*d));
            }
        }
    }
    Value::String(s)
}

/// A decimal string.
fn dec(raw: impl ToString) -> Value {
    Value::String(raw.to_string())
}

fn object(members: Vec<(&str, Value)>) -> Value {
    let mut o = Object::with_capacity(members.len());
    for (k, v) in members {
        o.insert(k, v);
    }
    Value::Object(o)
}

/// The JSON form of a bridge command: an object whose member `type` names
/// the variant, with ids as decimal strings and digests as lowercase
/// hexadecimal. A confirmed or edited value is held as its data. The
/// form names one command, for a step-up digest or a log. No decoder
/// reads it back yet (pending the cell codec, lead).
impl ToJson for BridgeCommand {
    fn to_json(&self) -> Value {
        let BridgeCommand::ResolveImport {
            programme,
            proposal,
            shown,
            resolution,
            conflict_acknowledged,
            base,
        } = self;
        let resolution = match resolution {
            ClientResolution::Confirm { value, digest } => object(vec![
                ("digest", hex(digest.bytes())),
                ("kind", Value::String("Confirm".to_owned())),
                ("value", value.data_value()),
            ]),
            ClientResolution::Edit { value, digest } => object(vec![
                ("digest", hex(digest.bytes())),
                ("kind", Value::String("Edit".to_owned())),
                ("value", value.data_value()),
            ]),
            ClientResolution::Dismiss => {
                object(vec![("kind", Value::String("Dismiss".to_owned()))])
            }
        };
        object(vec![
            (
                "base",
                object(vec![
                    ("entry", dec(base.entry().raw())),
                    ("seq", dec(base.seq())),
                ]),
            ),
            ("conflict_acknowledged", Value::Bool(*conflict_acknowledged)),
            ("programme", dec(programme.raw())),
            ("proposal", dec(proposal.raw())),
            ("resolution", resolution),
            ("shown", hex(shown.bytes())),
            ("type", Value::String("ResolveImport".to_owned())),
        ])
    }
}

/// The JSON form of an import command, in the same shape as
/// [`BridgeCommand`]'s. The document and the recorded proposals take the
/// form of the import record codec, and a batch's values follow in
/// proposal order.
pub fn import_command_json(cmd: &ImportCommand) -> Value {
    match cmd {
        ImportCommand::RegisterDocument(doc) => object(vec![
            (
                "record",
                fstp_import::ImportRecord::DocumentRegistered(*doc).to_json(),
            ),
            ("type", Value::String("RegisterDocument".to_owned())),
        ]),
        ImportCommand::RecordProposals {
            document,
            proposals,
        } => object(vec![
            (
                "record",
                fstp_import::ImportRecord::ProposalsRecorded {
                    document: *document,
                    proposals: proposals.iter().map(ImportProposal::recorded).collect(),
                }
                .to_json(),
            ),
            ("type", Value::String("RecordProposals".to_owned())),
            (
                "values",
                Value::Array(proposals.iter().map(|p| p.value.data_value()).collect()),
            ),
        ]),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use fstp_domain::command::SystemCause;
    use fstp_domain::id::{BindingId, CommandId};
    use fstp_domain::record::{BindingEnded, BindingGranted, BindingSuspended};
    use fstp_domain::roles::{BindingScope, CoolingOff};
    use fstp_domain::{Record as CoreRecord, Via};
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

    fn grant(binding: u128, programme: ProgrammeId, role: Role, start: i64) -> CoreRecord {
        CoreRecord::BindingGranted(BindingGranted {
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
    fn core(records: &[CoreRecord]) -> State {
        let mut s = State::genesis();
        let mut all = vec![
            CoreRecord::ProgrammeCreated {
                programme: P,
                currency: Currency::Eur,
                by: ADMIN,
            },
            CoreRecord::ProgrammeCreated {
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
            CoreRecord::BindingEnded(BindingEnded {
                binding: BindingId::from_raw(1),
                at: at(1),
                barred_through: 1,
                p12: CoolingOff(1),
            }),
        ]);
        assert!(!programme_manager_at(&ended, P, A, at(5)));
        let suspended = core(&[
            grant(1, P, Role::ProgrammeManager, 0),
            CoreRecord::BindingSuspended(BindingSuspended {
                binding: BindingId::from_raw(1),
                rule: RuleRef::I01,
                epoch: fstp_domain::id::VaultEpoch::from_raw(1),
            }),
        ]);
        assert!(!programme_manager_at(&suspended, P, A, at(5)));
        let scheduled = core(&[
            grant(1, P, Role::ProgrammeManager, 0),
            CoreRecord::BindingEndScheduled {
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
