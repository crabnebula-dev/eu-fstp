//! The activation step of every setup, and the core I-67 builder reference (M4 design section 3.4, D1, D2 and D8).
//!
//! Lane W1b (L-DOM) owned this file until step W2e. The engine lane
//! (m4eng) holds it now (M4 design section 13).
//!
//! - Since D1, `CreateProgramme` creates a programme in `Draft` status.
//!   Nothing runs on a draft beside policy edits and programme manager
//!   grants (D3). So every setup activates each programme right after
//!   creating it, through [`activation_step`] or [`activate`].
//! - Since D2e holds for every programme (M4 design section 15.0,
//!   Daniel's answer of 2026-10-30), the engine refuses every core
//!   `ActivateProgramme` through `execute` with I-66, and its fold
//!   refuses every `ProgrammeActivated` without the creator's
//!   `ActivationApproved` in the same entry. So a setup step names the
//!   core `ActivateProgramme`, and [`run_core`] appends the paired entry
//!   of a creator `ApproveActivation` for it: the approval of the draft's
//!   head revision, then the core records of the activation that
//!   `fstp_engine::compose::activate_command` builds from it.
//! - A setup `CreateProgramme` becomes the entry of a creator `OpenDraft`
//!   in the same way, so every setup programme has a draft. The setups
//!   name their own policies, which the creator's blank spec cannot
//!   express, so they cannot run the creator commands themselves.
//! - [`reference_builders`] is the core builder set, folded from raw
//!   records and written from `SPEC/02-domain/invariants.md` I-67 and the
//!   interim reading of Q1 (M4 design sections 3.2 and 12.3): the opener,
//!   every policy author while the programme is a draft, and every grantor
//!   of a binding on the draft. The creator adds its own builders through
//!   `creator_builders`. It never reads a production structure.
//! - [`forge_programme_activated`] builds the `ProgrammeActivated` record
//!   through the record codec, because its payload has private fields
//!   (D2). Reference runs use it, and a test checks that it equals what
//!   production records.
//!
//! The approver of every setup is [`APPROVER`], a tenant admin who built
//! nothing. Readings marked as test-author choices fill gaps in the
//! design, so the implementer can match them or raise them with Daniel.

use std::collections::BTreeSet;

use fstp_creator::{CreatorRecord, DraftRevision};
use fstp_domain::command::{Actor, Command, Ctx};
use fstp_domain::id::{AccountId, DecisionId, ProgrammeId};
use fstp_domain::oracle::Answers;
use fstp_domain::policy::PolicyVersion;
use fstp_domain::policy::activation::ReportDigest;
use fstp_domain::record::Record;
use fstp_domain::refusal::{Refusal, RefusalReason, RuleRef};
use fstp_domain::time::Timestamp;
use fstp_engine::{Decider, Engine, EngineState, ExecError, IdentityOracle, OpenError};
use fstp_ledger::{AppendError, MemStore, RecordStore, Seq};

use crate::r#gen::roster::{ADMIN_2, Flags, Step};
use crate::scenario::Scenario;

/// An engine record: the envelope of a core, finding, creator, import or
/// tenant record.
type EngineRecord = fstp_engine::Record;

/// The second tenant admin who approves every setup's activation. It is
/// [`crate::r#gen::roster::ADMIN_2`], a verified tenant admin with its own
/// identity, who never creates a programme, edits a policy or grants a
/// binding in a setup.
pub const APPROVER: AccountId = ADMIN_2;

/// The report digest every setup step's core `ActivateProgramme` names.
/// The engine refuses that command through `execute` (D2e). The paired
/// entry of [`run_core`] records the creator's report instead
/// ([`setup_report`]), so no engine ledger holds this value.
pub const SETUP_REPORT: [u8; 32] = [0xa5; 32];

/// The draft revision every setup step's core `ActivateProgramme` names:
/// the revision of a draft right after its opening, when a setup
/// activates it. The paired entry of [`run_core`] records the draft's
/// head revision whatever the step names.
pub const SETUP_REVISION: u32 = 1;

/// The activation decision of `programme`: 77_000 plus its number, so it
/// never meets the decision ids of calls, knock-outs, admissions or
/// cut-offs in the setups.
pub fn activation_decision(programme: ProgrammeId) -> DecisionId {
    DecisionId::from_raw(77_000u128.saturating_add(programme.raw()))
}

/// The core `ActivateProgramme` of `programme` with no creator builders,
/// as every setup issues it until D2e.
pub fn activate_command(programme: ProgrammeId) -> Command {
    activate_with(programme, BTreeSet::new())
}

/// The core `ActivateProgramme` of `programme` with `creator_builders`.
pub fn activate_with(programme: ProgrammeId, creator_builders: BTreeSet<AccountId>) -> Command {
    Command::ActivateProgramme {
        programme,
        decision: activation_decision(programme),
        report: ReportDigest::from_bytes(SETUP_REPORT),
        revision: SETUP_REVISION,
        creator_builders,
    }
}

/// The setup step that activates `programme`: [`activate_command`] by
/// [`APPROVER`], whom the shell attests as a tenant admin.
pub fn activation_step(programme: ProgrammeId) -> Step {
    Step::by(APPROVER, Flags::ADMIN, activate_command(programme))
}

/// Activates `programme` on `scenario` at `now`, approved by `approver`,
/// whom the shell attests as a tenant admin (M4 design section 3.4, D8).
pub fn activate(
    scenario: &mut Scenario,
    programme: ProgrammeId,
    approver: AccountId,
    now: Timestamp,
) -> Result<Seq, ExecError> {
    let mut ctx = scenario.ctx(now, Actor::Account(approver));
    ctx.tenant_admin = true;
    scenario.run_core(&activate_command(programme), ctx)
}

/// The core builder set of `programme`, folded from `records` in ledger
/// order up to its activation (I-67, Q1 interim reading):
///
/// - the account that created it (`ProgrammeCreated::by`);
/// - every author of a policy version of it while it is a draft;
/// - every account that granted a binding in it while it is a draft.
///
/// Records after the programme's `ProgrammeActivated` add nobody, since
/// the set is fixed when the approval is checked. Test-author choice: a
/// grantee is not a builder for being granted, only for what it then
/// authors (Q1 names grantors, not grantees).
pub fn reference_builders(records: &[Record], programme: ProgrammeId) -> BTreeSet<AccountId> {
    let mut out = BTreeSet::new();
    for r in records {
        match r {
            Record::ProgrammeCreated {
                programme: p, by, ..
            } if *p == programme => {
                out.insert(*by);
            }
            Record::PolicyVersionRecorded { version, author } if version.programme == programme => {
                out.insert(*author);
            }
            Record::BindingGranted(g) if g.programme == programme => {
                out.insert(g.granted_by);
            }
            Record::ProgrammeActivated(a) if a.programme() == programme => break,
            _ => {}
        }
    }
    out
}

/// Whether `records` hold the activation of `programme`.
pub fn activated(records: &[Record], programme: ProgrammeId) -> bool {
    records
        .iter()
        .any(|r| matches!(r, Record::ProgrammeActivated(a) if a.programme() == programme))
}

/// A `ProgrammeActivated` record with these fields, built through the
/// record codec because its payload has private fields (D2), at schema
/// version 1.
///
/// The JSON form follows the codec rules of `fstp_domain::codec`: ids as
/// decimal strings, the digest as lowercase hexadecimal, the builder set
/// as an ascending list, the revision and the rules version as numbers,
/// and no currency member, since the record holds no amount.
pub fn forge_programme_activated(
    programme: ProgrammeId,
    decision: DecisionId,
    report: [u8; 32],
    revision: u32,
    approver: AccountId,
    builders: &BTreeSet<AccountId>,
    rules: u16,
) -> Result<Record, String> {
    let hex: String = report.iter().map(|b| format!("{b:02x}")).collect();
    let set: Vec<String> = builders
        .iter()
        .map(|a| format!("\"{}\"", a.raw()))
        .collect();
    let text = format!(
        "{{\"approver\":\"{}\",\"builders\":[{}],\"decision\":\"{}\",\"programme\":\"{}\",\
         \"report\":\"{hex}\",\"revision\":{revision},\"rules\":{rules},\
         \"type\":\"ProgrammeActivated\"}}",
        approver.raw(),
        set.join(","),
        decision.raw(),
        programme.raw(),
    );
    let v = fstp_json::parse(text.as_bytes()).map_err(|e| format!("json: {e:?}"))?;
    fstp_domain::codec::record_from_json_at(fstp_ledger::SCHEMA_V1, &v)
        .map_err(|e| format!("the record codec refuses the ProgrammeActivated form {text}: {e:?}"))
}

// ---------------------------------------------------------------------------
// Draft scenarios for the activation tests
// ---------------------------------------------------------------------------

/// A third tenant admin, verified with its own identity, for the I-67
/// tests: an approver when [`APPROVER`] has become a builder.
pub const ADMIN_3: AccountId = AccountId::from_raw(5);

/// A verified account that shares [`crate::r#gen::roster::ADMIN`]'s
/// identity: a second account of the opener (corpus variant "Sybil",
/// Q2). The tests attest it as a tenant admin.
pub const SYBIL_OF_ADMIN: AccountId = AccountId::from_raw(8);

/// The identity of [`crate::r#gen::roster::ADMIN`] in
/// [`crate::r#gen::roster::add_staff`].
pub const ADMIN_IDENTITY: u64 = 901;

/// The vault of the activation tests: the staff of
/// [`crate::r#gen::roster::add_staff`], [`ADMIN_3`] with its own verified
/// identity, and [`SYBIL_OF_ADMIN`] verified under the opener's identity.
pub fn activation_truth() -> crate::vault::GroundTruth {
    let mut t = crate::vault::GroundTruth::new();
    crate::r#gen::roster::add_staff(&mut t);
    t.set_identity(ADMIN_3, crate::vault::IdentityTag::new(905));
    t.verify(ADMIN_3);
    t.set_identity(
        SYBIL_OF_ADMIN,
        crate::vault::IdentityTag::new(ADMIN_IDENTITY),
    );
    t.verify(SYBIL_OF_ADMIN);
    t
}

/// The first policy version of `programme` in the setups.
pub fn draft_version(programme: ProgrammeId) -> Result<fstp_domain::policy::PolicyVersion, String> {
    crate::r#gen::roster::SodSetup::one(1, &[]).version(programme)
}

/// A scenario over `truth` in which [`crate::r#gen::roster::ADMIN`] has
/// created `programme` at [`crate::r#gen::roster::T0`] and nothing else
/// happened, so the programme is a draft (D1).
pub fn draft_scenario(
    truth: crate::vault::GroundTruth,
    programme: ProgrammeId,
) -> Result<Scenario, String> {
    let mut s = Scenario::new(truth).map_err(|e| format!("open: {e:?}"))?;
    let create = Step::by(
        crate::r#gen::roster::ADMIN,
        Flags::ADMIN,
        Command::CreateProgramme {
            policy: Box::new(draft_version(programme)?),
        },
    );
    match crate::r#gen::review::run_records(&mut s, &create, crate::r#gen::roster::T0)? {
        Ok(_) => Ok(s),
        Err(r) => Err(format!("CreateProgramme refused: {r}")),
    }
}

/// The record a correct engine appends for [`activation_step`] of
/// `programme` approved at the draft revision `revision`, whose builders
/// are `builders`, under `rules`. Since D2e the record names the
/// creator's report and revision ([`run_core`]), so its report is
/// [`setup_report`] of `revision` and its revision is that revision's
/// count.
pub fn setup_activation_record(
    programme: ProgrammeId,
    revision: DraftRevision,
    builders: &BTreeSet<AccountId>,
    rules: u16,
) -> Result<Record, String> {
    forge_programme_activated(
        programme,
        activation_decision(programme),
        setup_report(programme, revision)?.bytes(),
        revision.seq(),
        APPROVER,
        builders,
        rules,
    )
}

/// The report reference the core activation of a setup records when the
/// draft of `programme` is approved at `revision`:
/// `fstp_engine::compose::report_ref` of the empty report of that
/// revision, which [`activation_records`] approves.
pub fn setup_report(
    programme: ProgrammeId,
    revision: DraftRevision,
) -> Result<ReportDigest, String> {
    match approval_record(
        programme,
        revision,
        activation_decision(programme),
        APPROVER,
        &BTreeSet::new(),
    )? {
        CreatorRecord::ActivationApproved(a) => Ok(fstp_engine::compose::report_ref(a.report())),
        other => Err(format!("not an approval: {other:?}")),
    }
}

/// The core `ActivateProgramme` `cmd` as the paired entry of [`run_core`]
/// composes it when the draft's head revision is `head`: the report
/// reference of [`setup_report`] and the revision count of `head` in
/// place of the step's own. A reference that expects the records of a
/// setup activation reads them from this command. Any other command is
/// returned unchanged.
pub fn as_composed(cmd: &Command, head: DraftRevision) -> Result<Command, String> {
    match cmd {
        Command::ActivateProgramme {
            programme,
            decision,
            creator_builders,
            ..
        } => Ok(Command::ActivateProgramme {
            programme: *programme,
            decision: *decision,
            report: setup_report(*programme, head)?,
            revision: head.seq(),
            creator_builders: creator_builders.clone(),
        }),
        other => Ok(other.clone()),
    }
}

// ---------------------------------------------------------------------------
// The paired entries of the setups (D2e for every programme)
// ---------------------------------------------------------------------------

/// The account of a setup context, or the refusal of a system actor.
fn account_of(ctx: &Ctx) -> Result<AccountId, ExecError> {
    match ctx.actor {
        Actor::Account(a) => Ok(a),
        Actor::System(_) => Err(ExecError::Refused(Refusal::new(
            RuleRef::Actor,
            RefusalReason::WrongActor,
        ))),
    }
}

/// The answers of `oracle` to the vault questions of the core `cmd`.
fn core_answers<O: IdentityOracle>(
    oracle: &O,
    state: &EngineState,
    cmd: &Command,
    ctx: &Ctx,
) -> Result<Answers, ExecError> {
    let mut answers = Answers::new();
    for q in fstp_domain::queries(&state.core, cmd, ctx).map_err(ExecError::Refused)? {
        let a = oracle.ask(&q).map_err(|_| {
            ExecError::Refused(Refusal::new(
                RuleRef::OracleDown,
                RefusalReason::OracleUnavailable,
            ))
        })?;
        answers.insert(q, a);
    }
    Ok(answers)
}

/// The records of the core `cmd`, decided on `state` with the answers of
/// `oracle`.
fn core_records<O: IdentityOracle>(
    oracle: &O,
    state: &EngineState,
    cmd: &Command,
    ctx: &Ctx,
) -> Result<Vec<EngineRecord>, ExecError> {
    let answers = core_answers(oracle, state, cmd, ctx)?;
    let records =
        fstp_domain::decide(&state.core, cmd, ctx, &answers).map_err(ExecError::Refused)?;
    Ok(records.into_iter().map(EngineRecord::Core).collect())
}

/// The entry a creator `OpenDraft` appends for a programme whose first
/// policy version is `policy` (M4 design section 3.2): the creator's
/// `DraftOpened` by the context's account, then the records of the core
/// `CreateProgramme`, as `fstp_engine::compose` composes them.
///
/// The creator compiles the policy from a funder profile's blank spec.
/// The setups name their own policy instead, which the core checks as it
/// checks every `CreateProgramme`. The draft's profile is the policy's
/// P-53.
pub fn open_records<O: IdentityOracle>(
    state: &EngineState,
    oracle: &O,
    policy: &PolicyVersion,
    ctx: &Ctx,
) -> Result<Vec<EngineRecord>, ExecError> {
    let by = account_of(ctx)?;
    let create = Command::CreateProgramme {
        policy: Box::new(policy.clone()),
    };
    let core = core_records(oracle, state, &create, ctx)?;
    let mut out = vec![EngineRecord::Creator(CreatorRecord::DraftOpened {
        programme: policy.programme,
        profile: policy.frozen.p53.clone(),
        by,
    })];
    out.extend(core);
    Ok(out)
}

/// The creator's `ActivationApproved` of `programme` at `revision` by
/// `approver` under `decision`, checked against `builders`, with an empty
/// report of that revision. Only a clearance builds one in code, so it is
/// decoded from its stored form, as `fstp-engine/tests/m4_envelope.rs`
/// builds its approvals.
pub fn approval_record(
    programme: ProgrammeId,
    revision: DraftRevision,
    decision: DecisionId,
    approver: AccountId,
    builders: &BTreeSet<AccountId>,
) -> Result<CreatorRecord, String> {
    let rev = format!(
        "{{\"entry\":\"{}\",\"seq\":\"{}\"}}",
        revision.entry().raw(),
        revision.seq()
    );
    let set: Vec<String> = builders
        .iter()
        .map(|a| format!("\"{}\"", a.raw()))
        .collect();
    let text = format!(
        "{{\"approver\":\"{}\",\"builders\":[{}],\"decision\":\"{}\",\"kind\":\"ActivationApproved\",\
         \"programme\":\"{}\",\"report\":{{\"programme\":\"{}\",\"revision\":{rev},\"rows\":[]}},\
         \"revision\":{rev}}}",
        approver.raw(),
        set.join(","),
        decision.raw(),
        programme.raw(),
        programme.raw(),
    );
    fstp_creator::decode_record(text.as_bytes())
        .map_err(|e| format!("the creator codec refuses the approval {text}: {e:?}"))
}

/// The entry a creator `ApproveActivation` appends for the core
/// activation `cmd` by the context's account (M4 design section 3.4, D2e):
/// the creator's `ActivationApproved`, then the records of the core
/// `ActivateProgramme` that `fstp_engine::compose::activate_command`
/// builds from it.
///
/// - The approval names the draft's head revision and an empty report of
///   it, as the creator's clean report of a setup draft. So the core
///   record's report reference and revision come from the draft, as on
///   the creator path, and never from `cmd`.
/// - Its decision and approver are those of `cmd` and the context. Its
///   builders are the draft's builders plus the creator builders `cmd`
///   names, so the core guard checks both again (I-67).
/// - The creator's own checks (a live request, a clean report, verified
///   builders) are not run: the setups name no creator step. The core
///   guards run as on the creator path, and refuse what they refuse there.
/// - A programme with no draft has no approval, so its activation is
///   refused with I-66, as the engine refuses it.
pub fn activation_records<O: IdentityOracle>(
    state: &EngineState,
    oracle: &O,
    cmd: &Command,
    ctx: &Ctx,
) -> Result<Vec<EngineRecord>, ExecError> {
    let Command::ActivateProgramme {
        programme,
        decision,
        creator_builders,
        ..
    } = cmd
    else {
        return Err(ExecError::Refused(Refusal::new(
            RuleRef::I66,
            RefusalReason::GuardFailed,
        )));
    };
    let approver = account_of(ctx)?;
    let (Some(draft), Some(head)) = (
        state.creator.draft(*programme),
        state.creator.head(*programme),
    ) else {
        return Err(ExecError::Refused(Refusal::new(
            RuleRef::I66,
            RefusalReason::GuardFailed,
        )));
    };
    let mut builders = draft.builders().clone();
    builders.extend(creator_builders.iter().copied());
    let approved = approval_record(*programme, head, *decision, approver, &builders)
        .map_err(|_| ExecError::Unfoldable(fstp_domain::FoldError::Inconsistent))?;
    let CreatorRecord::ActivationApproved(a) = &approved else {
        return Err(ExecError::Unfoldable(fstp_domain::FoldError::Inconsistent));
    };
    let core = core_records(
        oracle,
        state,
        &fstp_engine::compose::activate_command(a),
        ctx,
    )?;
    let mut out = vec![EngineRecord::Creator(approved)];
    out.extend(core);
    Ok(out)
}

/// The engine error of a fold refusal of a composed entry: a time before
/// the ledger's latest is the engine's clock refusal (design section
/// 2.2), any other is an unfoldable batch.
fn fold_error(e: fstp_domain::FoldError) -> ExecError {
    match e {
        fstp_domain::FoldError::TimeBackwards => {
            ExecError::Refused(Refusal::new(RuleRef::Ledger, RefusalReason::ClockBackwards))
        }
        other => ExecError::Unfoldable(other),
    }
}

/// Appends `records` to `engine` as one entry under the context's command
/// id and time, and folds it.
///
/// The batch is folded on a copy of the state first, as the driver does,
/// so an entry the fold refuses is never appended. The engine is then
/// opened again over its store, which replays the store from genesis.
pub fn append_entry<O, D>(
    engine: &mut Engine<MemStore<EngineRecord>, O, D>,
    ctx: &Ctx,
    records: Vec<EngineRecord>,
) -> Result<Seq, ExecError>
where
    O: IdentityOracle + Clone,
    D: Decider + Clone,
{
    let command = ctx.command.bytes();
    let mut next = engine.state().clone();
    let mut seq = engine.head();
    for r in &records {
        seq = Seq::from_raw(seq.raw().saturating_add(1));
        fstp_engine::apply_in(&mut next, seq, ctx.now, Some(command), r).map_err(fold_error)?;
    }
    fstp_engine::finish(&mut next).map_err(fold_error)?;
    let head = engine.head();
    let (mut store, oracle, decider) = engine.clone().into_parts();
    let at = match store.append(head, ctx.now.micros(), command, records) {
        Ok(at) => at,
        Err(AppendError::DuplicateCommand { at }) => return Err(ExecError::Duplicate { at }),
        Err(AppendError::StaleHead { .. }) => return Err(ExecError::Contended),
        Err(AppendError::Store(e)) => return Err(ExecError::Store(e)),
    };
    *engine = Engine::open_with(store, oracle, decider).map_err(|e| match e {
        OpenError::Store(e) => ExecError::Store(e),
        OpenError::Fold(e) => ExecError::Fold(e),
    })?;
    Ok(at)
}

/// Runs the core command `cmd` of a setup on `engine` with `ctx`.
///
/// Since D2e holds for every programme (M4 design section 15.0, Daniel's
/// answer of 2026-10-30), only the creator's approval activates a
/// programme, and only a programme with a creator draft can be approved.
/// So the test kit appends the entries the creator path appends, as
/// `fstp_engine::compose` composes them:
///
/// - a `CreateProgramme` becomes the entry of a creator `OpenDraft`
///   ([`open_records`]);
/// - an `ActivateProgramme` becomes the entry of a creator
///   `ApproveActivation` ([`activation_records`]);
/// - every other command runs through `Engine::execute`.
///
/// Before a composed entry the vault change is processed, as the driver
/// processes it, and a reserved command id is refused. The core decides
/// the composed core command on the current state, so every core guard
/// runs as on the creator path.
pub fn run_core<O, D>(
    engine: &mut Engine<MemStore<EngineRecord>, O, D>,
    cmd: &Command,
    ctx: Ctx,
) -> Result<Seq, ExecError>
where
    O: IdentityOracle + Clone,
    D: Decider + Clone,
{
    let compose = matches!(
        cmd,
        Command::CreateProgramme { .. } | Command::ActivateProgramme { .. }
    );
    if !compose {
        return engine.execute(fstp_engine::Command::Core(cmd.clone()), ctx);
    }
    if fstp_engine::is_reserved_command_id(ctx.command) {
        return Err(ExecError::ReservedCommandId);
    }
    engine.sync_vault(ctx)?;
    if ctx.now < engine.state().now_floor() {
        return Err(fold_error(fstp_domain::FoldError::TimeBackwards));
    }
    let records = match cmd {
        Command::CreateProgramme { policy } => {
            open_records(engine.state(), engine.oracle(), policy, &ctx)?
        }
        _ => activation_records(engine.state(), engine.oracle(), cmd, &ctx)?,
    };
    append_entry(engine, &ctx, records)
}
