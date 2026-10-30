//! The activation step of every setup, and the core I-67 builder reference (M4 design section 3.4, D1, D2 and D8).
//!
//! Lane W1b (L-DOM) owned this file until step W2e. The engine lane
//! (m4eng) holds it now (M4 design section 13).
//!
//! - Since D1, `CreateProgramme` creates a programme in `Draft` status.
//!   Nothing runs on a draft beside policy edits and programme manager
//!   grants (D3). So every setup activates each programme right after
//!   creating it, through [`activation_step`] or [`activate`].
//! - Activation is the core `ActivateProgramme` by a second tenant admin
//!   through `Scenario::execute`. Since D2e the engine refuses that path
//!   for a programme with a creator draft, and folds its activation only
//!   with the creator's approval. A setup programme comes from a core
//!   `CreateProgramme` and has no draft, so the engine still accepts it
//!   (interim, pending Daniel). [`activate`] switches to the creator's
//!   `ApproveActivation` once `fstp_creator::decide_creator` opens drafts
//!   (D8 sequencing, step 2).
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

use fstp_domain::command::{Actor, Command};
use fstp_domain::id::{AccountId, DecisionId, ProgrammeId};
use fstp_domain::policy::activation::ReportDigest;
use fstp_domain::record::Record;
use fstp_domain::time::Timestamp;
use fstp_engine::ExecError;
use fstp_ledger::Seq;

use crate::r#gen::roster::{ADMIN_2, Flags, Step};
use crate::scenario::Scenario;

/// The second tenant admin who approves every setup's activation. It is
/// [`crate::r#gen::roster::ADMIN_2`], a verified tenant admin with its own
/// identity, who never creates a programme, edits a policy or grants a
/// binding in a setup.
pub const APPROVER: AccountId = ADMIN_2;

/// The report digest every setup activation names. The core never checks
/// it; the engine pairs it with the creator's report once D2e lands.
pub const SETUP_REPORT: [u8; 32] = [0xa5; 32];

/// The draft revision every setup activation names.
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
    scenario.execute(fstp_engine::Command::Core(activate_command(programme)), ctx)
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
/// `programme`, whose builders are `builders`, under `rules`.
pub fn setup_activation_record(
    programme: ProgrammeId,
    builders: &BTreeSet<AccountId>,
    rules: u16,
) -> Result<Record, String> {
    forge_programme_activated(
        programme,
        activation_decision(programme),
        SETUP_REPORT,
        SETUP_REVISION,
        APPROVER,
        builders,
        rules,
    )
}
