//! The cell of the creator path tests (crate documentation): the core and
//! creator states, a ledger position, the shell environment and a vault.
//!
//! Every value is synthetic. The cast holds no person.

use std::collections::{BTreeMap, BTreeSet};

use fstp_creator::{
    ActivationApproved, CheckId, CheckSubject, CreatorCommand, CreatorInputs, CreatorRecord,
    CreatorRefusal, CreatorState, DraftRevision, FieldEdit, PortPresence, ProbeSet, Provenance,
    SodPreview, Theme, ValidationReport, ValueDigest, VaultChecks, WarningKey, decide_creator,
    validate, vault_questions,
};
use fstp_domain::Command;
use fstp_domain::command::{Actor, Ctx, Via};
use fstp_domain::id::{
    AccountId, BindingId, CommandId, ContentDigest, DecisionId, PolicyVersionId, ProgrammeId,
    TextId, TextRef, VaultEpoch,
};
use fstp_domain::oracle::{Answer, Answers, Query};
use fstp_domain::policy::PolicyVersion;
use fstp_domain::policy::activation::ReportDigest as CoreReportDigest;
use fstp_domain::programme::{ProgrammeStatus, programme_status};
use fstp_domain::record::Record;
use fstp_domain::refusal::{Refusal, RefusalReason, RuleRef};
use fstp_domain::roles::Role;
use fstp_domain::state::State;
use fstp_domain::time::Timestamp;
use fstp_guide::{
    FunderProfile as GuideProfile, HORIZON_EUROPE, ProfileError, ProfileFiles, ProfileSource,
    ShippedProfiles,
};
use fstp_ledger::Seq;
use fstp_programme::{
    CompileIds, Field, FieldId, FieldValue, FunderProfile, ProgrammeSpec, compile,
    decode_field_value, supersafe_fixture,
};

// ---------------------------------------------------------------------------
// The synthetic cast
// ---------------------------------------------------------------------------

/// The draft programme.
pub(crate) const P: ProgrammeId = ProgrammeId::from_raw(7);
/// The first policy version `OpenDraft` names.
pub(crate) const V1: PolicyVersionId = PolicyVersionId::from_raw(70);
/// The tenant admin who opens the draft.
pub(crate) const TA: AccountId = AccountId::from_raw(0xA1);
/// The second tenant admin, who builds nothing and approves.
pub(crate) const TB: AccountId = AccountId::from_raw(0xA2);
/// A third tenant admin.
pub(crate) const TC: AccountId = AccountId::from_raw(0xA3);
/// The programme manager who builds the draft.
pub(crate) const M1: AccountId = AccountId::from_raw(0xB1);
/// A second programme manager.
pub(crate) const M2: AccountId = AccountId::from_raw(0xB2);
/// An invited account.
pub(crate) const OUT: AccountId = AccountId::from_raw(0xC1);

/// The accounts the shell attests as tenant admins.
pub(crate) const ADMINS: [AccountId; 3] = [TA, TB, TC];

/// The wording the synthetic profile puts where the shipped Guide holds a
/// legal marker. It is not the testkit's marker (rule A9b).
pub(crate) const SYNTHETIC_WORDING: &str =
    "Synthetic wording for the creator path tests. Not legal text.";

// ---------------------------------------------------------------------------
// Profiles and the Guide
// ---------------------------------------------------------------------------

/// A profile source over one Guide text, as a test source (rule A9b).
struct OneGuide(String);

impl ProfileSource for OneGuide {
    fn files(&self, _name: &str) -> Result<ProfileFiles<'_>, ProfileError> {
        Ok(ProfileFiles {
            guide: self.0.as_bytes(),
        })
    }
}

/// The shipped Horizon Europe profile. Its legal wording is pending (Q6).
pub(crate) fn shipped_profile() -> GuideProfile {
    ShippedProfiles.profile(HORIZON_EUROPE).unwrap()
}

/// The shipped Horizon Europe Guide with every legal marker line replaced
/// by [`SYNTHETIC_WORDING`], so its wording counts as approved. Every
/// section and placeholder of the shipped template stays.
pub(crate) fn approved_profile() -> GuideProfile {
    let shipped = ShippedProfiles.files(HORIZON_EUROPE).unwrap();
    let text = std::str::from_utf8(shipped.guide).unwrap();
    let mut out = String::new();
    for line in text.lines() {
        if line.starts_with(fstp_guide::LEGAL_MARKER) {
            out.push_str(SYNTHETIC_WORDING);
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    let p = OneGuide(out).profile(HORIZON_EUROPE).unwrap();
    assert!(
        !p.legal_wording_pending(),
        "the synthetic profile still holds a legal marker"
    );
    p
}

/// Whether the Guide API parses and renders the template of `profile`.
/// Until lane m4guide lands, `fstp_guide::parse_template` refuses with
/// `NotImplemented`, and the Guide checks must fail closed.
pub(crate) fn guide_works(profile: &GuideProfile) -> bool {
    fstp_guide::parse_template(profile.guide_template().as_bytes())
        .and_then(|t| fstp_guide::render(&t))
        .is_ok()
}

/// The checks that need the Guide API (design 3.2: `GuideSectionMissing`
/// for I-52 and `GuideBindingUnresolved` for I-51).
pub(crate) const GUIDE_CHECKS: [CheckId; 2] = [
    CheckId::GuideSectionMissing,
    CheckId::GuideBindingUnresolved,
];

// ---------------------------------------------------------------------------
// The shell environment and the vault
// ---------------------------------------------------------------------------

/// The shell facts of a cell where every check that does not need the
/// Guide can clear: every probe passes, the three admins are attested,
/// the Q35 vault answers are yes, a pre-check port exists (the e2e cell's
/// fake port, design 3.10), the default theme, and the approved synthetic
/// profile.
pub(crate) fn clean_env() -> CreatorInputs {
    CreatorInputs {
        unresolved_imports: 0,
        probes: ProbeSet::passing(),
        sod: SodPreview::default(),
        vault: VaultChecks {
            is_verified: BTreeMap::new(),
            same_identity: BTreeMap::new(),
            exclusion_classes_known: Some(true),
            proximity_lists_declared: Some(true),
        },
        tenant_admins: ADMINS.into_iter().collect(),
        ports: PortPresence {
            precheck: true,
            score_tools: false,
        },
        theme: Theme::m4_default(),
        profile: Some(approved_profile()),
    }
}

/// A vault where every account is verified with its own identity, no
/// conflict or exclusion holds and every cap is kept, except for the
/// accounts and pairs it names.
#[derive(Clone, Debug, Default)]
pub(crate) struct Vault {
    /// Accounts the vault does not verify.
    pub(crate) unverified: BTreeSet<AccountId>,
    /// Pairs of accounts with one verified identity (T-SOD-SYBIL).
    pub(crate) sybil: BTreeSet<(AccountId, AccountId)>,
}

impl Vault {
    fn same(&self, a: AccountId, b: AccountId) -> bool {
        a != b && (self.sybil.contains(&(a, b)) || self.sybil.contains(&(b, a)))
    }

    /// The answer to `q`.
    pub(crate) fn answer(&self, q: &Query) -> Answer {
        let holds = match q {
            Query::IsVerified { account } => !self.unverified.contains(account),
            Query::SameIdentityAsAny { subject, others } => {
                others.iter().any(|o| self.same(*subject, *o))
            }
            Query::WithinRecipientCap { .. } | Query::AllRecipientsWithinCap { .. } => true,
            _ => false,
        };
        Answer {
            holds,
            accounts: matches!(q, Query::ChangedSince { .. }).then(BTreeSet::new),
            epoch: VaultEpoch::from_raw(0),
            digest: ContentDigest::from_bytes([0x5a; 32]),
        }
    }

    fn answers(&self, qs: &[Query]) -> Answers {
        let mut a = Answers::new();
        for q in qs {
            a.insert(q.clone(), self.answer(q));
        }
        a
    }
}

// ---------------------------------------------------------------------------
// Entries
// ---------------------------------------------------------------------------

/// One record of an entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Rec {
    /// A creator record.
    Creator(CreatorRecord),
    /// A core record.
    Core(Record),
}

/// Why a command appended nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fail {
    /// The creator refused it.
    Creator(CreatorRefusal),
    /// The core refused a composed command.
    Core(Refusal),
}

/// Whether the command reads the validation report, so the engine asks
/// the vault about the builders (`fstp_engine::compose`).
fn reads_report(cmd: &CreatorCommand) -> bool {
    matches!(
        cmd,
        CreatorCommand::AcknowledgeWarning { .. }
            | CreatorCommand::RequestActivation { .. }
            | CreatorCommand::ApproveActivation { .. }
    )
}

/// The approver an approval names.
fn approver(cmd: &CreatorCommand, ctx: &Ctx) -> Option<AccountId> {
    match (cmd, ctx.actor) {
        (CreatorCommand::ApproveActivation { .. }, Actor::Account(a)) => Some(a),
        _ => None,
    }
}

/// The reference the core `ActivateProgramme` keeps for the report, as
/// `fstp_engine::compose::report_ref` builds it.
fn report_ref(a: &ActivationApproved) -> CoreReportDigest {
    let mut b = [0u8; 32];
    let rev = a.report().revision();
    let rows = u32::try_from(a.report().rows().len()).unwrap_or(u32::MAX);
    let parts: [&[u8]; 4] = [
        &a.report().programme().raw().to_be_bytes(),
        &rev.seq().to_be_bytes(),
        &rev.entry().raw().to_be_bytes(),
        &rows.to_be_bytes(),
    ];
    for (slot, byte) in b.iter_mut().zip(parts.into_iter().flatten()) {
        *slot = *byte;
    }
    CoreReportDigest::from_bytes(b)
}

/// The core `ActivateProgramme` an approval composes (D2e).
pub(crate) fn activate_command(a: &ActivationApproved) -> Command {
    Command::ActivateProgramme {
        programme: a.programme(),
        decision: a.decision(),
        report: report_ref(a),
        revision: a.revision().seq(),
        creator_builders: a.builders().clone(),
    }
}

/// One cell: the folded states, every appended entry, the shell
/// environment and the vault.
pub(crate) struct Cell {
    /// The core state.
    pub(crate) core: State,
    /// The creator state.
    pub(crate) creator: CreatorState,
    /// The shell's creator inputs.
    pub(crate) env: CreatorInputs,
    /// The vault.
    pub(crate) vault: Vault,
    /// Every appended entry, in order.
    pub(crate) entries: Vec<Vec<Rec>>,
    seq: u64,
    clock: i64,
    commands: u64,
}

impl Cell {
    /// The empty cell with the clean environment.
    pub(crate) fn genesis() -> Cell {
        Cell {
            core: State::genesis(),
            creator: CreatorState::genesis(),
            env: clean_env(),
            vault: Vault::default(),
            entries: Vec::new(),
            seq: 0,
            clock: 0,
            commands: 0,
        }
    }

    /// The context of the next command by `actor`, one second after the
    /// last.
    pub(crate) fn ctx(&mut self, actor: AccountId) -> Ctx {
        self.clock = self.clock.saturating_add(1_000_000);
        self.commands = self.commands.saturating_add(1);
        let mut command = [0u8; 16];
        command[..8].copy_from_slice(&self.commands.to_be_bytes());
        Ctx {
            now: Timestamp::from_micros(self.clock),
            actor: Actor::Account(actor),
            command: CommandId::from_bytes(command),
            via: Via::Web,
            tenant_admin: ADMINS.contains(&actor),
            second_tenant_admin: None,
            binds_tenant_admin: false,
        }
    }

    /// The vault answers the engine writes into the inputs: `IsVerified`
    /// for every builder and the approver, and `SameIdentityAsAny` for the
    /// approver against the builders.
    fn vault_checks(&self, approver: Option<AccountId>) -> CreatorInputs {
        let mut inputs = self.env.clone();
        let q = vault_questions(&self.creator, P, approver);
        let mut is_verified = BTreeMap::new();
        for a in &q.is_verified {
            let ans = self.vault.answer(&Query::IsVerified { account: *a });
            is_verified.insert(*a, ans.holds);
        }
        let mut same_identity = BTreeMap::new();
        if let Some((subject, others)) = q.same_identity {
            let ans = self
                .vault
                .answer(&Query::SameIdentityAsAny { subject, others });
            same_identity.insert(subject, ans.holds);
        }
        inputs.vault.is_verified = is_verified;
        inputs.vault.same_identity = same_identity;
        inputs
    }

    /// The inputs the creator reads for `cmd`, as the engine builds them.
    pub(crate) fn inputs(&self, cmd: &CreatorCommand, ctx: &Ctx) -> CreatorInputs {
        if reads_report(cmd) {
            self.vault_checks(approver(cmd, ctx))
        } else {
            let mut inputs = self.env.clone();
            inputs.vault.is_verified = BTreeMap::new();
            inputs.vault.same_identity = BTreeMap::new();
            inputs
        }
    }

    /// Decides one composed core command on `scratch` and folds it there.
    fn core_on(&self, scratch: &mut State, c: &Command, ctx: &Ctx) -> Result<Vec<Rec>, Fail> {
        let qs = fstp_domain::queries(scratch, c, ctx).map_err(Fail::Core)?;
        let answers = self.vault.answers(&qs);
        let records = fstp_domain::decide(scratch, c, ctx, &answers).map_err(Fail::Core)?;
        let seq = Seq::from_raw(self.seq.saturating_add(1));
        for r in &records {
            fstp_domain::apply(scratch, seq, ctx.now, r)
                .unwrap_or_else(|e| panic!("a composed core record does not fold: {e:?}"));
        }
        Ok(records.into_iter().map(Rec::Core).collect())
    }

    /// The entry `cmd` by the actor of `ctx` would append (crate
    /// documentation, steps 1 to 4). Appends nothing.
    pub(crate) fn decide(&self, cmd: &CreatorCommand, ctx: &Ctx) -> Result<Vec<Rec>, Fail> {
        let inputs = self.inputs(cmd, ctx);
        let d =
            decide_creator(&self.core, &self.creator, cmd, ctx, &inputs).map_err(Fail::Creator)?;
        let mut scratch = self.core.clone();
        let mut out = Vec::new();
        let mut tail = Vec::new();
        for r in &d.records {
            if let CreatorRecord::ActivationApproved(a) = r {
                tail.extend(self.core_on(&mut scratch, &activate_command(a), ctx)?);
            }
            out.push(Rec::Creator(r.clone()));
        }
        for c in &d.core {
            if matches!(c, Command::ActivateProgramme { .. }) {
                // Only an approval composes the activation (D2e).
                return Err(Fail::Core(Refusal::new(
                    RuleRef::I66,
                    RefusalReason::WrongActor,
                )));
            }
            out.extend(self.core_on(&mut scratch, c, ctx)?);
        }
        out.extend(tail);
        Ok(out)
    }

    /// Folds `records` as one ledger entry at `at` (crate documentation,
    /// step 5). A record the folds refuse fails the test.
    pub(crate) fn append(&mut self, records: &[Rec], at: Timestamp) {
        self.seq = self.seq.saturating_add(1);
        let seq = Seq::from_raw(self.seq);
        for r in records {
            match r {
                Rec::Creator(c) => self
                    .creator
                    .apply(seq, c)
                    .unwrap_or_else(|e| panic!("the creator fold refuses {c:?}: {e}")),
                Rec::Core(c) => {
                    fstp_domain::apply(&mut self.core, seq, at, c)
                        .unwrap_or_else(|e| panic!("the core fold refuses {c:?}: {e:?}"));
                    self.creator
                        .observe_core(seq, c)
                        .unwrap_or_else(|e| panic!("the creator refuses to observe {c:?}: {e}"));
                }
            }
        }
        self.entries.push(records.to_vec());
    }

    /// Decides `cmd` by `actor` and appends its entry.
    pub(crate) fn run(&mut self, cmd: &CreatorCommand, actor: AccountId) -> Result<Vec<Rec>, Fail> {
        let ctx = self.ctx(actor);
        let records = self.decide(cmd, &ctx)?;
        self.append(&records, ctx.now);
        // Step 6 (crate documentation): the shell holds the saved values
        // outside the ledger, whose body keeps only their digests.
        if let CreatorCommand::SaveFields {
            programme, fields, ..
        } = cmd
        {
            assert!(
                self.creator.hold_saved(*programme, fields),
                "a value of the appended save is not held"
            );
        }
        Ok(records)
    }

    /// Grants `to` the `role` on the draft by TA, through the core. A
    /// refusal fails the test.
    pub(crate) fn grant(&mut self, to: AccountId, role: Role, binding: u128) {
        self.try_grant(TA, to, role, binding)
            .unwrap_or_else(|f| panic!("the grant of {role:?} to {to:?} is refused: {f:?}"));
    }

    /// Grants `to` the `role` on the draft by `by`, through the core, and
    /// appends the entry unless the core refuses.
    pub(crate) fn try_grant(
        &mut self,
        by: AccountId,
        to: AccountId,
        role: Role,
        binding: u128,
    ) -> Result<(), Fail> {
        let ctx = self.ctx(by);
        let cmd = Command::GrantRole {
            binding: BindingId::from_raw(binding),
            account: to,
            programme: P,
            role,
            start: ctx.now,
            second_admin: None,
            confidentiality: Some(TextRef::new(
                TextId::from_raw(50_000_u128.saturating_add(binding)),
                ContentDigest::from_bytes([4; 32]),
            )),
            organisation: None,
            end: None,
        };
        let mut scratch = self.core.clone();
        let records = self.core_on(&mut scratch, &cmd, &ctx)?;
        self.append(&records, ctx.now);
        Ok(())
    }

    /// Decides the core command `make` builds at the context of `by` and
    /// appends its entry, unless the core refuses.
    pub(crate) fn run_core(
        &mut self,
        by: AccountId,
        make: impl FnOnce(&Ctx) -> Command,
    ) -> Result<Vec<Rec>, Fail> {
        let ctx = self.ctx(by);
        let cmd = make(&ctx);
        let mut scratch = self.core.clone();
        let records = self.core_on(&mut scratch, &cmd, &ctx)?;
        self.append(&records, ctx.now);
        Ok(records)
    }

    /// The entry of a creator decision made outside [`Cell::decide`], such
    /// as the bridge's import save: its creator records, then the records
    /// of each composed core command, decided in order at `ctx`.
    pub(crate) fn compose(
        &self,
        d: &fstp_creator::CreatorDecision,
        ctx: &Ctx,
    ) -> Result<Vec<Rec>, Fail> {
        let mut scratch = self.core.clone();
        let mut out: Vec<Rec> = d.records.iter().cloned().map(Rec::Creator).collect();
        for c in &d.core {
            out.extend(self.core_on(&mut scratch, c, ctx)?);
        }
        Ok(out)
    }

    /// The draft's head revision.
    pub(crate) fn head(&self) -> DraftRevision {
        self.creator.head(P).expect("the draft is open")
    }

    /// The core head policy of the draft.
    pub(crate) fn policy(&self) -> &PolicyVersion {
        fstp_domain::policy::head(&self.core, P).expect("the draft has a policy")
    }

    /// The programme status in the core.
    pub(crate) fn status(&self) -> Option<ProgrammeStatus> {
        programme_status(&self.core, P)
    }

    /// The report the approval of `approver` would read: the draft's
    /// profile, or the shipped one when the shell has none.
    pub(crate) fn report(&self, approver: Option<AccountId>) -> ValidationReport {
        let inputs = self.vault_checks(approver);
        let profile = inputs.profile.clone().unwrap_or_else(shipped_profile);
        validate(&self.core, &self.creator, P, &profile, &inputs)
    }

    /// `SaveFields` of `fields` at the head, by `by`.
    pub(crate) fn save(&mut self, by: AccountId, fields: Vec<FieldEdit>) -> Result<Vec<Rec>, Fail> {
        let cmd = CreatorCommand::SaveFields {
            programme: P,
            base: self.head(),
            fields,
        };
        self.run(&cmd, by)
    }

    /// `AcknowledgeWarning` of `check` on the draft at the head, by `by`.
    pub(crate) fn acknowledge(&mut self, by: AccountId, check: CheckId) -> Result<Vec<Rec>, Fail> {
        let cmd = CreatorCommand::AcknowledgeWarning {
            programme: P,
            revision: self.head(),
            warning: WarningKey {
                check,
                subject: CheckSubject::Draft,
            },
        };
        self.run(&cmd, by)
    }

    /// `RequestActivation` at the head, by `by`.
    pub(crate) fn request(&mut self, by: AccountId) -> Result<Vec<Rec>, Fail> {
        let cmd = CreatorCommand::RequestActivation {
            programme: P,
            revision: self.head(),
        };
        self.run(&cmd, by)
    }

    /// `ApproveActivation` at the head with decision `decision`.
    pub(crate) fn approve_command(&self, decision: u128) -> CreatorCommand {
        CreatorCommand::ApproveActivation {
            programme: P,
            revision: self.head(),
            decision: DecisionId::from_raw(decision),
        }
    }

    /// `ApproveActivation` at the head, by `by`.
    pub(crate) fn approve(&mut self, by: AccountId, decision: u128) -> Result<Vec<Rec>, Fail> {
        let cmd = self.approve_command(decision);
        self.run(&cmd, by)
    }
}

// ---------------------------------------------------------------------------
// Specs and field values
// ---------------------------------------------------------------------------

/// The Horizon Europe profile of `fstp_programme`.
pub(crate) fn he() -> FunderProfile {
    FunderProfile::horizon_europe()
}

/// The profile-default policy of P: the blank Horizon Europe spec,
/// compiled with the ids `OpenDraft` names.
pub(crate) fn blank_policy() -> PolicyVersion {
    compile(&he().blank(), &he(), CompileIds::new(P, V1, None))
        .unwrap()
        .policy
}

/// The `OpenDraft` of P by a tenant admin.
pub(crate) fn open_draft_command() -> CreatorCommand {
    CreatorCommand::OpenDraft {
        programme: P,
        version: V1,
        profile: blank_policy().frozen.p53,
    }
}

/// The entry a correct `OpenDraft` of P by TA appends at `ctx`: the
/// creator's `DraftOpened` and the records of the core `CreateProgramme`
/// of the profile-default policy (design 3.2).
pub(crate) fn expected_open_entry(ctx: &Ctx) -> Vec<Rec> {
    let create = Command::CreateProgramme {
        policy: Box::new(blank_policy()),
    };
    let core = fstp_domain::decide(&State::genesis(), &create, ctx, &Answers::new())
        .expect("the core creates the profile-default draft");
    let mut out = vec![Rec::Creator(CreatorRecord::DraftOpened {
        programme: P,
        profile: blank_policy().frozen.p53,
        by: TA,
    })];
    out.extend(core.into_iter().map(Rec::Core));
    out
}

/// A cell whose draft TA opened through `OpenDraft`, with M1 granted the
/// programme manager role by TA.
pub(crate) fn opened() -> Cell {
    let mut c = Cell::genesis();
    let cmd = open_draft_command();
    c.run(&cmd, TA)
        .unwrap_or_else(|f| panic!("OpenDraft by a tenant admin is refused: {f:?}"));
    c.grant(M1, Role::ProgrammeManager, 1);
    c
}

/// A cell whose draft was opened by the entry a correct `OpenDraft`
/// appends ([`expected_open_entry`]), with M1 granted the programme
/// manager role by TA. For the commands after `OpenDraft`, so each test
/// is red or green at its own command.
pub(crate) fn forged() -> Cell {
    let mut c = Cell::genesis();
    let ctx = c.ctx(TA);
    let entry = expected_open_entry(&ctx);
    c.append(&entry, ctx.now);
    c.grant(M1, Role::ProgrammeManager, 1);
    c
}

/// The value of `field` in `spec`, which must set it.
pub(crate) fn value_of(spec: &ProgrammeSpec, field: FieldId) -> FieldValue {
    match spec.get(field) {
        Field::Set(v) => v,
        Field::Unset => panic!("the spec leaves {} unset", field.key()),
    }
}

/// Decodes `json` as the value of `field`.
pub(crate) fn decode(field: FieldId, json: &str) -> FieldValue {
    decode_field_value(field, json.as_bytes())
        .unwrap_or_else(|e| panic!("{} does not decode {json}: {e:?}", field.key()))
}

/// An ADR-006 EUR string of `minor` cents.
pub(crate) fn adr006(minor: u32) -> String {
    format!("{}.{:02}", minor / 100, minor % 100)
}

/// The P-09 knock-outs of the fixture, with each wording stored as a
/// `TextRef` (ADR-007), so the compiled policy can go into a ledger body.
fn stored_p09() -> FieldValue {
    let item = |id: u8| {
        let hex: String = std::iter::repeat_n(format!("{id:02x}"), 32).collect();
        format!("{{\"id\":\"{id}\",\"text\":{{\"digest\":\"{hex}\",\"text\":\"10{id}\"}}}}")
    };
    decode(
        FieldId::P09,
        &format!("[{},{},{}]", item(1), item(2), item(3)),
    )
}

/// The synthetic draft spec: the SuperSAFE fixture, which sets every
/// field, with the P-09 wording stored (ADR-007). P-05 equals P-58, so
/// I-50 holds.
pub(crate) fn synthetic_spec() -> ProgrammeSpec {
    let mut spec = supersafe_fixture().unwrap().spec;
    spec.set(stored_p09());
    spec
}

/// The digest the shell would send for one value. Synthetic: the field's
/// position and a tag, so equal tags give equal digests.
pub(crate) fn digest(field: FieldId, tag: u8) -> ValueDigest {
    let pos = FieldId::ALL.iter().position(|f| *f == field).unwrap_or(0);
    let mut b = [tag; 32];
    b[..8].copy_from_slice(&(pos as u64).to_be_bytes());
    ValueDigest::new(ContentDigest::from_bytes(b))
}

/// A manual edit of `value`.
pub(crate) fn edit(value: FieldValue, tag: u8) -> FieldEdit {
    FieldEdit {
        field: value.field(),
        digest: digest(value.field(), tag),
        value,
        provenance: Provenance::Manual,
    }
}

/// Manual edits of every field `spec` sets, except P-53, which
/// `OpenDraft` sets, and except `omit`.
pub(crate) fn full_save(spec: &ProgrammeSpec, omit: Option<FieldId>) -> Vec<FieldEdit> {
    FieldId::ALL
        .iter()
        .filter(|f| **f != FieldId::P53 && Some(**f) != omit)
        .filter_map(|f| match spec.get(*f) {
            Field::Set(v) => Some(edit(v, 1)),
            Field::Unset => None,
        })
        .collect()
}

/// A valid synthetic draft (crate documentation): opened by TA through
/// `OpenDraft`, M1 granted, every field of `spec` but P-53 and `omit`
/// saved by M1, `before_ack` run, and the `RosterShort` warning
/// acknowledged by M1. No activation is requested yet.
pub(crate) fn draft_with(
    spec: &ProgrammeSpec,
    omit: Option<FieldId>,
    before_ack: impl FnOnce(&mut Cell),
) -> Cell {
    let mut c = opened();
    c.save(M1, full_save(spec, omit))
        .unwrap_or_else(|f| panic!("the save of the synthetic draft is refused: {f:?}"));
    before_ack(&mut c);
    c.acknowledge(M1, CheckId::RosterShort)
        .unwrap_or_else(|f| panic!("the RosterShort warning cannot be acknowledged: {f:?}"));
    c
}

/// The valid synthetic draft of [`synthetic_spec`].
pub(crate) fn valid_draft() -> Cell {
    draft_with(&synthetic_spec(), None, |_| {})
}

/// The builder set of the draft, computed from the raw entries (Q1,
/// interim, pending Daniel): the author of every creator record but an
/// approval, and of every core `ProgrammeCreated`, `PolicyVersionRecorded`,
/// `BindingGranted` and `BindingReinstated` on the draft, up to the
/// activation.
pub(crate) fn reference_builders(entries: &[Vec<Rec>]) -> BTreeSet<AccountId> {
    let mut out = BTreeSet::new();
    for entry in entries {
        if entry.iter().any(|r| {
            matches!(r, Rec::Creator(CreatorRecord::ActivationApproved(a)) if a.programme() == P)
        }) {
            break;
        }
        for r in entry {
            let by = match r {
                Rec::Creator(c) => match c {
                    CreatorRecord::DraftOpened { by, .. }
                    | CreatorRecord::StartApplied { by, .. }
                    | CreatorRecord::FieldsSaved { by, .. }
                    | CreatorRecord::NarrativeAccepted { by, .. }
                    | CreatorRecord::InvitationRecorded { by, .. }
                    | CreatorRecord::InvitationWithdrawn { by, .. }
                    | CreatorRecord::WarningAcknowledged { by, .. }
                    | CreatorRecord::ActivationRequested { by, .. }
                    | CreatorRecord::TemplateSaved { by, .. } => Some(*by),
                    CreatorRecord::ProbeRecorded { .. } | CreatorRecord::ActivationApproved(_) => {
                        None
                    }
                },
                Rec::Core(Record::ProgrammeCreated { programme, by, .. }) if *programme == P => {
                    Some(*by)
                }
                Rec::Core(Record::PolicyVersionRecorded { version, author })
                    if version.programme == P =>
                {
                    Some(*author)
                }
                Rec::Core(Record::BindingGranted(g)) if g.programme == P => Some(g.granted_by),
                Rec::Core(Record::BindingReinstated(r)) => Some(r.by),
                Rec::Core(_) => None,
            };
            out.extend(by);
        }
    }
    out
}
