//! The creator path of the M4 demo through `Engine::execute` with
//! `CreatorDecider` and a test `CreatorEnvironment` (lane m4creator; M4
//! design sections 3.2, 3.3, 3.4 and 3.10; R-PG-02, R-PG-03, I-51, I-52,
//! I-65, I-66 and I-67).
//!
//! `crates/fstp-creator/tests/creator_path` replays the same entries
//! without the engine, since `fstp-creator` may not take `fstp-engine` as
//! a dev-dependency (layering rules A3 and A4 count dev edges).
//!
//! The Guide checks run over the real Guide API. The approved-wording
//! profile is the shipped Horizon Europe Guide with each legal marker line
//! replaced by synthetic wording. It lives in this test only, through a
//! test `ProfileSource`, never in `fstp-guide` (rule A9b).
//!
//! The tests also cover the driver's held values (`driver.rs`, "Held
//! values"): saves and import resolutions are held after their entry is
//! appended, a replay holds only what the import store can give back, and
//! every value the engine cannot recover fails its checks closed.
//!
//! Every value is synthetic. The cast holds no person.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::{BTreeMap, BTreeSet};

use fstp_creator::{
    CheckDetail, CheckId, CheckSubject, CreatorCommand, CreatorInputs, CreatorRecord,
    DraftRevision, FieldEdit, PortPresence, ProbeSet, Provenance, SodPreview, Theme,
    ValidationReport, ValueDigest, VaultChecks, WarningKey,
};
use fstp_domain::Via;
use fstp_domain::command::{Actor, Ctx, SystemCause};
use fstp_domain::id::{
    AccountId, BindingId, CommandId, ContentDigest, DecisionId, PolicyVersionId, ProgrammeId,
    TextId, TextRef, VaultEpoch,
};
use fstp_domain::oracle::{Answer, OracleDown, Query};
use fstp_domain::programme::{ProgrammeStatus, programme_status};
use fstp_domain::refusal::{Refusal, RefusalReason, RuleRef};
use fstp_domain::roles::Role;
use fstp_domain::time::Timestamp;
use fstp_engine::bridge::BridgeCommand;
use fstp_engine::compose::CreatorEnvironment;
use fstp_engine::{
    Command, CreatorDecider, Engine, EngineState, ExecError, IdentityOracle, Record, replay,
};
use fstp_guide::{HORIZON_EUROPE, ProfileError, ProfileFiles, ProfileSource, ShippedProfiles};
use fstp_import::{
    AccountRef, BlobAddress, ClientResolution, ImportCommand, ImportConfigId, ImportDocument,
    ImportDocumentId, ImportMedia, ImportProposal, ImportProposalId, ProgrammeRef, SaltedDigest,
    Span, TextDigest, UntrustedValue, ValueTextId, ValueTextRef,
};
use fstp_ledger::{Entry, MemStore, RecordStore, Seq};
use fstp_programme::{
    CompileIds, Field, FieldId, FieldValue, FunderProfile, ProgrammeSpec, compile,
    decode_field_value, supersafe_fixture,
};

const P: ProgrammeId = ProgrammeId::from_raw(7);
const V1: PolicyVersionId = PolicyVersionId::from_raw(70);
/// The tenant admin who opens the draft.
const TA: AccountId = AccountId::from_raw(0xA1);
/// The second tenant admin, who builds nothing and approves.
const TB: AccountId = AccountId::from_raw(0xA2);
/// The programme manager who builds the draft.
const M1: AccountId = AccountId::from_raw(0xB1);
const ADMINS: [AccountId; 2] = [TA, TB];
const DOC: ImportDocumentId = ImportDocumentId::from_raw(9);

/// The wording put where the shipped Guide holds a legal marker. It is
/// not the testkit's marker (rule A9b).
const SYNTHETIC_WORDING: &str = "Synthetic wording for the creator path tests. Not legal text.";

// ---------------------------------------------------------------------------
// The vault, the profiles and the shell environment
// ---------------------------------------------------------------------------

/// A vault where every account is verified with its own identity, except
/// the pairs it names, and every cap is kept.
#[derive(Clone, Debug, Default)]
struct Vault {
    sybil: BTreeSet<(AccountId, AccountId)>,
}

impl IdentityOracle for Vault {
    fn ask(&self, q: &Query) -> Result<Answer, OracleDown> {
        let holds = match q {
            Query::IsVerified { .. }
            | Query::WithinRecipientCap { .. }
            | Query::AllRecipientsWithinCap { .. } => true,
            Query::SameIdentityAsAny { subject, others } => others.iter().any(|o| {
                self.sybil.contains(&(*subject, *o)) || self.sybil.contains(&(*o, *subject))
            }),
            _ => false,
        };
        Ok(Answer {
            holds,
            accounts: matches!(q, Query::ChangedSince { .. }).then(BTreeSet::new),
            epoch: VaultEpoch::from_raw(0),
            digest: ContentDigest::from_bytes([0x5a; 32]),
        })
    }

    fn epoch(&self) -> Result<VaultEpoch, OracleDown> {
        Ok(VaultEpoch::from_raw(0))
    }
}

/// A test profile source over one Guide text (rule A9b).
struct OneGuide(String);

impl ProfileSource for OneGuide {
    fn files(&self, _name: &str) -> Result<ProfileFiles<'_>, ProfileError> {
        Ok(ProfileFiles {
            guide: self.0.as_bytes(),
        })
    }
}

/// The shipped Horizon Europe profile, whose legal wording is pending.
fn shipped_profile() -> fstp_guide::FunderProfile {
    ShippedProfiles.profile(HORIZON_EUROPE).unwrap()
}

/// The shipped Guide with each legal marker line replaced by
/// [`SYNTHETIC_WORDING`], so its wording counts as approved. Every section
/// and placeholder of the shipped template stays.
fn approved_profile() -> fstp_guide::FunderProfile {
    let shipped = ShippedProfiles.files(HORIZON_EUROPE).unwrap();
    let mut out = String::new();
    for line in std::str::from_utf8(shipped.guide).unwrap().lines() {
        if line.starts_with(fstp_guide::LEGAL_MARKER) {
            out.push_str(SYNTHETIC_WORDING);
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    let p = OneGuide(out).profile(HORIZON_EUROPE).unwrap();
    assert!(!p.legal_wording_pending());
    p
}

/// The shell facts: every probe passes, TA and TB are attested, the Q35
/// answers are yes, a pre-check port exists, the default theme and the
/// given profile.
#[derive(Clone, Debug)]
struct Env(CreatorInputs);

impl Env {
    fn with(profile: fstp_guide::FunderProfile) -> Env {
        Env(CreatorInputs {
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
            profile: Some(profile),
        })
    }

    fn clean() -> Env {
        Env::with(approved_profile())
    }
}

impl CreatorEnvironment for Env {
    fn creator_inputs(&self, _: &EngineState, _: &CreatorCommand, _: &Ctx) -> CreatorInputs {
        self.0.clone()
    }
}

type E = Engine<MemStore<Record>, Vault, CreatorDecider<Env>>;

fn engine(vault: Vault) -> E {
    Engine::open_with(MemStore::new(), vault, CreatorDecider(Env::clean())).unwrap()
}

/// The engine replayed from the store of `e`, with the same vault and
/// environment. Nothing is held but what the replay can give back.
fn reopened(e: E) -> E {
    let (store, vault, decider) = e.into_parts();
    Engine::open_with(store, vault, decider).unwrap()
}

fn ctx(actor: Actor, t: i64) -> Ctx {
    let mut command = [0u8; 16];
    command[..8].copy_from_slice(&t.to_be_bytes());
    let admin = matches!(actor, Actor::Account(a) if ADMINS.contains(&a));
    Ctx {
        now: Timestamp::from_micros(t.saturating_mul(1_000_000)),
        actor,
        command: CommandId::from_bytes(command),
        via: Via::Web,
        tenant_admin: admin,
        second_tenant_admin: None,
        binds_tenant_admin: false,
    }
}

fn by(account: AccountId, t: i64) -> Ctx {
    ctx(Actor::Account(account), t)
}

fn entries(e: &E) -> Vec<Entry<Record>> {
    let mut out = Vec::new();
    e.store().read(Seq::ZERO, usize::MAX, &mut out).unwrap();
    out
}

fn head(e: &E) -> DraftRevision {
    e.state().creator.head(P).unwrap()
}

fn he() -> FunderProfile {
    FunderProfile::horizon_europe()
}

fn blank_policy() -> fstp_domain::policy::PolicyVersion {
    compile(&he().blank(), &he(), CompileIds::new(P, V1, None))
        .unwrap()
        .policy
}

fn refused(rule: RuleRef, why: RefusalReason) -> Result<Seq, ExecError> {
    Err(ExecError::Refused(Refusal::new(rule, why)))
}

// ---------------------------------------------------------------------------
// The creator path
// ---------------------------------------------------------------------------

fn open(e: &mut E) -> Result<Seq, ExecError> {
    e.execute(
        Command::Creator(CreatorCommand::OpenDraft {
            programme: P,
            version: V1,
            profile: blank_policy().frozen.p53,
        }),
        by(TA, 1),
    )
}

fn grant_m1(e: &mut E) {
    let c = by(TA, 2);
    let grant = fstp_domain::Command::GrantRole {
        binding: BindingId::from_raw(1),
        account: M1,
        programme: P,
        role: Role::ProgrammeManager,
        start: c.now,
        second_admin: None,
        confidentiality: Some(TextRef::new(
            TextId::from_raw(50_001),
            ContentDigest::from_bytes([4; 32]),
        )),
        organisation: None,
        end: None,
    };
    e.execute(Command::Core(grant), c).unwrap();
}

/// The fixture spec with the P-09 wording stored as TextRefs (ADR-007).
fn synthetic_spec() -> ProgrammeSpec {
    let item = |id: u8| {
        let hex: String = std::iter::repeat_n(format!("{id:02x}"), 32).collect();
        format!("{{\"id\":\"{id}\",\"text\":{{\"digest\":\"{hex}\",\"text\":\"10{id}\"}}}}")
    };
    let p09 = format!("[{},{},{}]", item(1), item(2), item(3));
    let mut spec = supersafe_fixture().unwrap().spec;
    spec.set(decode_field_value(FieldId::P09, p09.as_bytes()).unwrap());
    spec
}

/// A synthetic digest per field.
fn digest_of(i: usize) -> ValueDigest {
    let mut b = [1u8; 32];
    b[..8].copy_from_slice(&(i as u64).to_be_bytes());
    ValueDigest::new(ContentDigest::from_bytes(b))
}

/// A manual save of every field `spec` sets, P-53 and the fields of
/// `skip` aside.
fn save_of(spec: &ProgrammeSpec, skip: &[FieldId]) -> Vec<FieldEdit> {
    FieldId::ALL
        .iter()
        .enumerate()
        .filter(|(_, f)| **f != FieldId::P53 && !skip.contains(f))
        .filter_map(|(i, f)| match spec.get(*f) {
            Field::Set(value) => {
                let value: FieldValue = value;
                Some(FieldEdit {
                    field: *f,
                    value,
                    digest: digest_of(i),
                    provenance: Provenance::Manual,
                })
            }
            Field::Unset => None,
        })
        .collect()
}

/// Opens the draft and grants M1 the programme manager role.
fn opened(vault: Vault) -> E {
    let mut e = engine(vault);
    open(&mut e).unwrap_or_else(|r| panic!("OpenDraft is refused: {r:?}"));
    grant_m1(&mut e);
    e
}

/// Saves `fields` by M1 at time `t`.
fn save(e: &mut E, fields: Vec<FieldEdit>, t: i64) -> Result<Seq, ExecError> {
    let cmd = CreatorCommand::SaveFields {
        programme: P,
        base: head(e),
        fields,
    };
    e.execute(Command::Creator(cmd), by(M1, t))
}

/// Acknowledges the roster warning and requests activation, by M1.
fn acknowledge_and_request(e: &mut E, t: i64) {
    let ack = CreatorCommand::AcknowledgeWarning {
        programme: P,
        revision: head(e),
        warning: WarningKey {
            check: CheckId::RosterShort,
            subject: CheckSubject::Draft,
        },
    };
    e.execute(Command::Creator(ack), by(M1, t))
        .unwrap_or_else(|r| panic!("the acknowledgement is refused: {r:?}"));
    let request = CreatorCommand::RequestActivation {
        programme: P,
        revision: head(e),
    };
    e.execute(Command::Creator(request), by(M1, t + 1))
        .unwrap_or_else(|r| panic!("the request is refused: {r:?}"));
}

/// Opens the draft, grants M1, saves the synthetic spec, acknowledges the
/// roster warning and requests activation, through the engine.
fn requested(vault: Vault) -> E {
    let mut e = opened(vault);
    save(&mut e, save_of(&synthetic_spec(), &[]), 3)
        .unwrap_or_else(|r| panic!("SaveFields is refused: {r:?}"));
    acknowledge_and_request(&mut e, 4);
    e
}

fn approve(e: &mut E, approver: AccountId, t: i64) -> Result<Seq, ExecError> {
    let cmd = CreatorCommand::ApproveActivation {
        programme: P,
        revision: head(e),
        decision: DecisionId::from_raw(900),
    };
    e.execute(Command::Creator(cmd), by(approver, t))
}

/// The report of the draft over the engine state, with the environment's
/// facts and the vault verifying every builder and `approver`.
fn report(e: &E, approver: Option<AccountId>) -> ValidationReport {
    let state = e.state();
    let mut inputs = e.decider().0.0.clone();
    let q = fstp_creator::vault_questions(&state.creator, P, approver);
    inputs.vault.is_verified = q.is_verified.iter().map(|a| (*a, true)).collect();
    if let Some((subject, _)) = q.same_identity {
        inputs.vault.same_identity.insert(subject, false);
    }
    let profile = inputs.profile.clone().unwrap();
    fstp_creator::validate(&state.core, &state.creator, P, &profile, &inputs)
}

fn failures(r: &ValidationReport) -> BTreeSet<CheckId> {
    r.failures().map(|x| x.check).collect()
}

fn status(e: &E) -> Option<ProgrammeStatus> {
    programme_status(&e.state().core, P)
}

/// R-PG-02, D1: `OpenDraft` through the engine appends one entry: the
/// creator's `DraftOpened` and the core `ProgrammeCreated` and
/// `PolicyVersionRecorded` of the profile-default policy. The programme
/// is a draft, and the replay of the store equals the live state.
#[test]
fn r_pg_02_d1_open_draft_through_the_engine_is_one_entry() {
    let mut e = engine(Vault::default());
    let last = open(&mut e).unwrap_or_else(|r| panic!("OpenDraft is refused: {r:?}"));
    let all = entries(&e);
    // The append returns the last record's number. Every record of the
    // entry carries the command id of `OpenDraft`.
    let id = by(TA, 1).command.bytes();
    assert!(all.iter().all(|x| x.command == id && x.seq <= last));
    let entry: Vec<&Record> = all.iter().map(|x| &x.record).collect();
    assert!(matches!(
        entry.first(),
        Some(Record::Creator(CreatorRecord::DraftOpened { programme, by, .. })) if *programme == P && *by == TA
    ));
    assert!(entry.iter().any(|r| matches!(
        r,
        Record::Core(fstp_domain::Record::PolicyVersionRecorded { version, .. }) if **version == blank_policy()
    )));
    assert_eq!(status(&e), Some(ProgrammeStatus::Draft));
    assert_eq!(&replay(&all).unwrap(), e.state());
}

/// R-PG-03, I-66, I-67: the builder path through the engine with the real
/// Guide and an approved-wording profile. TA, the opener, is refused with
/// I-67 and nothing is appended. TB, a tenant admin who built nothing,
/// approves, and the programme is active. The replay of the store equals
/// the live state.
#[test]
fn r_pg_03_i66_i67_creator_path_activates_through_the_engine() {
    let mut e = requested(Vault::default());
    let clean = report(&e, Some(TB));
    assert!(
        failures(&clean).is_empty(),
        "the synthetic draft does not clear: {:?}",
        clean.failures().collect::<Vec<_>>()
    );
    let before = e.head();
    assert_eq!(
        approve(&mut e, TA, 6),
        refused(RuleRef::I67, RefusalReason::GuardFailed)
    );
    assert_eq!(e.head(), before);
    approve(&mut e, TB, 7).unwrap_or_else(|r| panic!("the clean approval is refused: {r:?}"));
    assert_eq!(status(&e), Some(ProgrammeStatus::Active));
    let all = entries(&e);
    let approved: Vec<_> = all
        .iter()
        .filter_map(|x| match &x.record {
            Record::Creator(CreatorRecord::ActivationApproved(a)) => Some(a),
            _ => None,
        })
        .collect();
    let [a] = approved.as_slice() else {
        panic!("expected one approval: {approved:?}");
    };
    assert_eq!(a.approver(), TB);
    assert!(a.builders().contains(&TA) && a.builders().contains(&M1));
    assert!(!a.builders().contains(&TB));
    assert_eq!(&replay(&all).unwrap(), e.state());
}

/// I-67 (Q2, T-SOD-SYBIL): through the engine, TB, who shares a verified
/// identity with M1, a builder, is refused with I-67 and appends nothing.
#[test]
fn i67_engine_refuses_a_sybil_approver() {
    let mut vault = Vault::default();
    vault.sybil.insert((TB, M1));
    let mut e = requested(vault);
    let before = e.head();
    assert_eq!(
        approve(&mut e, TB, 6),
        refused(RuleRef::I67, RefusalReason::VaultRefused)
    );
    assert_eq!(e.head(), before);
    assert_eq!(status(&e), Some(ProgrammeStatus::Draft));
}

/// I-66 (Q6): with the shipped Horizon Europe profile, whose legal
/// wording is pending, the same draft fails only `LegalWordingPending`,
/// and the approval by TB is refused with I-66 and appends nothing.
#[test]
fn i66_q6_shipped_profile_refuses_with_legal_wording_pending() {
    let mut e = requested(Vault::default());
    *e.decider_mut() = CreatorDecider(Env::with(shipped_profile()));
    let r = report(&e, Some(TB));
    assert_eq!(
        failures(&r),
        [CheckId::LegalWordingPending].into_iter().collect()
    );
    let before = e.head();
    assert_eq!(
        approve(&mut e, TB, 6),
        refused(RuleRef::I66, RefusalReason::GuardFailed)
    );
    assert_eq!(e.head(), before);
    assert_eq!(status(&e), Some(ProgrammeStatus::Draft));
}

/// I-51, I-52: the Guide checks run over the real Guide API, never over
/// the fail-closed branch. On the full synthetic draft no Guide row and
/// no unavailable source is reported. A draft without its programme name
/// fails `GuideBindingUnresolved` on `programme.name`, the placeholder
/// that binds it, beside `FieldUnset`.
#[test]
fn i51_i52_engine_guide_checks_use_the_guide_api() {
    let full = requested(Vault::default());
    let r = report(&full, Some(TB));
    assert!(
        r.results()
            .iter()
            .all(|x| !matches!(x.detail, CheckDetail::Unavailable(_))),
        "{:?}",
        r.results()
    );
    for check in [
        CheckId::GuideSectionMissing,
        CheckId::GuideBindingUnresolved,
    ] {
        assert!(!failures(&r).contains(&check), "{check:?}");
    }
    let mut gap = opened(Vault::default());
    save(
        &mut gap,
        save_of(&synthetic_spec(), &[FieldId::ProgrammeName]),
        3,
    )
    .unwrap();
    let r = report(&gap, Some(TB));
    let guide: Vec<&CheckSubject> = r
        .failures()
        .filter(|x| x.check == CheckId::GuideBindingUnresolved)
        .map(|x| &x.subject)
        .collect();
    assert_eq!(
        guide,
        vec![&CheckSubject::Placeholder("programme.name".to_owned())]
    );
    assert!(r.failures().any(|x| x.check == CheckId::FieldUnset
        && x.subject == CheckSubject::Field(FieldId::ProgrammeName)));
}

// ---------------------------------------------------------------------------
// Held values
// ---------------------------------------------------------------------------

/// I-66, I-49: after the entry of a `SaveFields` is appended, the engine
/// holds every saved value, so the checks that read one run over it.
#[test]
fn i66_engine_holds_every_saved_value_after_its_entry() {
    let e = requested(Vault::default());
    for f in save_of(&synthetic_spec(), &[]) {
        assert!(e.state().creator.is_held(P, f.field), "{:?}", f.field);
    }
    let r = report(&e, Some(TB));
    assert!(!failures(&r).contains(&CheckId::FlowDownMissing));
}

/// I-66: a replay cannot recover a saved value, which the ledger keeps
/// only as a digest. So after `Engine::open_with` the checks that read
/// one fail closed and the approval is refused with I-66. Once the shell
/// holds each value again from its value store, the approval clears.
#[test]
fn i66_replayed_saves_fail_closed_until_the_shell_holds_them() {
    let e = reopened(requested(Vault::default()));
    assert!(!e.state().creator.is_held(P, FieldId::FlowDown));
    let r = report(&e, Some(TB));
    assert!(
        r.failures().any(|x| x.check == CheckId::FlowDownMissing
            && matches!(x.detail, CheckDetail::Unavailable(_)))
    );
    assert!(failures(&r).contains(&CheckId::GuideBindingUnresolved));
    let mut e = e;
    let before = e.head();
    assert_eq!(
        approve(&mut e, TB, 6),
        refused(RuleRef::I66, RefusalReason::GuardFailed)
    );
    assert_eq!(e.head(), before);
    for f in save_of(&synthetic_spec(), &[]) {
        assert!(e.hold_value(P, f.field, f.digest, f.value), "{:?}", f.field);
    }
    approve(&mut e, TB, 7).unwrap_or_else(|r| panic!("the re-held approval is refused: {r:?}"));
    assert_eq!(status(&e), Some(ProgrammeStatus::Active));
}

/// I-66: the shell holds a value only under the digest of the field's
/// latest save, and only a value of that field.
#[test]
fn i66_shell_holds_only_the_latest_saved_value() {
    let mut e = reopened(requested(Vault::default()));
    let faq = save_of(&synthetic_spec(), &[])
        .into_iter()
        .find(|f| f.field == FieldId::Faq)
        .unwrap();
    let other = ValueDigest::new(ContentDigest::from_bytes([0xee; 32]));
    assert!(!e.hold_value(P, FieldId::Faq, other, faq.value.clone()));
    let name = decode_field_value(FieldId::ProgrammeName, b"\"Synthetic\"").unwrap();
    assert!(!e.hold_value(P, FieldId::Faq, faq.digest, name));
    assert!(!e.state().creator.is_held(P, FieldId::Faq));
    assert!(e.hold_value(P, FieldId::Faq, faq.digest, faq.value));
    assert!(e.state().creator.is_held(P, FieldId::Faq));
}

fn document() -> ImportDocument {
    ImportDocument {
        id: DOC,
        programme: ProgrammeRef::from_raw(P.raw()),
        blob: BlobAddress::from_bytes([1; 32]),
        media: ImportMedia::TextPlain,
        digest: TextDigest::from_bytes([2; 32]),
        text_bytes: 64,
        uploaded_by: AccountRef::from_raw(M1.raw()),
    }
}

/// The proposal of the action acronym, with the value text it names.
fn acronym_proposal() -> ImportProposal {
    ImportProposal {
        id: ImportProposalId::from_raw(1),
        document: DOC,
        field: FieldId::ActionAcronym,
        value: UntrustedValue::parse(b"\"SYNTHACRO\"").unwrap(),
        text: ValueTextRef::new(
            ValueTextId::from_raw(101),
            SaltedDigest::from_bytes([1; 32]),
        ),
        evidence: vec![Span { start: 0, end: 8 }],
        config: ImportConfigId::from_raw(1),
        conflicts_with_profile: Vec::new(),
    }
}

/// The draft with the document uploaded by M1 and the acronym proposal
/// recorded.
fn proposed() -> E {
    let mut e = opened(Vault::default());
    e.execute(
        Command::Import(ImportCommand::RegisterDocument(document())),
        by(M1, 3),
    )
    .unwrap();
    e.execute(
        Command::Import(ImportCommand::RecordProposals {
            document: DOC,
            proposals: vec![acronym_proposal()],
        }),
        ctx(Actor::System(SystemCause::Timeline), 4),
    )
    .unwrap();
    e
}

fn resolve(e: &mut E, resolution: ClientResolution, t: i64) -> Result<Seq, ExecError> {
    let cmd = Command::Bridge(BridgeCommand::ResolveImport {
        programme: P,
        proposal: ImportProposalId::from_raw(1),
        shown: SaltedDigest::from_bytes([1; 32]),
        resolution,
        conflict_acknowledged: false,
        base: head(e),
    });
    e.execute(cmd, by(M1, t))
}

/// The value the draft's creator holds for the acronym, if any.
fn held_acronym(e: &E) -> bool {
    e.state().creator.is_held(P, FieldId::ActionAcronym)
}

/// I-65: a confirmed import value is held once its entry is appended,
/// under the digest the entry saved. After a replay it is not held, and
/// once the shell holds the proposal's value text again, the engine holds
/// the confirmed value again from the import store.
#[test]
fn i65_confirmed_import_value_is_held_and_held_again_after_replay() {
    let mut e = proposed();
    let digest = fstp_import::ValueDigest::from_bytes([7; 32]);
    resolve(
        &mut e,
        ClientResolution::Confirm {
            value: acronym_proposal().value,
            digest,
        },
        5,
    )
    .unwrap();
    assert!(held_acronym(&e));
    let saved = e
        .state()
        .creator
        .draft(P)
        .unwrap()
        .fields()
        .get(&FieldId::ActionAcronym)
        .cloned()
        .unwrap();
    assert_eq!(
        saved.0,
        ValueDigest::new(ContentDigest::from_bytes([7; 32]))
    );
    let mut e = reopened(e);
    assert!(!held_acronym(&e));
    let p = acronym_proposal();
    e.hold_import(p.text, p.value).unwrap();
    assert!(held_acronym(&e));
}

/// I-65: an edited import value is held once its entry is appended. The
/// ledger keeps only its digest and the import store holds the proposal,
/// not the edit, so after a replay it stays unheld and fails closed.
#[test]
fn i65_edited_import_value_is_held_but_never_recovered_by_replay() {
    let mut e = proposed();
    resolve(
        &mut e,
        ClientResolution::Edit {
            value: UntrustedValue::parse(b"\"EDITED\"").unwrap(),
            digest: fstp_import::ValueDigest::from_bytes([8; 32]),
        },
        5,
    )
    .unwrap();
    assert!(held_acronym(&e));
    let mut e = reopened(e);
    let p = acronym_proposal();
    e.hold_import(p.text, p.value).unwrap();
    assert!(!held_acronym(&e));
}

/// I-65: a dismissal saves nothing, so nothing is held for its field.
#[test]
fn i65_dismissed_import_holds_nothing() {
    let mut e = proposed();
    resolve(&mut e, ClientResolution::Dismiss, 5).unwrap();
    assert!(!held_acronym(&e));
    assert!(
        !e.state()
            .creator
            .draft(P)
            .unwrap()
            .fields()
            .contains_key(&FieldId::ActionAcronym)
    );
}
