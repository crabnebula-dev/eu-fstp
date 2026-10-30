//! Independent review of the creator hold seams (lane m4creator, M4
//! design sections 3.2 and 3.10; I-51, I-66). The harness is copied from
//! `m4_creator_path.rs`, whose helpers a second test binary cannot share.
//!
//! Every value is synthetic. The cast holds no person.

#![allow(dead_code, unused_imports)]
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

/// I-51, I-66 reproducer: a held policy value stands in for the head
/// policy after the ledger recorded a newer one.
///
/// M1 saves the synthetic spec through the creator, so P-23 (pre-check
/// enabled) is held. M1 then edits the draft policy with a core
/// `EditPolicy` that disables P-23. The engine accepts it on a draft (D3
/// gates no `EditPolicy`). The draft's latest `FieldsSaved` for P-23 still
/// names the old digest, so the creator keeps reading the held value.
///
/// The Guide over the head policy cannot bind `{{P-23.per_day}}`: the
/// pre-check is disabled and the template describes it. So the report
/// must fail `GuideBindingUnresolved` and the approval must be refused
/// with I-66. Today the Guide preview reads the stale held P-23, the
/// report is clean, and the programme activates.
#[test]
fn review_invariants_held_policy_value_outlives_a_core_edit() {
    let mut e = requested(Vault::default());
    let state = e.state();
    let head = fstp_domain::policy::head(&state.core, P).unwrap().clone();
    assert!(state.creator.is_held(P, FieldId::P23));
    let mut spec = fstp_programme::policy_spec(&head);
    let Field::Set(FieldValue::P23(mut precheck)) = spec.get(FieldId::P23) else {
        panic!("the head holds no P-23");
    };
    assert!(precheck.enabled);
    precheck.enabled = false;
    spec.set(FieldValue::P23(precheck));
    let next = PolicyVersionId::from_raw(4_242);
    let version = compile(&spec, &he(), CompileIds::new(P, next, Some(head.id)))
        .unwrap()
        .policy;
    e.execute(
        Command::Core(fstp_domain::Command::EditPolicy {
            base: head.id,
            version: Box::new(version),
        }),
        by(M1, 10),
    )
    .unwrap_or_else(|r| panic!("the core EditPolicy is refused: {r:?}"));
    let now = fstp_domain::policy::head(&e.state().core, P).unwrap();
    assert!(
        matches!(fstp_programme::policy_spec(now).get(FieldId::P23), Field::Set(FieldValue::P23(p)) if !p.enabled),
        "the head disables the pre-check"
    );
    // The creator still holds the P-23 of the earlier save.
    assert!(e.state().creator.is_held(P, FieldId::P23));

    let r = report(&e, Some(TB));
    assert!(
        r.failures()
            .any(|x| x.check == CheckId::GuideBindingUnresolved
                && x.subject == CheckSubject::Placeholder("P-23.per_day".to_owned())),
        "the report reads the held P-23, not the head policy: {:?}",
        r.failures().collect::<Vec<_>>()
    );

    acknowledge_and_request(&mut e, 11);
    let before = e.head();
    assert_eq!(
        approve(&mut e, TB, 14),
        refused(RuleRef::I66, RefusalReason::GuardFailed),
        "a programme whose policy cannot bind the Guide activated"
    );
    assert_eq!(e.head(), before);
    assert_eq!(status(&e), Some(ProgrammeStatus::Draft));
}
