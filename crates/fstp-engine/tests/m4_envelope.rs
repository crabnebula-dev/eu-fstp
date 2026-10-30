//! The M4 envelope of the engine: creator, bridge and import commands, the
//! entry pairings of D2e and the bridge, and replay over the new records
//! (M4 design sections 3.2 to 3.4 and 4.2; I-23, I-50, I-65, I-66, I-67,
//! I-85).
//!
//! `fstp_creator::decide_creator` refuses `OpenDraft` until the creator's
//! compile seam closes, so the draft of these tests is opened by a forged
//! entry. The entry is the one a correct `OpenDraft` appends: the
//! creator's `DraftOpened` and the records of the core `CreateProgramme`
//! of the compiled SuperSAFE fixture, decided by `fstp_domain::decide`.
//! Every later command runs through `Engine::execute`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fstp_creator::{
    CreatorCommand, CreatorInputs, CreatorRecord, DraftRevision, InvitationId, Invitee,
    PortPresence, ProbeSet, Provenance, SodPreview, Theme, ValueDigest, VaultChecks,
};
use fstp_domain::command::{Actor, Ctx, SystemCause};
use fstp_domain::id::{
    AccountId, BindingId, CommandId, ContentDigest, DecisionId, PolicyVersionId, ProgrammeId,
    TextId, TextRef, VaultEpoch,
};
use fstp_domain::oracle::{Answer, Answers, OracleDown, Query};
use fstp_domain::programme::{ProgrammeStatus, programme_status};
use fstp_domain::refusal::{Refusal, RefusalReason, RuleRef};
use fstp_domain::roles::Role;
use fstp_domain::time::Timestamp;
use fstp_domain::{FoldError, Via};
use fstp_engine::bridge::BridgeCommand;
use fstp_engine::compose::{CreatorEnvironment, activate_command};
use fstp_engine::{
    Command, CreatorDecider, DomainDecider, Engine, EngineState, EnvelopeKind, ExecError,
    IdentityOracle, OpenError, Record, record_from_json_at, replay,
};
use fstp_import::{
    AccountRef, BlobAddress, ClientResolution, ConflictRule, ImportCommand, ImportConfigId,
    ImportDocument, ImportDocumentId, ImportMedia, ImportProposal, ImportProposalId, ImportRecord,
    ProgrammeRef, SaltedDigest, Span, TextDigest, UntrustedValue, ValueTextId, ValueTextRef,
};
use fstp_json::{FromJson, ToJson};
use fstp_ledger::{Entry, MemStore, RecordStore, Seq};
use fstp_programme::FieldId;

const P: ProgrammeId = ProgrammeId::from_raw(1);
const ADMIN: AccountId = AccountId::from_raw(11);
const ADMIN_2: AccountId = AccountId::from_raw(12);
const PM: AccountId = AccountId::from_raw(21);
const OUTSIDER: AccountId = AccountId::from_raw(31);
const DOC: ImportDocumentId = ImportDocumentId::from_raw(7);

/// A vault in which every account is verified with its own identity, no
/// conflict or exclusion holds and every cap is kept, at epoch 0.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Vault;

impl IdentityOracle for Vault {
    fn ask(&self, q: &Query) -> Result<Answer, OracleDown> {
        let holds = matches!(
            q,
            Query::IsVerified { .. }
                | Query::WithinRecipientCap { .. }
                | Query::AllRecipientsWithinCap { .. }
        );
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

fn at(t: i64) -> Timestamp {
    Timestamp::from_micros(t)
}

fn id(tag: &str, n: u8) -> [u8; 16] {
    let mut b = [0u8; 16];
    for (slot, byte) in b.iter_mut().zip(tag.bytes()) {
        *slot = byte;
    }
    b[15] = n;
    b
}

fn ctx(actor: Actor, now: i64, n: u8) -> Ctx {
    let admin = matches!(actor, Actor::Account(a) if a == ADMIN || a == ADMIN_2);
    Ctx {
        now: at(now),
        actor,
        command: CommandId::from_bytes(id("m4env", n)),
        via: Via::Web,
        tenant_admin: admin,
        second_tenant_admin: None,
        binds_tenant_admin: false,
    }
}

/// The compiled SuperSAFE policy of P.
fn policy() -> fstp_domain::policy::PolicyVersion {
    let fixture = fstp_programme::supersafe_fixture().unwrap();
    fstp_programme::compile(
        &fixture.spec,
        &fstp_programme::FunderProfile::horizon_europe(),
        fstp_programme::CompileIds::new(P, PolicyVersionId::from_raw(P.raw()), None),
    )
    .unwrap()
    .policy
}

/// The entry a correct `OpenDraft` by ADMIN appends (module documentation).
fn open_entry() -> Vec<Record> {
    let v = policy();
    let profile = v.frozen.p53.clone();
    let create = fstp_domain::Command::CreateProgramme {
        policy: Box::new(v),
    };
    let core = fstp_domain::decide(
        &fstp_domain::State::genesis(),
        &create,
        &ctx(Actor::Account(ADMIN), 1, 0),
        &Answers::new(),
    )
    .unwrap();
    let mut out = vec![Record::Creator(CreatorRecord::DraftOpened {
        programme: P,
        profile,
        by: ADMIN,
    })];
    out.extend(core.into_iter().map(Record::Core));
    out
}

/// An engine over the opened draft of P, with PM granted the programme
/// manager role by ADMIN at time 2.
fn drafted() -> E {
    let mut store = MemStore::new();
    store
        .append(Seq::ZERO, 1, id("open", 1), open_entry())
        .unwrap();
    let mut e = Engine::open_with(store, Vault, CreatorDecider(Env)).unwrap();
    let grant = fstp_domain::Command::GrantRole {
        binding: BindingId::from_raw(1),
        account: PM,
        programme: P,
        role: Role::ProgrammeManager,
        start: at(2),
        second_admin: None,
        confidentiality: Some(TextRef::new(
            TextId::from_raw(50_001),
            ContentDigest::from_bytes([4; 32]),
        )),
        organisation: None,
        end: None,
    };
    e.execute(Command::Core(grant), ctx(Actor::Account(ADMIN), 2, 1))
        .unwrap();
    e
}

fn entries(e: &E) -> Vec<Entry<Record>> {
    let mut out = Vec::new();
    e.store().read(Seq::ZERO, usize::MAX, &mut out).unwrap();
    out
}

fn head(e: &E) -> DraftRevision {
    e.state().creator.head(P).unwrap()
}

fn inputs() -> CreatorInputs {
    CreatorInputs {
        unresolved_imports: 0,
        probes: ProbeSet::passing(),
        sod: SodPreview::default(),
        vault: VaultChecks::default(),
        tenant_admins: [ADMIN, ADMIN_2].into_iter().collect(),
        ports: PortPresence::default(),
        theme: Theme::m4_default(),
        profile: None,
    }
}

fn creator(cmd: CreatorCommand) -> Command {
    Command::Creator(cmd)
}

/// The shell facts of the tests: every probe passing, ADMIN and ADMIN_2
/// attested as tenant admins, no SoD preview and no profile.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
struct Env;

impl CreatorEnvironment for Env {
    fn creator_inputs(&self, _: &EngineState, _: &CreatorCommand, _: &Ctx) -> CreatorInputs {
        inputs()
    }
}

/// The engine of the tests.
type E = Engine<MemStore<Record>, Vault, CreatorDecider<Env>>;

fn refused_rule(r: Result<Seq, ExecError>) -> RuleRef {
    match r {
        Err(ExecError::Refused(refusal)) => refusal.rule,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// The ActivationApproved record of P at `revision` by `approver`, decoded
/// from its stored form, since only a clearance builds one in code.
fn approval(revision: DraftRevision, approver: AccountId, decision: u128) -> CreatorRecord {
    let rev = format!(
        "{{\"entry\":\"{}\",\"seq\":\"{}\"}}",
        revision.entry().raw(),
        revision.seq()
    );
    let text = format!(
        "{{\"approver\":\"{}\",\"builders\":[\"{}\",\"{}\"],\"decision\":\"{decision}\",\"kind\":\"ActivationApproved\",\"programme\":\"{}\",\"report\":{{\"programme\":\"{}\",\"revision\":{rev},\"rows\":[]}},\"revision\":{rev}}}",
        approver.raw(),
        ADMIN.raw(),
        PM.raw(),
        P.raw(),
        P.raw(),
    );
    fstp_creator::decode_record(text.as_bytes()).unwrap()
}

/// The core records of the activation an approval composes, decided on the
/// engine's core by `approver`.
fn activation_records(e: &E, approved: &CreatorRecord, approver: AccountId) -> Vec<Record> {
    let CreatorRecord::ActivationApproved(a) = approved else {
        panic!("not an approval");
    };
    let cmd = activate_command(a);
    let c = ctx(Actor::Account(approver), 9, 9);
    let mut answers = Answers::new();
    for q in fstp_domain::queries(&e.state().core, &cmd, &c).unwrap() {
        let a = Vault.ask(&q).unwrap();
        answers.insert(q, a);
    }
    fstp_domain::decide(&e.state().core, &cmd, &c, &answers)
        .unwrap()
        .into_iter()
        .map(Record::Core)
        .collect()
}

/// Appends `batch` as one forged entry at time 9 and replays the store.
fn forge(e: E, batch: Vec<Record>) -> (Result<EngineState, FoldError>, Result<(), OpenError>) {
    let (mut store, _, _) = e.into_parts();
    let h = Seq::from_raw(u64::try_from(store_len(&store)).unwrap());
    store.append(h, 9, id("forged", 1), batch).unwrap();
    let mut all = Vec::new();
    store.read(Seq::ZERO, usize::MAX, &mut all).unwrap();
    let replayed = replay(&all);
    let opened = Engine::open_with(store, Vault, CreatorDecider(Env)).map(|_| ());
    (replayed, opened)
}

fn store_len(s: &MemStore<Record>) -> usize {
    let mut all = Vec::new();
    s.read(Seq::ZERO, usize::MAX, &mut all).unwrap();
    all.len()
}

/// I-66, D2e: a core `ActivateProgramme` of a drafted programme through
/// `execute` is refused with I-66, even by a tenant admin outside the
/// builder set whom the core guard would admit, and appends nothing.
#[test]
fn i66_execute_refuses_core_activate_programme_of_a_draft() {
    let mut e = drafted();
    let before = e.head();
    let cmd = fstp_domain::Command::ActivateProgramme {
        programme: P,
        decision: DecisionId::from_raw(66),
        report: fstp_domain::policy::activation::ReportDigest::from_bytes([6; 32]),
        revision: 1,
        creator_builders: BTreeSet::new(),
    };
    let c = ctx(Actor::Account(ADMIN_2), 5, 2);
    let mut answers = Answers::new();
    for q in fstp_domain::queries(&e.state().core, &cmd, &c).unwrap() {
        let a = Vault.ask(&q).unwrap();
        answers.insert(q, a);
    }
    assert!(
        fstp_domain::decide(&e.state().core, &cmd, &c, &answers).is_ok(),
        "the core guard admits the approver, so the refusal is the engine's"
    );
    assert_eq!(refused_rule(e.execute(Command::Core(cmd), c)), RuleRef::I66);
    assert_eq!(e.head(), before);
}

/// I-66, D2e: an entry with the `ProgrammeActivated` of a draft and no
/// `ActivationApproved` beside it is refused by the fold, on replay and
/// on open.
#[test]
fn i66_fold_refuses_unpaired_programme_activated_of_a_draft() {
    let e = drafted();
    let approved = approval(head(&e), ADMIN_2, 70);
    let core = activation_records(&e, &approved, ADMIN_2);
    let (replayed, opened) = forge(e, core);
    assert_eq!(replayed.err(), Some(FoldError::Inconsistent));
    assert_eq!(opened.err(), Some(OpenError::Fold(FoldError::Inconsistent)));
}

/// I-66, D2e: an approval and its activation in one entry fold, and the
/// programme becomes active on both sides.
#[test]
fn i66_fold_accepts_activation_paired_with_its_approval() {
    let e = drafted();
    let approved = approval(head(&e), ADMIN_2, 70);
    let mut batch = vec![Record::Creator(approved.clone())];
    batch.extend(activation_records(&e, &approved, ADMIN_2));
    let (replayed, opened) = forge(e, batch);
    let s = replayed.unwrap();
    assert!(opened.is_ok());
    assert_eq!(programme_status(&s.core, P), Some(ProgrammeStatus::Active));
    assert!(s.creator.draft(P).unwrap().active().is_some());
}

/// I-66, D2e: an approval whose entry holds no activation, or an
/// activation of another approval, is refused.
#[test]
fn i66_fold_refuses_dangling_or_mismatched_approval() {
    let e = drafted();
    let approved = approval(head(&e), ADMIN_2, 70);
    let (alone, _) = forge(drafted(), vec![Record::Creator(approved.clone())]);
    assert_eq!(alone.err(), Some(FoldError::Inconsistent));
    let other = approval(head(&e), ADMIN_2, 71);
    let mut batch = vec![Record::Creator(approved)];
    batch.extend(activation_records(&e, &other, ADMIN_2));
    let (mismatched, _) = forge(e, batch);
    assert_eq!(mismatched.err(), Some(FoldError::Inconsistent));
}

/// I-67: the creator refuses an approval by a builder with I-67, and the
/// engine appends nothing.
#[test]
fn i67_creator_approval_by_a_builder_is_refused() {
    let mut e = drafted();
    let before = e.head();
    let revision = head(&e);
    let r = e.execute(
        creator(CreatorCommand::ApproveActivation {
            programme: P,
            revision,
            decision: DecisionId::from_raw(80),
        }),
        ctx(Actor::Account(ADMIN), 5, 3),
    );
    assert_eq!(refused_rule(r), RuleRef::I67);
    assert_eq!(e.head(), before);
}

/// I-66: a requested activation whose recomputed report does not clear is
/// refused with I-66 when a non-builder approves it.
#[test]
fn i66_creator_approval_of_an_uncleared_report_is_refused() {
    let mut e = drafted();
    let revision = head(&e);
    e.execute(
        creator(CreatorCommand::RequestActivation {
            programme: P,
            revision,
        }),
        ctx(Actor::Account(PM), 5, 3),
    )
    .unwrap();
    let before = e.head();
    let r = e.execute(
        creator(CreatorCommand::ApproveActivation {
            programme: P,
            revision: head(&e),
            decision: DecisionId::from_raw(80),
        }),
        ctx(Actor::Account(ADMIN_2), 6, 4),
    );
    assert_eq!(
        r,
        Err(ExecError::Refused(Refusal::new(
            RuleRef::I66,
            RefusalReason::GuardFailed
        )))
    );
    assert_eq!(e.head(), before);
}

/// I-85: a high-risk creator command through MCP is refused.
#[test]
fn i85_creator_approval_through_mcp_is_refused() {
    let mut e = drafted();
    let mut c = ctx(Actor::Account(ADMIN_2), 5, 3);
    c.via = Via::Mcp;
    let r = e.execute(
        creator(CreatorCommand::ApproveActivation {
            programme: P,
            revision: head(&e),
            decision: DecisionId::from_raw(80),
        }),
        c,
    );
    assert_eq!(refused_rule(r), RuleRef::I85);
}

/// I-23, I-67: a creator command runs through the engine as one entry. Its
/// author joins the builder set, the draft revision moves once, and the
/// replay of the store equals the live state.
#[test]
fn i23_creator_invitation_is_one_entry_and_replays() {
    let mut e = drafted();
    let before = head(&e);
    let seq = e
        .execute(
            creator(CreatorCommand::Invite {
                programme: P,
                invitation: InvitationId::from_raw(5),
                role: Role::CallDrafter,
                invitee: Invitee::Account(OUTSIDER),
                organisation: None,
            }),
            ctx(Actor::Account(PM), 5, 3),
        )
        .unwrap();
    let after = head(&e);
    assert_eq!(after.seq(), before.seq().saturating_add(1));
    assert_eq!(after.entry(), seq);
    let d = e.state().creator.draft(P).unwrap();
    assert!(d.builders().contains(&PM));
    assert!(d.invitations().contains_key(&InvitationId::from_raw(5)));
    assert_eq!(&replay(&entries(&e)).unwrap(), e.state());
}

fn document(by: AccountId) -> ImportDocument {
    ImportDocument {
        id: DOC,
        programme: ProgrammeRef::from_raw(P.raw()),
        blob: BlobAddress::from_bytes([1; 32]),
        media: ImportMedia::TextPlain,
        digest: TextDigest::from_bytes([2; 32]),
        text_bytes: 64,
        uploaded_by: AccountRef::from_raw(by.raw()),
    }
}

fn proposal(n: u128, field: FieldId, value: &str) -> ImportProposal {
    ImportProposal {
        id: ImportProposalId::from_raw(n),
        document: DOC,
        field,
        value: UntrustedValue::parse(value.as_bytes()).unwrap(),
        text: ValueTextRef::new(
            ValueTextId::from_raw(100u128.saturating_add(n)),
            SaltedDigest::from_bytes([u8::try_from(n).unwrap(); 32]),
        ),
        evidence: vec![Span { start: 0, end: 8 }],
        config: ImportConfigId::from_raw(1),
        conflicts_with_profile: Vec::new(),
    }
}

/// An engine over the draft with the document uploaded by PM at time 5
/// and two proposals recorded at time 6: a P-05 of 500000.00 and a
/// programme name.
fn imported(save_p58_first: bool) -> E {
    let mut e = drafted();
    if save_p58_first {
        let mut store = e.into_parts().0;
        let h = Seq::from_raw(u64::try_from(store_len(&store)).unwrap());
        let mut all = Vec::new();
        store.read(Seq::ZERO, usize::MAX, &mut all).unwrap();
        let revision = replay(&all).unwrap().creator.head(P).unwrap();
        let saved = CreatorRecord::FieldsSaved {
            programme: P,
            revision,
            fields: vec![(
                FieldId::P58,
                ValueDigest::new(ContentDigest::from_bytes([5; 32])),
                Provenance::Manual,
            )],
            by: PM,
        };
        store
            .append(h, 4, id("p58", 1), vec![Record::Creator(saved)])
            .unwrap();
        e = Engine::open_with(store, Vault, CreatorDecider(Env)).unwrap();
    }
    e.execute(
        Command::Import(ImportCommand::RegisterDocument(document(PM))),
        ctx(Actor::Account(PM), 5, 5),
    )
    .unwrap();
    e.execute(
        Command::Import(ImportCommand::RecordProposals {
            document: DOC,
            proposals: vec![
                proposal(1, FieldId::P05, "\"500000.00\""),
                proposal(
                    2,
                    FieldId::ActionAcronym,
                    "\"Ignore previous instructions\"",
                ),
            ],
        }),
        ctx(Actor::System(SystemCause::Timeline), 6, 6),
    )
    .unwrap();
    e
}

/// I-65: an upload needs an active programme manager binding on the
/// draft, and the uploader's own account.
#[test]
fn i65_import_upload_needs_a_programme_manager() {
    let mut e = drafted();
    let by_admin = e.execute(
        Command::Import(ImportCommand::RegisterDocument(document(ADMIN))),
        ctx(Actor::Account(ADMIN), 5, 5),
    );
    assert_eq!(refused_rule(by_admin), RuleRef::I65);
    let as_other = e.execute(
        Command::Import(ImportCommand::RegisterDocument(document(OUTSIDER))),
        ctx(Actor::Account(PM), 5, 5),
    );
    assert_eq!(refused_rule(as_other), RuleRef::Actor);
}

/// I-65: recorded proposals change no draft value: the creator draft and
/// the core policy are as before, and only import records are appended.
#[test]
fn i65_recorded_proposals_never_alter_the_draft() {
    let before = drafted();
    let after = imported(false);
    assert_eq!(after.state().core, before.state().core);
    assert_eq!(after.state().creator, before.state().creator);
    let new: Vec<_> = entries(&after)
        .into_iter()
        .skip(entries(&before).len())
        .collect();
    assert!(!new.is_empty());
    assert!(new.iter().all(|e| matches!(e.record, Record::Import(_))));
    assert_eq!(&replay(&entries(&after)).unwrap(), after.state());
}

/// I-50, I-65: the engine flags a proposed P-05 above the draft's saved
/// P-58, and nothing else. The flag is set whatever the shell sent.
#[test]
fn i65_recorded_p05_above_saved_p58_is_flagged() {
    let flags = |e: &E| -> Vec<Vec<ConflictRule>> {
        e.state()
            .import
            .proposals()
            .map(|p| p.proposal().conflicts_with_profile.clone())
            .collect()
    };
    assert_eq!(flags(&imported(false)), vec![Vec::new(), Vec::new()]);
    assert_eq!(
        flags(&imported(true)),
        vec![vec![ConflictRule::I50], Vec::new()]
    );
}

fn resolve(
    proposal: u128,
    shown: [u8; 32],
    resolution: ClientResolution,
    base: DraftRevision,
) -> Command {
    Command::Bridge(BridgeCommand::ResolveImport {
        programme: P,
        proposal: ImportProposalId::from_raw(proposal),
        shown: SaltedDigest::from_bytes(shown),
        resolution,
        conflict_acknowledged: false,
        base,
    })
}

/// I-65: a dismissal with the shown digest of the stored value appends
/// only its import record. The resolver joins the builder set and the
/// draft revision moves once. A forged digest or a stale base is refused.
#[test]
fn i65_dismissal_records_only_the_import_record() {
    let mut e = imported(false);
    let base = head(&e);
    let forged = e.execute(
        resolve(2, [9; 32], ClientResolution::Dismiss, base),
        ctx(Actor::Account(PM), 7, 7),
    );
    assert_eq!(refused_rule(forged), RuleRef::I65);
    let stale = DraftRevision::new(base.seq().saturating_sub(1), base.entry());
    let r = e.execute(
        resolve(2, [2; 32], ClientResolution::Dismiss, stale),
        ctx(Actor::Account(PM), 7, 7),
    );
    assert_eq!(refused_rule(r), RuleRef::Input);
    let by_outsider = e.execute(
        resolve(2, [2; 32], ClientResolution::Dismiss, base),
        ctx(Actor::Account(ADMIN), 7, 7),
    );
    assert_eq!(refused_rule(by_outsider), RuleRef::I65);
    let n = entries(&e).len();
    e.execute(
        resolve(2, [2; 32], ClientResolution::Dismiss, base),
        ctx(Actor::Account(PM), 7, 7),
    )
    .unwrap();
    let all = entries(&e);
    assert_eq!(all.len(), n.saturating_add(1));
    assert!(matches!(
        all.last().map(|x| &x.record),
        Some(Record::Import(ImportRecord::ProposalResolved { .. }))
    ));
    assert_eq!(head(&e).seq(), base.seq().saturating_add(1));
    assert_eq!(&replay(&all).unwrap(), e.state());
}

/// I-65: a `FieldsSaved` with import provenance folds only after the
/// `ProposalResolved` of the same proposal, resolution and account in its
/// entry, and a confirmation must save its value.
#[test]
fn i65_fold_pairs_imported_values_with_their_resolution() {
    let e = imported(false);
    let revision = head(&e);
    let saved = Record::Creator(CreatorRecord::FieldsSaved {
        programme: P,
        revision,
        fields: vec![(
            FieldId::ActionAcronym,
            ValueDigest::new(ContentDigest::from_bytes([3; 32])),
            Provenance::Import {
                proposal: fstp_creator::ImportProposalId::from_raw(2),
                resolution: fstp_creator::ImportResolution::Confirmed,
            },
        )],
        by: PM,
    });
    let resolved = |by: AccountId| {
        Record::Import(ImportRecord::ProposalResolved {
            proposal: ImportProposalId::from_raw(2),
            resolution: fstp_import::ImportResolution::Confirmed,
            by: AccountRef::from_raw(by.raw()),
        })
    };
    let (alone, _) = forge(imported(false), vec![saved.clone()]);
    assert_eq!(alone.err(), Some(FoldError::Inconsistent));
    let (unsaved, _) = forge(imported(false), vec![resolved(PM)]);
    assert_eq!(unsaved.err(), Some(FoldError::Inconsistent));
    let (other, _) = forge(imported(false), vec![resolved(ADMIN), saved.clone()]);
    assert_eq!(other.err(), Some(FoldError::Inconsistent));
    let (paired, opened) = forge(e, vec![resolved(PM), saved]);
    let s = paired.unwrap();
    assert!(opened.is_ok());
    assert!(
        s.creator
            .draft(P)
            .unwrap()
            .fields()
            .contains_key(&FieldId::ActionAcronym)
    );
}

/// I-65: an imported value folds only into the programme and the field
/// of the proposal its entry resolved. A forged entry that resolves the
/// acronym proposal and saves its value into P-05, or into another
/// programme, is refused.
#[test]
fn i65_fold_binds_imported_values_to_the_proposal_field_and_programme() {
    let e = imported(false);
    let revision = head(&e);
    let saved = |programme: ProgrammeId, field: FieldId| {
        Record::Creator(CreatorRecord::FieldsSaved {
            programme,
            revision,
            fields: vec![(
                field,
                ValueDigest::new(ContentDigest::from_bytes([3; 32])),
                Provenance::Import {
                    proposal: fstp_creator::ImportProposalId::from_raw(2),
                    resolution: fstp_creator::ImportResolution::Confirmed,
                },
            )],
            by: PM,
        })
    };
    let resolved = Record::Import(ImportRecord::ProposalResolved {
        proposal: ImportProposalId::from_raw(2),
        resolution: fstp_import::ImportResolution::Confirmed,
        by: AccountRef::from_raw(PM.raw()),
    });
    let (other_field, _) = forge(
        imported(false),
        vec![resolved.clone(), saved(P, FieldId::P05)],
    );
    assert_eq!(other_field.err(), Some(FoldError::Inconsistent));
    let (other_programme, _) = forge(
        imported(false),
        vec![
            resolved.clone(),
            saved(
                ProgrammeId::from_raw(P.raw().saturating_add(1)),
                FieldId::ActionAcronym,
            ),
        ],
    );
    assert_eq!(other_programme.err(), Some(FoldError::Inconsistent));
    let (paired, _) = forge(e, vec![resolved, saved(P, FieldId::ActionAcronym)]);
    assert!(paired.is_ok());
}

/// I-23: creator and import records round-trip through the stored
/// envelope on their own side, and an unknown member is refused.
#[test]
fn i23_creator_and_import_records_round_trip_on_their_side() {
    for r in [
        Record::Creator(CreatorRecord::DraftOpened {
            programme: P,
            profile: policy().frozen.p53,
            by: ADMIN,
        }),
        Record::Import(ImportRecord::DocumentRegistered(document(PM))),
    ] {
        let v = r.to_json();
        let (kind, _) = fstp_engine::envelope_from_json(&v).unwrap();
        assert_eq!(kind, EnvelopeKind::of(&r));
        assert_eq!(Record::from_json(&v).unwrap(), r);
        assert_eq!(record_from_json_at(1, &v).unwrap(), r);
        assert!(record_from_json_at(2, &v).is_err());
    }
    let bad = fstp_json::parse(br#"{"tenant":{}}"#).unwrap();
    assert!(Record::from_json(&bad).is_err());
}

/// I-67, Q31: without shell facts no tenant admin is attested, so the
/// production decider refuses every approval and appends nothing.
#[test]
fn i67_no_environment_attests_no_tenant_admin() {
    let e = drafted();
    let revision = head(&e);
    let (store, _, _) = e.into_parts();
    let mut plain: Engine<MemStore<Record>, Vault, DomainDecider> =
        Engine::open(store, Vault).unwrap();
    let before = plain.head();
    let r = plain.execute(
        creator(CreatorCommand::ApproveActivation {
            programme: P,
            revision,
            decision: DecisionId::from_raw(80),
        }),
        ctx(Actor::Account(ADMIN_2), 5, 3),
    );
    assert_eq!(refused_rule(r), RuleRef::Actor);
    assert_eq!(plain.head(), before);
}

/// I-78: the form of a bridge command and of an import command names one
/// command: equal commands give equal canonical text, and commands that
/// differ give different text.
#[test]
fn i78_bridge_and_import_command_forms_name_one_command() {
    let value = UntrustedValue::parse(b"\"400000.00\"").unwrap();
    let digest = fstp_import::ValueDigest::from_bytes([3; 32]);
    let base = DraftRevision::new(2, Seq::from_raw(5));
    let forms: Vec<String> = [
        ClientResolution::Confirm {
            value: value.clone(),
            digest,
        },
        ClientResolution::Edit {
            value: value.clone(),
            digest,
        },
        ClientResolution::Dismiss,
    ]
    .into_iter()
    .map(|r| {
        let c = BridgeCommand::ResolveImport {
            programme: P,
            proposal: ImportProposalId::from_raw(1),
            shown: SaltedDigest::from_bytes([1; 32]),
            resolution: r,
            conflict_acknowledged: false,
            base,
        };
        let text = c.to_json().to_canonical().unwrap();
        assert_eq!(c.clone().to_json().to_canonical().unwrap(), text);
        text
    })
    .collect();
    let distinct: BTreeSet<&String> = forms.iter().collect();
    assert_eq!(distinct.len(), forms.len());
    let register =
        fstp_engine::bridge::import_command_json(&ImportCommand::RegisterDocument(document(PM)));
    let record = fstp_engine::bridge::import_command_json(&ImportCommand::RecordProposals {
        document: DOC,
        proposals: vec![proposal(1, FieldId::P05, "\"500000.00\"")],
    });
    assert_ne!(
        register.to_canonical().unwrap(),
        record.to_canonical().unwrap()
    );
}
