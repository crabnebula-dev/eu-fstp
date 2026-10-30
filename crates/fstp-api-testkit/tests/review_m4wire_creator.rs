//! Review reproducers for lane m4wire (M4 design sections 3.2 and 3.7,
//! ADR-007).
//!
//! The draft is opened by a forged entry, as the lane's own
//! `fake/creator_forged_tests.rs` does, since `fstp_creator::decide_creator`
//! refuses `OpenDraft` until lane m4creator merges. Every later step runs
//! through `ApiCore::dispatch` on the fake cell.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_core::OpResult;
use fstp_api_core::port::LoginMethod;
use fstp_api_testkit::fake::FakeCell;
use fstp_api_testkit::fake::creator_requests as rq;
use fstp_api_testkit::fake::fixture::{self, ADMIN, OWNER};
use fstp_creator::{CreatorCommand, CreatorRecord, Invitee};
use fstp_domain::command::{Actor, Ctx, Via};
use fstp_domain::id::{BindingId, CommandId, PolicyVersionId, ProgrammeId};
use fstp_domain::oracle::Answers;
use fstp_domain::roles::Role;
use fstp_domain_testkit::r#gen::roster;
use fstp_engine::{Command, Record};
use fstp_ledger::{RecordStore, Seq};

/// The forged draft.
const PD: ProgrammeId = ProgrammeId::from_raw(9_001);

/// A cell over the I-85 world with the forged draft PD opened by A1, and
/// M1 granted the programme manager role on it.
fn cell() -> FakeCell {
    let mut world = fixture::pending_world().unwrap();
    let mut entries = Vec::new();
    world
        .store
        .read(Seq::ZERO, usize::MAX, &mut entries)
        .unwrap();
    let state = fstp_engine::replay(&entries).unwrap();
    let spec = fstp_programme::supersafe_fixture().unwrap().spec;
    let policy = fstp_programme::compile(
        &spec,
        &fstp_programme::FunderProfile::horizon_europe(),
        fstp_programme::CompileIds::new(PD, PolicyVersionId::from_raw(PD.raw()), None),
    )
    .unwrap()
    .policy;
    let profile = policy.frozen.p53.clone();
    let at = roster::T0;
    let ctx = Ctx {
        now: at,
        actor: Actor::Account(ADMIN),
        command: CommandId::from_bytes(*b"review:open:0001"),
        via: Via::Web,
        tenant_admin: true,
        second_tenant_admin: None,
        binds_tenant_admin: false,
    };
    let core = fstp_domain::decide(
        &state.core,
        &fstp_domain::Command::CreateProgramme {
            policy: Box::new(policy),
        },
        &ctx,
        &Answers::new(),
    )
    .unwrap();
    let mut records = vec![Record::Creator(CreatorRecord::DraftOpened {
        programme: PD,
        profile,
        by: ADMIN,
    })];
    records.extend(core.into_iter().map(Record::Core));
    let head = world.store.head();
    world
        .store
        .append(head, at.micros(), *b"review:open:0001", records)
        .unwrap();
    let c = FakeCell::from_world(&world).unwrap();
    let now = c.ports.clock.read();
    let step = roster::grant(
        BindingId::from_raw(91_001),
        OWNER,
        PD,
        Role::ProgrammeManager,
        now,
    );
    c.ports
        .engine
        .environment(
            Command::Core(step.cmd.clone()),
            step.ctx(now, CommandId::from_bytes(*b"review:grant:001")),
        )
        .unwrap();
    c
}

/// ADR-007 ("The digest is keyed with a random salt stored with the
/// text and destroyed with it"), I-81: the invitation's contact is a
/// `TextRef` inside the ledger body of `InvitationRecorded`. Its digest
/// must not be the unkeyed SHA-256 of the email, or the immutable ledger
/// confirms a guessed address after erasure.
#[test]
fn review_adr007_invitation_contact_digest_is_not_unkeyed_sha256_of_email() {
    let c = cell();
    let owner = c.login(OWNER, LoginMethod::Passkey);
    let email = "r1@e2e.invalid";
    let r = c.web(&owner, rq::invite(PD, email, "committee_member", None));
    assert!(matches!(r, Ok(OpResult::Done { .. })), "invite: {r:?}");
    let contact = c
        .ports
        .engine
        .appended()
        .into_iter()
        .rev()
        .find_map(|e| match e.cmd {
            Command::Creator(CreatorCommand::Invite {
                invitee: Invitee::Pending { contact },
                ..
            }) => Some(contact),
            _ => None,
        })
        .expect("no Invite was appended");
    assert_ne!(
        contact.digest().bytes(),
        fstp_crypto::sha256(email.as_bytes()),
        "ADR-007: the ledger body carries the unkeyed SHA-256 of the invitee's email"
    );
}

/// I-66, M4 design sections 3.2 (`CreatorInputs::theme`) and 8.4
/// (`i66_seeded_failure_never_activates`: "seeded failures from every
/// `CheckId` of severity Failure"): the theme is a shell fact the creator
/// environment supplies, as the probes are. So the production adapter can
/// seed a theme fault through the cell's environment. It must not refuse
/// a theme seed outright, or the production variant stays red for
/// `ContrastFailure` and `MandatoryElementMissing` after every lane
/// merges.
#[test]
fn review_i66_production_adapter_seeds_theme_faults_through_the_environment() {
    use fstp_api_testkit::mc::activate_model::production::{GAP_THEME, ProductionSystem};
    use fstp_api_testkit::reference::creator::{RefCheck, seeded_plan};
    for check in [RefCheck::ContrastFailure, RefCheck::MandatoryElementMissing] {
        let got = ProductionSystem::open(&seeded_plan(check)).map(|_| ());
        assert_ne!(
            got,
            Err(GAP_THEME),
            "I-66: the production adapter refuses to seed {} although the environment supplies the theme",
            check.name()
        );
    }
}
