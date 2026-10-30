//! Dispatch tests of the creator, bridge and import operations over a
//! draft whose opening entry is forged (lane m4wire production agent).
//!
//! `fstp_creator::decide_creator` refuses `OpenDraft` at its compile seam
//! until lane m4creator merges, so the journeys of `creator_wire_tests.rs`
//! stop at the opening. These tests open the draft as the engine's own
//! M4 envelope tests do: the world's ledger gets the entry a correct
//! `OpenDraft` by A1 appends, the creator's `DraftOpened` and the records
//! of the core `CreateProgramme` of the compiled SuperSAFE fixture,
//! decided by `fstp_domain::decide`. Every later step runs through
//! `ApiCore::dispatch`, the fake engine port and its creator environment.
//!
//! The tests assert only what holds before and after the parallel lanes
//! merge. No assertion depends on a seam's refusal.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_core::{ApiError, ErrorCode, OpResult};
use fstp_creator::{CreatorCommand, CreatorRecord, Invitee};
use fstp_domain::command::{Actor, Ctx, Via};
use fstp_domain::id::{BindingId, CommandId, PolicyVersionId, ProgrammeId};
use fstp_domain::oracle::Answers;
use fstp_domain::roles::Role;
use fstp_domain_testkit::r#gen::roster;
use fstp_engine::{Command, Record};
use fstp_json::{ToJson, Value};
use fstp_ledger::{RecordStore, Seq};

use super::cell::{Class, class};
use super::creator_requests as rq;
use super::fixture::{self, ADMIN, ADMIN_2, LEAD, OWNER};
use super::{FakeCell, WebLogin};
use fstp_api_core::port::LoginMethod;

/// The forged draft.
const PD: ProgrammeId = ProgrammeId::from_raw(9_001);

/// A synthetic annex the cell's proposer reads.
const ANNEX: &str = "SYNTHETIC ANNEX. NOT A REAL FUNDING DOCUMENT.\n\
Action number: 101000001\n\
Maximum per recipient: EUR 400000.00\n";

/// The context of the forged opening by A1.
fn open_ctx(now: fstp_domain::time::Timestamp) -> Ctx {
    Ctx {
        now,
        actor: Actor::Account(ADMIN),
        command: CommandId::from_bytes(*b"forged:open:0001"),
        via: Via::Web,
        tenant_admin: true,
        second_tenant_admin: None,
        binds_tenant_admin: false,
    }
}

/// A cell over the I-85 world with the forged draft PD opened by A1, and
/// M1 granted the programme manager role on it by A1.
fn cell() -> FakeCell {
    let mut world = fixture::pending_world().unwrap();
    let mut entries = Vec::new();
    world
        .store
        .read(Seq::ZERO, usize::MAX, &mut entries)
        .unwrap();
    let state = fstp_engine::replay(&entries).unwrap();
    let fixture = fstp_programme::supersafe_fixture().unwrap();
    let policy = fstp_programme::compile(
        &fixture.spec,
        &fstp_programme::FunderProfile::horizon_europe(),
        fstp_programme::CompileIds::new(PD, PolicyVersionId::from_raw(PD.raw()), None),
    )
    .unwrap()
    .policy;
    let profile = policy.frozen.p53.clone();
    let at = roster::T0;
    let core = fstp_domain::decide(
        &state.core,
        &fstp_domain::Command::CreateProgramme {
            policy: Box::new(policy),
        },
        &open_ctx(at),
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
        .append(head, at.micros(), *b"forged:open:0001", records)
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
            step.ctx(now, CommandId::from_bytes(*b"forged:grant:001")),
        )
        .unwrap();
    c
}

fn login(c: &FakeCell, a: fstp_domain::id::AccountId) -> WebLogin {
    c.login(a, LoginMethod::Passkey)
}

/// The JSON body of a completed call.
fn done(r: Result<OpResult, ApiError>, what: &str) -> Value {
    match r {
        Ok(OpResult::Done { body, .. }) => body.to_json(),
        other => panic!("{what} gave {other:?}"),
    }
}

fn str_of(v: &Value, k: &str) -> String {
    v.get(k)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no {k} in {}", v.to_compact()))
        .to_owned()
}

fn rows<'a>(v: &'a Value, k: &str) -> &'a [Value] {
    v.get(k)
        .and_then(Value::as_array)
        .map(|a| &a[..])
        .unwrap_or_else(|| panic!("no {k} in {}", v.to_compact()))
}

/// The rule of a refusal.
fn rule(r: &Result<OpResult, ApiError>) -> Option<&'static str> {
    match r {
        Err(ApiError::Refused { rule, .. }) => Some(*rule),
        _ => None,
    }
}

/// The report of PD as `l` reads it.
fn report(c: &FakeCell, l: &WebLogin) -> Value {
    done(c.web(l, rq::get_report(PD)), "creator.get_report")
}

/// The revision string of PD's head.
fn head(c: &FakeCell) -> String {
    let h = c.ports.engine.state().creator.head(PD).unwrap();
    format!("{}.{}", h.seq(), h.entry().raw())
}

/// Every creator command the engine port appended.
fn appended_creator(c: &FakeCell) -> Vec<CreatorCommand> {
    c.ports
        .engine
        .appended()
        .into_iter()
        .filter_map(|e| match e.cmd {
            Command::Creator(cmd) => Some(cmd),
            _ => None,
        })
        .collect()
}

/// I-66, R-PG-01, design section 3.2 "Validation": the report of the
/// opened draft is at its head revision, names catalogue checks only,
/// holds a failure and never names an account (R-CF-03). The applicant
/// cannot read it (R-AC-01).
#[test]
fn i66_r_pg_01_report_of_an_opened_draft_reads_at_its_head() {
    let c = cell();
    let owner = login(&c, OWNER);
    let r = report(&c, &owner);
    assert_eq!(str_of(&r, "revision"), head(&c));
    let results = rows(&r, "results");
    assert!(results.iter().any(|x| str_of(x, "severity") == "failure"));
    for x in results {
        let check = str_of(x, "check");
        assert!(
            fstp_creator::CheckId::from_name(&check).is_some(),
            "{check}"
        );
        let text = x.to_compact();
        for a in [ADMIN, ADMIN_2, OWNER] {
            assert!(
                !text.contains(&format!("\"{}\"", a.raw())),
                "a row names an account: {text}"
            );
        }
    }
    let lead = login(&c, LEAD);
    assert!(class(&c.web(&lead, rq::get_report(PD))).refused());
}

/// I-66, design section 3.2 "Bound to a revision": M1 acknowledges the
/// RosterShort warning by its listed key at the head revision. The engine
/// port appends `AcknowledgeWarning`, and the report then shows the row
/// acknowledged.
#[test]
fn i66_acknowledging_a_listed_warning_shows_it_acknowledged() {
    let c = cell();
    let owner = login(&c, OWNER);
    let r = report(&c, &owner);
    let row = rows(&r, "results")
        .iter()
        .find(|x| str_of(x, "check") == "RosterShort")
        .cloned()
        .unwrap_or_else(|| panic!("no RosterShort row: {}", r.to_compact()));
    assert_eq!(
        row.get("acknowledged").and_then(Value::as_bool),
        Some(false)
    );
    let key = str_of(&row, "key");
    done(
        c.web(&owner, rq::acknowledge(PD, &str_of(&r, "revision"), &key)),
        "creator.acknowledge",
    );
    assert!(
        appended_creator(&c)
            .iter()
            .any(|cmd| matches!(cmd, CreatorCommand::AcknowledgeWarning { .. }))
    );
    let again = report(&c, &owner);
    let row = rows(&again, "results")
        .iter()
        .find(|x| str_of(x, "key") == key)
        .cloned()
        .unwrap();
    assert_eq!(row.get("acknowledged").and_then(Value::as_bool), Some(true));
    let stale = c.web(&owner, rq::acknowledge(PD, &str_of(&r, "revision"), &key));
    assert_eq!(rule(&stale), Some("Input"), "a stale revision: {stale:?}");
}

/// I-66, R-PG-03, design section 3.7: a request for activation of a draft
/// whose report holds a failure is refused with the rule text I-66 only,
/// and nothing is appended.
#[test]
fn i66_request_with_a_failing_report_is_refused_with_i66() {
    let c = cell();
    let owner = login(&c, OWNER);
    let before = appended_creator(&c).len();
    let r = c.web(&owner, rq::request_activation(PD, &head(&c)));
    assert_eq!(class(&r), Class::Refused(ErrorCode::Refused), "{r:?}");
    assert_eq!(rule(&r), Some("I-66"));
    assert_eq!(appended_creator(&c).len(), before);
}

/// R-PG-01, SoD-09, ADR-007: M1 invites by email. The engine port appends
/// `Invite` with a drawn id and the email as a stored contact, the
/// invitation list shows it as invited and unchecked, and the withdrawal
/// removes it from the list.
#[test]
fn r_pg_01_invite_lists_and_withdraws_over_the_forged_draft() {
    let c = cell();
    let owner = login(&c, OWNER);
    done(
        c.web(
            &owner,
            rq::invite(PD, "r1@e2e.invalid", "committee_member", Some("3")),
        ),
        "creator.invite",
    );
    let Some(CreatorCommand::Invite {
        invitation,
        role,
        invitee: Invitee::Pending { contact },
        organisation,
        ..
    }) = appended_creator(&c).pop()
    else {
        panic!("no invitation was appended");
    };
    assert_eq!(role, Role::CommitteeMember);
    assert_eq!(organisation.map(|o| o.raw()), Some(3));
    // ADR-007: the stored text is the salt, then the email, and the
    // contact's digest is keyed with that salt.
    let stored = c
        .ports
        .texts
        .peek(fstp_api_core::port::TextRef(contact.id().raw()))
        .unwrap();
    let (salt, text) = fstp_api_core::salted::split(&stored).unwrap();
    assert_eq!(text, b"r1@e2e.invalid");
    assert!(fstp_api_core::salted::verify(
        &salt,
        text,
        &contact.digest().bytes()
    ));
    let id = invitation.raw().to_string();
    let list = done(c.web(&owner, rq::invitations(PD)), "creator.invitations");
    let row = rows(&list, "invitations")
        .iter()
        .find(|r| str_of(r, "id") == id)
        .cloned()
        .unwrap();
    assert_eq!(str_of(&row, "email"), "r1@e2e.invalid");
    assert_eq!(str_of(&row, "role"), "committee_member");
    assert_eq!(str_of(&row, "state"), "invited");
    assert_eq!(str_of(&row, "sod"), "unchecked");
    done(
        c.web(&owner, rq::withdraw_invitation(PD, &id)),
        "creator.withdraw_invitation",
    );
    let list = done(c.web(&owner, rq::invitations(PD)), "creator.invitations");
    assert!(
        rows(&list, "invitations")
            .iter()
            .all(|r| str_of(r, "id") != id)
    );
}

/// I-65, design section 3.3: M1 uploads an annex. The engine port
/// registers it, the cell's proposer records its proposals as the system,
/// and the import list shows each one with its value, its evidence text
/// and its digest. No creator record follows from the upload. M1
/// dismisses the action number with the listed digest, and the list shows
/// it dismissed. A tenant admin without the binding cannot resolve one.
#[test]
fn i65_upload_lists_proposals_and_a_dismissal_resolves_one() {
    let c = cell();
    let owner = login(&c, OWNER);
    let before = c.ports.engine.state().creator.head(PD);
    done(
        c.web(&owner, rq::import_upload(PD, "text/markdown", ANNEX)),
        "import.upload",
    );
    assert_eq!(
        c.ports.engine.state().creator.head(PD),
        before,
        "the upload changed the draft"
    );
    let list = done(c.web(&owner, rq::import_list(PD)), "import.list");
    let proposals = rows(&list, "proposals");
    assert_eq!(proposals.len(), 2, "{}", list.to_compact());
    let number = proposals
        .iter()
        .find(|p| str_of(p, "field") == "funder.action_number")
        .cloned()
        .unwrap();
    assert_eq!(
        number.get("value").and_then(Value::as_str),
        Some("101000001")
    );
    assert_eq!(number.get("flagged").and_then(Value::as_bool), Some(false));
    let evidence = rows(&number, "evidence");
    assert_eq!(str_of(&evidence[0], "text"), "Action number: 101000001");
    let id = str_of(&number, "id");
    let shown = str_of(&number, "digest");
    let dismiss = || Value::Object(rq::object(vec![("kind", rq::s("dismiss"))]));
    let admin = login(&c, ADMIN);
    let r = c.web(
        &admin,
        rq::import_resolve(PD, &id, &head(&c), &shown, dismiss(), false),
    );
    assert_eq!(rule(&r), Some("I-65"), "{r:?}");
    done(
        c.web(
            &owner,
            rq::import_resolve(PD, &id, &head(&c), &shown, dismiss(), false),
        ),
        "import.resolve",
    );
    let list = done(c.web(&owner, rq::import_list(PD)), "import.list");
    let number = rows(&list, "proposals")
        .iter()
        .find(|p| str_of(p, "id") == id)
        .cloned()
        .unwrap();
    assert_eq!(
        number.get("resolution").and_then(Value::as_str),
        Some("dismissed")
    );
}

/// Appends a forged `ActivationRequested` by M1 at PD's head, with the
/// report the creator computes there.
fn forge_request(c: &FakeCell) {
    let state = c.ports.engine.state();
    let d = state.creator.draft(PD).unwrap();
    let cmd = CreatorCommand::RequestActivation {
        programme: PD,
        revision: d.head(),
    };
    let ctx = Ctx {
        now: c.ports.clock.read(),
        actor: Actor::Account(OWNER),
        command: CommandId::from_bytes([0; 16]),
        via: Via::Web,
        tenant_admin: false,
        second_tenant_admin: None,
        binds_tenant_admin: false,
    };
    let inputs = c.ports.engine.creator_inputs_now(&state, &cmd, &ctx);
    let profile = inputs.profile.clone().unwrap();
    let report = fstp_creator::validate(&state.core, &state.creator, PD, &profile, &inputs);
    let record = CreatorRecord::ActivationRequested {
        programme: PD,
        revision: d.head(),
        report: report.digest(),
        by: OWNER,
    };
    c.ports
        .engine
        .append_forged(
            c.ports.clock.read(),
            *b"forged:request:1",
            vec![Record::Creator(record)],
        )
        .unwrap();
}

/// I-67, R-PG-03, Q1: the approval inbox lists the requested activation
/// at the draft's head. A1, who opened the draft, is a builder and reads
/// it as not approvable. A2 reads it as approvable.
#[test]
fn i67_inbox_offers_the_approval_to_the_second_admin_only() {
    let c = cell();
    forge_request(&c);
    let row = |l: &WebLogin| {
        let v = done(c.web(l, rq::approvals()), "admin.approvals");
        rows(&v, "approvals")
            .iter()
            .find(|r| str_of(r, "programme") == PD.raw().to_string())
            .cloned()
            .unwrap_or_else(|| panic!("no row: {}", v.to_compact()))
    };
    let a1 = row(&login(&c, ADMIN));
    assert_eq!(a1.get("approvable").and_then(Value::as_bool), Some(false));
    assert_eq!(str_of(&a1, "revision"), head(&c));
    let a2 = row(&login(&c, ADMIN_2));
    assert_eq!(a2.get("approvable").and_then(Value::as_bool), Some(true));
    let lead = login(&c, LEAD);
    assert!(class(&c.web(&lead, rq::approvals())).refused());
}

/// I-67, I-78, design section 3.7 step 5: A1's approval is refused with
/// I-67 by the dry run, and A2's approval of a report with failures with
/// I-66, both before any step-up is begun. Nothing is appended.
#[test]
fn i67_i66_approvals_are_refused_before_any_step_up() {
    let c = cell();
    forge_request(&c);
    let approve = |l: &WebLogin| c.web(l, rq::approve_activation(PD, &head(&c)));
    let r = approve(&login(&c, ADMIN));
    assert_eq!(rule(&r), Some("I-67"), "{r:?}");
    let r = approve(&login(&c, ADMIN_2));
    assert_eq!(rule(&r), Some("I-66"), "{r:?}");
    assert!(c.ports.step_up.begun().is_empty());
    assert!(
        !appended_creator(&c)
            .iter()
            .any(|cmd| matches!(cmd, CreatorCommand::ApproveActivation { .. }))
    );
}

/// I-66, design section 3.2 "Fresh probes": the dry run of an approval
/// peeks at the probes and never runs them. So an approval refused with
/// I-66 by its dry run runs no probe, and nothing with an external effect
/// happens before the decision.
#[test]
fn i66_refused_approval_runs_no_probe() {
    let c = cell();
    forge_request(&c);
    let r = c.web(&login(&c, ADMIN_2), rq::approve_activation(PD, &head(&c)));
    assert_eq!(rule(&r), Some("I-66"), "{r:?}");
    assert!(
        c.ports.prober.seen().is_empty(),
        "the dry run ran {:?}",
        c.ports.prober.seen()
    );
}

/// Q35 (interim), NOTE 5: the creator environment asks the vault port
/// whether it knows the draft's P-13 classes and the P-38 lists, and
/// records each answer. A vault that answers no makes the report show
/// the failure and the warning as checked.
#[test]
fn i66_q35_answers_come_from_the_vault_and_are_recorded() {
    let c = cell();
    let owner = login(&c, OWNER);
    let detail = |r: &Value, check: &str| {
        rows(r, "results")
            .iter()
            .find(|x| str_of(x, "check") == check)
            .map(Value::to_compact)
    };
    let clean = report(&c, &owner);
    assert_eq!(detail(&clean, "ExclusionClassUnknown"), None);
    assert_eq!(detail(&clean, "ProximityListMissing"), None);
    c.ports.vault.set_q35(false, false);
    let before = c.ports.vault_audit.records().len();
    let r = report(&c, &owner);
    let unknown = detail(&r, "ExclusionClassUnknown").unwrap_or_else(|| r.to_compact());
    assert!(
        !unknown.contains("not_checked"),
        "the vault answered: {unknown}"
    );
    assert!(
        detail(&r, "ProximityListMissing").is_some(),
        "{}",
        r.to_compact()
    );
    let recorded: Vec<bool> = c
        .ports
        .vault_audit
        .records()
        .into_iter()
        .skip(before)
        .map(|x| x.answer)
        .collect();
    assert!(
        recorded.iter().filter(|b| !**b).count() >= 2,
        "the two Q35 answers are recorded: {recorded:?}"
    );
}

/// H-07, NOTE 5: the per-account limit on reads that ask the vault is
/// checked before the first question. A report read over the limit is
/// refused with H-07, and neither the shell facts nor the builders'
/// answers ask the vault, so no answer is recorded.
#[test]
fn h07_over_limit_report_asks_the_vault_nothing() {
    let c = cell();
    let owner = login(&c, OWNER);
    let limit = fstp_api_core::rate::DRY_RUN_VAULT_PER_ACCOUNT.count;
    for _ in 0..limit {
        let _ = report(&c, &owner);
    }
    let recorded = c.ports.vault_audit.records().len();
    let asked = c.ports.vault.port_asks().len();
    let r = c.web(&owner, rq::get_report(PD));
    assert_eq!(rule(&r), Some("H-07"), "{r:?}");
    assert_eq!(c.ports.vault_audit.records().len(), recorded);
    assert_eq!(c.ports.vault.port_asks().len(), asked);
}

/// I-66, design sections 3.2 and 8.4: a theme fault the production
/// adapter seeds reaches the production report through the cell's
/// environment, as a probe seed does. This holds for each theme check
/// of severity Failure. The clean plan's theme shows neither.
#[test]
fn i66_seeded_theme_fault_reaches_the_production_report() {
    use std::collections::{BTreeMap, BTreeSet};

    use crate::fake::draft_cell::{self, DraftCell};
    use crate::mc::activate_model::production::theme_of;
    use crate::reference::creator::{DraftPlan, RefCheck, clean_plan, seeded_plan};

    let checks = |plan: &DraftPlan| -> BTreeSet<String> {
        let mut store = fstp_ledger::MemStore::new();
        draft_cell::forged_open(&mut store, PD, ADMIN, roster::T0).unwrap();
        let admins: BTreeSet<_> = [ADMIN].into_iter().collect();
        let cell = DraftCell::open_with_theme(
            store,
            fstp_domain_testkit::vault::GroundTruth::new(),
            admins.clone(),
            &BTreeMap::new(),
            false,
            theme_of(plan),
        )
        .unwrap();
        let state = cell.state();
        let cmd = CreatorCommand::RequestActivation {
            programme: PD,
            revision: state.creator.head(PD).unwrap(),
        };
        let ctx = draft_cell::ctx(ADMIN, roster::T0, 1, &admins);
        let inputs = cell.inputs(&cmd, &ctx, None);
        let profile = inputs.profile.clone().unwrap();
        fstp_creator::validate(&state.core, &state.creator, PD, &profile, &inputs)
            .results()
            .iter()
            .map(|r| r.check.name().to_owned())
            .collect()
    };
    let clean = checks(&clean_plan());
    for c in [RefCheck::ContrastFailure, RefCheck::MandatoryElementMissing] {
        assert!(!clean.contains(c.name()), "{}", c.name());
        assert!(checks(&seeded_plan(c)).contains(c.name()), "{}", c.name());
    }
}

/// R-PG-04, D3: a draft has no call, so its impact lists none. The
/// applicant cannot read it.
#[test]
fn r_pg_04_impact_of_a_draft_lists_no_call() {
    let c = cell();
    let v = done(c.web(&login(&c, OWNER), rq::impact(PD)), "creator.impact");
    assert_eq!(v.to_compact(), r#"{"calls":[]}"#);
    assert!(class(&c.web(&login(&c, LEAD), rq::impact(PD))).refused());
}

/// R-PG-02, I-19: the forged draft is one of the tenant's programmes.
#[test]
fn r_pg_02_the_draft_is_listed_with_the_tenant_programmes() {
    let c = cell();
    let v = done(
        c.web(&login(&c, ADMIN), rq::list_programmes()),
        "creator.list_programmes",
    );
    let ids: Vec<String> = rows(&v, "programmes")
        .iter()
        .map(|r| str_of(r, "id"))
        .collect();
    assert!(ids.contains(&PD.raw().to_string()), "{ids:?}");
}

/// R-PG-02, design section 3.1: the template catalogue lists exactly the
/// shipped templates of `fstp_programme::shipped_templates`, by id,
/// version and name. The API core keeps a copy, since it has no edge to
/// `fstp-programme`, and this test keeps the copy equal to the source.
#[test]
fn r_pg_02_template_catalogue_equals_the_shipped_templates() {
    let c = cell();
    let v = done(
        c.web(&login(&c, ADMIN), rq::list_templates()),
        "creator.list_templates",
    );
    let listed: Vec<(String, u64, String)> = rows(&v, "templates")
        .iter()
        .map(|r| {
            (
                str_of(r, "id"),
                r.get("version").and_then(Value::as_u64).unwrap(),
                str_of(r, "name"),
            )
        })
        .collect();
    let shipped: Vec<(String, u64, String)> = fstp_programme::shipped_templates()
        .unwrap()
        .iter()
        .map(|t| {
            (
                t.id.raw().to_string(),
                u64::from(t.version.get()),
                t.name.to_owned(),
            )
        })
        .collect();
    assert_eq!(listed, shipped);
}
