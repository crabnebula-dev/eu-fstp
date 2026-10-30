//! Tenant commands through the reference driver (M4 design sections 3.5
//! and 4.2; R-TN-01, SoD-07, Q5, Q22, Q31, I-23, I-85; lane m4tenant).
//!
//! Each test runs `Command::Tenant` through `Engine::execute` with the
//! production decider. The engine answers the vault's `IsVerified` for
//! each tenant admin, the agreement versions of the provisioning record
//! and the Receiving check. The prober outcomes are the shell's facts in
//! the request.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fstp_domain::command::{Actor, Ctx, Via};
use fstp_domain::id::{
    AccountId, CommandId, ContentDigest, LlmConfigId, TextId, TextRef, VaultEpoch,
};
use fstp_domain::oracle::{Answer, OracleDown, Query};
use fstp_domain::refusal::{RefusalReason, RuleRef};
use fstp_domain::time::Timestamp;
use fstp_engine::{
    Command, Engine, ExecError, IdentityOracle, Provisioning, Record, TenantEntry, TenantRequest,
    replay,
};
use fstp_json::FromJson;
use fstp_ledger::{MemStore, RecordStore, Seq};
use fstp_tenant::{
    AgreementVersions, BankInterface, BrandingPackage, CellKind, DomainName, InferenceDefault,
    InvitationId, OnboardingStep, PaymentMode, ProbeKind, ProbeOutcome, RpMode, SettingValue,
    StepFailure, StepOutcome, StepStatus, StepValues, TenantCommand, Token, TokenDigest,
    VerifyMethod,
};

const A1: AccountId = AccountId::from_raw(21);
const A2: AccountId = AccountId::from_raw(22);
const INVITATION: InvitationId = InvitationId::from_raw(9);
const DIGEST: TokenDigest = TokenDigest::from_bytes([0x5e; 32]);
const RECORDED: AgreementVersions = AgreementVersions {
    saas_terms: 1,
    dpa: 1,
    sub_processors: 1,
};

/// A vault that verifies the accounts it holds, at epoch 0.
#[derive(Clone, Debug, Default)]
struct Verified(BTreeSet<AccountId>);

impl IdentityOracle for Verified {
    fn ask(&self, q: &Query) -> Result<Answer, OracleDown> {
        let holds = matches!(q, Query::IsVerified { account } if self.0.contains(account));
        Ok(Answer {
            holds,
            accounts: None,
            epoch: VaultEpoch::from_raw(0),
            digest: ContentDigest::from_bytes([0; 32]),
        })
    }

    fn epoch(&self) -> Result<VaultEpoch, OracleDown> {
        Ok(VaultEpoch::from_raw(0))
    }
}

type Driver = Engine<MemStore<Record>, Verified>;

/// An engine over a ledger that holds one provisioning record.
fn provisioned(
    cell: CellKind,
    agreements: Option<AgreementVersions>,
    verified: &[AccountId],
) -> Driver {
    let mut store = MemStore::new();
    store
        .append(
            Seq::ZERO,
            1_000_000,
            [0x7e; 16],
            vec![Record::Tenant(TenantEntry::Provisioned(Provisioning {
                first_admin: A1,
                cell,
                agreements,
            }))],
        )
        .unwrap();
    Engine::open(store, Verified(verified.iter().copied().collect())).unwrap()
}

/// The clock and command ids of one test.
struct Run {
    engine: Driver,
    n: u8,
}

impl Run {
    fn new(engine: Driver) -> Run {
        Run { engine, n: 0 }
    }

    fn ctx(&mut self, actor: AccountId, via: Via) -> Ctx {
        self.n = self.n.wrapping_add(1);
        Ctx {
            now: Timestamp::from_micros(2_000_000_i64.saturating_add(i64::from(self.n))),
            actor: Actor::Account(actor),
            command: CommandId::from_bytes([self.n; 16]),
            via,
            tenant_admin: true,
            second_tenant_admin: None,
            binds_tenant_admin: false,
        }
    }

    fn run(&mut self, by: AccountId, req: TenantRequest) -> Result<Seq, ExecError> {
        let ctx = self.ctx(by, Via::Web);
        self.engine.execute(Command::Tenant(req), ctx)
    }

    fn cmd(&mut self, by: AccountId, cmd: TenantCommand) -> Result<Seq, ExecError> {
        self.run(by, TenantRequest::new(cmd))
    }

    /// Saves `values` against the current revision, with `probe` as the
    /// shell's outcome of the check the step needs, if any.
    fn save(&mut self, values: StepValues, probe: Option<ProbeOutcome>) -> Result<Seq, ExecError> {
        let base = self.state().revision();
        let mut req = TenantRequest::new(TenantCommand::SaveStep {
            values: values.clone(),
            base,
        });
        if let (Some(kind), Some(outcome)) = (fstp_tenant::rules::probe_for(&values), probe) {
            req.facts.probe(kind, outcome);
        }
        // The shell draws a configuration id for every Inference save
        // (design 3.5).
        if matches!(values, StepValues::Inference(_)) {
            req.inference_config = Some(config(self.n));
        }
        self.run(A1, req)
    }

    fn state(&self) -> &fstp_tenant::TenantState {
        self.engine.state().tenant.state().unwrap()
    }

    fn outcome(&self, step: OnboardingStep) -> Option<StepOutcome> {
        self.state().saved_outcome(step)
    }
}

fn token(s: &str) -> Token {
    Token::new(s).unwrap()
}

fn values(step: OnboardingStep) -> StepValues {
    match step {
        OnboardingStep::Organisation => StepValues::Organisation {
            data_protection_contact: TextRef::new(
                TextId::from_raw(1),
                ContentDigest::from_bytes([3; 32]),
            ),
            signatories: [A1].into_iter().collect(),
        },
        OnboardingStep::Agreements => StepValues::Agreements {
            saas_terms: 1,
            dpa: 1,
            sub_processors: 1,
        },
        OnboardingStep::Branding => StepValues::Branding {
            package: BrandingPackage::Default,
        },
        OnboardingStep::DomainsAndEmail => StepValues::DomainsAndEmail {
            sending_domain: DomainName::new("mail.e2e.invalid").unwrap(),
        },
        OnboardingStep::Identity => StepValues::Identity {
            p18: [VerifyMethod::EudiWallet].into_iter().collect(),
            p45: RpMode::TenantRegistration,
        },
        OnboardingStep::Inference => StepValues::Inference(InferenceDefault {
            provider: token("placeholder"),
            primary: token("placeholder-model"),
            fallbacks: Vec::new(),
        }),
        OnboardingStep::Payments => StepValues::Payments {
            bank_interface: BankInterface::NotConnected,
        },
        OnboardingStep::Channels => StepValues::Channels {
            matrix_homeserver: None,
            whatsapp: false,
        },
        OnboardingStep::Administrators => StepValues::Administrators {
            admins: [A1, A2].into_iter().collect(),
        },
    }
}

/// Walks a self-hosted cell to a validated Administrators step with A2
/// joined, every probe passing.
fn walk_self_hosted(r: &mut Run) {
    for step in [
        OnboardingStep::Organisation,
        OnboardingStep::Branding,
        OnboardingStep::DomainsAndEmail,
        OnboardingStep::Identity,
        OnboardingStep::Inference,
    ] {
        r.save(values(step), Some(ProbeOutcome::Passed)).unwrap();
    }
    r.cmd(
        A1,
        TenantCommand::SetSetting {
            value: SettingValue::P20(PaymentMode::RecordOnly),
        },
    )
    .unwrap();
    r.save(values(OnboardingStep::Payments), None).unwrap();
    r.save(values(OnboardingStep::Channels), Some(ProbeOutcome::Passed))
        .unwrap();
    r.cmd(
        A1,
        TenantCommand::InviteAdmin {
            invitation: INVITATION,
            invitee: A2,
            token_digest: DIGEST,
        },
    )
    .unwrap();
    r.cmd(
        A2,
        TenantCommand::AcceptAdminInvitation {
            invitation: INVITATION,
            token_digest: DIGEST,
        },
    )
    .unwrap();
    r.save(values(OnboardingStep::Administrators), None)
        .unwrap();
}

fn refused(r: Result<Seq, ExecError>) -> (RuleRef, RefusalReason) {
    match r {
        Err(ExecError::Refused(f)) => (f.rule, f.reason),
        other => panic!("wanted a refusal, got {other:?}"),
    }
}

/// R-TN-01: a step save runs through the driver and the tenant decider.
/// It validates the step, moves the revision on by the two records of
/// one entry, and opens the next step.
#[test]
fn r_tn_01_driver_saves_and_validates_a_step_through_the_tenant_decider() {
    let mut r = Run::new(provisioned(CellKind::SelfHosted, None, &[A1]));
    let head = r.engine.head();
    r.save(values(OnboardingStep::Organisation), None).unwrap();
    assert_eq!(
        r.engine.head().raw(),
        head.raw() + 2,
        "R-TN-01: one entry, two records"
    );
    assert_eq!(
        r.state().status(OnboardingStep::Organisation),
        StepStatus::Validated
    );
    assert_eq!(r.state().revision().raw(), 2);
    assert_eq!(r.state().status(OnboardingStep::Branding), StepStatus::Open);
}

/// Q5: a probed step validates only on the shell's passing outcome. With
/// no outcome in the request it fails closed as having no prober, and a
/// failed probe fails it.
#[test]
fn q5_driver_fails_a_probed_step_closed_without_the_shells_outcome() {
    let mut r = Run::new(provisioned(CellKind::SelfHosted, None, &[A1]));
    r.save(values(OnboardingStep::Organisation), None).unwrap();
    r.save(values(OnboardingStep::Branding), None).unwrap();
    let step = OnboardingStep::DomainsAndEmail;
    r.save(values(step), None).unwrap();
    assert_eq!(
        r.outcome(step),
        Some(StepOutcome::Failed(StepFailure::ProberAbsent))
    );
    r.save(values(step), Some(ProbeOutcome::Failed)).unwrap();
    assert_eq!(
        r.outcome(step),
        Some(StepOutcome::Failed(StepFailure::ProbeFailed))
    );
    r.save(values(step), Some(ProbeOutcome::Passed)).unwrap();
    assert_eq!(r.outcome(step), Some(StepOutcome::Validated));
}

/// Q22: the Agreements step of a SaaS cell validates only when the saved
/// versions are the ones the provisioning record holds. A cell
/// provisioned with none fails the step closed.
#[test]
fn q22_driver_validates_agreements_only_against_the_provisioned_versions() {
    let step = OnboardingStep::Agreements;
    let other = StepValues::Agreements {
        saas_terms: 2,
        dpa: 1,
        sub_processors: 1,
    };
    let mut r = Run::new(provisioned(CellKind::Saas, Some(RECORDED), &[A1]));
    r.save(values(OnboardingStep::Organisation), None).unwrap();
    r.save(other, None).unwrap();
    assert_eq!(
        r.outcome(step),
        Some(StepOutcome::Failed(StepFailure::AgreementsNotRecorded))
    );
    r.save(values(step), None).unwrap();
    assert_eq!(r.outcome(step), Some(StepOutcome::Validated));

    let mut none = Run::new(provisioned(CellKind::Saas, None, &[A1]));
    none.save(values(OnboardingStep::Organisation), None)
        .unwrap();
    none.save(values(step), None).unwrap();
    assert_eq!(
        none.outcome(step),
        Some(StepOutcome::Failed(StepFailure::AgreementsNotRecorded))
    );
}

/// SoD-07, Q2: onboarding completes only when the vault verifies every
/// tenant admin. With A2 unverified the completion is refused under
/// SoD-07 and appends nothing. With both verified it completes.
#[test]
fn sod07_driver_completes_only_when_the_vault_verifies_every_admin() {
    let mut r = Run::new(provisioned(CellKind::SelfHosted, None, &[A1]));
    walk_self_hosted(&mut r);
    let head = r.engine.head();
    assert_eq!(
        refused(r.cmd(A1, TenantCommand::Complete)),
        (RuleRef::Sod07, RefusalReason::VaultRefused)
    );
    assert_eq!(
        r.engine.head(),
        head,
        "SoD-07: a refused completion appended"
    );

    let mut ok = Run::new(provisioned(CellKind::SelfHosted, None, &[A1, A2]));
    walk_self_hosted(&mut ok);
    ok.cmd(A1, TenantCommand::Complete).unwrap();
    assert!(ok.state().onboarded(), "SoD-07: two verified admins");
}

/// I-85: a high-risk tenant command through MCP is refused by the tenant
/// decider as a second line, and appends nothing.
#[test]
fn i85_driver_refuses_a_high_risk_tenant_command_through_mcp() {
    let mut r = Run::new(provisioned(CellKind::Saas, Some(RECORDED), &[A1]));
    let head = r.engine.head();
    let ctx = r.ctx(A1, Via::Mcp);
    let cmd = Command::Tenant(TenantRequest::new(TenantCommand::SetSetting {
        value: SettingValue::P69("MIT".to_owned()),
    }));
    assert_eq!(
        refused(r.engine.execute(cmd, ctx)).0,
        RuleRef::I85,
        "I-85: a setting change through MCP"
    );
    assert_eq!(r.engine.head(), head);
}

/// Q31 A: a tenant command before the provisioning record is refused, and
/// a command by an account outside the ledger's admin set is refused
/// under R-AC-01. Neither appends.
#[test]
fn q31_driver_refuses_outside_a_provisioned_admin_set() {
    let mut empty = Run::new(Engine::open(MemStore::new(), Verified::default()).unwrap());
    let r = empty.cmd(A1, TenantCommand::Complete);
    assert_eq!(refused(r).0, RuleRef::Input, "Q31: no provisioning record");
    assert_eq!(empty.engine.head(), Seq::ZERO);

    let mut r = Run::new(provisioned(CellKind::Saas, Some(RECORDED), &[A1]));
    let head = r.engine.head();
    let set = TenantCommand::SetSetting {
        value: SettingValue::P69("MIT".to_owned()),
    };
    assert_eq!(refused(r.cmd(A2, set)).0, RuleRef::Rac01);
    assert_eq!(r.engine.head(), head);
}

/// I-23: after a walk through every step and a completion, the driver's
/// state equals the replay of its store, and the stored entries decode
/// back from their canonical text.
#[test]
fn i23_driver_state_equals_the_replay_of_its_tenant_ledger() {
    let mut r = Run::new(provisioned(CellKind::SelfHosted, None, &[A1, A2]));
    walk_self_hosted(&mut r);
    r.cmd(A1, TenantCommand::Complete).unwrap();
    let mut entries = Vec::new();
    r.engine
        .store()
        .read(Seq::ZERO, usize::MAX, &mut entries)
        .unwrap();
    assert_eq!(&replay(&entries).unwrap(), r.engine.state());
    for e in &entries {
        let text = e.canonical_text().unwrap();
        let raw = fstp_ledger::Entry::<fstp_json::Value>::from_json(
            &fstp_json::parse(text.as_bytes()).unwrap(),
        )
        .unwrap();
        let back = raw
            .try_map_record(|schema, rec| fstp_engine::record_from_json_at(schema, &rec))
            .unwrap();
        assert_eq!(&back, e, "I-23: a stored tenant entry decodes to another");
    }
}

/// Q5: the shell's probe facts name their check. A request whose
/// facts name another check leaves the step's own check absent.
#[test]
fn q5_driver_reads_only_the_outcome_of_the_steps_own_check() {
    let mut r = Run::new(provisioned(CellKind::SelfHosted, None, &[A1]));
    r.save(values(OnboardingStep::Organisation), None).unwrap();
    r.save(values(OnboardingStep::Branding), None).unwrap();
    let step = OnboardingStep::DomainsAndEmail;
    let base = r.state().revision();
    let mut req = TenantRequest::new(TenantCommand::SaveStep {
        values: values(step),
        base,
    });
    req.facts.probe(ProbeKind::Channels, ProbeOutcome::Passed);
    req.facts.probe(
        ProbeKind::SendingDomain(DomainName::new("other.e2e.invalid").unwrap()),
        ProbeOutcome::Passed,
    );
    r.run(A1, req).unwrap();
    assert_eq!(
        r.outcome(step),
        Some(StepOutcome::Failed(StepFailure::ProberAbsent))
    );
}

// ---------------------------------------------------------------------------
// The inference configuration record (design 3.5, fix round 1)
// ---------------------------------------------------------------------------

/// The configuration id of an Inference save made when the run has
/// issued `n` commands.
fn config(n: u8) -> LlmConfigId {
    LlmConfigId::from_raw(0x1c00 + u128::from(n))
}

/// Walks a self-hosted cell to the Inference step, every probe passing.
fn walk_to_inference(r: &mut Run) {
    for step in [
        OnboardingStep::Organisation,
        OnboardingStep::Branding,
        OnboardingStep::DomainsAndEmail,
        OnboardingStep::Identity,
    ] {
        r.save(values(step), Some(ProbeOutcome::Passed)).unwrap();
    }
}

/// R-LA-05, design 3.5 ("The Inference step also records an
/// `InferenceConfigRecorded` entry"): a validated Inference save records
/// the step's models under the shell's configuration id, in the same
/// entry, so the ledger supplies the publication configuration.
#[test]
fn r_la_05_validated_inference_save_records_the_inference_config() {
    let mut r = Run::new(provisioned(CellKind::SelfHosted, None, &[A1]));
    walk_to_inference(&mut r);
    assert!(r.state().publication_config().is_none());
    let head = r.engine.head();
    let n = r.n;
    r.save(values(OnboardingStep::Inference), None).unwrap();
    assert_eq!(
        r.engine.head().raw(),
        head.raw() + 3,
        "design 3.5: the save, its validation and the inference record"
    );
    let want = config(n);
    assert_eq!(
        r.state().publication_config(),
        Some((want, &token("placeholder-model"))),
        "R-LA-05: the ledger names the configuration and its primary"
    );
    let mut entries = Vec::new();
    r.engine
        .store()
        .read(Seq::ZERO, usize::MAX, &mut entries)
        .unwrap();
    let replayed = replay(&entries).unwrap();
    assert_eq!(
        replayed.tenant.state().and_then(|t| t.publication_config()),
        Some((want, &token("placeholder-model"))),
        "I-23: the inference record replays"
    );
}

/// R-LA-05, Q5 (fail closed): an Inference save that validates without a
/// configuration id is refused as facts incomplete and appends nothing.
/// A command other than an Inference save that carries one is refused.
#[test]
fn r_la_05_inference_record_needs_the_shells_config_id() {
    let mut r = Run::new(provisioned(CellKind::SelfHosted, None, &[A1]));
    walk_to_inference(&mut r);
    let head = r.engine.head();
    let bare = TenantRequest::new(TenantCommand::SaveStep {
        values: values(OnboardingStep::Inference),
        base: r.state().revision(),
    });
    assert_eq!(
        refused(r.run(A1, bare)).0,
        RuleRef::FactsIncomplete,
        "Q5: a validating Inference save without a configuration id"
    );
    let mut stray = TenantRequest::new(TenantCommand::Complete);
    stray.inference_config = Some(config(0xee));
    assert_eq!(refused(r.run(A1, stray)).0, RuleRef::Ledger);
    assert_eq!(r.engine.head(), head, "a refused command appended");
}

/// R-LA-05, P-21: an Inference save that does not validate records no
/// inference configuration, so the ledger names none.
#[test]
fn r_la_05_failed_inference_save_records_no_config() {
    let mut r = Run::new(provisioned(CellKind::SelfHosted, None, &[A1]));
    walk_to_inference(&mut r);
    let bad = StepValues::Inference(InferenceDefault {
        provider: token("placeholder"),
        primary: token("placeholder-model"),
        fallbacks: vec![token("placeholder-model")],
    });
    r.save(bad, None).unwrap();
    assert_ne!(
        r.outcome(OnboardingStep::Inference),
        Some(StepOutcome::Validated)
    );
    assert!(r.state().publication_config().is_none());
}
