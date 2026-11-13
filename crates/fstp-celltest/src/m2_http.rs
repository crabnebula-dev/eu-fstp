//! The M2 machines over a running cell (M3 design section 14.6,
//! `seam_m2_suites_over_pg`, lane m3/m2-over-http).
//!
//! [`HttpDriver`] is the third [`M2Driver`] beside the M2 engine over a
//! `MemStore` and the reference alone. It sends each command of an M2
//! machine through the cell's command route, with software passkeys and
//! a step-up where `fstp_cell_core::gate` asks for one. The cell runs it
//! over its PostgreSQL store and its vault, which the driver seeds through
//! the world's seeded vault (design section 6.9).
//!
//! [`SodOverHttp`] runs the SoD machine of `fstp_domain_testkit` in
//! lockstep: each command goes to the M2 engine, which the machine checks
//! against its reference as it always does, and to the cell. The cell
//! must accept and refuse as the engine does and append the same M2 core
//! records, and the machine's invariants must hold over the cell's ledger.
//!
//! How the driver maps the machine onto the cell:
//!
//! - Accounts. Each generator account enrols at its own id through an
//!   invitation of the world's first tenant admin
//!   (`AuthClient::enrol_at`). [`ADMIN`] and [`ADMIN_2`] are granted
//!   tenant admin. The first admin itself is the harness's and names no
//!   generator account.
//! - Programmes. A setup's `CreateProgramme` runs the creator path of M4
//!   design section 3.4: the first admin opens the draft and grants the
//!   harness builder ([`BUILDER`]) the programme manager role, the
//!   builder saves the synthetic spec and requests activation, and
//!   [`ADMIN_2`] approves. The builder then records the generator's
//!   policy with one `EditPolicy` under the generator's version id, and
//!   the first admin ends the builder's binding. The setup's core
//!   `ActivateProgramme` is skipped: the creator's approval activated the
//!   programme (D2e).
//! - Instants. The cell runs on the world's clock. Each step sets it to
//!   the step's instant, which never runs backwards. The setup's
//!   enrolments and creator path run before the setup instant.
//! - Vault facts. A verified account's identity tag is a synthetic
//!   attribute tuple of its own, so accounts of one tag share a person.
//!   An exclusion is a partner staff affiliation in its class on one
//!   verified account of its identity, which the vault counts for every
//!   account of that person, and a relation is a relationship
//!   between one verified account of each identity. After a vault change
//!   a probe command that the domain refuses makes the cell process the
//!   new epoch, as its next command would (design section 5.2 step 4).
//!
//! Interim readings, pending Daniel, of what a reduced case is. A cell
//! derives what a generator step states as flags, and the vault holds
//! facts of verified persons only (as `tests/seam_vault.rs` notes). So
//! [`SodOverHttp`] rewrites each drawn command before both sides run it:
//!
//! - The setup verifies every account that has an identity. An
//!   unverified account's exclusions and relations have no vault form.
//! - A step's tenant admin flags are the cell's own: the actor is a
//!   tenant admin when it is [`ADMIN`] or [`ADMIN_2`], and a second admin
//!   is never attested, since no tenant approval ceremony runs.
//! - A draft is minor-flagged, as the cell flags every draft (I-18,
//!   interim reading of Q13).
//! - An end is never scheduled later than its step, since the cell's
//!   timeline commits a due end on its own tick.
//! - An identity merge is drawn only for an account whose identity has no
//!   exclusion or relation, since the vault cannot retract a fact.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use fstp_cell_core::CellCommand;
use fstp_cell_core::gate::{Action, HighRiskAction};
use fstp_creator::{CheckId, CheckSubject, CreatorCommand, WarningKey};
use fstp_domain::command::{Actor, Command};
use fstp_domain::id::{AccountId, BindingId, DecisionId, PolicyVersionId, ProposalId};
use fstp_domain::policy::PolicyVersion;
use fstp_domain::record::Record;
use fstp_domain::refusal::{Refusal, RefusalReason, RuleRef};
use fstp_domain::roles::Role;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::driver::M2Driver;
use fstp_domain_testkit::r#gen::roster::{
    ADMIN, ADMIN_2, MachineCmd, MachineModel, MachineOutput, MachineSut, SodFocus, SodMachine,
    Step, T0, VaultOp,
};
use fstp_domain_testkit::reference::sod::{
    View, check_bars, check_i01, check_i02, check_i04, check_i06,
};
use fstp_domain_testkit::vault::{GroundTruth, IdentityTag};
use fstp_engine::ExecError;
use fstp_ledger::Seq;
use fstp_prop::{Config, Gen, Outcome, StateMachine};
use fstp_vault_core::fact::{Fact, Org};
use fstp_vault_proto::{WireAccount, WireClass};

use crate::NotImplemented;
use crate::mc::auth_model::RosterChange;
use crate::mc::auth_model::http::{AuthClient, Cookie, FIRST_ADMIN, Reply};
use crate::reference::auth::RefMethod;
use crate::vault_seed::SeedSource;

/// The harness account that builds each setup programme's draft. It is
/// no generator account, and its binding ends before the setup's steps.
pub const BUILDER: AccountId = AccountId::from_raw(990_005);

/// The model key of a generator account in the auth client. The client
/// keys the world's first admin by [`FIRST_ADMIN`], which is also the
/// generator's [`ADMIN`], so each generator account gets a key of its own.
const KEY_BASE: u128 = 1 << 100;

/// The driver's name for the world's first admin, the harness's own
/// tenant admin. No generator account has it.
const HARNESS: AccountId = AccountId::from_raw(u128::MAX);

/// The draft version of a setup programme's creator path. The generator's
/// own version follows it.
const DRAFT_VERSION_BASE: u128 = 990_000;
/// The builder's binding on a setup programme.
const BUILDER_BINDING_BASE: u128 = 990_100;
/// The activation decision of a setup programme.
const ACTIVATION_BASE: u128 = 990_200;

/// The proposal of the probe command. No machine drafts it.
const PROBE_PROPOSAL: u128 = 990_999_999;

/// A step of the driver the cell did not take as a step of its own: a
/// harness failure, not a refusal. The driver's log says which.
pub const DRIVER_FAILED: &str = "fstp_celltest::m2_http: the cell driver failed a step it should take (its log is on standard error)";

/// The machine found a divergence between the cell and the engine, or a
/// broken invariant over the cell's ledger. Not a seam: the failure is
/// on standard error.
pub const MACHINE_FAILED: &str = "fstp_celltest::m2_http: the reduced case of the M2 suite failed over the cell (the failing step is on standard error)";

/// The reduced case ran too few steps on the cell to count as a run.
pub const CASE_TOO_SHORT: &str = "fstp_celltest::m2_http: the reduced case ran too few steps on the cell to count (the tally is on standard error)";

/// The least core steps the cell must commit in a reduced case.
const MIN_ACCEPTED: usize = 4;
/// The least steps a reduced case must send after its setup.
const MIN_STEPS: usize = 10;

/// An `m2-suite` step names a suite the driver has no machine for yet.
pub const SUITE_SEAM: &str = "fstp_celltest::m2_http: the m2-suite step names an M2 suite whose machine has no cell driver yet; the SoD machine (I-04, I-06) runs over the cell, and the review, money and ledger machines (I-03, I-35, I-13, I-14, I-15, I-23) still drive fstp_domain_testkit's own drivers only";

/// The model key of `account`.
fn key(account: AccountId) -> AccountId {
    AccountId::from_raw(KEY_BASE.saturating_add(account.raw()))
}

/// The synthetic attribute tuple of identity `t`.
fn attributes(t: IdentityTag) -> Vec<u8> {
    format!("m2-identity-{}", t.raw()).into_bytes()
}

/// The organisation of a partner staff affiliation in class `class`.
fn class_org(class: fstp_domain::id::ClassId) -> Org {
    Org(700_000u128.saturating_add(class.raw()))
}

/// The refusal an [`HttpDriver`] gives for a step the cell refused. The
/// cell's own rule and reason are in the driver's log.
const fn remote_refusal() -> Refusal {
    Refusal::new(RuleRef::Input, RefusalReason::GuardFailed)
}

/// The M2 driver over a running world cell.
pub struct HttpDriver<'c, 'w> {
    client: &'c AuthClient<'w>,
    truth: GroundTruth,
    sessions: BTreeMap<AccountId, Cookie>,
    tenant_admins: BTreeSet<AccountId>,
    /// The person of each account the vault verified.
    persons: BTreeMap<AccountId, IdentityTag>,
    /// The exclusions seeded, by identity and class.
    classes: BTreeSet<(IdentityTag, fstp_domain::id::ClassId)>,
    /// The relationships seeded.
    relationships: BTreeSet<(AccountId, AccountId)>,
    /// The M2 core records of the cell's ledger at the last read.
    records: Vec<Record>,
    /// The number of entries of the cell's ledger at the last read.
    entries: usize,
    /// Whether each seeded write is processed at once, as during the
    /// setup, where many writes would otherwise wait for one command.
    settle_each: bool,
    /// The first harness failure, if any.
    fault: Option<String>,
    /// What the cell did with the machine's steps after the setup.
    tally: Tally,
}

/// What a cell did with the steps of a reduced case.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tally {
    /// Whether the setup ran.
    pub setup: bool,
    /// Core steps the cell committed.
    pub accepted: usize,
    /// Core steps the cell refused.
    pub refused: usize,
    /// Vault changes the cell processed.
    pub vault: usize,
}

impl std::fmt::Debug for HttpDriver<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpDriver")
            .field("records", &self.records.len())
            .field("fault", &self.fault)
            .finish_non_exhaustive()
    }
}

impl<'c, 'w> HttpDriver<'c, 'w> {
    /// A driver over the cell of `client`.
    pub fn new(client: &'c AuthClient<'w>) -> HttpDriver<'c, 'w> {
        HttpDriver {
            client,
            truth: GroundTruth::new(),
            sessions: BTreeMap::new(),
            tenant_admins: BTreeSet::new(),
            persons: BTreeMap::new(),
            classes: BTreeSet::new(),
            relationships: BTreeSet::new(),
            records: Vec::new(),
            entries: 0,
            settle_each: true,
            fault: None,
            tally: Tally::default(),
        }
    }

    /// The first harness failure: a step the cell should take that the
    /// driver could not run, as opposed to a refusal by the cell.
    pub fn fault(&self) -> Option<&str> {
        self.fault.as_deref()
    }

    /// Records a harness failure and gives the refusal the trait returns.
    fn fail(&mut self, what: String) -> ExecError {
        eprintln!("fstp_celltest::m2_http: {what}");
        if self.fault.is_none() {
            self.fault = Some(what);
        }
        ExecError::Refused(Refusal::not_implemented())
    }

    /// Reads the cell's ledger and keeps its M2 core records.
    fn read(&mut self) -> Result<Seq, ExecError> {
        let ledger = match self.client.cell().ledger() {
            Ok(l) => l,
            Err(e) => return Err(self.fail(format!("the ledger read failed: {e}"))),
        };
        self.entries = ledger.len();
        self.records = ledger
            .into_iter()
            .filter_map(|e| match e.record {
                fstp_cell_core::CellRecord::Engine(fstp_engine::Record::Core(r)) => Some(r),
                _ => None,
            })
            .collect();
        Ok(Seq::from_raw(
            u64::try_from(self.entries).unwrap_or(u64::MAX),
        ))
    }

    /// Moves the cell clock to `at`. It never runs backwards.
    fn clock_to(&mut self, at: Timestamp) -> Result<(), ExecError> {
        let clock = self.client.cell().clock();
        let now = clock.now();
        if now > at.micros() {
            return Err(self.fail(format!(
                "the step's instant {} is before the cell clock {now}",
                at.micros()
            )));
        }
        clock.set(at.micros());
        Ok(())
    }

    /// The session of `account`, after a passkey login when it has none.
    fn session(&mut self, account: AccountId) -> Result<Cookie, ExecError> {
        if let Some(c) = self.sessions.get(&account) {
            return Ok(c.clone());
        }
        self.login(account)
    }

    /// A new passkey login of `account`.
    fn login(&mut self, account: AccountId) -> Result<Cookie, ExecError> {
        let k = if account == HARNESS {
            FIRST_ADMIN
        } else {
            key(account)
        };
        match self.client.login(k, RefMethod::Passkey) {
            Ok(Some(c)) => {
                self.sessions.insert(account, c.clone());
                Ok(c)
            }
            Ok(None) => Err(self.fail(format!("the passkey login of {account:?} was refused"))),
            Err(e) => Err(self.fail(format!("the passkey login of {account:?}: {e}"))),
        }
    }

    /// Whether the cell knows `account` as a generator account.
    fn is_generator(&self, account: AccountId) -> bool {
        self.client.cell_account(key(account)).is_some()
    }

    /// The harness's session of the world's first admin.
    fn harness_admin(&mut self) -> Result<Cookie, ExecError> {
        self.session(HARNESS)
    }

    /// Enrols the generator account `account` at its own id.
    fn enrol(&mut self, account: AccountId) -> Result<(), ExecError> {
        if self.is_generator(account) {
            return Ok(());
        }
        match self.client.enrol_at(key(account), account) {
            Ok(true) => Ok(()),
            Ok(false) => Err(self.fail(format!("the enrolment of {account:?} was refused"))),
            Err(e) => Err(self.fail(format!("the enrolment of {account:?}: {e}"))),
        }
    }

    /// Sends `command` in `account`'s session, with a step-up when the
    /// gate asks for one. `Ok(true)` when the cell committed it,
    /// `Ok(false)` when it refused it.
    fn send(&mut self, account: AccountId, command: &CellCommand) -> Result<bool, ExecError> {
        let stepup = !matches!(
            HighRiskAction::of(&Action::Command(command.clone())),
            Ok(None)
        );
        for attempt in 0..2 {
            let session = self.session(account)?;
            let reply = match self.client.command_reply(&session, command, stepup) {
                Ok(r) => r,
                Err(e) => return Err(self.fail(format!("{command:?} by {account:?}: {e}"))),
            };
            match reply {
                Some(r) if r.ok() => return Ok(true),
                // A session the cell ended: log in again once.
                Some(r) if r.status == 401 && attempt == 0 => {
                    self.sessions.remove(&account);
                    let _ = r;
                }
                Some(r) if refused(&r) => {
                    eprintln!(
                        "fstp_celltest::m2_http: refused {command:?} by {account:?}: {} {}",
                        r.status,
                        String::from_utf8_lossy(&r.body)
                    );
                    return Ok(false);
                }
                Some(r) => {
                    return Err(self.fail(format!(
                        "{command:?} by {account:?}: {} {}",
                        r.status,
                        String::from_utf8_lossy(&r.body)
                    )));
                }
                None => {
                    return Err(self.fail(format!(
                        "the step-up of {command:?} by {account:?} was refused"
                    )));
                }
            }
        }
        Err(self.fail(format!("{command:?} by {account:?}: no session")))
    }

    /// Sends a harness command that must commit.
    fn must(&mut self, account: AccountId, command: CellCommand) -> Result<(), ExecError> {
        if self.send(account, &command)? {
            Ok(())
        } else {
            Err(self.fail(format!("the harness command {command:?} was refused")))
        }
    }

    /// Seeds a verification of `account` with the person of `attrs`.
    fn seed_person(&mut self, account: AccountId, attrs: &[u8]) -> Result<(), ExecError> {
        match self.client.cell().seed_verification(account, attrs) {
            Ok(_) => self.settle(),
            Err(e) => Err(self.fail(format!("the seeded verification of {account:?}: {e}"))),
        }
    }

    /// Seeds `fact` from `source`.
    fn seed_fact(&mut self, source: SeedSource, fact: Fact) -> Result<(), ExecError> {
        match self.client.cell().seed_vault_fact(source, fact.clone()) {
            Ok(_) => self.settle(),
            Err(e) => Err(self.fail(format!("the seeded fact {fact:?}: {e}"))),
        }
    }

    /// Seeds every fact of the mirror the vault does not hold yet. Returns
    /// whether it seeded any.
    fn sync_vault(&mut self) -> Result<bool, ExecError> {
        let mut seeded = false;
        let verified: Vec<(AccountId, IdentityTag)> = self
            .truth
            .identities()
            .filter(|(a, _)| self.truth.is_verified(*a))
            .collect();
        for (a, t) in &verified {
            if self.persons.get(a) != Some(t) {
                self.seed_person(*a, &attributes(*t))?;
                self.persons.insert(*a, *t);
                seeded = true;
            }
        }
        let exclusions: Vec<_> = self.truth.exclusions().collect();
        for (t, class) in exclusions {
            // One write on one verified account of the identity: the vault
            // counts it for every account of the person, and one write is
            // one epoch, as the M2 vault's one change is.
            if let Some((a, _)) = verified.iter().find(|(_, u)| *u == t)
                && self.classes.insert((t, class))
            {
                {
                    self.seed_fact(
                        SeedSource::SyntheticAffiliation,
                        Fact::AffiliationDeclared {
                            account: WireAccount(a.raw()),
                            org: class_org(class),
                            class: Some(WireClass(class.raw())),
                            partner_staff: true,
                        },
                    )?;
                    seeded = true;
                }
            }
        }
        let relations: Vec<_> = self.truth.relations().collect();
        for (x, y, _) in relations {
            let first = |t: IdentityTag| verified.iter().find(|(_, u)| *u == t).map(|(a, _)| *a);
            if let (Some(a), Some(b)) = (first(x), first(y))
                && self.relationships.insert((a, b))
            {
                self.seed_fact(
                    SeedSource::SyntheticAffiliation,
                    Fact::Relationship {
                        a: WireAccount(a.raw()),
                        b: WireAccount(b.raw()),
                    },
                )?;
                seeded = true;
            }
        }
        Ok(seeded)
    }

    /// Processes a seeded write at once during the setup ([`HttpDriver::probe`]).
    fn settle(&mut self) -> Result<(), ExecError> {
        if self.settle_each {
            self.probe()
        } else {
            Ok(())
        }
    }

    /// A command the domain refuses after the cell processed any newer
    /// vault epoch: a withdrawal of a proposal no machine drafts, by the
    /// harness's first admin (design section 5.2 step 4).
    fn probe(&mut self) -> Result<(), ExecError> {
        let probe = crate::cycle::core(Command::Withdraw {
            proposal: ProposalId::from_raw(PROBE_PROPOSAL),
        });
        if self.send(HARNESS, &probe)? {
            return Err(self.fail("the probe withdrawal was committed".to_owned()));
        }
        Ok(())
    }

    /// The creator path of `policy`'s programme, then the generator's
    /// policy under its own version id (module documentation).
    fn create_programme(&mut self, policy: &PolicyVersion) -> Result<(), ExecError> {
        let p = policy.programme;
        let draft = PolicyVersionId::from_raw(DRAFT_VERSION_BASE.saturating_add(p.raw()));
        let he = fstp_programme::FunderProfile::horizon_europe();
        let profile = match fstp_programme::compile(
            &he.blank(),
            &he,
            fstp_programme::CompileIds::new(p, draft, None),
        ) {
            Ok(c) => c.policy.frozen.p53,
            Err(_) => return Err(self.fail("the blank policy did not compile".to_owned())),
        };
        self.must(
            ADMIN,
            crate::cycle::creator(CreatorCommand::OpenDraft {
                programme: p,
                version: draft,
                profile,
            }),
        )?;
        let binding = BindingId::from_raw(BUILDER_BINDING_BASE.saturating_add(p.raw()));
        let now = self.client.cell().clock().now();
        self.must(
            ADMIN,
            crate::cycle::core(Command::GrantRole {
                binding,
                account: BUILDER,
                programme: p,
                role: Role::ProgrammeManager,
                start: Timestamp::from_micros(now),
                second_admin: None,
                confidentiality: Some(crate::cycle::synthetic_text(0x0b)),
                organisation: None,
                end: None,
            }),
        )?;
        let spec = match crate::cycle::synthetic_spec() {
            Ok(s) => s,
            Err(e) => return Err(self.fail(format!("the synthetic spec: {e}"))),
        };
        let head = self.draft_head(p)?;
        self.must(
            BUILDER,
            crate::cycle::creator(CreatorCommand::SaveFields {
                programme: p,
                base: head,
                fields: crate::cycle::save_of(&spec),
            }),
        )?;
        let head = self.draft_head(p)?;
        self.must(
            BUILDER,
            crate::cycle::creator(CreatorCommand::AcknowledgeWarning {
                programme: p,
                revision: head,
                warning: WarningKey {
                    check: CheckId::RosterShort,
                    subject: CheckSubject::Draft,
                },
            }),
        )?;
        let head = self.draft_head(p)?;
        self.must(
            BUILDER,
            crate::cycle::creator(CreatorCommand::RequestActivation {
                programme: p,
                revision: head,
            }),
        )?;
        let head = self.draft_head(p)?;
        self.must(
            ADMIN_2,
            crate::cycle::creator(CreatorCommand::ApproveActivation {
                programme: p,
                revision: head,
                decision: DecisionId::from_raw(ACTIVATION_BASE.saturating_add(p.raw())),
            }),
        )?;
        let base = match self.policy_head(p)? {
            Some(h) => h,
            None => return Err(self.fail(format!("{p:?} has no policy head after activation"))),
        };
        let mut version = policy.clone();
        version.parent = Some(base);
        self.must(
            BUILDER,
            crate::cycle::core(Command::EditPolicy {
                base,
                version: Box::new(version),
            }),
        )?;
        let now = self.client.cell().clock().now();
        self.must(
            HARNESS,
            crate::cycle::core(Command::EndRole {
                binding,
                at: Timestamp::from_micros(now),
            }),
        )
    }

    /// The cell's state, replayed from its ledger.
    fn state(&mut self) -> Result<fstp_cell_core::CellState, ExecError> {
        let ledger = match self.client.cell().ledger() {
            Ok(l) => l,
            Err(e) => return Err(self.fail(format!("the ledger read failed: {e}"))),
        };
        match fstp_cell_core::replay(&ledger) {
            Ok(s) => Ok(s),
            Err(e) => Err(self.fail(format!("the ledger replay failed: {e:?}"))),
        }
    }

    /// The head revision of the draft of `p`.
    fn draft_head(
        &mut self,
        p: fstp_domain::id::ProgrammeId,
    ) -> Result<fstp_creator::DraftRevision, ExecError> {
        let head = self.state()?.engine().creator.head(p);
        match head {
            Some(h) => Ok(h),
            None => Err(self.fail(format!("the draft of {p:?} has no head"))),
        }
    }

    /// The head policy version of `p`.
    fn policy_head(
        &mut self,
        p: fstp_domain::id::ProgrammeId,
    ) -> Result<Option<PolicyVersionId>, ExecError> {
        let state = self.state()?;
        Ok(fstp_domain::policy::head(&state.engine().core, p).map(|v| v.id))
    }
}

/// Whether a reply is a refusal of the domain or the gate, as opposed to
/// a reply that a harness failure explains.
fn refused(r: &Reply) -> bool {
    match r.status {
        401 | 403 => true,
        409 => String::from_utf8_lossy(&r.body).contains("\"error\":\"refused\""),
        _ => false,
    }
}

/// The accounts a setup or a step names that must hold a cell account
/// before the step runs: its actor, and the account a grant, a member or
/// a guardian binds.
fn named_accounts(step: &Step) -> Vec<AccountId> {
    let mut out = Vec::new();
    if let Actor::Account(a) = step.actor {
        out.push(a);
    }
    match &step.cmd {
        Command::GrantRole { account, .. }
        | Command::AddTeamMember { account, .. }
        | Command::AddGuardian { account, .. } => out.push(*account),
        _ => {}
    }
    out
}

impl M2Driver for HttpDriver<'_, '_> {
    fn truth(&self) -> &GroundTruth {
        &self.truth
    }

    fn start(
        &mut self,
        truth: &GroundTruth,
        steps: &[Step],
        at: Timestamp,
    ) -> Result<Seq, ExecError> {
        self.truth = truth.clone();
        match self.client.enrol(FIRST_ADMIN) {
            Ok(true) => {}
            Ok(false) => return Err(self.fail("the first admin did not enrol".to_owned())),
            Err(e) => return Err(self.fail(format!("the first admin's enrolment: {e}"))),
        }
        // Every account the vault knows or a setup step names, with the
        // builder, holds a cell account at its own id before any record
        // names it (`fstp_cell_core::decide`, `account_known`).
        let mut accounts: BTreeSet<AccountId> = truth.identities().map(|(a, _)| a).collect();
        accounts.insert(BUILDER);
        for s in steps {
            accounts.extend(named_accounts(s));
        }
        for a in &accounts {
            self.enrol(*a)?;
        }
        let admin = self.harness_admin()?;
        for a in [ADMIN, ADMIN_2] {
            match self
                .client
                .roster(&admin, RosterChange::GrantAdmin { account: key(a) })
            {
                Ok(true) => {
                    self.tenant_admins.insert(a);
                }
                Ok(false) => {
                    return Err(self.fail(format!("the tenant admin grant of {a:?} was refused")));
                }
                Err(e) => return Err(self.fail(format!("the tenant admin grant of {a:?}: {e}"))),
            }
        }
        // The harness's own accounts are persons of their own (I-67).
        let first = match self.client.cell_account(FIRST_ADMIN) {
            Some(a) => a,
            None => return Err(self.fail("the first admin has no cell account".to_owned())),
        };
        self.seed_person(first, b"m2-harness-first-admin")?;
        self.seed_person(BUILDER, b"m2-harness-builder")?;
        self.sync_vault()?;
        for s in steps {
            match &s.cmd {
                Command::CreateProgramme { policy } => self.create_programme(policy)?,
                // The creator's approval activated it (D2e).
                Command::ActivateProgramme { .. } => {}
                _ => {
                    M2Driver::execute(self, s, at)?;
                }
            }
        }
        self.settle_each = false;
        self.tally = Tally {
            setup: true,
            ..Tally::default()
        };
        self.read()
    }

    fn execute(&mut self, step: &Step, now: Timestamp) -> Result<Seq, ExecError> {
        self.clock_to(now)?;
        let Actor::Account(actor) = step.actor else {
            return Err(self.fail(format!("a System step over HTTP: {:?}", step.cmd)));
        };
        for a in named_accounts(step) {
            if !self.is_generator(a) {
                return Err(self.fail(format!("{a:?} holds no cell account")));
            }
        }
        let command = crate::cycle::core(step.cmd.clone());
        let committed = self.send(actor, &command)?;
        let head = self.read()?;
        if committed {
            self.tally.accepted = self.tally.accepted.saturating_add(1);
            Ok(head)
        } else {
            self.tally.refused = self.tally.refused.saturating_add(1);
            Err(ExecError::Refused(remote_refusal()))
        }
    }

    fn change_vault(&mut self, op: VaultOp, now: Timestamp) -> Result<Seq, ExecError> {
        self.clock_to(now)?;
        let before = self.entries;
        op.apply(&mut self.truth);
        if !self.sync_vault()? {
            return Err(ExecError::Refused(Refusal::new(
                RuleRef::StaleFacts,
                RefusalReason::AnswerStale,
            )));
        }
        self.probe()?;
        let head = self.read()?;
        if self.entries > before {
            self.tally.vault = self.tally.vault.saturating_add(1);
            Ok(head)
        } else {
            Err(ExecError::Refused(Refusal::new(
                RuleRef::StaleFacts,
                RefusalReason::AnswerStale,
            )))
        }
    }

    fn run_due(&mut self, now: Timestamp) -> Result<Seq, ExecError> {
        Err(self.fail(format!(
            "System commands due at {}: the reduced case schedules no end",
            now.micros()
        )))
    }

    fn core_records(&self) -> Vec<Record> {
        self.records.clone()
    }
}

// ---------------------------------------------------------------------------
// The SoD machine in lockstep.

/// What the cell did with one machine command.
#[derive(Debug)]
pub struct RemoteOutput {
    /// Whether the cell took it.
    pub accepted: bool,
    /// The M2 core records it appended.
    pub appended: Vec<Record>,
    /// The harness failure, if any.
    pub fault: Option<String>,
}

/// The SoD machine of `fstp_domain_testkit` in lockstep with a cell
/// (module documentation).
pub struct SodOverHttp<'d, 'c, 'w> {
    inner: SodMachine,
    /// The cell, or none for a dry run on the engine alone, which picks
    /// the seed of a case that is long enough.
    remote: Option<RefCell<&'d mut HttpDriver<'c, 'w>>>,
    /// The setups run so far. Only the first case reaches the cell; a
    /// later case of the runner runs on the engine alone.
    cases: RefCell<u32>,
    /// The steps of the current case after its setup, and how many the
    /// engine accepted.
    counts: RefCell<(usize, usize)>,
    max_commands: usize,
}

impl<'d, 'c, 'w> SodOverHttp<'d, 'c, 'w> {
    /// The machine of `focus` over `remote`, with at most `max_commands`
    /// commands per case.
    pub fn new(
        focus: SodFocus,
        remote: &'d mut HttpDriver<'c, 'w>,
        max_commands: usize,
    ) -> SodOverHttp<'d, 'c, 'w> {
        SodOverHttp {
            inner: SodMachine::new(focus),
            remote: Some(RefCell::new(remote)),
            cases: RefCell::new(0),
            counts: RefCell::new((0, 0)),
            max_commands,
        }
    }

    /// The machine of `focus` on the engine alone.
    pub fn dry(focus: SodFocus, max_commands: usize) -> SodOverHttp<'d, 'c, 'w> {
        SodOverHttp {
            inner: SodMachine::new(focus),
            remote: None,
            cases: RefCell::new(0),
            counts: RefCell::new((0, 0)),
            max_commands,
        }
    }

    /// The steps of the last case after its setup, and how many the
    /// engine accepted.
    pub fn counts(&self) -> (usize, usize) {
        *self.counts.borrow()
    }

    /// `step` with the flags the cell derives and the draft flag the cell
    /// sets (module documentation).
    fn cell_step(step: &Step, now: i64) -> Step {
        let mut s = step.clone();
        let admins = [ADMIN, ADMIN_2];
        let actor = match s.actor {
            Actor::Account(a) => Some(a),
            Actor::System(_) => None,
        };
        s.flags.tenant_admin = actor.is_some_and(|a| admins.contains(&a));
        s.flags.second_admin = None;
        let bound = match &s.cmd {
            Command::GrantRole { account, .. }
            | Command::AddTeamMember { account, .. }
            | Command::AddGuardian { account, .. } => Some(*account),
            Command::CreateDraft { .. } => actor,
            _ => None,
        };
        s.flags.binds_tenant_admin = bound.is_some_and(|a| admins.contains(&a));
        match &mut s.cmd {
            Command::CreateDraft { minor, .. } => *minor = true,
            Command::EndRole { at, .. } if at.micros() > now => *at = Timestamp::from_micros(now),
            _ => {}
        }
        s
    }

    /// The setup's vault with every account that has an identity
    /// verified (module documentation).
    fn cell_truth(truth: &GroundTruth) -> GroundTruth {
        let mut t = truth.clone();
        let accounts: Vec<AccountId> = truth.identities().map(|(a, _)| a).collect();
        for a in accounts {
            if !t.is_verified(a) {
                t.verify(a);
            }
        }
        t
    }
}

/// The text of `records` with the vault's epochs and answer digests left
/// out, which differ between the synthetic vault and `fstp-vault`.
fn masked(records: &[Record]) -> Vec<String> {
    records
        .iter()
        .map(|r| {
            let text = format!("{r:?}");
            let text = mask_between(&text, "VaultEpoch(", ")");
            if text.starts_with("VaultOutcome") {
                mask_between(&text, "digest: ContentDigest(", ")")
            } else {
                text
            }
        })
        .collect()
}

/// The masked records apart from the vault answers, and the vault
/// answers. Interim reading, pending Daniel: `fstp-vault` lists every
/// account of a changed person as changed, where the M2 vault lists the
/// changed account, so the cell's reaction may ask more questions and
/// record more `VaultOutcome` audit records. Every other record must be
/// equal and in order, and every answer the engine recorded must be among
/// the cell's.
fn split_outcomes(records: &[String]) -> (Vec<String>, Vec<String>) {
    records
        .iter()
        .cloned()
        .partition(|r| !r.starts_with("VaultOutcome"))
}

/// `text` with whatever follows each `open` up to the next `close`
/// replaced by `_`.
fn mask_between(text: &str, open: &str, close: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find(open) {
        let (head, tail) = rest.split_at(i);
        out.push_str(head);
        out.push_str(open);
        let after = tail.get(open.len()..).unwrap_or("");
        match after.find(close) {
            Some(j) => {
                out.push('_');
                rest = after.get(j..).unwrap_or("");
            }
            None => {
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

impl StateMachine for SodOverHttp<'_, '_, '_> {
    type Model = MachineModel;
    type Sut = MachineSut;
    type Command = MachineCmd;
    type Output = (MachineOutput, RemoteOutput);

    fn init_model(&self) -> MachineModel {
        self.inner.init_model()
    }

    fn init_sut(&self) -> MachineSut {
        self.inner.init_sut()
    }

    fn command(&self, g: &mut Gen, model: &MachineModel) -> MachineCmd {
        match self.inner.command(g, model) {
            MachineCmd::Setup { truth, subjects } => MachineCmd::Setup {
                truth: Box::new(Self::cell_truth(&truth)),
                subjects,
            },
            MachineCmd::Core { now, step } => MachineCmd::Core {
                now,
                step: Box::new(Self::cell_step(&step, now)),
            },
            other => other,
        }
    }

    fn precondition(&self, model: &MachineModel, cmd: &MachineCmd) -> bool {
        if let MachineCmd::Vault {
            op: VaultOp::Merge(account, _),
            ..
        } = cmd
        {
            let Some(old) = model.truth.identity_of(*account) else {
                return false;
            };
            if model.truth.exclusions().any(|(t, _)| t == old)
                || model
                    .truth
                    .relations()
                    .any(|(x, y, _)| x == old || y == old)
            {
                return false;
            }
        }
        self.inner.precondition(model, cmd)
    }

    fn run(&self, sut: &mut MachineSut, cmd: &MachineCmd) -> (MachineOutput, RemoteOutput) {
        let out = self.inner.run(sut, cmd);
        let first = {
            let mut n = self.cases.borrow_mut();
            if matches!(cmd, MachineCmd::Setup { .. }) {
                *n = n.saturating_add(1);
            }
            *n == 1
        };
        if first {
            let mut c = self.counts.borrow_mut();
            if !matches!(cmd, MachineCmd::Setup { .. }) {
                c.0 = c.0.saturating_add(1);
                if out.result.is_ok() {
                    c.1 = c.1.saturating_add(1);
                }
            }
        }
        let Some(remote) = self.remote.as_ref().filter(|_| first) else {
            let mirror = RemoteOutput {
                accepted: out.result.is_ok(),
                appended: out.appended.clone(),
                fault: None,
            };
            return (out, mirror);
        };
        let mut remote = remote.borrow_mut();
        let before = remote.records.len();
        let result = match cmd {
            MachineCmd::Setup { truth, .. } => match SodMachine::setup().steps() {
                Ok(steps) => remote.start(truth, &steps, T0),
                Err(e) => Err(remote.fail(format!("the setup steps: {e}"))),
            },
            MachineCmd::Core { now, step } => remote.execute(step, Timestamp::from_micros(*now)),
            MachineCmd::Vault { now, op } => remote.change_vault(*op, Timestamp::from_micros(*now)),
            MachineCmd::Due { now } => remote.run_due(Timestamp::from_micros(*now)),
        };
        let appended = match cmd {
            MachineCmd::Setup { .. } => Vec::new(),
            _ => remote.records.get(before..).unwrap_or_default().to_vec(),
        };
        let output = RemoteOutput {
            accepted: result.is_ok(),
            appended,
            fault: remote.fault().map(str::to_owned),
        };
        (out, output)
    }

    fn postcondition(
        &self,
        model: &MachineModel,
        cmd: &MachineCmd,
        output: &(MachineOutput, RemoteOutput),
    ) -> Result<(), String> {
        let (out, remote) = output;
        self.inner.postcondition(model, cmd, out)?;
        if let Some(f) = &remote.fault {
            return Err(format!("the cell driver failed: {f}"));
        }
        let engine = out.result.is_ok();
        if engine != remote.accepted {
            return Err(format!(
                "{}: the engine {} it, the cell {} it",
                out.context,
                if engine { "accepts" } else { "refuses" },
                if remote.accepted {
                    "accepts"
                } else {
                    "refuses"
                }
            ));
        }
        if !matches!(cmd, MachineCmd::Setup { .. }) {
            let (want, want_asked) = split_outcomes(&masked(&out.appended));
            let (got, mut got_asked) = split_outcomes(&masked(&remote.appended));
            let asked_all =
                want_asked
                    .iter()
                    .all(|w| match got_asked.iter().position(|g| g == w) {
                        Some(i) => {
                            got_asked.swap_remove(i);
                            true
                        }
                        None => false,
                    });
            if want != got || !asked_all {
                return Err(format!(
                    "{}: the cell appended other M2 records\n  engine: {:?}\n  cell:   {:?}",
                    out.context,
                    masked(&out.appended),
                    masked(&remote.appended)
                ));
            }
        }
        Ok(())
    }

    fn next_state(&self, model: &mut MachineModel, cmd: &MachineCmd) {
        self.inner.next_state(model, cmd);
    }

    fn invariant(&self, model: &MachineModel, sut: &MachineSut) -> Result<(), String> {
        self.inner.invariant(model, sut)?;
        let Some(remote) = self.remote.as_ref().filter(|_| *self.cases.borrow() == 1) else {
            return Ok(());
        };
        let remote = remote.borrow();
        if remote.records.is_empty() {
            return Ok(());
        }
        let view = View::of(remote.records.iter())
            .map_err(|e| format!("the reference cannot follow the cell's ledger: {e}"))?;
        let truth = M2Driver::truth(&**remote);
        check_i01(&view)?;
        check_bars(&view)?;
        check_i02(&view)?;
        check_i04(&view, truth)?;
        check_i06(&view, truth)
    }

    fn max_commands(&self) -> usize {
        self.max_commands.min(self.inner.max_commands())
    }
}

/// The commands of one reduced case over the cell.
const REDUCED_COMMANDS: usize = 24;

/// The seed of the reduced case of each suite: fixed, so a red run
/// replays the same commands.
fn seed_of(suite: &str) -> u64 {
    suite
        .bytes()
        .fold(SEED_BASE, |h, b| h.rotate_left(5) ^ u64::from(b))
}

/// The base of [`seed_of`].
const SEED_BASE: u64 = 0x5eed_0002;

/// Runs the reduced case of the M2 suite `suite` (an invariant id such
/// as `I-04`) over the cell of `client` (design section 14.6).
///
/// # Errors
///
/// [`SUITE_SEAM`] for a suite with no cell driver yet, [`DRIVER_FAILED`]
/// for a harness failure, or the machine's failure, written to standard
/// error.
pub fn run_suite(client: &AuthClient<'_>, suite: &str) -> Result<(), NotImplemented> {
    let focus = match suite {
        "I-04" => SodFocus::I04,
        "I-06" => SodFocus::I06,
        _ => return Err(NotImplemented::new(SUITE_SEAM)),
    };
    let name = format!("m2-suite:{suite}:reduced over the cell");
    let seed = pick_seed(focus, suite, &name)?;
    let mut driver = HttpDriver::new(client);
    let machine = SodOverHttp::new(focus, &mut driver, REDUCED_COMMANDS);
    let outcome = fstp_prop::run_machine(&name, case_config(seed), &machine);
    drop(machine);
    let tally = driver.tally;
    eprintln!("fstp_celltest::m2_http {name}, seed {seed}: {tally:?}");
    match outcome {
        // A case so short that it tells nothing is no pass.
        Outcome::Passed { .. }
            if !tally.setup
                || tally.accepted < MIN_ACCEPTED
                || tally
                    .accepted
                    .saturating_add(tally.refused)
                    .saturating_add(tally.vault)
                    < MIN_STEPS =>
        {
            Err(NotImplemented::new(CASE_TOO_SHORT))
        }
        Outcome::Passed { .. } => Ok(()),
        Outcome::Failed(f) => {
            eprintln!(
                "fstp_celltest::m2_http {name}: {}\n{}",
                f.message,
                f.notes.join("\n")
            );
            Err(NotImplemented::new(MACHINE_FAILED))
        }
    }
}

/// The configuration of a reduced case under `seed`. The first case runs
/// the simplest values, which send no command. The second is the reduced
/// case. A failure is reported as found, since the cell cannot run a
/// shrunk case again from genesis.
fn case_config(seed: u64) -> Config {
    Config::default()
        .with_cases(2)
        .with_seed(seed)
        .with_max_shrink_steps(0)
}

/// How many seeds [`pick_seed`] tries.
const SEED_TRIES: u64 = 256;

/// The first seed from [`seed_of`] on whose reduced case the engine
/// alone passes the machine, with at least twice [`MIN_STEPS`] steps and
/// twice [`MIN_ACCEPTED`] accepted ones. The seed picks a case, never an
/// outcome on the cell: the cell runs the case the engine ran.
fn pick_seed(focus: SodFocus, suite: &str, name: &str) -> Result<u64, NotImplemented> {
    let base = seed_of(suite);
    for i in 0..SEED_TRIES {
        let seed = base.wrapping_add(i);
        let dry = SodOverHttp::dry(focus, REDUCED_COMMANDS);
        let outcome = fstp_prop::run_machine(name, case_config(seed), &dry);
        let (steps, accepted) = dry.counts();
        if outcome.is_passed()
            && steps >= MIN_STEPS.saturating_mul(2)
            && accepted >= MIN_ACCEPTED.saturating_mul(2)
        {
            return Ok(seed);
        }
    }
    Err(NotImplemented::new(CASE_TOO_SHORT))
}
