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
//! [`OverHttp`] runs an M2 machine of `fstp_domain_testkit` in lockstep:
//! each command goes to the M2 engine, which the machine checks against
//! its reference as it always does, and to the cell. The cell must accept
//! and refuse as the engine does and append the same M2 core records, and
//! the machine's invariants must hold over the cell's ledger. The SoD
//! machine (I-04, I-06), the review machine (I-03, I-35), the money
//! machine (I-13, I-14, I-15) and the ledger machine (I-23) implement
//! [`CellMachine`]. A reduced case is one case of at most
//! [`REDUCED_COMMANDS`] commands under a fixed seed. The seed is the
//! first from the suite's own on which the engine alone runs a case long
//! enough to count, and shows the suite's [`Witness`] if it has one. So
//! it picks the commands, never the cell's outcome.
//!
//! How the driver maps a machine onto the cell:
//!
//! - Accounts. Each generator account enrols at its own id through an
//!   invitation of the world's first tenant admin
//!   (`AuthClient::enrol_at`). [`ADMIN`] and [`ADMIN_2`] are granted
//!   tenant admin. The first admin itself is the harness's and names no
//!   generator account.
//! - Programmes. A setup's `CreateProgramme` runs the creator path of M4
//!   design section 3.4: [`ADMIN`] opens the draft and grants the harness
//!   builder ([`BUILDER`]) the programme manager role, the builder saves
//!   the synthetic spec and requests activation, and [`ADMIN_2`]
//!   approves. The builder then records the generator's policy with one
//!   `EditPolicy` under the generator's version id, and the first admin
//!   ends the builder's binding. The setup's core `ActivateProgramme` is
//!   skipped: the creator's approval activated the programme (D2e).
//! - Instants. The cell runs on the world's clock. Each step sets it to
//!   the step's instant, which never runs backwards. The setup's
//!   enrolments and creator path run before the setup instant.
//! - Vault facts. A verified account's identity tag is a synthetic
//!   attribute tuple of its own, so accounts of one tag share a person.
//!   An exclusion is a partner staff affiliation in its class on one
//!   verified account of its identity, which the vault counts for every
//!   account of that person. A relation is a relationship between one
//!   verified account of each identity. An affiliation on a P-38 list is
//!   an affiliation with the list's one organisation, and the setup
//!   declares every list of its policies. A change that leaves every fact
//!   as it was, such as an affiliation declared again, writes one changed
//!   account's verification again, so it is a new epoch on both sides.
//! - Reactions. After a vault change a probe command that the domain
//!   refuses makes the cell process the new epoch, as its next command
//!   would (design section 5.2 step 4).
//!
//! Interim readings, pending Daniel, of what a reduced case is. A cell
//! derives what a generator step states as flags, and the vault holds
//! facts of verified persons only (as `tests/seam_vault.rs` notes). So
//! [`OverHttp`] rewrites each drawn command before both sides run it, or
//! leaves it out:
//!
//! - The setup verifies every account that has an identity. An
//!   unverified account's exclusions and relations have no vault form.
//! - A step's tenant admin flags are the cell's own: the actor is a
//!   tenant admin when it is [`ADMIN`] or [`ADMIN_2`], and a second admin
//!   is never attested, since no tenant approval ceremony runs.
//! - A draft a machine step names is minor-flagged, as the cell flags
//!   every draft (I-18, interim reading of Q13). The setup drafts keep
//!   their flags on the engine side.
//! - An end is never scheduled later than its step, since the cell's
//!   timeline commits a due end on its own tick.
//! - An identity merge is drawn only for an account whose identity has no
//!   exclusion or relation, and no relation ends, since the vault cannot
//!   retract a fact.
//! - The records are compared with the vault's epochs and answer digests
//!   left out. The cell may record more vault answers than the engine,
//!   since `fstp-vault` lists every account of a changed person as
//!   changed (`split_outcomes`).

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
use fstp_domain_testkit::r#gen::money::{
    MoneyCmd, MoneyFocus, MoneyMachine, MoneyModel, MoneyOutput, machine_setup as money_setup,
};
use fstp_domain_testkit::r#gen::review::{
    RevCmd, RevFocus, RevModel, RevOp, RevOutput, ReviewMachine, machine_setup as review_setup,
};
use fstp_domain_testkit::r#gen::roster::{
    ADMIN, ADMIN_2, MachineCmd, MachineModel, MachineOutput, SodFocus, SodMachine, Step, T0,
    VaultOp,
};
use fstp_domain_testkit::mc::ledger_model::{
    LedgerCmd, LedgerGhost, LedgerMachine, LedgerOutput, LedgerSut, LedgerVaultOp,
    check_corrections, ledger_machine_setup, ledger_truth, machine_genesis_steps,
};
use fstp_domain_testkit::reference::money::{
    MoneyView, check_i13, check_i14, check_i15, check_i64,
};
use fstp_domain_testkit::reference::review::{
    RevView, check_handles, check_i02_assignments, check_i03, check_i36, check_i36_held,
    check_one_organisation, check_rcf02,
};
use fstp_domain_testkit::reference::sod::{
    View, check_bars, check_i01, check_i02, check_i04, check_i06,
};
use fstp_domain_testkit::vault::{GroundTruth, IdentityTag};
use fstp_engine::ExecError;
use fstp_ledger::Seq;
use fstp_prop::{Config, Gen, Outcome, StateMachine};
use fstp_vault_core::fact::{Fact, Org};
use fstp_vault_proto::{WireAccount, WireClass, WireList};

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

/// An `m2-suite` step names a suite the driver has no machine for.
pub const SUITE_SEAM: &str = "fstp_celltest::m2_http: the m2-suite step names an M2 suite with no cell driver; the SoD machine (I-04, I-06), the review machine (I-03, I-35), the money machine (I-13, I-14, I-15) and the ledger machine (I-23) run over the cell";

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

/// The one organisation of the P-38 list `list` in the vault.
fn list_org(list: fstp_domain::id::ProximityListId) -> Org {
    Org(800_000u128.saturating_add(list.raw()))
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
    /// The over-18 attestations seeded, with their instants.
    adults: BTreeMap<AccountId, i64>,
    /// The P-38 lists the vault holds.
    lists: BTreeSet<fstp_domain::id::ProximityListId>,
    /// The affiliations on a list seeded, by account and list.
    affiliated: BTreeSet<(AccountId, fstp_domain::id::ProximityListId)>,
    /// The M2 core records of the cell's ledger at the last read.
    records: Vec<Record>,
    /// The number of entries of the cell's ledger at the last read.
    entries: usize,
    /// The M2 core records of the cell's ledger at the last read, one
    /// batch per command id (lane m3/money-drivers).
    batches: Vec<Vec<Record>>,
    /// The cell's ledger at the last read.
    ledger: Vec<fstp_ledger::Entry<fstp_cell_core::CellRecord>>,
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
            adults: BTreeMap::new(),
            lists: BTreeSet::new(),
            affiliated: BTreeSet::new(),
            records: Vec::new(),
            entries: 0,
            batches: Vec::new(),
            ledger: Vec::new(),
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
        let mut batches: Vec<Vec<Record>> = Vec::new();
        let mut last: Option<[u8; 16]> = None;
        for e in &ledger {
            let fstp_cell_core::CellRecord::Engine(fstp_engine::Record::Core(r)) = &e.record else {
                continue;
            };
            match batches.last_mut() {
                Some(b) if last == Some(e.command) => b.push(r.clone()),
                _ => batches.push(vec![r.clone()]),
            }
            last = Some(e.command);
        }
        self.records = batches.iter().flatten().cloned().collect();
        self.batches = batches;
        self.ledger = ledger;
        Ok(Seq::from_raw(
            u64::try_from(self.entries).unwrap_or(u64::MAX),
        ))
    }

    /// The M2 core records of the cell's ledger at the last read, one
    /// batch per command.
    pub fn batches(&self) -> &[Vec<Record>] {
        &self.batches
    }

    /// The cell's ledger at the last read.
    pub fn ledger(&self) -> &[fstp_ledger::Entry<fstp_cell_core::CellRecord>] {
        &self.ledger
    }

    /// Runs the System step `step` at `now` through the cell's system
    /// task for it, as a serving cell does (lane m3/money-drivers):
    ///
    /// - The contract port's EFFECTIVE fact goes through
    ///   `CellHandle::contract_effective`, which the gate admits under
    ///   the system task `ContractPort` only.
    /// - A command of the timeline's cause runs as one tick of the
    ///   timeline task (`CellHandle::timeline_tick`). The tick issues
    ///   every command due at `now`, so a reduced case sends such a step
    ///   only where the engine has no other System command due
    ///   ([`only_due`]). The cell took it when the tick appended M2 core
    ///   records.
    ///
    /// Any other System step has no task in the cell, and the driver
    /// fails it.
    fn system(&mut self, step: &Step, now: Timestamp) -> Result<Seq, ExecError> {
        use fstp_domain::command::{ContractEvent, SystemCause};
        let before = self.records.len();
        let cell = self.client.cell();
        let took = match (&step.actor, &step.cmd) {
            (
                Actor::System(SystemCause::ContractPort),
                Command::ContractFact {
                    proposal,
                    contract,
                    event: ContractEvent::Effective,
                },
            ) => match cell.contract_effective(*proposal, *contract) {
                Ok(()) => true,
                Err(e) => {
                    eprintln!("fstp_celltest::m2_http: refused {:?}: {e}", step.cmd);
                    false
                }
            },
            (Actor::System(SystemCause::Timeline), _) => match cell.timeline_tick() {
                Ok(_) => false,
                Err(e) => return Err(self.fail(format!("the timeline tick at {now:?}: {e}"))),
            },
            _ => {
                return Err(self.fail(format!(
                    "a System step the cell has no task for: {:?} by {:?}",
                    step.cmd, step.actor
                )));
            }
        };
        let head = self.read()?;
        // A tick took the step when it appended M2 core records.
        let took = took || self.records.len() > before;
        if took {
            self.tally.accepted = self.tally.accepted.saturating_add(1);
            Ok(head)
        } else {
            self.tally.refused = self.tally.refused.saturating_add(1);
            Err(ExecError::Refused(remote_refusal()))
        }
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
                // A step-up refused on a session the cell ended, such as
                // one that expired while the clock moved on: log in again
                // once (lane m3/money-drivers).
                None if attempt == 0 => {
                    self.sessions.remove(&account);
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
        let adults: Vec<(AccountId, Timestamp)> = self
            .truth
            .adults()
            .filter(|(a, _)| self.truth.is_verified(*a))
            .collect();
        for (a, from) in adults {
            if self.adults.get(&a) != Some(&from.micros()) {
                self.seed_fact(
                    SeedSource::SyntheticVerification,
                    Fact::AdultAttestation {
                        account: WireAccount(a.raw()),
                        adult_from: from.micros(),
                    },
                )?;
                self.adults.insert(a, from.micros());
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
        let affiliations: Vec<_> = self.truth.affiliations().collect();
        for (a, list) in affiliations {
            if self.lists.insert(list) {
                self.seed_fact(
                    SeedSource::SyntheticAffiliation,
                    Fact::ProximityListDeclared {
                        list: WireList(list.raw()),
                        orgs: BTreeSet::from([list_org(list)]),
                    },
                )?;
                seeded = true;
            }
            if self.affiliated.insert((a, list)) {
                self.seed_fact(
                    SeedSource::SyntheticAffiliation,
                    Fact::AffiliationDeclared {
                        account: WireAccount(a.raw()),
                        org: list_org(list),
                        class: None,
                        partner_staff: false,
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

    /// A change of the M2 vault that moved its epoch past `epoch` but left
    /// every fact the vault holds as it was, such as an affiliation
    /// declared again, is a new epoch in `fstp-vault` too: the
    /// verification of one changed account is written again. Returns
    /// whether it wrote one.
    fn touch(&mut self, epoch: fstp_domain::id::VaultEpoch) -> Result<bool, ExecError> {
        let changed = self.truth.changed_since(epoch);
        let again = changed
            .iter()
            .find_map(|a| self.persons.get(a).map(|t| (*a, *t)));
        match again {
            Some((a, t)) => {
                self.seed_person(a, &attributes(t))?;
                Ok(true)
            }
            None => Ok(false),
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

impl HttpDriver<'_, '_> {
    /// Starts from genesis over `truth` and runs `steps`, each at its own
    /// instant, as [`M2Driver::start`] does at one instant. A path of
    /// `crate::mc::driver_model::paths` runs this way.
    ///
    /// # Errors
    ///
    /// The refusal of the first step that did not run, or the driver's
    /// failure.
    pub fn start_timed(
        &mut self,
        truth: &GroundTruth,
        steps: &[(Step, Timestamp)],
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
        for (s, _) in steps {
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
        // The P-38 lists of the setup's policies, so a later affiliation
        // on a list is one write, as the M2 vault's change is one epoch.
        for (s, _) in steps {
            if let Command::CreateProgramme { policy } = &s.cmd {
                for list in policy.live.p38.0.values() {
                    if self.lists.insert(*list) {
                        self.seed_fact(
                            SeedSource::SyntheticAffiliation,
                            Fact::ProximityListDeclared {
                                list: WireList(list.raw()),
                                orgs: BTreeSet::from([list_org(*list)]),
                            },
                        )?;
                    }
                }
            }
        }
        self.sync_vault()?;
        for (s, at) in steps {
            match &s.cmd {
                Command::CreateProgramme { policy } => self.create_programme(policy)?,
                // The creator's approval activated it (D2e).
                Command::ActivateProgramme { .. } => {}
                _ => {
                    M2Driver::execute(self, s, *at)?;
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
}

impl HttpDriver<'_, '_> {
    /// Continues a cell on which an earlier driver ran a path over a part
    /// of `truth`, and runs `steps`, each at its own instant (lane
    /// m3/cycle-steps). The vault already holds the persons and
    /// attestations of every account the cell knows as a generator
    /// account, so only the accounts new in `truth` or in `steps` enrol,
    /// and only their facts are seeded. No setup runs again.
    ///
    /// # Errors
    ///
    /// The refusal of the first step that did not run, or the driver's
    /// failure.
    pub fn continue_timed(
        &mut self,
        truth: &GroundTruth,
        steps: &[(Step, Timestamp)],
    ) -> Result<Seq, ExecError> {
        self.truth = truth.clone();
        let known: Vec<(AccountId, IdentityTag)> = truth
            .identities()
            .filter(|(a, _)| truth.is_verified(*a) && self.is_generator(*a))
            .collect();
        for (a, t) in known {
            self.persons.insert(a, t);
        }
        let adults: Vec<(AccountId, Timestamp)> = truth.adults().collect();
        for (a, from) in adults {
            if self.is_generator(a) {
                self.adults.insert(a, from.micros());
            }
        }
        let mut accounts: BTreeSet<AccountId> = truth.identities().map(|(a, _)| a).collect();
        for (s, _) in steps {
            accounts.extend(named_accounts(s));
        }
        for a in &accounts {
            self.enrol(*a)?;
        }
        self.sync_vault()?;
        self.settle_each = false;
        for (s, at) in steps {
            M2Driver::execute(self, s, *at)?;
        }
        self.tally = Tally {
            setup: true,
            ..Tally::default()
        };
        self.read()
    }
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
        let timed: Vec<(Step, Timestamp)> = steps.iter().map(|s| (s.clone(), at)).collect();
        self.start_timed(truth, &timed)
    }

    fn execute(&mut self, step: &Step, now: Timestamp) -> Result<Seq, ExecError> {
        self.clock_to(now)?;
        let Actor::Account(actor) = step.actor else {
            return self.system(step, now);
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

    fn change_vault(
        &mut self,
        change: &dyn Fn(&mut GroundTruth),
        now: Timestamp,
    ) -> Result<Seq, ExecError> {
        self.clock_to(now)?;
        let before = self.entries;
        let epoch = self.truth.epoch();
        change(&mut self.truth);
        if !self.sync_vault()? && !self.touch(epoch)? {
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
// The machines in lockstep.

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

/// What the engine did with one machine command: whether it took it, the
/// M2 core records it appended and the step's description.
pub type EngineSide<'a> = (bool, &'a [Record], &'a str);

/// The engine's side before a command: its domain state and its vault
/// facts. A reduced case reads it to leave out what the cell cannot
/// express (lane m3/money-drivers).
#[derive(Clone, Debug)]
pub struct EngineView {
    /// The engine's domain state.
    pub state: fstp_domain::State,
    /// The engine's vault facts.
    pub truth: GroundTruth,
}

/// The cell's ledger before a command.
pub type Prior = [fstp_ledger::Entry<fstp_cell_core::CellRecord>];

/// An M2 machine that runs in lockstep over a cell ([`OverHttp`]).
pub trait CellMachine: StateMachine {
    /// Whether `cmd` is the machine's setup from genesis.
    fn is_setup(cmd: &Self::Command) -> bool;

    /// `cmd` as both sides run it: with the cell's own flags, the cell's
    /// draft flag and a verified setup vault (module documentation).
    fn for_cell(cmd: Self::Command) -> Self::Command;

    /// Whether the cell can express `cmd` in `model`, where `engine` is
    /// the engine's side before it, if the machine gives one: a vault
    /// change the vault cannot hold, or a System step whose tick would
    /// issue more than the step, is left out of a reduced case.
    fn cell_admits(model: &Self::Model, cmd: &Self::Command, engine: Option<&EngineView>) -> bool;

    /// The engine's side in `sut`, for [`CellMachine::cell_admits`].
    fn engine_view(sut: &Self::Sut) -> Option<EngineView> {
        let _ = sut;
        None
    }

    /// The setup the cell runs before the first command of a case, for a
    /// machine whose start state is built outside its commands. `None`
    /// for a machine whose first command is its setup.
    fn implicit_setup(&self, remote: &mut HttpDriver<'_, '_>) -> Option<Result<Seq, ExecError>> {
        let _ = remote;
        None
    }

    /// Sends `cmd` to the cell, where `out` is what the engine did with
    /// it.
    ///
    /// # Errors
    ///
    /// The cell's refusal, or the driver's failure.
    fn drive(
        remote: &mut HttpDriver<'_, '_>,
        cmd: &Self::Command,
        out: &Self::Output,
    ) -> Result<Seq, ExecError>;

    /// What the engine did with the command of `out`.
    fn engine_side(out: &Self::Output) -> EngineSide<'_>;

    /// The machine's invariants over the cell's ledger after a command,
    /// where `prior` is the ledger before it.
    ///
    /// # Errors
    ///
    /// The first invariant that fails.
    fn cell_invariant(prior: &Prior, remote: &HttpDriver<'_, '_>) -> Result<(), String>;
}

/// `step` with the flags the cell derives and the draft flag the cell
/// sets, and no end later than the step (module documentation).
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

/// The setup's vault with every account that has an identity verified
/// (module documentation).
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

impl CellMachine for SodMachine {
    fn is_setup(cmd: &MachineCmd) -> bool {
        matches!(cmd, MachineCmd::Setup { .. })
    }

    fn for_cell(cmd: MachineCmd) -> MachineCmd {
        match cmd {
            MachineCmd::Setup { truth, subjects } => MachineCmd::Setup {
                truth: Box::new(cell_truth(&truth)),
                subjects,
            },
            MachineCmd::Core { now, step } => MachineCmd::Core {
                now,
                step: Box::new(cell_step(&step, now)),
            },
            other => other,
        }
    }

    fn cell_admits(model: &MachineModel, cmd: &MachineCmd, _engine: Option<&EngineView>) -> bool {
        let MachineCmd::Vault {
            op: VaultOp::Merge(account, _),
            ..
        } = cmd
        else {
            return true;
        };
        let Some(old) = model.truth.identity_of(*account) else {
            return false;
        };
        !(model.truth.exclusions().any(|(t, _)| t == old)
            || model
                .truth
                .relations()
                .any(|(x, y, _)| x == old || y == old))
    }

    fn drive(
        remote: &mut HttpDriver<'_, '_>,
        cmd: &MachineCmd,
        _out: &MachineOutput,
    ) -> Result<Seq, ExecError> {
        match cmd {
            MachineCmd::Setup { truth, .. } => match SodMachine::setup().steps() {
                Ok(steps) => remote.start(truth, &steps, T0),
                Err(e) => Err(remote.fail(format!("the setup steps: {e}"))),
            },
            MachineCmd::Core { now, step } => remote.execute(step, Timestamp::from_micros(*now)),
            MachineCmd::Vault { now, op } => {
                remote.change_vault(&|t| op.apply(t), Timestamp::from_micros(*now))
            }
            MachineCmd::Due { now } => remote.run_due(Timestamp::from_micros(*now)),
        }
    }

    fn engine_side(out: &MachineOutput) -> EngineSide<'_> {
        (out.result.is_ok(), &out.appended, &out.context)
    }

    fn cell_invariant(_prior: &Prior, remote: &HttpDriver<'_, '_>) -> Result<(), String> {
        let (records, truth) = (&remote.records, &remote.truth);
        let view = View::of(records.iter())
            .map_err(|e| format!("the reference cannot follow the cell's ledger: {e}"))?;
        check_i01(&view)?;
        check_bars(&view)?;
        check_i02(&view)?;
        check_i04(&view, truth)?;
        check_i06(&view, truth)
    }
}

impl CellMachine for ReviewMachine {
    fn is_setup(cmd: &RevCmd) -> bool {
        matches!(cmd, RevCmd::Setup { .. })
    }

    fn for_cell(cmd: RevCmd) -> RevCmd {
        match cmd {
            RevCmd::Setup { truth } => RevCmd::Setup {
                truth: Box::new(cell_truth(&truth)),
            },
            RevCmd::Core { now, step } => RevCmd::Core {
                now,
                step: Box::new(cell_step(&step, now)),
            },
            other => other,
        }
    }

    /// The vault holds no end of a relationship, so a reduced case draws
    /// no `Unrelate`.
    fn cell_admits(_model: &RevModel, cmd: &RevCmd, _engine: Option<&EngineView>) -> bool {
        !matches!(
            cmd,
            RevCmd::Vault {
                op: RevOp::Unrelate(..),
                ..
            }
        )
    }

    fn drive(
        remote: &mut HttpDriver<'_, '_>,
        cmd: &RevCmd,
        _out: &RevOutput,
    ) -> Result<Seq, ExecError> {
        match cmd {
            RevCmd::Setup { truth } => match review_setup().steps() {
                Ok(steps) => remote.start(truth, &steps, T0),
                Err(e) => Err(remote.fail(format!("the setup steps: {e}"))),
            },
            RevCmd::Core { now, step } => remote.execute(step, Timestamp::from_micros(*now)),
            RevCmd::Vault { now, op } => {
                remote.change_vault(&|t| op.apply(t), Timestamp::from_micros(*now))
            }
        }
    }

    fn engine_side(out: &RevOutput) -> EngineSide<'_> {
        (out.result.is_ok(), &out.appended, &out.context)
    }

    fn cell_invariant(_prior: &Prior, remote: &HttpDriver<'_, '_>) -> Result<(), String> {
        let records = &remote.records;
        let view = View::of(records.iter())
            .map_err(|e| format!("the roles reference cannot follow the cell's ledger: {e}"))?;
        let rev = RevView::of(records.iter())
            .map_err(|e| format!("the review reference cannot follow the cell's ledger: {e}"))?;
        check_i03(&rev)?;
        check_rcf02(&view, &rev)?;
        check_handles(&rev)?;
        check_i02_assignments(&view, &rev)?;
        check_i02(&view)?;
        check_i36_held(&view, &rev)?;
        check_one_organisation(&view, &rev)?;
        check_i36(&rev)
    }
}

/// The instant of the money machine's commands and of its prelude
/// (`fstp_domain_testkit::mc::life_model::T_EVAL`).
const MONEY_LATE: Timestamp = fstp_domain_testkit::mc::life_model::T_EVAL;

/// Whether every System command the engine in `state` has due at `now`
/// is among `cmds`. A timeline tick issues every due command, so a System
/// step of the timeline's cause runs over the cell only where it would
/// issue nothing else (lane m3/money-drivers).
fn only_due(state: &fstp_domain::State, now: Timestamp, cmds: &[Command]) -> bool {
    fstp_domain::due(state, now)
        .iter()
        .all(|c| cmds.contains(c))
}

/// The money machine over a cell (lane m3/money-drivers). Its start
/// state is built outside its commands, so the cell runs the setup of
/// [`money_setup`] before the first command, from genesis by the same
/// steps (`MoneySetup::timed_steps`). The engine side is the machine's
/// mirror ([`MoneyMachine::mirrored`]), and each command goes to the cell
/// as the step the mirror ran. Interim readings, pending Daniel:
///
/// - The contract port's EFFECTIVE fact runs through the cell's contract
///   port task in process, which stands for a completed signature.
/// - `StartExecution` runs as one tick of the cell's timeline. A reduced
///   case draws it only where the engine has no other System command
///   due ([`only_due`]).
/// - The invariants over the cell fold its ledger into the money
///   reference view, batch by batch, and check I-13, I-14, I-15 and
///   I-64 on it.
impl CellMachine for MoneyMachine {
    fn is_setup(_cmd: &MoneyCmd) -> bool {
        false
    }

    /// No money step is a tenant admin's or names a draft, so the cell
    /// derives the flags the step carries.
    fn for_cell(cmd: MoneyCmd) -> MoneyCmd {
        cmd
    }

    fn cell_admits(model: &MoneyModel, cmd: &MoneyCmd, engine: Option<&EngineView>) -> bool {
        match cmd {
            MoneyCmd::Start(p) => engine.is_some_and(|e| {
                only_due(
                    &e.state,
                    model.world.now(),
                    &[Command::StartExecution { proposal: *p }],
                )
            }),
            _ => true,
        }
    }

    fn engine_view(sut: &Option<MoneyModel>) -> Option<EngineView> {
        sut.as_ref().map(|m| EngineView {
            state: m.world.life.rev.sod.state.clone(),
            truth: m.world.truth().clone(),
        })
    }

    fn implicit_setup(&self, remote: &mut HttpDriver<'_, '_>) -> Option<Result<Seq, ExecError>> {
        let setup = money_setup();
        Some(match setup.timed_steps() {
            Ok(steps) => {
                let mut timed: Vec<(Step, Timestamp)> =
                    steps.into_iter().map(|(at, s)| (s, at)).collect();
                timed.extend(self.prelude.iter().map(|s| (s.clone(), MONEY_LATE)));
                remote.start_timed(&cell_truth(&setup.truth()), &timed)
            }
            Err(e) => Err(remote.fail(format!("the money setup steps: {e}"))),
        })
    }

    /// The step the mirror ran, at its instant. A command the mirror did
    /// not turn into a step reaches neither side.
    fn drive(
        remote: &mut HttpDriver<'_, '_>,
        _cmd: &MoneyCmd,
        out: &MoneyOutput,
    ) -> Result<Seq, ExecError> {
        match &out.step {
            Some(step) => remote.execute(step, out.at),
            None => Err(ExecError::Refused(Refusal::not_implemented())),
        }
    }

    fn engine_side(out: &MoneyOutput) -> EngineSide<'_> {
        (out.accepted, &out.appended, &out.context)
    }

    fn cell_invariant(_prior: &Prior, remote: &HttpDriver<'_, '_>) -> Result<(), String> {
        let truth = &remote.truth;
        let mut view = MoneyView::new();
        for b in remote.batches() {
            view.fold_batch(b, truth)
                .map_err(|e| format!("the money reference cannot follow the cell's ledger: {e}"))?;
        }
        check_i13(&view)?;
        check_i14(&view, truth)?;
        check_i15(&view)?;
        check_i64(&view)
    }
}

/// Whether the identity of `account` in `truth` has an exclusion or a
/// relation, which a vault account cannot carry to another person.
fn identity_has_facts(truth: &GroundTruth, account: AccountId) -> bool {
    let Some(t) = truth.identity_of(account) else {
        return true;
    };
    truth.exclusions().any(|(u, _)| u == t) || truth.relations().any(|(x, y, _)| x == t || y == t)
}

/// The ledger machine of I-23 over a cell (lane m3/money-drivers). Its
/// engine side is the machine's own run over a `MemStore`
/// ([`LedgerOutput`]). The cell runs its setup from genesis through the
/// creator path, then each command: core steps over HTTP, System steps
/// through the cell's system tasks ([`HttpDriver::system`]) and vault
/// changes through the seeded vault. Interim readings, pending Daniel:
///
/// - A step at an instant later than the cell's clock runs only when it
///   is one System command of the timeline that the engine has due then.
///   The cell's clock cannot run backwards, so a later step the engine
///   refuses, which leaves the engine's instant where it was, is left out
///   of a reduced case. A System step of the timeline at the current
///   instant runs only where the engine has nothing else due
///   ([`only_due`]).
/// - A merge or a split moves an account to another person. The vault
///   cannot move its facts, so a reduced case draws one only for an
///   account whose identity has no exclusion or relation.
/// - I-23 over the cell: the ledger before each command is a prefix of the
///   ledger after it, entry for entry, the ledger replays, and every
///   correction among its M2 records targets an earlier record of the
///   same kind.
impl CellMachine for LedgerMachine {
    fn is_setup(cmd: &LedgerCmd) -> bool {
        matches!(cmd, LedgerCmd::Setup { .. })
    }

    fn for_cell(cmd: LedgerCmd) -> LedgerCmd {
        match cmd {
            LedgerCmd::Core {
                now,
                step,
                scripted,
            } => LedgerCmd::Core {
                now,
                step: Box::new(step.iter().map(|s| cell_step(s, now.micros())).collect()),
                scripted,
            },
            other => other,
        }
    }

    fn cell_admits(model: &LedgerGhost, cmd: &LedgerCmd, engine: Option<&EngineView>) -> bool {
        match cmd {
            LedgerCmd::Setup { .. } => true,
            LedgerCmd::Vault { op, .. } => match op {
                LedgerVaultOp::Merge(a, _) | LedgerVaultOp::Split(a) => {
                    engine.is_some_and(|e| !identity_has_facts(&e.truth, *a))
                }
                LedgerVaultOp::Relate(..) | LedgerVaultOp::Exclude(_) => true,
            },
            LedgerCmd::Core { now, step, .. } => {
                let Some(e) = engine else {
                    return false;
                };
                let timeline: Vec<Command> = step
                    .iter()
                    .filter(|s| {
                        matches!(
                            s.actor,
                            Actor::System(fstp_domain::command::SystemCause::Timeline)
                        )
                    })
                    .map(|s| s.cmd.clone())
                    .collect();
                let later = model.now.is_some_and(|t| *now > t);
                if later {
                    let due = fstp_domain::due(&e.state, *now);
                    timeline.len() == step.len() && !due.is_empty() && due == timeline
                } else {
                    timeline.is_empty() || only_due(&e.state, *now, &timeline)
                }
            }
        }
    }

    fn engine_view(sut: &LedgerSut) -> Option<EngineView> {
        sut.run.as_ref().map(|r| EngineView {
            state: r.scenario.state().core.clone(),
            truth: r.scenario.truth().clone(),
        })
    }

    fn drive(
        remote: &mut HttpDriver<'_, '_>,
        cmd: &LedgerCmd,
        _out: &LedgerOutput,
    ) -> Result<Seq, ExecError> {
        match cmd {
            LedgerCmd::Setup { .. } => {
                let setup = ledger_machine_setup();
                match machine_genesis_steps(&setup) {
                    Ok(steps) => {
                        let timed: Vec<(Step, Timestamp)> =
                            steps.into_iter().map(|(at, s)| (s, at)).collect();
                        remote.start_timed(&cell_truth(&ledger_truth(&setup)), &timed)
                    }
                    Err(e) => Err(remote.fail(format!("the ledger setup steps: {e}"))),
                }
            }
            LedgerCmd::Core { now, step, .. } => {
                let mut last = Err(ExecError::Refused(Refusal::not_implemented()));
                for s in step.iter() {
                    last = remote.execute(s, *now);
                    if last.is_err() {
                        break;
                    }
                }
                last
            }
            LedgerCmd::Vault { now, op } => remote.change_vault(&|t| op.apply(t), *now),
        }
    }

    fn engine_side(out: &LedgerOutput) -> EngineSide<'_> {
        match &out.applied {
            Ok(a) => (a.accepted, &a.appended, &out.context),
            Err(_) => (false, &[], &out.context),
        }
    }

    fn cell_invariant(prior: &Prior, remote: &HttpDriver<'_, '_>) -> Result<(), String> {
        let ledger = remote.ledger();
        if ledger.get(..prior.len()) != Some(prior) {
            return Err(format!(
                "I-23: the cell's ledger of {} entries is no longer a prefix of its ledger of {} entries",
                prior.len(),
                ledger.len()
            ));
        }
        fstp_cell_core::replay(ledger)
            .map_err(|e| format!("I-23: the cell's ledger does not replay: {e:?}"))?;
        let engine: Vec<fstp_ledger::Entry<fstp_engine::Record>> = ledger
            .iter()
            .filter_map(|e| {
                e.clone()
                    .try_map_record(|_, r| match r {
                        fstp_cell_core::CellRecord::Engine(r) => Ok(r),
                        _ => Err(()),
                    })
                    .ok()
            })
            .collect();
        check_corrections(&engine)
    }
}
/// What a reduced case must show on the engine side to count: called on
/// each engine output of the first case after its setup, it answers
/// `true` once it saw it. The seed is picked on the engine alone, so the
/// witness picks commands, never an outcome on the cell.
pub type Witness<M> = Box<dyn FnMut(&<M as StateMachine>::Output) -> bool>;

/// An M2 machine in lockstep with a cell (module documentation). Each
/// command runs on the machine's own engine, which the machine checks as
/// it always does, and on the cell, which must agree with the engine.
pub struct OverHttp<'d, 'c, 'w, M: StateMachine> {
    inner: M,
    /// The cell, or none for a dry run on the engine alone, which picks
    /// the seed of a case that is long enough.
    remote: Option<RefCell<&'d mut HttpDriver<'c, 'w>>>,
    /// The cases that sent a command so far. Only the first reaches the
    /// cell; a later case of the runner runs on the engine alone.
    cases: RefCell<u32>,
    /// Set when a case starts, cleared by its first command.
    fresh: RefCell<bool>,
    /// The engine's side after the latest command.
    engine: RefCell<Option<EngineView>>,
    /// The cell's ledger before the latest command.
    prior: RefCell<Vec<fstp_ledger::Entry<fstp_cell_core::CellRecord>>>,
    /// What the first case must show on the engine side to count, if
    /// anything, and whether it showed it ([`Witness`]).
    witness: RefCell<Option<Witness<M>>>,
    witnessed: RefCell<bool>,
    /// The steps of the first case after its setup, and how many the
    /// engine accepted.
    counts: RefCell<(usize, usize)>,
    max_commands: usize,
}

impl<'d, 'c, 'w, M: CellMachine> OverHttp<'d, 'c, 'w, M> {
    /// `inner` over `remote`, with at most `max_commands` commands per
    /// case.
    pub fn new(
        inner: M,
        remote: &'d mut HttpDriver<'c, 'w>,
        max_commands: usize,
    ) -> OverHttp<'d, 'c, 'w, M> {
        OverHttp::with(inner, Some(RefCell::new(remote)), max_commands)
    }

    /// `inner` on the engine alone.
    pub fn dry(inner: M, max_commands: usize) -> OverHttp<'d, 'c, 'w, M> {
        OverHttp::with(inner, None, max_commands)
    }

    fn with(
        inner: M,
        remote: Option<RefCell<&'d mut HttpDriver<'c, 'w>>>,
        max_commands: usize,
    ) -> OverHttp<'d, 'c, 'w, M> {
        OverHttp {
            inner,
            remote,
            cases: RefCell::new(0),
            fresh: RefCell::new(false),
            engine: RefCell::new(None),
            prior: RefCell::new(Vec::new()),
            witness: RefCell::new(None),
            witnessed: RefCell::new(true),
            counts: RefCell::new((0, 0)),
            max_commands,
        }
    }

    /// The machine whose first case counts only once `witness` saw an
    /// engine output it looks for.
    pub fn with_witness(self, witness: Witness<M>) -> OverHttp<'d, 'c, 'w, M> {
        self.witness.replace(Some(witness));
        self.witnessed.replace(false);
        self
    }

    /// Whether the first case showed what its witness looks for.
    pub fn witnessed(&self) -> bool {
        *self.witnessed.borrow()
    }

    /// The steps of the first case after its setup, and how many the
    /// engine accepted.
    pub fn counts(&self) -> (usize, usize) {
        *self.counts.borrow()
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

/// Compares what the engine and the cell appended for one step.
fn compare(context: &str, engine: &[Record], cell: &[Record]) -> Result<(), String> {
    let (want, want_asked) = split_outcomes(&masked(engine));
    let (got, mut got_asked) = split_outcomes(&masked(cell));
    let asked_all = want_asked
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
            "{context}: the cell appended other M2 records\n  engine: {:?}\n  cell:   {:?}",
            masked(engine),
            masked(cell)
        ));
    }
    Ok(())
}

impl<M: CellMachine> StateMachine for OverHttp<'_, '_, '_, M> {
    type Model = M::Model;
    type Sut = M::Sut;
    type Command = M::Command;
    type Output = (M::Output, RemoteOutput);

    fn init_model(&self) -> M::Model {
        self.inner.init_model()
    }

    fn init_sut(&self) -> M::Sut {
        let sut = self.inner.init_sut();
        self.fresh.replace(true);
        self.engine.replace(M::engine_view(&sut));
        sut
    }

    fn command(&self, g: &mut Gen, model: &M::Model) -> M::Command {
        M::for_cell(self.inner.command(g, model))
    }

    fn precondition(&self, model: &M::Model, cmd: &M::Command) -> bool {
        M::cell_admits(model, cmd, self.engine.borrow().as_ref())
            && self.inner.precondition(model, cmd)
    }

    fn run(&self, sut: &mut M::Sut, cmd: &M::Command) -> (M::Output, RemoteOutput) {
        let out = self.inner.run(sut, cmd);
        self.engine.replace(M::engine_view(sut));
        let setup = M::is_setup(cmd);
        // A case counts from its first command, which is the setup of a
        // machine whose setup is a command.
        let starting = self.fresh.replace(false);
        let first = {
            let mut n = self.cases.borrow_mut();
            if starting {
                *n = n.saturating_add(1);
            }
            *n == 1
        };
        let (accepted, appended, _) = M::engine_side(&out);
        if first && !setup {
            let mut c = self.counts.borrow_mut();
            c.0 = c.0.saturating_add(1);
            if accepted {
                c.1 = c.1.saturating_add(1);
            }
            if let Some(w) = self.witness.borrow_mut().as_mut()
                && w(&out)
            {
                self.witnessed.replace(true);
            }
        }
        let Some(remote) = self.remote.as_ref().filter(|_| first) else {
            let mirror = RemoteOutput {
                accepted,
                appended: appended.to_vec(),
                fault: None,
            };
            return (out, mirror);
        };
        let mut remote = remote.borrow_mut();
        if starting
            && !setup
            && let Some(Err(e)) = self.inner.implicit_setup(&mut remote)
        {
            let _ = remote.fail(format!("the setup did not run on the cell: {e:?}"));
        }
        self.prior.replace(remote.ledger.clone());
        let before = remote.records.len();
        let result = M::drive(&mut remote, cmd, &out);
        let appended = if setup {
            Vec::new()
        } else {
            remote.records.get(before..).unwrap_or_default().to_vec()
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
        model: &M::Model,
        cmd: &M::Command,
        output: &(M::Output, RemoteOutput),
    ) -> Result<(), String> {
        let (out, remote) = output;
        self.inner.postcondition(model, cmd, out)?;
        if let Some(f) = &remote.fault {
            return Err(format!("the cell driver failed: {f}"));
        }
        let (engine, appended, context) = M::engine_side(out);
        if engine != remote.accepted {
            return Err(format!(
                "{context}: the engine {} it, the cell {} it",
                if engine { "accepts" } else { "refuses" },
                if remote.accepted {
                    "accepts"
                } else {
                    "refuses"
                }
            ));
        }
        if M::is_setup(cmd) {
            return Ok(());
        }
        compare(context, appended, &remote.appended)
    }

    fn next_state(&self, model: &mut M::Model, cmd: &M::Command) {
        self.inner.next_state(model, cmd);
    }

    fn invariant(&self, model: &M::Model, sut: &M::Sut) -> Result<(), String> {
        self.inner.invariant(model, sut)?;
        let Some(remote) = self.remote.as_ref().filter(|_| *self.cases.borrow() == 1) else {
            return Ok(());
        };
        let remote = remote.borrow();
        if remote.records.is_empty() {
            return Ok(());
        }
        M::cell_invariant(&self.prior.borrow(), &remote)
    }

    fn max_commands(&self) -> usize {
        self.max_commands.min(self.inner.max_commands())
    }
}

/// The commands of one reduced case over the cell.
pub const REDUCED_COMMANDS: usize = 24;

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
/// The suites and their machines: I-04 and I-06 run the SoD machine
/// (`SodFocus::I04`, `SodFocus::I06`), I-03 and I-35 the review machine
/// (`RevFocus::I03`, `RevFocus::I34_I35`). I-13 and I-15 run the money
/// machine on grant sequences (`MoneyFocus::GRANTS`), and I-14 on P-05
/// edits among grants (`MoneyFocus::P05`). Interim reading, pending
/// Daniel: each money suite counts only with an engine-side witness of
/// its invariant ([`grant_witness`], [`p05_witness`],
/// [`repeat_witness`]).
///
/// # Errors
///
/// [`SUITE_SEAM`] for a suite with no cell driver yet,
/// [`MACHINE_FAILED`] for a divergence, a broken invariant or a harness
/// failure, and [`CASE_TOO_SHORT`] for a case that ran too few steps.
/// The details are on standard error.
pub fn run_suite(client: &AuthClient<'_>, suite: &str) -> Result<(), NotImplemented> {
    match suite {
        "I-04" => run_machine(client, suite, || SodMachine::new(SodFocus::I04), None),
        "I-06" => run_machine(client, suite, || SodMachine::new(SodFocus::I06), None),
        "I-03" => run_machine(client, suite, || ReviewMachine::new(RevFocus::I03), None),
        "I-35" => run_machine(
            client,
            suite,
            || ReviewMachine::new(RevFocus::I34_I35),
            None,
        ),
        "I-13" => run_machine(
            client,
            suite,
            || MoneyMachine::mirrored(MoneyFocus::GRANTS),
            Some(&grant_witness),
        ),
        "I-14" => run_machine(
            client,
            suite,
            || MoneyMachine::mirrored(MoneyFocus::P05),
            Some(&p05_witness),
        ),
        "I-23" => run_machine(
            client,
            suite,
            || LedgerMachine::new(REDUCED_COMMANDS),
            Some(&correction_witness),
        ),
        "I-15" => match MoneyMachine::repeat_prelude() {
            Ok(prelude) => run_machine(
                client,
                suite,
                || MoneyMachine::mirrored_after(MoneyFocus::GRANTS, prelude.clone()),
                Some(&repeat_witness),
            ),
            Err(e) => {
                eprintln!("fstp_celltest::m2_http I-15: the prelude: {e}");
                Err(NotImplemented::new(DRIVER_FAILED))
            }
        },
        _ => Err(NotImplemented::new(SUITE_SEAM)),
    }
}

/// The proposals of the money machine whose leads share one identity
/// (`fstp_domain_testkit::r#gen::money::machine_setup`).
const SYBIL_PROPOSALS: [u128; 3] = [11, 12, 14];

/// I-13: the case determines an amount within P-04 and has one
/// determination refused.
fn grant_witness() -> Witness<MoneyMachine> {
    let (mut determined, mut refused) = (false, false);
    Box::new(move |out: &MoneyOutput| {
        let determine = matches!(
            out.step.as_ref().map(|s| &s.cmd),
            Some(Command::DetermineAmount { .. })
        );
        determined |= out
            .appended
            .iter()
            .any(|r| matches!(r, Record::AmountDetermined { .. }));
        refused |= determine && !out.accepted;
        determined && refused
    })
}

/// I-14: the case reserves under the cap and records a P-05 edit.
fn p05_witness() -> Witness<MoneyMachine> {
    let mut reserved = false;
    Box::new(move |out: &MoneyOutput| {
        reserved |= out
            .appended
            .iter()
            .any(|r| matches!(r, Record::CapReserved { .. }));
        reserved
            && out
                .appended
                .iter()
                .any(|r| matches!(r, Record::PolicyVersionRecorded { .. }))
    })
}

/// I-23: the case appends a correction: a corrected score, a new policy
/// version, or a binding ended, suspended, voided or reinstated.
fn correction_witness() -> Witness<LedgerMachine> {
    Box::new(|out: &LedgerOutput| {
        let Ok(a) = &out.applied else {
            return false;
        };
        a.accepted
            && (out.context.starts_with("CorrectScore")
                || a.appended.iter().any(|r| {
                    matches!(
                        r,
                        Record::PolicyVersionRecorded { .. }
                            | Record::BindingEnded(_)
                            | Record::BindingSuspended(_)
                            | Record::BindingVoided(_)
                            | Record::BindingReinstated(_)
                            | Record::ScoreVoided(_)
                    )
                }))
    })
}

/// I-15: the case starts with lead a's proposal granted
/// (`MoneyMachine::repeat_prelude`). It then either declines another
/// proposal of the same identity for its incomplete deliverable record,
/// or sends a grant fact of one whose amount it determined: a repeat
/// grant to the same applicant, which needs its public deliverables.
fn repeat_witness() -> Witness<MoneyMachine> {
    let mut determined: BTreeSet<ProposalId> = BTreeSet::new();
    Box::new(move |out: &MoneyOutput| {
        let repeat = |p: ProposalId| p.raw() != 11 && SYBIL_PROPOSALS.contains(&p.raw());
        for r in &out.appended {
            match r {
                Record::AmountDetermined { proposal, .. } if repeat(*proposal) => {
                    determined.insert(*proposal);
                }
                Record::NegotiationDeclined { proposal, .. } if repeat(*proposal) => return true,
                _ => {}
            }
        }
        match out.step.as_ref().map(|s| &s.cmd) {
            Some(
                Command::AcceptGrant { proposal, .. }
                | Command::ApproveGrant { proposal, .. }
                | Command::ContractFact { proposal, .. },
            ) => determined.contains(proposal),
            _ => false,
        }
    })
}

/// Runs the reduced case of the machine `make` builds over the cell of
/// `client` ([`run_suite`]), whose engine side must show what `witness`
/// looks for, if anything.
fn run_machine<M: CellMachine>(
    client: &AuthClient<'_>,
    suite: &str,
    make: impl Fn() -> M,
    witness: Option<&dyn Fn() -> Witness<M>>,
) -> Result<(), NotImplemented> {
    let name = format!("m2-suite:{suite}:reduced over the cell");
    let seed = pick_seed(&make, witness, suite, &name)?;
    let mut driver = HttpDriver::new(client);
    let mut machine = OverHttp::new(make(), &mut driver, REDUCED_COMMANDS);
    if let Some(w) = witness {
        machine = machine.with_witness(w());
    }
    let outcome = fstp_prop::run_machine(&name, case_config(seed), &machine);
    let witnessed = machine.witnessed();
    drop(machine);
    let tally = driver.tally;
    eprintln!("fstp_celltest::m2_http {name}, seed {seed}: {tally:?}");
    match outcome {
        // A case so short that it tells nothing is no pass.
        Outcome::Passed { .. }
            if !witnessed
                || !tally.setup
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
/// twice [`MIN_ACCEPTED`] accepted ones, and that shows what `witness`
/// looks for, if anything. The seed picks a case, never an outcome on the
/// cell: the cell runs the case the engine ran.
fn pick_seed<M: CellMachine>(
    make: &impl Fn() -> M,
    witness: Option<&dyn Fn() -> Witness<M>>,
    suite: &str,
    name: &str,
) -> Result<u64, NotImplemented> {
    let base = seed_of(suite);
    for i in 0..SEED_TRIES {
        let seed = base.wrapping_add(i);
        let mut dry: OverHttp<'_, '_, '_, M> = OverHttp::dry(make(), REDUCED_COMMANDS);
        if let Some(w) = witness {
            dry = dry.with_witness(w());
        }
        let outcome = fstp_prop::run_machine(name, case_config(seed), &dry);
        let (steps, accepted) = dry.counts();
        if outcome.is_passed()
            && dry.witnessed()
            && steps >= MIN_STEPS.saturating_mul(2)
            && accepted >= MIN_ACCEPTED.saturating_mul(2)
        {
            return Ok(seed);
        }
    }
    Err(NotImplemented::new(CASE_TOO_SHORT))
}

/// A path step names a state outside `paths::STATES`, or the path could
/// not be built.
pub const PATH_SEAM: &str = "fstp_celltest::m2_http: the m2:path-to step names a state that crate::mc::driver_model::paths does not reach (draft, submitted, stage1, stage2, ranked, irc-review, negotiation)";

/// The cell refused a step of an M2 path, or the driver failed one. Not a
/// seam: the step is on standard error.
pub const PATH_REFUSED: &str = "fstp_celltest::m2_http: the cell did not take a step of the M2 path (the step and the cell's reply are on standard error)";

/// `m2:path-to-ranked-with-tie` continues the cell of `m2:path-to-submitted`
/// only: it refuses on a cell where PR1 is not SUBMITTED.
pub const TIE_PATH_SEAM: &str = "fstp_celltest::m2_http: m2:path-to-ranked-with-tie continues a cell on which m2:path-to-submitted left PR1 in SUBMITTED, and this cell has no such PR1";

/// `m2:path-to-ranked-with-tie` (lane m3/cycle-steps, NOTE 6): on a cell
/// where `m2:path-to-submitted` left PR1 SUBMITTED, the steps of
/// `crate::mc::driver_model::paths::tie_rest` run over
/// `paths::tie_truth`, so PR1 and L2's PR2 end RANKED with one score. The
/// path is first replayed on the M2 domain from genesis, so a path the
/// domain refuses is a [`PATH_SEAM`], never a cell refusal.
fn run_tie_path(client: &AuthClient<'_>, step: &str) -> Result<(), NotImplemented> {
    use crate::mc::driver_model::paths;
    use fstp_domain::rules::StateTag;
    let pr1 = ProposalId::from_raw(fstp_domain_testkit::r#gen::review::PR1.raw());
    let submitted = client
        .cell()
        .ledger()
        .ok()
        .and_then(|l| fstp_cell_core::replay(&l).ok())
        .and_then(|s| fstp_domain::view::proposal_state(&s.engine().core, pr1))
        == Some(StateTag::Submitted);
    if !submitted {
        return Err(NotImplemented::new(TIE_PATH_SEAM));
    }
    let rest = paths::tie_rest().map_err(|e| {
        eprintln!("fstp_celltest::m2_http {step}: {e}");
        NotImplemented::new(PATH_SEAM)
    })?;
    let mut whole = paths::to(StateTag::Submitted).map_err(|e| {
        eprintln!("fstp_celltest::m2_http {step}: {e}");
        NotImplemented::new(PATH_SEAM)
    })?;
    whole.extend(rest.iter().cloned());
    if let Err(e) = paths::check_with_domain(&whole, paths::tie_truth()) {
        eprintln!("fstp_celltest::m2_http {step}: the M2 domain refused the path: {e}");
        return Err(NotImplemented::new(PATH_SEAM));
    }
    let timed: Vec<(Step, Timestamp)> = rest.into_iter().map(|p| (p.step, p.at)).collect();
    let mut driver = HttpDriver::new(client);
    match driver.continue_timed(&paths::tie_truth(), &timed) {
        Ok(_) => {
            // Both proposals must end RANKED on the cell, as on the domain.
            let pr2 = ProposalId::from_raw(fstp_domain_testkit::r#gen::review::PR2.raw());
            let states = client
                .cell()
                .ledger()
                .ok()
                .and_then(|l| fstp_cell_core::replay(&l).ok())
                .map(|s| {
                    [pr1, pr2].map(|p| fstp_domain::view::proposal_state(&s.engine().core, p))
                });
            if states == Some([Some(StateTag::Ranked); 2]) {
                return Ok(());
            }
            eprintln!("fstp_celltest::m2_http {step}: PR1 and PR2 ended in {states:?}");
            Err(NotImplemented::new(PATH_REFUSED))
        }
        Err(e) => {
            eprintln!(
                "fstp_celltest::m2_http {step}: {e:?}; driver fault: {:?}",
                driver.fault()
            );
            Err(NotImplemented::new(PATH_REFUSED))
        }
    }
}

/// The state a path step names.
fn path_state(name: &str) -> Option<fstp_domain::rules::StateTag> {
    use fstp_domain::rules::StateTag;
    Some(match name {
        "draft" => StateTag::Draft,
        "submitted" => StateTag::Submitted,
        "stage1" => StateTag::Stage1,
        "stage2" => StateTag::Stage2,
        "ranked" => StateTag::Ranked,
        "irc-review" => StateTag::IrcReview,
        "negotiation" => StateTag::Negotiation,
        _ => return None,
    })
}

/// Runs an `m2:` step of a cycle script over the cell of `client`:
///
/// - `m2:random-commands` runs random M2 commands as the reduced case of
///   the review machine, whose Judging staff assign, declare and read
///   ([`run_suite`] of I-03).
/// - `m2:path-to-<state>` runs the path of
///   `crate::mc::driver_model::paths` that takes PR1 to `<state>`, over
///   the path's vault with L1 an adult (`paths::truth(true)`), from a
///   cell with no programme yet. Every step must be taken.
///
/// # Errors
///
/// [`PATH_SEAM`], [`PATH_REFUSED`], the errors of [`run_suite`], or
/// `crate::cycle::M2_SETUP_SEAM` for another `m2:` step.
pub fn run_m2_step(client: &AuthClient<'_>, step: &str) -> Result<(), NotImplemented> {
    use crate::mc::driver_model::paths;
    if step == "m2:random-commands" {
        return run_suite(client, "I-03");
    }
    let Some(name) = step.strip_prefix("m2:path-to-") else {
        return Err(NotImplemented::new(crate::cycle::M2_SETUP_SEAM));
    };
    if name == "ranked-with-tie" {
        return run_tie_path(client, step);
    }
    let Some(target) = path_state(name) else {
        return Err(NotImplemented::new(crate::cycle::M2_SETUP_SEAM));
    };
    let path = paths::to(target).map_err(|e| {
        eprintln!("fstp_celltest::m2_http {step}: {e}");
        NotImplemented::new(PATH_SEAM)
    })?;
    let timed: Vec<(Step, Timestamp)> = path.into_iter().map(|p| (p.step, p.at)).collect();
    let mut driver = HttpDriver::new(client);
    match driver.start_timed(&paths::truth(true), &timed) {
        Ok(_) => Ok(()),
        Err(e) => {
            eprintln!(
                "fstp_celltest::m2_http {step}: {e:?}; driver fault: {:?}",
                driver.fault()
            );
            Err(NotImplemented::new(PATH_REFUSED))
        }
    }
}
