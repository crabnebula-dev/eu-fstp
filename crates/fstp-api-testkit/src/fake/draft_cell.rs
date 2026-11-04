//! A production engine for one draft, rebuilt from its ledger (lane
//! m4wire). The production adapters of M-ACTIVATE and M-IMPORT
//! (`mc/activate_model.rs`, `mc/import_model.rs`) keep a draft as its
//! ledger and vault facts, so their state has equality and a hash. Each
//! step opens [`DraftCell`] over them: the production driver
//! `fstp_engine::Engine` with `CreatorDecider` over the cell's creator
//! environment (`shell.rs`), the synthetic vault, the recording prober
//! and the recorder of vault answers.
//!
//! [`forged_open`] appends the entry a correct `OpenDraft` appends, as the
//! engine's own M4 envelope tests do. Only the adapters whose subject is a
//! guard or a fold after the opening use it. Every adapter that runs a
//! draft through its plan opens it with `OpenDraft` through the engine.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use fstp_api_core::port::{ProbeKind, ProbeOutcome};
use fstp_creator::{CreatorInputs, CreatorRecord, PortPresence, Theme};
use fstp_domain::command::{Actor, Ctx, Via};
use fstp_domain::id::{AccountId, CommandId, PolicyVersionId, ProgrammeId};
use fstp_domain::oracle::{Answers, Query};
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::vault::{GroundTruth, IdentityTag};
use fstp_engine::{Command, CreatorDecider, CreatorEnvironment, Engine, EngineState, Record};
use fstp_ledger::{Entry, MemStore, RecordStore, Seq};

use super::shell::CellEnvironment;
use super::vault::Q35Known;
use super::{FakeProber, FakeVault, FakeVaultAudit};

/// The driver of a draft cell.
pub type DraftEngine = Engine<MemStore<Record>, super::CellOracle, CreatorDecider<CellEnvironment>>;

/// One account of a draft's vault: its person, if the vault knows one,
/// and whether it is verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VaultAccount {
    /// The account.
    pub account: AccountId,
    /// The synthetic person of the account.
    pub person: Option<u64>,
    /// Whether the vault verifies it.
    pub verified: bool,
}

/// The synthetic vault facts of `accounts`.
pub fn truth_of(accounts: &[VaultAccount]) -> GroundTruth {
    let mut t = GroundTruth::new();
    for a in accounts {
        if let Some(p) = a.person {
            t.set_identity(a.account, IdentityTag::new(p));
        }
        if a.verified {
            t.verify(a.account);
        }
    }
    t
}

/// The shell facts of a draft cell that a test sets (I-66, design 3.2
/// and 8.4).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DraftShell {
    /// Whether the shipped profiles stand in for the synthetic ones, so
    /// the legal wording is pending (Q6).
    pub shipped: bool,
    /// The theme the cell shows.
    pub theme: Theme,
    /// The ports the cell has.
    pub ports: PortPresence,
    /// What the vault knows for the Q35 answers, or `None` for the fixed
    /// answers of the fake vault.
    pub q35: Option<Q35Known>,
}

impl Default for DraftShell {
    /// The fake cell's shell: the synthetic wording, the M4 default theme,
    /// a pre-check provider, no score tools and fixed Q35 answers.
    fn default() -> DraftShell {
        DraftShell {
            shipped: false,
            theme: Theme::m4_default(),
            ports: PortPresence {
                precheck: true,
                score_tools: false,
            },
            q35: None,
        }
    }
}

/// The production engine of one draft and the fakes beside it.
pub struct DraftCell {
    /// The driver.
    pub engine: DraftEngine,
    /// The synthetic vault.
    pub vault: FakeVault,
    /// The recording prober.
    pub prober: FakeProber,
    /// The recorder of vault answers.
    pub audit: FakeVaultAudit,
}

impl DraftCell {
    /// The cell over `store` and `truth`, with the attested admin set
    /// `admins`, the probe outcomes `probes`, where `None` is a probe with
    /// no prober (Q5), and, when `shipped` holds, the shipped profiles in
    /// place of the synthetic wording.
    pub fn open(
        store: MemStore<Record>,
        truth: GroundTruth,
        admins: BTreeSet<AccountId>,
        probes: &BTreeMap<ProbeKind, Option<ProbeOutcome>>,
        shipped: bool,
    ) -> Result<DraftCell, String> {
        DraftCell::open_with_theme(store, truth, admins, probes, shipped, Theme::m4_default())
    }

    /// The cell of [`DraftCell::open`], whose environment shows `theme`
    /// in place of the M4 default, as a test seeds a theme fault (I-66,
    /// design 8.4).
    pub fn open_with_theme(
        store: MemStore<Record>,
        truth: GroundTruth,
        admins: BTreeSet<AccountId>,
        probes: &BTreeMap<ProbeKind, Option<ProbeOutcome>>,
        shipped: bool,
        theme: Theme,
    ) -> Result<DraftCell, String> {
        let shell = DraftShell {
            shipped,
            theme,
            ..DraftShell::default()
        };
        DraftCell::open_with_shell(store, truth, admins, probes, &shell)
    }

    /// The cell of [`DraftCell::open`] with the shell facts of `shell`.
    pub fn open_with_shell(
        store: MemStore<Record>,
        truth: GroundTruth,
        admins: BTreeSet<AccountId>,
        probes: &BTreeMap<ProbeKind, Option<ProbeOutcome>>,
        shell: &DraftShell,
    ) -> Result<DraftCell, String> {
        let vault = FakeVault::new(truth);
        vault.set_q35_known(shell.q35.clone());
        let prober = FakeProber::default();
        for (k, o) in probes {
            match o {
                Some(o) => prober.set(*k, *o),
                None => prober.set_absent(*k),
            }
        }
        let audit = FakeVaultAudit::default();
        let env = CellEnvironment::new(
            &vault,
            prober.clone(),
            Arc::new(Mutex::new(admins)),
            audit.clone(),
        )
        .with_shipped_profiles(shell.shipped)
        .with_theme(shell.theme.clone())
        .with_ports(shell.ports);
        let engine = Engine::open_with(store, vault.oracle(), CreatorDecider(env))
            .map_err(|e| format!("open the draft cell: {e:?}"))?;
        Ok(DraftCell {
            engine,
            vault,
            prober,
            audit,
        })
    }

    /// The engine state.
    pub fn state(&self) -> &EngineState {
        self.engine.state()
    }

    /// Runs `cmd` with `ctx` on the driver.
    pub fn execute(&mut self, cmd: Command, ctx: Ctx) -> Result<Seq, fstp_engine::ExecError> {
        self.engine.execute(cmd, ctx)
    }

    /// The shell facts a decision on `cmd` by `ctx` reads, with the parts
    /// the engine owns filled as the engine fills them: the count of
    /// unresolved imports and the builders' `IsVerified` answers.
    pub fn inputs(
        &self,
        cmd: &fstp_creator::CreatorCommand,
        ctx: &Ctx,
        approver: Option<AccountId>,
    ) -> CreatorInputs {
        let state = self.engine.state();
        let programme = cmd.programme();
        let mut inputs = self.engine.decider().0.creator_inputs(state, cmd, ctx);
        inputs.unresolved_imports = state
            .import
            .unresolved(fstp_import::ProgrammeRef::from_raw(programme.raw()));
        let q = fstp_creator::vault_questions(&state.creator, programme, approver);
        let truth = self.vault.truth();
        for a in &q.is_verified {
            let _ = inputs
                .vault
                .is_verified
                .insert(*a, truth.holds(&Query::IsVerified { account: *a }));
        }
        if let Some((subject, others)) = q.same_identity {
            let holds = truth.holds(&Query::SameIdentityAsAny { subject, others });
            let _ = inputs.vault.same_identity.insert(subject, holds);
        }
        inputs
    }

    /// The store, giving up the cell.
    pub fn into_store(self) -> MemStore<Record> {
        let (store, _, _) = self.engine.into_parts();
        store
    }
}

/// Every entry of `store`, in order.
pub fn entries(store: &MemStore<Record>) -> Result<Vec<Entry<Record>>, String> {
    let mut out = Vec::new();
    store
        .read(Seq::ZERO, usize::MAX, &mut out)
        .map_err(|e| format!("read the draft ledger: {e:?}"))?;
    Ok(out)
}

/// The context of a command by `actor` at `now` with command number `n`,
/// attested as a tenant admin when `admins` holds it.
pub fn ctx(actor: AccountId, now: Timestamp, n: u32, admins: &BTreeSet<AccountId>) -> Ctx {
    let mut b = *b"draft-cell:\0\0\0\0\0";
    for (slot, x) in b.iter_mut().skip(12).zip(n.to_be_bytes()) {
        *slot = x;
    }
    Ctx {
        now,
        actor: Actor::Account(actor),
        command: CommandId::from_bytes(b),
        via: Via::Web,
        tenant_admin: admins.contains(&actor),
        second_tenant_admin: None,
        binds_tenant_admin: false,
    }
}

/// Appends to `store` the entry a correct `OpenDraft` of `programme` by
/// `opener` at `at` appends (module documentation): the creator's
/// `DraftOpened` and the records of the core `CreateProgramme` of the
/// compiled SuperSAFE fixture, decided by `fstp_domain::decide` on the
/// replay of `store`.
pub fn forged_open(
    store: &mut MemStore<Record>,
    programme: ProgrammeId,
    opener: AccountId,
    at: Timestamp,
) -> Result<(), String> {
    let state = fstp_engine::replay(&entries(store)?).map_err(|e| format!("replay: {e:?}"))?;
    let fixture = fstp_programme::supersafe_fixture().map_err(|e| format!("fixture: {e}"))?;
    let policy = fstp_programme::compile(
        &fixture.spec,
        &fstp_programme::FunderProfile::horizon_europe(),
        fstp_programme::CompileIds::new(
            programme,
            PolicyVersionId::from_raw(programme.raw()),
            None,
        ),
    )
    .map_err(|e| format!("compile: {e}"))?
    .policy;
    let profile = policy.frozen.p53.clone();
    let mut c = ctx(opener, at, 0, &[opener].into_iter().collect());
    c.command = CommandId::from_bytes(*b"draft-cell:open\0");
    let core = fstp_domain::decide(
        &state.core,
        &fstp_domain::Command::CreateProgramme {
            policy: Box::new(policy),
        },
        &c,
        &Answers::new(),
    )
    .map_err(|r| format!("CreateProgramme: {r:?}"))?;
    let mut records = vec![Record::Creator(CreatorRecord::DraftOpened {
        programme,
        profile,
        by: opener,
    })];
    records.extend(core.into_iter().map(Record::Core));
    let head = store.head();
    store
        .append(head, at.micros(), c.command.bytes(), records)
        .map_err(|e| format!("append the opening: {e:?}"))?;
    Ok(())
}

/// The SuperSAFE fixture spec with its P-09 wording stored as synthetic
/// `TextRef`s, as a ledger body must hold it (ADR-007). A save refuses
/// P-09 wording that is still inline, so every adapter that saves the
/// whole fixture saves this spec.
pub fn synthetic_spec() -> Result<fstp_programme::ProgrammeSpec, String> {
    let item = |id: u8| {
        let hex: String = std::iter::repeat_n(format!("{id:02x}"), 32).collect();
        format!("{{\"id\":\"{id}\",\"text\":{{\"digest\":\"{hex}\",\"text\":\"10{id}\"}}}}")
    };
    let p09 = format!("[{},{},{}]", item(1), item(2), item(3));
    let mut spec = fstp_programme::supersafe_fixture()
        .map_err(|e| format!("fixture: {e}"))?
        .spec;
    let value = fstp_programme::decode_field_value(fstp_programme::FieldId::P09, p09.as_bytes())
        .map_err(|e| format!("P-09: {e:?}"))?;
    spec.set(value);
    Ok(spec)
}

/// The manual field edit of `value`, with the SHA-256 of its canonical
/// text as its digest.
pub fn manual_edit(value: fstp_programme::FieldValue) -> fstp_creator::FieldEdit {
    let canonical = fstp_programme::encode_field_value(&value);
    fstp_creator::FieldEdit {
        field: value.field(),
        value,
        digest: fstp_creator::ValueDigest::new(fstp_domain::id::ContentDigest::from_bytes(
            fstp_crypto::sha256(canonical.as_bytes()),
        )),
        provenance: fstp_creator::Provenance::Manual,
    }
}

/// Holds again, on `cell`, the value of every field the draft of
/// `programme` saved, from `values` by field and digest, as the shell resolves its
/// value store after a replay (`fstp_engine` driver, "Held values"). A
/// rebuilt cell holds no saved value until then, so the checks that read
/// one fail closed.
pub fn hold_saved(
    cell: &mut DraftCell,
    programme: ProgrammeId,
    values: &BTreeMap<
        (fstp_programme::FieldId, fstp_creator::ValueDigest),
        fstp_programme::FieldValue,
    >,
) {
    let saved: Vec<(fstp_programme::FieldId, fstp_creator::ValueDigest)> = cell
        .state()
        .creator
        .draft(programme)
        .map(|d| {
            d.fields()
                .iter()
                .map(|(f, (digest, _))| (*f, *digest))
                .collect()
        })
        .unwrap_or_default();
    for (field, digest) in saved {
        if let Some(v) = values.get(&(field, digest)) {
            let _ = cell.engine.hold_value(programme, field, digest, v.clone());
        }
    }
}
