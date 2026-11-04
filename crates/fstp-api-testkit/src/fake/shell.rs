//! The shell of the fake cell beside its engine port (M4 design sections
//! 3.2 and 3.3; lane m4wire).
//!
//! - [`CellEnvironment`] is the `fstp_engine::CreatorEnvironment` of the
//!   fake engine port. It answers the shell facts of a creator decision
//!   from the synthetic vault and the fixture: the probes of the
//!   recording prober, the live SoD previews, the Q35 answers of the
//!   synthetic vault, the attested tenant admin set, the ports present,
//!   the default theme and the synthetic legal-wording profile. The API
//!   core reads the same facts through `AsyncEngine::creator_inputs`.
//! - [`ImportShell`] runs the proposer once an upload is registered and
//!   records its proposals as the system (`ImportCommand::RecordProposals`),
//!   as the shell does in design 3.3 step 2.
//!
//! # Readings, interim, pending Daniel
//!
//! - The probes run, and are recorded by the prober, only for an executed
//!   approval (design 3.2 "Fresh probes"). Its dry run, every other
//!   decision and every read peek at the outcome the next probe would
//!   give, so one approval runs each probe once.
//! - A SoD preview runs `fstp_domain::roles::preview_grant` for each
//!   target of `fstp_creator::preview_targets`, as the draft's opener
//!   would grant it at the instant of the decision. The grant carries a
//!   placeholder binding id and confidentiality reference, which no SoD
//!   guard reads. Every vault answer is recorded as a query digest and
//!   its bit (`overview.md` NOTE 5). A preview whose answer cannot be
//!   recorded has no outcome, so its invitation fails closed as
//!   `InviteeRefused`.
//! - The Q35 answers come from the vault port, through the
//!   `classes_defined_now` and `proximity_lists_declared_now` answers of
//!   `FakeVault`, each recorded as a query digest and its bit (NOTE 5). The classes are
//!   the live P-13 of the draft's head policy version. The partner
//!   organisations are the keys of its live P-38. A vault that is down,
//!   or an answer that cannot be recorded, gives no answer, so the check
//!   fails closed.
//! - The theme is the M4 default unless a test seeds a theme fault
//!   through [`CellEnvironment::with_theme`] (design 3.2 and 8.4).
//! - The cell has a pre-check provider (`FakePrecheck`) and no score
//!   tools.
//! - The proposer is the fixture-driven `fstp_import::FakeProposer` over
//!   the entries of [`annex_entries`] whose evidence the document holds.
//!   The proposal ids derive from the document id. The blob holds the
//!   text digest's salt before the uploaded bytes, and a text that does
//!   not match its registered digest proposes nothing. The value texts
//!   go to the fake text store, each with a fresh salt stored inside it
//!   and a digest keyed with that salt (`fstp_api_core::salted`).
//!   `RecordProposals` runs with the `Timeline` system cause, as the
//!   engine's own tests issue it, since the domain names no import cause.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use fstp_api_core::port::{
    BlobOwner, BlobRef, ExclusionClasses, ProbeKind as PortProbe, ProbeOutcome as PortOutcome,
    QueryDigest, TextClass, TextOwner,
};
use fstp_api_core::salted;
use fstp_creator::{
    CreatorCommand, CreatorInputs, PortPresence, PreviewOutcome, ProbeKind, ProbeOutcome, ProbeSet,
    SodPreview, Theme, VaultChecks,
};
use fstp_domain::command::{Actor, Ctx, SystemCause, Via};
use fstp_domain::id::{
    AccountId, BindingId, CommandId, ContentDigest, OrganisationId, TextId, TextRef,
};
use fstp_domain::oracle::{Answers, OracleDown, Query};
use fstp_domain::policy::FunderProfileRef;
use fstp_engine::{CreatorEnvironment, EngineState, IdentityOracle};
use fstp_guide::{FunderProfile, ProfileSource};
use fstp_import::{
    BindIds, FakeProposer, FixtureEntry, ImportCommand, ImportConfig, ImportConfigId,
    ImportDocument, ImportLimits, ImportProposalId, Proposer, SaltedDigest, UntrustedValue,
    ValueTextId, ValueTextRef,
};
use fstp_programme::FieldId;

use super::{CellOracle, FakeBlobs, FakeProber, FakeTexts, FakeVault, FakeVaultAudit, lock};
use crate::profiles::SyntheticProfiles;

/// The creator environment of the fake engine port (module
/// documentation). Cloning shares the prober, the admin set and the
/// audit sink.
#[derive(Clone, Debug)]
pub struct CellEnvironment {
    oracle: CellOracle,
    /// The vault port, for the Q35 answers. `None` for a detached
    /// environment, so both Q35 checks fail closed.
    vault: Option<FakeVault>,
    prober: Option<FakeProber>,
    admins: Arc<Mutex<BTreeSet<AccountId>>>,
    vault_audit: Option<FakeVaultAudit>,
    profiles: SyntheticProfiles,
    /// Whether the shipped profiles stand in for the synthetic ones, so
    /// the legal wording is pending (Q6).
    shipped: bool,
    /// The theme the cell shows: the M4 default unless a test seeds a
    /// theme fault (I-66, design 8.4).
    theme: Theme,
    /// The ports the cell has: a pre-check provider and no score tools
    /// unless a test sets otherwise (I-66, design 3.2).
    ports: PortPresence,
    /// Whether the decisions are dry runs, which peek at the probes and
    /// never run them (design 3.2 "Fresh probes").
    dry: bool,
}

impl CellEnvironment {
    /// The environment of a cell: its vault, prober, attested admin set
    /// and the recorder of vault answers.
    pub fn new(
        vault: &FakeVault,
        prober: FakeProber,
        admins: Arc<Mutex<BTreeSet<AccountId>>>,
        vault_audit: FakeVaultAudit,
    ) -> CellEnvironment {
        CellEnvironment {
            oracle: vault.oracle(),
            vault: Some(vault.clone()),
            prober: Some(prober),
            admins,
            vault_audit: Some(vault_audit),
            profiles: SyntheticProfiles::default(),
            shipped: false,
            theme: Theme::m4_default(),
            ports: PortPresence {
                precheck: true,
                score_tools: false,
            },
            dry: false,
        }
    }

    /// An environment with no prober, no vault port and no recorder of
    /// vault answers, over the admin set `admins`. Every probe is absent
    /// and the Q35 answers are missing, so those checks fail closed, and
    /// no SoD preview has an outcome.
    pub fn detached(oracle: CellOracle, admins: BTreeSet<AccountId>) -> CellEnvironment {
        CellEnvironment {
            oracle,
            vault: None,
            prober: None,
            admins: Arc::new(Mutex::new(admins)),
            vault_audit: None,
            profiles: SyntheticProfiles::default(),
            shipped: false,
            theme: Theme::m4_default(),
            ports: PortPresence {
                precheck: true,
                score_tools: false,
            },
            dry: false,
        }
    }

    /// The same environment over the shipped profiles, whose legal
    /// wording is pending (Q6), when `shipped` holds.
    pub fn with_shipped_profiles(mut self, shipped: bool) -> CellEnvironment {
        self.shipped = shipped;
        self
    }

    /// The same environment showing `theme` in place of the M4 default,
    /// as a test seeds a theme fault (I-66, design 8.4).
    pub fn with_theme(mut self, theme: Theme) -> CellEnvironment {
        self.theme = theme;
        self
    }

    /// The same environment with the ports `ports`, as a test seeds a
    /// check that reads a port: `PrecheckUnavailable` without a pre-check
    /// provider, `AiActReassessment` with score tools (I-66, design 3.2).
    pub fn with_ports(mut self, ports: PortPresence) -> CellEnvironment {
        self.ports = ports;
        self
    }

    /// Marks the decisions of this environment as dry runs, or not. A dry
    /// run peeks at the probes and never runs them, so an approval runs
    /// them once, at its execution.
    pub fn set_dry(&mut self, dry: bool) {
        self.dry = dry;
    }

    /// Every vault answer the environment obtained, in order: the answers
    /// of its SoD previews.
    pub fn asks(&self) -> Vec<(Query, fstp_domain::oracle::Answer)> {
        self.oracle.asks()
    }

    /// The probe results of `cmd`: run for an executed approval, peeked
    /// for its dry run and for everything else.
    fn probes(&self, cmd: &CreatorCommand) -> ProbeSet {
        let Some(prober) = &self.prober else {
            return ProbeSet::absent();
        };
        let run = !self.dry && matches!(cmd, CreatorCommand::ApproveActivation { .. });
        let mut set = ProbeSet::absent();
        for p in ProbeKind::ALL {
            let port = match p {
                ProbeKind::Channel => PortProbe::Channel,
                ProbeKind::SendingDomain => PortProbe::SendingDomain,
                ProbeKind::Inference => PortProbe::Inference,
            };
            if prober.is_absent(port) {
                set.set(p, ProbeOutcome::Absent);
                continue;
            }
            let outcome = if run {
                prober.run(port)
            } else {
                prober.outcome(port)
            };
            set.set(
                p,
                match outcome {
                    PortOutcome::Pass => ProbeOutcome::Pass,
                    PortOutcome::Fail => ProbeOutcome::Fail,
                },
            );
        }
        set
    }

    /// The live SoD previews of the draft of `cmd` (module documentation).
    fn previews(&self, state: &EngineState, cmd: &CreatorCommand, ctx: &Ctx) -> SodPreview {
        let mut out = SodPreview::default();
        let programme = cmd.programme();
        let (Some(draft), Some(audit)) = (state.creator.draft(programme), &self.vault_audit) else {
            return out;
        };
        let granter = Ctx {
            actor: Actor::Account(draft.opener()),
            tenant_admin: true,
            second_tenant_admin: None,
            binds_tenant_admin: false,
            ..*ctx
        };
        for t in fstp_creator::preview_targets(&state.creator, programme) {
            let grant = fstp_domain::Command::GrantRole {
                binding: BindingId::from_raw(0),
                account: t.account,
                programme,
                role: t.role,
                start: ctx.now,
                second_admin: None,
                confidentiality: Some(TextRef::new(
                    TextId::from_raw(0),
                    ContentDigest::from_bytes([0; 32]),
                )),
                organisation: t.organisation,
                end: None,
            };
            let granter = Ctx {
                binds_tenant_admin: lock(&self.admins).contains(&t.account),
                ..granter
            };
            let outcome =
                match fstp_domain::roles::preview_grant_queries(&state.core, &grant, &granter) {
                    Err(r) => Some(PreviewOutcome::Refused(r.rule)),
                    Ok(queries) => self.answers(audit, &queries).map(|answers| {
                        match fstp_domain::roles::preview_grant(
                            &state.core,
                            &grant,
                            &granter,
                            &answers,
                        ) {
                            Ok(()) => PreviewOutcome::Admitted,
                            Err(r) => PreviewOutcome::Refused(r.rule),
                        }
                    }),
                };
            if let Some(o) = outcome {
                let _ = out.outcomes.insert(t.invitation, o);
            }
        }
        out
    }

    /// The answers to `queries`, each recorded. `None` when the vault
    /// cannot answer or an answer cannot be recorded (fail closed).
    fn answers(&self, audit: &FakeVaultAudit, queries: &[Query]) -> Option<Answers> {
        let mut answers = Answers::new();
        for q in queries {
            let a = self.oracle.ask(q).ok()?;
            audit
                .record_now(QueryDigest(a.digest.bytes()), a.holds, a.epoch)
                .ok()?;
            answers.insert(q.clone(), a);
        }
        Some(answers)
    }

    /// The Q35 answers for the draft of `cmd`, each asked of the vault
    /// port and recorded (module documentation). An answer the vault
    /// does not give, or that cannot be recorded, is `None`, which fails
    /// its check closed.
    fn q35(&self, state: &EngineState, cmd: &CreatorCommand) -> (Option<bool>, Option<bool>) {
        let programme = cmd.programme();
        let (Some(vault), Some(audit), Some(policy)) = (
            &self.vault,
            &self.vault_audit,
            state.core.policy().head(programme),
        ) else {
            return (None, None);
        };
        let record = |a: Result<fstp_domain::oracle::Answer, OracleDown>| {
            let a = a.ok()?;
            audit
                .record_now(QueryDigest(a.digest.bytes()), a.holds, a.epoch)
                .ok()?;
            Some(a.holds)
        };
        let classes = ExclusionClasses(policy.live.p13.0.clone());
        let orgs: BTreeSet<OrganisationId> = policy.live.p38.0.keys().copied().collect();
        (
            record(vault.classes_defined_now(programme, &classes)),
            record(vault.proximity_lists_declared_now(programme, &orgs)),
        )
    }

    /// The funder profile of the draft of `cmd`, or of the profile an
    /// opening names.
    fn profile(&self, state: &EngineState, cmd: &CreatorCommand) -> Option<FunderProfile> {
        let reference = match cmd {
            CreatorCommand::OpenDraft { profile, .. } => profile.clone(),
            other => state.creator.draft(other.programme())?.profile().clone(),
        };
        let name = profile_name(&reference)?;
        if self.shipped {
            return fstp_guide::ShippedProfiles.profile(&name).ok();
        }
        self.profiles.profile(&name).ok()
    }
}

/// The profile name of a P-53 reference, `{"profile": name, "version": n}`.
fn profile_name(p: &FunderProfileRef) -> Option<String> {
    let v = fstp_json::parse(p.0.as_str().as_bytes()).ok()?;
    v.get("profile")?.as_str().map(str::to_owned)
}

impl CreatorEnvironment for CellEnvironment {
    fn creator_inputs(
        &self,
        state: &EngineState,
        cmd: &CreatorCommand,
        ctx: &Ctx,
    ) -> CreatorInputs {
        let (exclusion_classes_known, proximity_lists_declared) = self.q35(state, cmd);
        CreatorInputs {
            // The engine replaces it with the import store's count.
            unresolved_imports: 0,
            probes: self.probes(cmd),
            sod: self.previews(state, cmd, ctx),
            vault: VaultChecks {
                // The engine replaces both with the answers it obtained.
                is_verified: Default::default(),
                same_identity: Default::default(),
                exclusion_classes_known,
                proximity_lists_declared,
            },
            tenant_admins: lock(&self.admins).clone(),
            ports: self.ports,
            theme: self.theme.clone(),
            profile: self.profile(state, cmd),
        }
    }
}

// ---------------------------------------------------------------------------
// The import shell
// ---------------------------------------------------------------------------

/// The proposer's fixture: values a synthetic annex states, each with the
/// text that states it (module documentation). The texts are those of
/// the annex of `fake/creator_wire_tests.rs` and of
/// `e2e/creator/fixtures/synthetic-annex.md`.
pub fn annex_entries() -> Vec<FixtureEntry> {
    let entry = |field: FieldId, value: &str, evidence: &str| {
        UntrustedValue::new(&fstp_json::Value::from(value))
            .ok()
            .map(|value| FixtureEntry {
                field,
                value,
                evidence: evidence.to_owned(),
            })
    };
    [
        entry(
            FieldId::ActionNumber,
            "101000001",
            "Action number: 101000001",
        ),
        entry(
            FieldId::P05,
            "400000.00",
            "Maximum per recipient: EUR 400000.00",
        ),
        entry(
            FieldId::ActionNumber,
            "SYNTHETIC-111111111",
            "Action number: SYNTHETIC-111111111",
        ),
        entry(
            FieldId::ProgrammeScope,
            "open source tools for the synthetic e2e programme",
            "Scope: open source tools for the synthetic e2e programme.",
        ),
        entry(FieldId::P05, "450000.00", "EUR 450000.00"),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// What the shell needs to run the proposer: the stores of the cell.
#[derive(Clone, Debug)]
pub struct ImportShell {
    blobs: FakeBlobs,
    texts: FakeTexts,
}

impl ImportShell {
    /// The import shell over the cell's blob and text stores.
    pub fn new(blobs: FakeBlobs, texts: FakeTexts) -> ImportShell {
        ImportShell { blobs, texts }
    }

    /// The `RecordProposals` of a registered document, with the context
    /// it runs under, or `None` when the proposer proposes nothing.
    pub fn proposals(&self, doc: &ImportDocument, ctx: &Ctx) -> Option<(ImportCommand, Ctx)> {
        let programme = fstp_domain::id::ProgrammeId::from_raw(doc.programme.raw());
        let stored = self
            .blobs
            .peek(BlobOwner::Programme(programme), BlobRef(doc.blob.bytes()))?;
        // The blob holds the digest's salt before the uploaded bytes
        // (`fstp_api_core::salted`). A text that does not match its
        // registered digest proposes nothing.
        let (salt, bytes) = salted::split(&stored)?;
        let limits = ImportLimits::standard().ok()?;
        let text = fstp_import::normalise(bytes, doc.media, limits).ok()?;
        if !salted::verify(
            &salt,
            text.untrusted().as_data().as_bytes(),
            &doc.digest.bytes(),
        ) {
            return None;
        }
        let data = text.untrusted().as_data();
        let entries: Vec<FixtureEntry> = annex_entries()
            .into_iter()
            .filter(|e| data.contains(e.evidence.as_str()))
            .collect();
        let config = ImportConfig {
            id: ImportConfigId::from_raw(1),
        };
        let raw = FakeProposer::new(entries)
            .propose(&text, fstp_programme::FIELDS, &config)
            .ok()?;
        if raw.is_empty() {
            return None;
        }
        let mut proposals = Vec::with_capacity(raw.len());
        for (i, r) in raw.into_iter().enumerate() {
            let n = u128::try_from(i).ok()?.checked_add(1)?;
            let id = ImportProposalId::from_raw(doc.id.raw().checked_mul(256)?.checked_add(n)?);
            // ADR-007: the salt is stored inside the value text, before it
            // (`fstp_api_core::salted`), and erased with it.
            let salt = fstp_crypto::random_array::<{ salted::SALT_LEN }>().ok()?;
            let value = r.value.as_data().as_bytes();
            let stored = self.texts.put_now(
                TextClass::Confidential,
                TextOwner::Programme(programme),
                &salted::stored(&salt, value),
            );
            let digest = salted::digest(&salt, value);
            let ids = BindIds {
                id,
                document: doc.id,
                config: config.id,
                text: ValueTextRef::new(
                    ValueTextId::from_raw(stored.0),
                    SaltedDigest::from_bytes(digest),
                ),
            };
            proposals.push(r.bind(&text, ids).ok()?);
        }
        let mut command = *b"fake-imp\0\0\0\0\0\0\0\0";
        let low = doc.id.raw().to_be_bytes();
        for (slot, b) in command.iter_mut().skip(8).zip(low.iter().skip(8)) {
            *slot = *b;
        }
        let system = Ctx {
            actor: Actor::System(SystemCause::Timeline),
            command: CommandId::from_bytes(command),
            via: Via::Web,
            tenant_admin: false,
            second_tenant_admin: None,
            binds_tenant_admin: false,
            ..*ctx
        };
        Some((
            ImportCommand::RecordProposals {
                document: doc.id,
                proposals,
            },
            system,
        ))
    }
}
