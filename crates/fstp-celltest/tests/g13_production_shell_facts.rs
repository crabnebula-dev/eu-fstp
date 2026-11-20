//! G13, ADR-027: the facts of the production creator shell on a
//! PostgreSQL world.
//!
//! The cell reads its creator facts from `fstp_cell::shell::facts::FactsShell`,
//! the shell of a configured serving cell, in place of the world's
//! all-passing `WorldShell`. What is real and what stands in:
//!
//! - The Q35 answers are the world vault's (`fstp-vault-core`), asked by
//!   the cell's decision, since the shell gives none. The test seeds a
//!   partner staff affiliation for every P-13 class and a list for every
//!   P-38 entry of the synthetic programme.
//! - The prober is a fake: the channel and the sending domain pass, and
//!   inference is absent, as on a production cell (ADR-027). The script
//!   acknowledges `InferenceUnreachable` and `PrecheckUnavailable`, the two
//!   warnings of a cell with no inference probe and no pre-check provider.
//! - The Guide inputs are the shell's own: the profile template over the
//!   complete creator draft, the stored narratives read from the cell's
//!   text store, a synthetic platform address and synthetic data
//!   protection texts.
//! - The funder profile is the shipped one with synthetic wording in
//!   place of each legal marker (`world_profile`), which the test's own
//!   wrapper puts in. The production shell reads the shipped profiles only
//!   (rule A9b). The shipped profile
//!   differs only there, so on a production cell `LegalWordingPending`
//!   is the one failure left. Its wording waits for Daniel (`TODO(legal)`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]

use std::sync::Arc;

use fstp_cell::public::TextOpener;
use fstp_cell::shell::facts::{FactsShell, PlatformNotice};
use fstp_cell::shell::probe::{ProbeFuture, Prober};
use fstp_cell::shell::{CreatorShell, ShellFuture};
use fstp_cell_core::CellRecord;
use fstp_cell_core::CellState;
use fstp_cell_core::creator::{CreatorFacts, GuideInputs};
use fstp_celltest::vault_seed::SeedSource;
use fstp_celltest::world::{CellHandle, CycleScript, DbMode, VaultLayout, World, WorldSpec};
use fstp_celltest::world_shell::{SYNTHETIC_WORDING, world_profile};
use fstp_creator::{CreatorCommand, CreatorRecord, ProbeKind, ProbeOutcome};
use fstp_domain::id::CallId;
use fstp_guide::ProfileSource;
use fstp_vault_core::{Fact, Org};
use fstp_vault_proto::{WireAccount, WireClass, WireList};

/// The prober of the test: the channel and the sending domain reach their
/// fakes, and inference is absent, as on a production cell (ADR-027).
struct ReachableProber;

impl Prober for ReachableProber {
    fn run(&self, probe: ProbeKind) -> ProbeFuture<'_> {
        let outcome = match probe {
            ProbeKind::Channel | ProbeKind::SendingDomain => ProbeOutcome::Pass,
            ProbeKind::Inference => ProbeOutcome::Absent,
        };
        Box::pin(std::future::ready(outcome))
    }
}

/// The production shell with the world profile's synthetic wording in
/// place of the shipped legal markers (module documentation). Everything
/// else is the [`FactsShell`]'s own.
struct SyntheticWording(FactsShell);

impl SyntheticWording {
    fn profile(state: &CellState, cmd: &CreatorCommand) -> Option<fstp_guide::FunderProfile> {
        fstp_engine::compose::profile_ref(state.engine(), cmd)
            .and_then(|r| fstp_engine::compose::profile_name(&r))
            .and_then(|name| world_profile(&name))
    }

    fn reworded(state: &CellState, call: CallId, g: Option<GuideInputs>) -> Option<GuideInputs> {
        let mut g = g?;
        let engine = state.engine();
        let programme = fstp_domain::programme::call(&engine.core, call)?.programme();
        let head = fstp_domain::policy::head(&engine.core, programme)?;
        let name = fstp_engine::compose::profile_name(&head.frozen.p53)?;
        let profile = world_profile(&name)?;
        g.template = fstp_guide::parse_template(profile.guide_template().as_bytes()).ok()?;
        Some(g)
    }
}

impl CreatorShell for SyntheticWording {
    fn facts(&self, state: &CellState, cmd: &CreatorCommand) -> CreatorFacts {
        CreatorFacts {
            profile: Self::profile(state, cmd),
            ..self.0.facts(state, cmd)
        }
    }

    fn guide(&self, state: &CellState, call: CallId) -> Option<GuideInputs> {
        Self::reworded(state, call, self.0.guide(state, call))
    }

    fn facts_fresh<'a>(
        &'a self,
        state: &'a CellState,
        cmd: &'a CreatorCommand,
    ) -> ShellFuture<'a, CreatorFacts> {
        Box::pin(async move {
            let f = self.0.facts_fresh(state, cmd).await;
            CreatorFacts {
                profile: Self::profile(state, cmd),
                ..f
            }
        })
    }

    fn guide_fresh<'a>(
        &'a self,
        state: &'a CellState,
        call: CallId,
        texts: &'a dyn TextOpener,
    ) -> ShellFuture<'a, Option<GuideInputs>> {
        Box::pin(async move {
            let g = self.0.guide_fresh(state, call, texts).await;
            Self::reworded(state, call, g)
        })
    }
}

/// The shell of the test (module documentation).
fn shell() -> SyntheticWording {
    SyntheticWording(
        FactsShell::new(Some(Arc::new(ReachableProber)))
            .with_notice(PlatformNotice {
                summary: SYNTHETIC_WORDING.to_owned(),
                privacy_statement_url: "https://privacy.fstp.test/".to_owned(),
                approved: true,
            })
            .with_platform_url(Some("https://platform.fstp.test/".to_owned())),
    )
}

/// The P-13 classes and P-38 lists of the cycle's synthetic programme.
fn classes_and_lists() -> (Vec<u128>, Vec<u128>) {
    let fixture = fstp_programme::supersafe_fixture().unwrap();
    let profile = fstp_programme::FunderProfile::horizon_europe();
    let policy = fstp_programme::compile(
        &fixture.spec,
        &profile,
        fstp_programme::CompileIds::new(
            fstp_domain::id::ProgrammeId::from_raw(1),
            fstp_domain::id::PolicyVersionId::from_raw(1),
            None,
        ),
    )
    .unwrap()
    .policy;
    (
        policy.live.p13.0.iter().map(|c| c.raw()).collect(),
        policy.live.p38.0.values().map(|l| l.raw()).collect(),
    )
}

/// Q6, ADR-027: the shipped Horizon Europe profile still waits for its
/// legal wording, and the world profile differs from it only there.
#[test]
fn q6_shipped_wording_is_the_only_profile_difference() {
    let shipped = fstp_guide::ShippedProfiles
        .profile("horizon-europe")
        .unwrap();
    let world = world_profile("horizon-europe").unwrap();
    assert!(
        shipped.legal_wording_pending(),
        "TODO(legal): the shipped wording is pending until Daniel approves it"
    );
    assert!(!world.legal_wording_pending());
    let shipped_lines: Vec<&str> = shipped
        .guide_template()
        .lines()
        .filter(|l| !l.starts_with(fstp_guide::LEGAL_MARKER))
        .collect();
    let world_lines: Vec<&str> = world
        .guide_template()
        .lines()
        .filter(|l| *l != SYNTHETIC_WORDING)
        .collect();
    assert_eq!(shipped_lines, world_lines);
}

/// A one-cell world whose cell reads the facts of [`shell`].
fn world() -> World {
    World::start_with_shell(
        WorldSpec {
            cells: 1,
            mode: DbMode::Shared,
            vault_layout: VaultLayout::SeparateCluster,
            self_hosted: false,
            process_mode: false,
        },
        Arc::new(shell()),
    )
    .unwrap_or_else(|e| panic!("the world did not start: {e}"))
}

/// Seeds a partner staff affiliation for each of `classes` and a list for
/// each of `lists` into the vault of `cell` (Q35).
fn seed(cell: &CellHandle, classes: &[u128], lists: &[u128]) {
    for (i, class) in classes.iter().enumerate() {
        let n = u128::try_from(i).unwrap();
        cell.seed_vault_fact(
            SeedSource::SyntheticAffiliation,
            Fact::AffiliationDeclared {
                account: WireAccount(900_000 + n),
                org: Org(800_000 + n),
                class: Some(WireClass(*class)),
                partner_staff: true,
            },
        )
        .unwrap_or_else(|e| panic!("the class seed: {e}"));
    }
    for (i, list) in lists.iter().enumerate() {
        let n = u128::try_from(i).unwrap();
        cell.seed_vault_fact(
            SeedSource::SyntheticAffiliation,
            Fact::ProximityListDeclared {
                list: WireList(*list),
                orgs: [Org(700_000 + n)].into_iter().collect(),
            },
        )
        .unwrap_or_else(|e| panic!("the list seed: {e}"));
    }
}

/// Runs `steps` on cell 0 of `world`.
fn run(world: &World, steps: &[&str]) -> Result<(), fstp_celltest::NotImplemented> {
    world
        .run_cycle(
            0,
            &CycleScript {
                steps: steps.iter().map(|s| (*s).to_owned()).collect(),
            },
        )
        .result
}

/// The steps to the approval, with the two warnings of a cell with no
/// inference probe and no pre-check provider acknowledged.
const TO_APPROVAL: [&str; 4] = [
    "login",
    "acknowledge-warning:InferenceUnreachable",
    "acknowledge-warning:PrecheckUnavailable",
    "create-programme",
];

/// Every record of the ledger of `cell`.
fn records(cell: &CellHandle) -> Vec<CellRecord> {
    cell.ledger()
        .unwrap()
        .into_iter()
        .map(|e| e.record)
        .collect()
}

fn creator_record(records: &[CellRecord], want: fn(&CreatorRecord) -> bool) -> bool {
    records.iter().any(|r| match r {
        CellRecord::Engine(fstp_engine::Record::Creator(c)) => want(c),
        _ => false,
    })
}

/// I-66, I-67, Q35 A, Q5, ADR-027: with the production shell's facts all
/// good, the draft reaches a clean report and a second admin activates
/// it. I-51, I-52, R-GA-01: the call then publishes with the Guide the
/// shell built from the stored texts.
#[test]
fn i66_i51_i52_production_shell_facts_activate_and_publish_on_pg() {
    let world = world();
    let cell = world.cell(0).unwrap();
    let (classes, lists) = classes_and_lists();
    seed(cell, &classes, &lists);
    let mut steps = TO_APPROVAL.to_vec();
    steps.push("publish-call");
    assert_eq!(run(&world, &steps), Ok(()), "the cycle stopped");
    let records = records(cell);
    assert!(
        creator_record(&records, |c| matches!(
            c,
            CreatorRecord::ActivationApproved(_)
        )),
        "I-66: the clean report activated the programme"
    );
    let probes: Vec<(ProbeKind, ProbeOutcome)> =
        records
            .iter()
            .filter_map(|r| match r {
                CellRecord::Engine(fstp_engine::Record::Creator(
                    CreatorRecord::ProbeRecorded { probe, outcome, .. },
                )) => Some((*probe, *outcome)),
                _ => None,
            })
            .collect();
    assert_eq!(
        probes,
        vec![
            (ProbeKind::Channel, ProbeOutcome::Pass),
            (ProbeKind::SendingDomain, ProbeOutcome::Pass),
            (ProbeKind::Inference, ProbeOutcome::Absent),
        ],
        "design 3.2: the approval recorded the probes it ran"
    );
    let guide = records.iter().any(|r| {
        matches!(
            r,
            CellRecord::Engine(fstp_engine::Record::Core(
                fstp_domain::Record::GuidePublished { .. }
            ))
        )
    });
    assert!(guide, "I-52: the publication carries the shell's Guide");
}

/// I-66, I-04, Q35 A: when the vault does not know a P-13 class of the
/// draft, `ExclusionClassUnknown` fails the report, and the approval is
/// refused. The request for activation is recorded, so the draft got that
/// far, and the programme stays a draft.
#[test]
fn i66_q35_unknown_class_keeps_the_programme_a_draft_on_pg() {
    let (classes, lists) = classes_and_lists();
    assert!(!classes.is_empty(), "the synthetic programme names a class");
    let world = world();
    let cell = world.cell(0).unwrap();
    seed(cell, &[], &lists);
    assert!(
        run(&world, &TO_APPROVAL).is_err(),
        "the approval must be refused"
    );
    let records = records(cell);
    assert!(creator_record(&records, |c| matches!(
        c,
        CreatorRecord::ActivationRequested { .. }
    )));
    assert!(
        !creator_record(&records, |c| matches!(
            c,
            CreatorRecord::ActivationApproved(_)
        )),
        "I-66: an unknown class never activates"
    );
}
