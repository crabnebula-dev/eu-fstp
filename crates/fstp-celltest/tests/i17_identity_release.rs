//! I-17: Judging roles cannot read identity attributes of an applicant
//! before the proposal enters negotiation (design sections 6.5 and 14.4,
//! ADR-009 "Vault origin", "Tickets" and "Releases", TH-07).
//!
//! Lane W1c wrote these tests before the production code. Each compares
//! production with `fstp_celltest::reference::vault`. They are red until
//! `fstp-cell-core` (lane W2c), `fstp-vault-core` (lane W2d) and the cell
//! runtime (lane W3a) land. The reference and teeth tests are green now.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;

use fstp_cell_core::release::{ReleaseCommand, ReleaseRecord};
use fstp_cell_core::{CellCommand, CellRecord};
use fstp_celltest::NotImplemented;
use fstp_celltest::canary::{Canary, CanaryKind};
use fstp_celltest::mc::auth_model::{ProdCell, ProdError};
use fstp_celltest::mc::driver_model::paths::{self, PathStep};
use fstp_celltest::reference::vault::{
    RefTicket, RefVault, RouteKind, TICKET_LIFETIME_MAX_US, TicketCheck, TicketKind, TicketRefusal,
    WriteKind, release_ticket_allowed, sign_ticket, ticket_public_key,
};
use fstp_celltest::scan::{StoreSet, scan};
use fstp_celltest::world::{CycleScript, DbMode, VaultLayout, World, WorldSpec};
use fstp_domain::id::{AccountId, BindingId, ProposalId};
use fstp_domain::roles::Role;
use fstp_domain::rules::StateTag;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::review::{IRC, L1, PR1, R1, tag};
use fstp_domain_testkit::r#gen::roster::{ADMIN, P1, STAFF_PM, T0, grant};
use fstp_domain_testkit::harness::teeth::expect_prop_failure;
use fstp_prop::{Gen, prop_assert, prop_assert_eq};

// ---------------------------------------------------------------------------
// The release rule of the cell.

/// The Operations role holder of the tests: a finance approver of P1.
const FINANCE: AccountId = AccountId::from_raw(501);
const FINANCE_BINDING: BindingId = BindingId::from_raw(9_501);

/// The actors of the release property and their holdings.
const ACTORS: [AccountId; 6] = [ADMIN, FINANCE, R1, IRC, STAFF_PM, L1];

/// The vault of the release tests: the setup's, with FINANCE verified.
fn release_truth() -> fstp_domain_testkit::vault::GroundTruth {
    let mut t = paths::truth(true);
    t.set_identity(FINANCE, tag(FINANCE));
    t.verify(FINANCE);
    t
}

/// The path to `state`, with FINANCE granted the finance approver role in
/// P1 right after the programme's setup.
fn release_path(state: StateTag) -> Result<Vec<PathStep>, String> {
    let mut path = paths::to(state)?;
    let g = PathStep {
        step: grant(FINANCE_BINDING, FINANCE, P1, Role::FinanceApprover, T0),
        at: T0,
    };
    let draft_len = paths::to(StateTag::Draft)?.len();
    path.insert(draft_len, g);
    Ok(path)
}

/// The production decision: does the cell issue a release ticket for PR1
/// to `actor` with PR1 in `state`?
fn production_issues(state: StateTag, actor: AccountId) -> Result<bool, String> {
    let path = release_path(state)?;
    let mut cell = ProdCell::genesis(release_truth()).map_err(|e| e.to_string())?;
    cell.exec_tenant_admin_grant(ADMIN, ADMIN, T0)
        .map_err(|e| e.to_string())?;
    for p in &path {
        cell.exec_step(&p.step, p.at).map_err(|e| e.to_string())?;
    }
    let at = path.last().map_or(T0, |p| p.at);
    let cmd = CellCommand::Release(ReleaseCommand::IssueReleaseTicket {
        proposal: PR1.raw(),
    });
    match cell.exec(cmd, actor, at) {
        // Issuing a release ticket appends `IdentityReleaseIssued` (design
        // section 6.5, ADR-009). `TicketIssued` is the write ticket record.
        Ok(batch) => Ok(batch.iter().any(|r| {
            matches!(
                r,
                CellRecord::Release(ReleaseRecord::IdentityReleaseIssued { proposal, by, .. })
                    if *proposal == PR1.raw() && *by == actor
            )
        })),
        Err(ProdError::Refused(_)) => Ok(false),
        Err(e @ ProdError::NotImplemented(_)) => Err(e.to_string()),
    }
}

/// The reference decision for `actor` with PR1 in `state`.
fn reference_issues(state: StateTag, actor: AccountId) -> bool {
    release_ticket_allowed(actor == FINANCE, actor == ADMIN, state)
}

fn release_property(
    g: &mut Gen,
    candidate: &dyn Fn(StateTag, AccountId) -> Result<bool, String>,
) -> Result<(), String> {
    let state = *g.pick(&paths::STATES);
    let actor = *g.pick(&ACTORS);
    let got = candidate(state, actor)?;
    prop_assert_eq!(
        got,
        reference_issues(state, actor),
        "I-17: a release ticket for PR1 in {state:?} to {actor:?}"
    );
    Ok(())
}

/// I-17, design section 6.5: the cell issues a release ticket only to an
/// Operations role holder of the programme, for a proposal in NEGOTIATION
/// or later. Production `fstp_cell_core::decide` against the reference
/// over roles and states, every state built from genesis.
///
/// Gap: the paths reach NEGOTIATION. GRANTED and later need the contract
/// port of M5, so they are covered by the reference only.
#[test]
fn i17_release_ticket_only_for_operations_in_negotiation() {
    fstp_prop::check(
        "i17_release_ticket_only_for_operations_in_negotiation",
        |g: &mut Gen| release_property(g, &production_issues),
    );
}

/// I-17 teeth (design section 14.4): a rule that also issues release
/// tickets in RANKED fails the release property.
#[test]
fn i17_teeth_ticket_issued_in_ranked_is_caught() {
    let mutant = |state: StateTag, actor: AccountId| -> Result<bool, String> {
        Ok(reference_issues(state, actor)
            || (state == StateTag::Ranked && (actor == FINANCE || actor == ADMIN)))
    };
    let outcome = fstp_prop::run(
        "i17_teeth_ticket_issued_in_ranked_is_caught",
        fstp_prop::Config::default(),
        |g: &mut Gen| release_property(g, &mutant),
    );
    if let Err(e) = expect_prop_failure(&outcome, "I-17") {
        panic!("{e}");
    }
}

/// I-17: the paths of the release property reach their states through
/// the M2 domain, the finance grant included.
#[test]
fn i17_release_paths_reach_their_states() {
    for state in paths::STATES {
        let path = release_path(state).unwrap();
        assert_eq!(
            paths::check_with_domain(&path, release_truth()).unwrap(),
            Some(state),
            "the path to {state:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Tickets and the vault's second guard.

const CELL: [u8; 16] = [0xCE; 16];
const OTHER_CELL: [u8; 16] = [0xCF; 16];
const KEY: [u8; 32] = [0x11; 32];
const NEXT_KEY: [u8; 32] = [0x12; 32];
const FORGER: [u8; 32] = [0x66; 32];
const NOW: Timestamp = Timestamp::from_micros(10_000_000_000);
const SUBJECT: AccountId = AccountId::from_raw(301);
const P: ProposalId = ProposalId::from_raw(1);

/// How a test ticket is built (ADR-009 "Tickets").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mutation {
    Valid,
    SignedWithNextKey,
    Forged,
    Tampered,
    Expired,
    AtExpiry,
    Future,
    TooLong,
    Foreign,
    Replayed,
    WriteTicketOnReleaseRoute,
}

const MUTATIONS: [Mutation; 11] = [
    Mutation::Valid,
    Mutation::SignedWithNextKey,
    Mutation::Forged,
    Mutation::Tampered,
    Mutation::Expired,
    Mutation::AtExpiry,
    Mutation::Future,
    Mutation::TooLong,
    Mutation::Foreign,
    Mutation::Replayed,
    Mutation::WriteTicketOnReleaseRoute,
];

impl Mutation {
    /// The refusal the vault must give, or none for a ticket it honours.
    fn expected(self) -> Option<TicketRefusal> {
        match self {
            Mutation::Valid | Mutation::SignedWithNextKey => None,
            Mutation::Forged | Mutation::Tampered => Some(TicketRefusal::BadSignature),
            Mutation::Expired | Mutation::AtExpiry => Some(TicketRefusal::Expired),
            Mutation::Future => Some(TicketRefusal::NotYetValid),
            Mutation::TooLong => Some(TicketRefusal::TooLong),
            Mutation::Foreign => Some(TicketRefusal::ForeignCell),
            Mutation::Replayed => Some(TicketRefusal::Replayed),
            Mutation::WriteTicketOnReleaseRoute => Some(TicketRefusal::WrongKind),
        }
    }
}

/// A release ticket for SUBJECT and P, built with `m`, and a nonce from `g`.
fn ticket(g: &mut Gen, m: Mutation) -> Vec<u8> {
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&g.bytes(16..=16));
    let life = g.i64_in(1..=TICKET_LIFETIME_MAX_US);
    let issued = NOW.micros() - g.i64_in(0..=life - 1);
    let mut t = RefTicket {
        kind: TicketKind::Release,
        cell: CELL,
        account: SUBJECT,
        proposal: Some(P),
        scope: "attributes".to_owned(),
        issued_at: Timestamp::from_micros(issued),
        expires_at: Timestamp::from_micros(issued + life),
        nonce,
    };
    let mut key = KEY;
    match m {
        Mutation::Valid | Mutation::Replayed | Mutation::Tampered => {}
        Mutation::SignedWithNextKey => key = NEXT_KEY,
        Mutation::Forged => key = FORGER,
        Mutation::Expired => {
            t.expires_at = Timestamp::from_micros(NOW.micros() - g.i64_in(1..=1_000));
            t.issued_at = Timestamp::from_micros(t.expires_at.micros() - life);
        }
        Mutation::AtExpiry => {
            t.expires_at = NOW;
            t.issued_at = Timestamp::from_micros(NOW.micros() - life);
        }
        Mutation::Future => {
            t.issued_at = Timestamp::from_micros(NOW.micros() + g.i64_in(1..=1_000));
            t.expires_at = Timestamp::from_micros(t.issued_at.micros() + life);
        }
        Mutation::TooLong => {
            t.issued_at = Timestamp::from_micros(NOW.micros() - 1);
            t.expires_at = Timestamp::from_micros(
                t.issued_at.micros() + TICKET_LIFETIME_MAX_US + g.i64_in(1..=1_000),
            );
        }
        Mutation::Foreign => t.cell = OTHER_CELL,
        Mutation::WriteTicketOnReleaseRoute => {
            t.kind = TicketKind::Write(*g.pick(&WriteKind::ALL));
        }
    }
    let mut bytes = sign_ticket(&t, &key).unwrap();
    if m == Mutation::Tampered {
        let i = g.usize_in(0..=bytes.len() - 65);
        bytes[i] ^= 1 << g.u8_in(0..=7);
    }
    bytes
}

fn pinned() -> Vec<[u8; 32]> {
    vec![
        ticket_public_key(&KEY).unwrap(),
        ticket_public_key(&NEXT_KEY).unwrap(),
    ]
}

/// The reference outcome of presenting `bytes` once, or twice for
/// `Replayed`, with the negotiation fact `listed`.
fn reference_release(
    m: Mutation,
    bytes: &[u8],
    listed: Option<AccountId>,
) -> Result<(), TicketRefusal> {
    let mut v = RefVault::default();
    if let Some(a) = listed {
        v.negotiation_opened(P, BTreeSet::from([a]));
    }
    let keys = pinned();
    let check = TicketCheck {
        pinned: &keys,
        cell: CELL,
        route: RouteKind::Release,
        now: NOW,
    };
    if m == Mutation::Replayed {
        v.release(bytes, &check)?;
    }
    v.release(bytes, &check).map(|_| ())
}

/// The production outcome: the vault service of lane W2d, sans I/O. It
/// pins the cell id and the current and next ticket keys at provisioning,
/// takes the `NegotiationOpened` fact for `listed`, and presents the
/// ticket on `POST /r` once, or twice for `Replayed`. The service runs
/// `fstp_vault_core::check_ticket` and `release_guard`, and keeps the used
/// ticket ids, since single use is its part.
fn production_release(
    m: Mutation,
    bytes: &[u8],
    listed: Option<AccountId>,
) -> Result<Result<(), ()>, String> {
    let keys = pinned();
    let mut v =
        fstp_vault::Vault::new(CELL, &keys).map_err(|e| format!("provisioning refused: {e}"))?;
    if let Some(a) = listed {
        let accounts = BTreeSet::from([fstp_vault_proto::WireAccount(a.raw())]);
        v.negotiation_opened(fstp_vault_proto::WireProposal(P.raw()), &accounts, 1)
            .map_err(|e| format!("negotiation fact refused: {e}"))?;
    }
    if m == Mutation::Replayed && v.post_release(bytes, NOW.micros()).is_err() {
        return Ok(Err(()));
    }
    Ok(v.post_release(bytes, NOW.micros())
        .map(|_| ())
        .map_err(|_| ()))
}

/// I-17, ADR-009 "Tickets": the vault refuses a forged, tampered, expired,
/// future, over-long, foreign, replayed or wrong-route ticket, and honours
/// a valid one signed with the current or the next pinned key.
#[test]
fn i17_vault_refuses_forged_stale_replayed_or_foreign_tickets() {
    fstp_prop::check(
        "i17_vault_refuses_forged_stale_replayed_or_foreign_tickets",
        |g: &mut Gen| {
            let m = *g.pick(&MUTATIONS);
            let bytes = ticket(g, m);
            let want = reference_release(m, &bytes, Some(SUBJECT)).map_err(|_| ());
            let got = production_release(m, &bytes, Some(SUBJECT))?;
            prop_assert_eq!(got, want, "I-17: ticket {m:?}");
            Ok(())
        },
    );
}

/// I-17: the reference ticket check gives each mutation its own refusal.
#[test]
fn i17_reference_refuses_forged_stale_replayed_or_foreign_tickets() {
    fstp_prop::check(
        "i17_reference_refuses_forged_stale_replayed_or_foreign_tickets",
        |g: &mut Gen| {
            let m = *g.pick(&MUTATIONS);
            let bytes = ticket(g, m);
            let got = reference_release(m, &bytes, Some(SUBJECT)).err();
            prop_assert_eq!(got, m.expected(), "I-17: ticket {m:?}");
            Ok(())
        },
    );
}

/// I-17, the second guard of design section 6.5: the vault refuses a
/// release unless its own negotiation fact lists the subject, even for a
/// valid ticket.
#[test]
fn i17_vault_refuses_release_without_negotiation_fact() {
    fstp_prop::check(
        "i17_vault_refuses_release_without_negotiation_fact",
        |g: &mut Gen| {
            let listed = *g.pick(&[None, Some(SUBJECT), Some(AccountId::from_raw(302))]);
            let bytes = ticket(g, Mutation::Valid);
            let want = reference_release(Mutation::Valid, &bytes, listed);
            prop_assert_eq!(
                want.is_ok(),
                listed == Some(SUBJECT),
                "I-17: the reference with fact {listed:?}"
            );
            let got = production_release(Mutation::Valid, &bytes, listed)?;
            prop_assert_eq!(got, want.map_err(|_| ()), "I-17: fact {listed:?}");
            Ok(())
        },
    );
}

/// I-17, ADR-009 "Tickets", the second guard of design section 6.5: a
/// release the vault refuses for a missing negotiation fact releases
/// nothing and leaves the ticket unused. Once the cell pushes the fact,
/// the same ticket is honoured once, and a second use is refused.
///
/// Reading, open and reported to Daniel: ADR-009 says only that a second
/// use is refused. The reference reads a refused presentation as no use
/// (see `RefVault::release`).
#[test]
fn i17_reference_refused_release_leaves_the_ticket_unused() {
    fstp_prop::check(
        "i17_reference_refused_release_leaves_the_ticket_unused",
        |g: &mut Gen| {
            let bytes = ticket(g, Mutation::Valid);
            let keys = pinned();
            let check = TicketCheck {
                pinned: &keys,
                cell: CELL,
                route: RouteKind::Release,
                now: NOW,
            };
            let mut v = RefVault::default();
            let first = v.release(&bytes, &check).map(|_| ());
            prop_assert_eq!(
                first,
                Err(TicketRefusal::NoNegotiationFact),
                "I-17: a release with no negotiation fact"
            );
            prop_assert!(
                v.used_tickets().is_empty(),
                "I-17: the refused release used up the ticket"
            );
            v.negotiation_opened(P, BTreeSet::from([SUBJECT]));
            let second = v.release(&bytes, &check).map(|_| ());
            prop_assert_eq!(second, Ok(()), "I-17: the release after the fact");
            let third = v.release(&bytes, &check).map(|_| ());
            prop_assert_eq!(
                third,
                Err(TicketRefusal::Replayed),
                "I-17: a second use of the ticket"
            );
            Ok(())
        },
    );
}

// ---------------------------------------------------------------------------
// Canary machines over a running cell.

fn one_cell_world() -> World {
    World::start(WorldSpec {
        cells: 1,
        mode: DbMode::Shared,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: false,
        process_mode: false,
    })
    .unwrap_or_else(|e| panic!("the one-cell world did not start: {e}"))
}

/// The canaries of cell 0 that stand for identity attributes, login
/// emails included (Q22).
fn attribute_canaries() -> Vec<Canary> {
    [
        CanaryKind::Name,
        CanaryKind::Email,
        CanaryKind::Phone,
        CanaryKind::Country,
        CanaryKind::Document,
    ]
    .iter()
    .map(|k| Canary::generate(0, *k).unwrap())
    .collect()
}

/// The machine script: random M2 commands and vault-origin writes of the
/// country, an affiliation, a consent and a document, each carrying the
/// canaries, as the Judging and Drafting sessions read the cell.
fn canary_script(canaries: &[Canary]) -> CycleScript {
    let mut steps = vec![
        "m2:random-commands".to_owned(),
        "judging:read-every-route".to_owned(),
        "drafting:read-every-route".to_owned(),
    ];
    for c in canaries {
        steps.push(format!("vault-origin:write:{}", c.text()));
    }
    steps.push("judging:read-every-route".to_owned());
    CycleScript { steps }
}

/// The former seam of the response scan, closed by lane m3/cycle-steps:
/// `CellHandle` records the replies to sessions (`fstp_celltest::responses`).
const RESPONSES_SEAM: &str =
    "fstp_celltest::world::CellHandle records no HTTP responses for a session (lanes W1a and W3a)";

/// Every reply cell 0 gave to a session of an account that held a Judging
/// or Drafting role there. The machine must have read something, so an
/// empty set is the seam, never a clean scan.
fn judging_responses(world: &World) -> Result<StoreSet, NotImplemented> {
    let set = world
        .cell(0)
        .and_then(|c| c.judging_and_drafting_responses().ok())
        .ok_or(NotImplemented::new(RESPONSES_SEAM))?;
    if set.stores.is_empty() {
        return Err(NotImplemented::new(RESPONSES_SEAM));
    }
    Ok(set)
}

/// I-17, TH-07 (T-PRIV-CANARY for M3): over a machine of M2 commands and
/// vault-origin writes, no response body or header to a Judging or
/// Drafting session holds an attribute canary.
#[test]
fn i17_canary_attributes_never_reach_judging_responses() {
    let world = one_cell_world();
    let canaries = attribute_canaries();
    world
        .run_cycle(0, &canary_script(&canaries))
        .result
        .unwrap_or_else(|e| panic!("the machine did not run: {e}"));
    let responses = judging_responses(&world).unwrap_or_else(|e| panic!("{e}"));
    let report = scan(&responses, &canaries).unwrap();
    assert!(report.is_clean(), "I-17: {:?}", report.hits);
}

/// I-17, R-NF-08: after the machine run, no application table holds a
/// canary of kind name, phone, country or document.
#[test]
fn i17_app_database_holds_no_identity_attribute() {
    let world = one_cell_world();
    let canaries: Vec<Canary> = attribute_canaries()
        .into_iter()
        .filter(|c| c.kind != CanaryKind::Email)
        .collect();
    world
        .run_cycle(0, &canary_script(&canaries))
        .result
        .unwrap_or_else(|e| panic!("the machine did not run: {e}"));
    let app: Vec<_> = world
        .databases()
        .unwrap()
        .into_iter()
        .filter(|d| d.kind == fstp_celltest::world::ClusterKind::Application)
        .collect();
    let mut stores = StoreSet::default();
    for (name, bytes) in world.stores().unwrap().stores {
        if app.iter().any(|d| d.owns(&name)) {
            stores.push(name, bytes);
        }
    }
    assert!(!stores.stores.is_empty(), "no application store was found");
    let report = scan(&stores, &canaries).unwrap();
    assert!(report.is_clean(), "I-17: {:?}", report.hits);
}

/// Whether a store is a log or a metrics sink.
fn is_log_or_metric(name: &str) -> bool {
    name.contains("/log/") || name.ends_with(".log") || name.contains("metrics")
}

/// I-17, R-NF-02: no log or metrics sink of the world holds an attribute
/// canary after the machine run.
#[test]
fn i17_logs_and_metrics_hold_no_attribute() {
    let world = one_cell_world();
    let canaries = attribute_canaries();
    world
        .run_cycle(0, &canary_script(&canaries))
        .result
        .unwrap_or_else(|e| panic!("the machine did not run: {e}"));
    let mut stores = StoreSet::default();
    for (name, bytes) in world.stores().unwrap().stores {
        if is_log_or_metric(&name) {
            stores.push(name, bytes);
        }
    }
    assert!(
        !stores.stores.is_empty(),
        "no log or metrics sink was found"
    );
    let report = scan(&stores, &canaries).unwrap();
    assert!(report.is_clean(), "I-17: {:?}", report.hits);
}

/// I-17 teeth (design section 14.4): an attribute written into a log line,
/// JSON-escaped, is found by the log scan of
/// `i17_logs_and_metrics_hold_no_attribute`.
#[test]
fn i17_teeth_attribute_logged_is_caught() {
    let canaries = attribute_canaries();
    let country = canaries
        .iter()
        .find(|c| c.kind == CanaryKind::Country)
        .unwrap();
    let line = format!(
        "{{\"event\":\"request\",\"detail\":\"{}\"}}\n",
        country.text().replace('-', "\\u002d")
    );
    let mut stores = StoreSet::default();
    stores.push("application/data/log/postgresql.log", line.into_bytes());
    stores.push("application/data/base/1/16384", b"no canary here".to_vec());
    let mut logs = StoreSet::default();
    for (name, bytes) in stores.stores {
        if is_log_or_metric(&name) {
            logs.push(name, bytes);
        }
    }
    let report = scan(&logs, &canaries).unwrap();
    assert!(
        report.hits.iter().any(|(_, c)| *c == country.text()),
        "teeth: the logged country canary went unseen: {:?}",
        report.hits
    );
}
