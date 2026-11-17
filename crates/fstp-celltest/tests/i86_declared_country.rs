//! The declared P-17 country reaches the vault only (I-86, R-NG-01,
//! overview NOTE 6, M4 design section 14 "I-86"; lane m4/country).
//!
//! The production cell serves `proposal.state_country` as a country
//! write ticket. The lead of a draft asks `POST /api/v1/vault-tickets`
//! with `write:country_stated` and the proposal. The cell records
//! `TicketIssued` and signs the ticket. The browser then writes the
//! country on the vault origin, so the cell never receives it (overview
//! "The vault origin", design section 6.5 "Write tickets").
//!
//! - The rule tests run production `fstp_cell_core::decide` over the
//!   ledgers of `driver_model::paths`, every state built from genesis.
//! - `i86_declared_country_never_reaches_app_tables` runs a one-cell
//!   PostgreSQL world: the production cell, its route, the seeded vault
//!   and its origin. It dumps the application and control-plane
//!   databases and scans them.
//!
//! The vault's write grammar holds a country as a code from 1 to 999
//! (`fstp_vault_core::fact::Fact::CountryStated`). A bare code is too
//! short to scan for. So the scan looks for the forms a leak would take:
//! the canonical write body the browser sends, which names the lead, the
//! programme and the code, and its `"country":<code>,` member, in every
//! encoding of `fstp_celltest::scan`. The canary text the code is drawn
//! from is scanned for too. All values are synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_cell_core::release::{ReleaseCommand, ReleaseRecord};
use fstp_cell_core::{CellCommand, CellRecord, WRITE_KIND_COUNTRY_STATED};
use fstp_celltest::canary::{Canary, CanaryKind};
use fstp_celltest::cycle::origin_writes::country_code;
use fstp_celltest::mc::auth_model::{ProdCell, ProdError};
use fstp_celltest::mc::driver_model::paths::{self, GUARDIAN};
use fstp_celltest::scan::{Needle, StoreSet, scan, scan_bytes};
use fstp_celltest::world::{ClusterKind, CycleScript, DbMode, VaultLayout, World, WorldSpec};
use fstp_domain::id::{AccountId, ProgrammeId, ProposalId};
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::review::{COORDINATOR, IRC, L1, PR1, R1, STRANGER};
use fstp_domain_testkit::r#gen::roster::{ADMIN, T0};
use fstp_vault_core::fact::Fact;
use fstp_vault_proto::{WireAccount, WireProgramme, WriteKind};

// ---------------------------------------------------------------------------
// The rule of the cell.

/// The actors of the rule tests: the lead, the guardian of the draft, a
/// tenant admin, Judging roles and an account with no role.
const ACTORS: [AccountId; 7] = [L1, GUARDIAN, ADMIN, R1, IRC, COORDINATOR, STRANGER];

/// What the cell does with a country ticket request.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Outcome {
    /// One `TicketIssued` of the country kind for PR1 to the actor.
    Issued,
    /// The actor refusal.
    Actor,
    /// The input refusal of a state guard.
    State,
}

/// The production decision for `actor` with PR1 in `state`.
fn production(state: StateTag, actor: AccountId) -> Result<Outcome, String> {
    let path = paths::to(state)?;
    let mut cell = ProdCell::genesis(paths::truth(true)).map_err(|e| e.to_string())?;
    cell.exec_tenant_admin_grant(ADMIN, ADMIN, T0)
        .map_err(|e| e.to_string())?;
    for p in &path {
        cell.exec_step(&p.step, p.at).map_err(|e| e.to_string())?;
    }
    let at = path.last().map_or(T0, |p| p.at);
    let cmd = CellCommand::Release(ReleaseCommand::IssueCountryTicket {
        proposal: PR1.raw(),
    });
    match cell.exec(cmd, actor, at) {
        Ok(batch) => {
            let issued = batch.iter().filter(|r| {
                matches!(
                    r,
                    CellRecord::Release(ReleaseRecord::TicketIssued { kind, proposal, holder, .. })
                        if *kind == WRITE_KIND_COUNTRY_STATED
                            && *proposal == PR1.raw()
                            && *holder == actor
                )
            });
            if issued.count() == 1 && batch.len() == 1 {
                Ok(Outcome::Issued)
            } else {
                Err(format!("an unexpected batch: {batch:?}"))
            }
        }
        Err(ProdError::Refused(r)) if r.contains("WrongActor") => Ok(Outcome::Actor),
        Err(ProdError::Refused(r)) if r.contains("WrongState") => Ok(Outcome::State),
        Err(e) => Err(e.to_string()),
    }
}

/// The rule of `fstp-api-core` for `proposal.state_country`: an actor
/// refusal for anyone but the lead, a state refusal outside DRAFT.
fn reference(state: StateTag, actor: AccountId) -> Outcome {
    if actor != L1 {
        Outcome::Actor
    } else if state == StateTag::Draft {
        Outcome::Issued
    } else {
        Outcome::State
    }
}

/// Every state and actor against `rule`.
fn check_rule(
    candidate: &dyn Fn(StateTag, AccountId) -> Result<Outcome, String>,
) -> Result<(), String> {
    for state in paths::STATES {
        for actor in ACTORS {
            let got = candidate(state, actor)?;
            let want = reference(state, actor);
            if got != want {
                return Err(format!(
                    "R-NG-01: a country ticket for PR1 in {state:?} to {actor:?}: {got:?}, want {want:?}"
                ));
            }
        }
    }
    Ok(())
}

/// R-NG-01, I-86, overview NOTE 6: the cell issues a country write ticket
/// only to the lead of a draft, as `fstp-api-core` admits
/// `proposal.state_country`. Anyone else gets the actor refusal, and the
/// lead outside DRAFT the input refusal. The issue is one `TicketIssued`
/// record: an id, the kind, the proposal and the lead, never a country.
#[test]
fn r_ng_01_country_ticket_only_for_the_lead_of_a_draft() {
    check_rule(&production).unwrap_or_else(|e| panic!("{e}"));
}

/// R-NG-01 teeth: a rule that also issues the ticket after submission
/// fails the rule check.
#[test]
fn r_ng_01_teeth_country_ticket_after_submission_is_caught() {
    let mutant = |state: StateTag, actor: AccountId| -> Result<Outcome, String> {
        Ok(match reference(state, actor) {
            Outcome::State if state == StateTag::Submitted => Outcome::Issued,
            o => o,
        })
    };
    assert!(
        check_rule(&mutant).is_err(),
        "teeth: a ticket issued in SUBMITTED went unseen"
    );
}

/// R-NG-01, ADR-009 "Write kinds": the kind the cell records is the
/// vault's `country_stated`, and the command round-trips the cell codec
/// byte for byte (I-78 action digests name one command).
#[test]
fn r_ng_01_country_ticket_names_the_vault_write_kind() {
    assert_eq!(WRITE_KIND_COUNTRY_STATED, WriteKind::CountryStated.code());
    let cmd = CellCommand::Release(ReleaseCommand::IssueCountryTicket {
        proposal: PR1.raw(),
    });
    let bytes = fstp_cell_core::encode_cell_command(&cmd);
    let back = fstp_cell_core::decode_cell_command(&bytes).unwrap();
    assert_eq!(back, cmd);
    assert_eq!(fstp_cell_core::encode_cell_command(&back), bytes);
}

// ---------------------------------------------------------------------------
// The PostgreSQL world.

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

/// The canonical write body of `CountryStated` for `lead`, `programme`
/// and `code`, as the browser sends it to the vault origin.
fn write_body(lead: AccountId, programme: ProgrammeId, code: u16) -> Vec<u8> {
    Fact::CountryStated {
        account: WireAccount(lead.raw()),
        programme: WireProgramme(programme.raw()),
        country: code,
    }
    .body_value()
    .and_then(|v| fstp_vault_proto::json::to_canonical(&v))
    .unwrap()
}

/// The forms a leaked country would take (module documentation).
fn country_needles(body: &[u8], code: u16) -> Vec<Needle> {
    vec![
        Needle {
            label: "the country write body".to_owned(),
            bytes: body.to_vec(),
        },
        Needle {
            label: "the country member".to_owned(),
            bytes: format!("\"country\":{code},").into_bytes(),
        },
    ]
}

/// The newest draft of the ledger: its proposal, its lead and its
/// programme.
fn newest_draft(
    ledger: &[fstp_ledger::Entry<CellRecord>],
) -> Option<(ProposalId, AccountId, ProgrammeId)> {
    let core = |r: &CellRecord| match r {
        CellRecord::Engine(fstp_engine::Record::Core(c)) => Some(c.clone()),
        _ => None,
    };
    let (proposal, call, lead) = ledger.iter().rev().find_map(|e| match core(&e.record)? {
        fstp_domain::Record::ProposalCreated {
            proposal,
            call,
            lead,
            ..
        } => Some((proposal, call, lead)),
        _ => None,
    })?;
    let programme = ledger.iter().find_map(|e| match core(&e.record)? {
        fstp_domain::Record::CallDrafted {
            call: c, programme, ..
        } if c == call => Some(programme),
        _ => None,
    })?;
    Some((proposal, lead, programme))
}

/// The UUID text of `n`, as PostgreSQL prints a `uuid`.
fn uuid_text(n: u128) -> String {
    let h = format!("{n:032x}");
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// I-86, R-NG-01, overview NOTE 6 (M4 design section 14, "I-86"): after
/// the lead of a draft states the country through the production cell's
/// `proposal.state_country`, a full dump of the application database
/// holds no country. Neither does the control-plane database.
///
/// The cycle drafts a proposal, then runs `state-country:<canary>`: the
/// lead's session asks the cell for the country write ticket, and the
/// country goes to the vault origin under it. Non-vacuity: the cell
/// recorded the issue, the vault holds the code for the lead and the
/// programme, and the vault database holds one sealed country fact of the
/// lead. The scan then covers every relation file and the logical dump of
/// each application and control-plane database.
#[test]
fn i86_declared_country_never_reaches_app_tables() {
    let world = one_cell_world();
    let canary = Canary::generate(0, CanaryKind::Country).unwrap();
    let code = country_code(&canary.text());
    let script = CycleScript {
        steps: vec![
            "minor-applicant:draft".to_owned(),
            format!("state-country:{}", canary.text()),
        ],
    };
    world
        .run_cycle(0, &script)
        .result
        .unwrap_or_else(|e| panic!("the cycle did not run: {e}"));
    let cell = world.cell(0).unwrap();
    let ledger = cell.ledger().unwrap();
    let (proposal, lead, programme) = newest_draft(&ledger).expect("the cycle drafted");

    // The cell recorded the issue, and the record names no country.
    let issued: Vec<&ReleaseRecord> = ledger
        .iter()
        .filter_map(|e| match &e.record {
            CellRecord::Release(r @ ReleaseRecord::TicketIssued { kind, .. })
                if *kind == WRITE_KIND_COUNTRY_STATED =>
            {
                Some(r)
            }
            _ => None,
        })
        .collect();
    assert_eq!(issued.len(), 1, "one country ticket issue: {issued:?}");
    assert!(
        matches!(
            issued[0],
            ReleaseRecord::TicketIssued { proposal: p, holder, .. }
                if *p == proposal.raw() && *holder == lead
        ),
        "the issue names the draft and its lead: {:?}",
        issued[0]
    );

    // Non-vacuity: the vault holds the country.
    assert_eq!(
        cell.vault_country(lead, programme).unwrap(),
        Some(code),
        "the vault holds the stated country"
    );
    let vault = world.cluster(ClusterKind::Vault).expect("a vault cluster");
    let rows = vault
        .server()
        .psql(
            &cell.vault_database(),
            &format!(
                "SELECT count(*) FROM vault.fact WHERE kind = 1 AND subject = '{}'",
                uuid_text(lead.raw())
            ),
        )
        .unwrap();
    assert_eq!(
        rows, "1",
        "the vault database holds one sealed country fact"
    );

    // The scan of the application and control-plane databases.
    let owners: Vec<_> = world
        .databases()
        .unwrap()
        .into_iter()
        .filter(|d| matches!(d.kind, ClusterKind::Application | ClusterKind::Control))
        .collect();
    let mut stores = StoreSet::default();
    for (name, bytes) in world.stores().unwrap().stores {
        if owners.iter().any(|d| d.owns(&name)) {
            stores.push(name, bytes);
        }
    }
    let app_dump = owners
        .iter()
        .find(|d| d.name == cell.app_database())
        .map(|d| format!("{}/dump/{}", d.cluster, d.name))
        .expect("the cell's application database");
    assert!(
        stores
            .stores
            .iter()
            .any(|(n, b)| *n == app_dump && !b.is_empty()),
        "the application database dump {app_dump} is in the scan"
    );
    assert!(
        owners.iter().any(|d| d.kind == ClusterKind::Control),
        "a control-plane database is in the scan"
    );
    let body = write_body(lead, programme, code);
    let report = scan_bytes(&stores, &country_needles(&body, code)).unwrap();
    assert!(report.is_clean(), "I-86, R-NG-01: {:?}", report.hits);
    let report = scan(&stores, std::slice::from_ref(&canary)).unwrap();
    assert!(report.is_clean(), "I-86, R-NG-01: {:?}", report.hits);
}

/// I-86 teeth: the scan of `i86_declared_country_never_reaches_app_tables`
/// finds the country write body as a `bytea` value in a dump row, and the
/// country member inside a `jsonb` text, so a cell that stored either
/// would fail it.
#[test]
fn i86_teeth_country_in_app_tables_is_caught() {
    let lead = AccountId::from_raw(0x5a5a);
    let programme = ProgrammeId::from_raw(0x7b7b);
    let code = 917;
    let body = write_body(lead, programme, code);
    let hex: String = body.iter().map(|b| format!("{b:02x}")).collect();
    let mut stores = StoreSet::default();
    stores.push(
        "application/dump/c_teeth",
        format!("COPY cell.leak (id, body) FROM stdin;\n1\t\\\\x{hex}\n\\.\n").into_bytes(),
    );
    stores.push(
        "application/data/base/1/16384",
        format!("{{\"note\":\"x\",\"country\":{code},\"y\":1}}").into_bytes(),
    );
    let report = scan_bytes(&stores, &country_needles(&body, code)).unwrap();
    let hit = |store: &str, label: &str| report.hits.iter().any(|(s, l)| s == store && l == label);
    assert!(
        hit("application/dump/c_teeth", "the country write body"),
        "teeth: the stored write body went unseen: {:?}",
        report.hits
    );
    assert!(
        hit("application/data/base/1/16384", "the country member"),
        "teeth: the stored country member went unseen: {:?}",
        report.hits
    );
}
