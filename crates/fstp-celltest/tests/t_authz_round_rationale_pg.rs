//! The cut-off round of a PostgreSQL test world names a rationale that the
//! cell's text store holds (R-EV-08, T-AUTHZ-MATRIX, CI run 45507712676).
//!
//! `committee.round` reads the round's rationale back from the text store
//! under the read's clearance, which is cleared on the round's call, and
//! fails closed on a text the store does not give (`fstp_api_core`
//! `stored_text`). A world that opens its round with a core command
//! therefore stores the rationale first, as the API core stores the text
//! of a round opened through its route: a confidential text of the call's
//! programme, named by its SHA-256 digest. Before this lane the PostgreSQL
//! matrix world named a synthetic reference that no store holds, so the
//! delegating committee member's `committee.round` cell answered
//! `Refused("text")` where the reference expects `Allow`. Every text here
//! is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing)]

use fstp_celltest::world::{DbMode, VaultLayout, World, WorldSpec};
use fstp_domain::id::{AccountId, CallId, ContentDigest, DecisionId, ProposalId};
use fstp_domain_testkit::r#gen::roster::P1;

/// The class byte of a confidential text in the cell's 18-byte text
/// header (`fstp_cell::api::content`).
const CONFIDENTIAL: u8 = 1;

/// The owner kind byte of a programme's text in the same header.
const PROGRAMME_OWNER: u8 = 2;

/// R-EV-08, I-17, T-AUTHZ-MATRIX (CI run 45507712676): the round a world
/// opens with `cycle::cut_off_round` names a rationale that the cell's
/// text store holds as a confidential text of the call's programme. Its
/// body matches the digest the round names, so a `committee.round` read
/// cleared on the call, such as the delegating member's, opens it.
#[test]
fn r_ev_08_t_authz_pg_world_round_rationale_is_stored_for_the_round_read() {
    let world = World::start_with_api(WorldSpec {
        cells: 1,
        mode: DbMode::Shared,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: false,
        process_mode: false,
    })
    .unwrap_or_else(|e| panic!("{e}"));
    let cell = world.cell(0).unwrap();
    let round = DecisionId::from_raw(4_101);
    let cmd = fstp_celltest::cycle::cut_off_round(
        cell,
        AccountId::from_raw(4_102),
        round,
        CallId::from_raw(4_103),
        P1,
        vec![ProposalId::from_raw(4_104), ProposalId::from_raw(4_105)],
        1,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let fstp_domain::Command::OpenCutOffRound {
        round: opened,
        rationale,
        tie_breaks,
        ..
    } = cmd
    else {
        panic!("cut_off_round gave {cmd:?}");
    };
    assert_eq!(opened, round);
    assert!(tie_breaks.is_none(), "the world's round has no tie-break");
    let plain = cell
        .open_text(rationale.id().raw().to_be_bytes())
        .unwrap()
        .expect("R-EV-08: the cell's text store does not hold the round's rationale");
    assert!(plain.len() > 18, "the stored rationale has no body");
    assert_eq!(plain[0], CONFIDENTIAL, "the rationale is confidential");
    assert_eq!(plain[1], PROGRAMME_OWNER, "the call's programme owns it");
    assert_eq!(plain[2..18], P1.raw().to_be_bytes(), "the programme is P1");
    let body = &plain[18..];
    assert!(std::str::from_utf8(body).is_ok(), "the rationale is text");
    assert_eq!(
        ContentDigest::from_bytes(fstp_crypto::sha256(body)),
        rationale.digest(),
        "the round names the digest of the stored rationale"
    );
}
