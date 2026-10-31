//! Review reproducers for lane W1g (I-38, TH-32): test strength.
//!
//! Each test fails against the current lane tests and passes once the
//! named defect is fixed. Each copies the predicate of the lane test it
//! reviews, since that predicate is private to its test binary.
//!
//! Fix round 1: lane W1g fixed both defects in the lane tests and
//! updated each copy below to the fixed predicate. The rollback test now
//! judges a stateful acceptor over sequences, and the witness test now
//! judges joined streams.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::egress::{Component, Direction, EgressLog, Endpoint, Peer, Route};
use fstp_celltest::reference::licence::{
    self as r, DAY_S, MetadataStore, RefCall, RefChannel, RefHosts, RefLicenceId, RefMetadata,
    RefVersion,
};
use fstp_celltest::scan::StoreSet;
use fstp_domain_testkit::harness::teeth::expect_prop_failure;
use fstp_prop::Gen;

// ---------------------------------------------------------------------------
// TH-32: the rollback test has no teeth against production.

const NOW: i64 = 1_800_000_000;

fn gen_metadata(g: &mut Gen, seq: u64, expires_at: i64) -> RefMetadata {
    let mut sha = [0u8; 32];
    for b in &mut sha {
        *b = g.u8();
    }
    RefMetadata {
        channel: RefChannel::Stable,
        seq,
        version: RefVersion {
            major: g.u16_in(0..=3),
            minor: g.u16(),
            patch: g.u16(),
        },
        expires_at,
        artifact_sha256: sha,
    }
}

type Step = (Vec<u8>, i64);

/// The property body of `th_32_t_update_rollback_and_expired_metadata_refused`
/// (`store_two_way`), over a stand-in for production's acceptor.
fn rollback_property(
    prod: impl Fn(&[Step]) -> Result<Vec<bool>, String>,
    g: &mut Gen,
) -> Result<(), String> {
    let mut store = MetadataStore::default();
    let mut now = NOW;
    let mut seen: Vec<RefMetadata> = Vec::new();
    let mut steps: Vec<Step> = Vec::new();
    let mut want = Vec::new();
    for _ in 0..g.usize_in(1..=6) {
        now += g.i64_in(0..=DAY_S);
        let m = match (seen.is_empty(), g.u8_in(0..=3)) {
            (false, 0) => *g.pick(seen.as_slice()),
            (false, 1) => {
                let mut m = *g.pick(seen.as_slice());
                m.artifact_sha256[0] ^= 1;
                m
            }
            _ => {
                let seq = g.u64_in(0..=8);
                let expires_at = now + g.i64_in(-2..=2);
                gen_metadata(g, seq, expires_at)
            }
        };
        let verdict = store.accept_with(&m, true, now);
        want.push(verdict.is_ok());
        if let Ok(next) = verdict {
            store = next;
        }
        seen.push(m);
        steps.push((r::metadata_bytes(&m, &[0; r::METADATA_SIG_LEN]), now));
    }
    let got = prod(&steps)?;
    if got == want {
        Ok(())
    } else {
        Err(format!(
            "TH-32: production accepted {got:?}, the reference {want:?}, over {seen:?}"
        ))
    }
}

/// TH-32, design section 10.3 ("The cell stores the highest metadata
/// version it has seen and refuses older or expired metadata"). A W2j
/// production with no metadata store at all: it accepts any well-framed
/// metadata, rollback or expired. Its `may_apply` would be false as M3
/// requires, but that no longer counts as a refusal of rollback.
/// `th_32_t_update_rollback_and_expired_metadata_refused` must catch it.
#[test]
fn review_th32_rollback_test_catches_production_without_rollback_check() {
    let outcome = fstp_prop::run(
        "review_th32_rollback_test_catches_production_without_rollback_check",
        fstp_prop::Config::default(),
        |g: &mut Gen| {
            rollback_property(
                |steps| {
                    // decode_release_metadata accepts by framing alone, so
                    // a rolled-back or expired version is accepted.
                    Ok(steps
                        .iter()
                        .map(|(bytes, _)| r::metadata_fields(bytes).is_some())
                        .collect())
                },
                g,
            )
        },
    );
    expect_prop_failure(&outcome, "TH-32").unwrap();
}

// ---------------------------------------------------------------------------
// I-38: the witness test judges one write at a time.

/// The outbound streams to CrabNebula hosts, as `crabnebula_streams`.
fn crabnebula_streams(log: &EgressLog) -> StoreSet {
    let all = log.store_set_where(|route| route.to == Peer::CrabNebula);
    StoreSet {
        stores: all
            .stores
            .into_iter()
            .filter(|(name, _)| name.ends_with("/out"))
            .collect(),
    }
}

/// The judgment of `i38_self_hosted_witness_never_targets_crabnebula`
/// (`off_template_streams`).
fn off_template_streams(log: &EgressLog, hosts: &RefHosts) -> Vec<String> {
    let foreign = log.store_set_where(|route| {
        route.to == Peer::CrabNebula && route.from.component != Component::Cell
    });
    let mut out: Vec<String> = foreign.stores.into_iter().map(|(name, _)| name).collect();
    out.extend(
        crabnebula_streams(log)
            .stores
            .into_iter()
            .filter(|(_, bytes)| r::split_requests(bytes, hosts).is_err())
            .map(|(name, _)| name),
    );
    out
}

/// I-38, `i38_self_hosted_witness_never_targets_crabnebula`: a correct
/// cell writes the licence refresh template in two writes, its headers and
/// then its body, or the TLS stream takes it in two partial writes. The
/// recorder keeps one capture per write. The witness test splits each
/// capture on its own, so it reports this correct request as an anchor or
/// another payload. Over-denial: it must judge the joined stream, as
/// `i38_self_hosted_captures_match_the_templates` does.
#[test]
fn review_i38_witness_test_accepts_a_template_written_in_two_writes() {
    let hosts = RefHosts {
        update: "updates.example.test".to_owned(),
        licence: "licences.example.test".to_owned(),
    };
    let call = RefCall::Licence {
        licence: RefLicenceId([0x4c; 16]),
        version: RefVersion {
            major: 1,
            minor: 2,
            patch: 3,
        },
    };
    let bytes = r::request(&call, &hosts);
    let cut = bytes.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let log = EgressLog::new();
    let route = Route::new(Endpoint::cell(0), Peer::CrabNebula, None);
    log.record(route, Direction::Outbound, 1, &bytes[..cut]);
    log.record(route, Direction::Outbound, 1, &bytes[cut..]);
    let off_template = off_template_streams(&log, &hosts);
    assert!(
        off_template.is_empty(),
        "I-38: the witness test flags a correct refresh written in two writes: {off_template:?}"
    );
}
