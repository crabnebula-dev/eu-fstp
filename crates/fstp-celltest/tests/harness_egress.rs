//! Self-tests of the egress recorder (M3 design section 14.3, lane W1a).
//! Written by the W1a implementer. The recorder is the instrument of the
//! I-16, I-19 and I-38 egress scans, so a canary that crosses a recorded
//! connection must be found, even when two writes split it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_celltest::canary::{Canary, CanaryKind};
use fstp_celltest::egress::{Component, Direction, EgressLog, Endpoint, Peer, Route};
use fstp_celltest::scan::scan;
use fstp_rt::IoExt as _;
use fstp_rt::future::block_on;

/// Design section 14.3: bytes written and read through a recorded
/// connection are captured with their peer and direction, and a canary
/// split across two writes is found in the joined outbound stream.
#[test]
fn harness_egress_finds_a_canary_split_across_writes() {
    let log = EgressLog::new();
    let (mut cell, mut vault) =
        log.connect(Route::new(Endpoint::cell(0), Peer::Vault, Some(0)), 64);
    let canary = Canary::generate(2, CanaryKind::Email).unwrap();
    let text = canary.text();
    let (head, tail) = text.as_bytes().split_at(10);
    block_on(async {
        cell.write_all(head).await.unwrap();
        cell.write_all(tail).await.unwrap();
        let mut got = vec![0u8; text.len()];
        vault.read_exact(&mut got).await.unwrap();
        assert_eq!(got, text.as_bytes());
        vault.write_all(b"ok").await.unwrap();
        let mut reply = [0u8; 2];
        cell.read_exact(&mut reply).await.unwrap();
    });
    let captures = log.captures();
    assert!(captures.len() >= 3, "{captures:?}");
    assert!(
        captures
            .iter()
            .all(|c| c.route.to == Peer::Vault && c.connection == 1)
    );
    let inbound: Vec<u8> = captures
        .iter()
        .filter(|c| c.direction == Direction::Inbound)
        .flat_map(|c| c.bytes.clone())
        .collect();
    assert_eq!(inbound, b"ok");
    let report = scan(&log.store_set(), &[canary]).unwrap();
    assert_eq!(
        report.hits,
        vec![("egress/cell-0/vault-0/1/out".to_owned(), text)],
        "{report:?}"
    );
    assert_eq!(log.peers_contacted(), vec![Peer::Vault]);
}

/// Design section 14.3: each connection gets its own number and stores,
/// so a hit names the peer it went to.
#[test]
fn harness_egress_keeps_connections_apart() {
    let log = EgressLog::new();
    let (mut a, mut a_peer) = log.connect(Route::new(Endpoint::cell(0), Peer::Witness, None), 64);
    let (mut b, mut b_peer) =
        log.connect(Route::new(Endpoint::cell(0), Peer::CrabNebula, None), 64);
    let canary = Canary::generate(1, CanaryKind::AccountId).unwrap();
    block_on(async {
        a.write_all(b"anchor").await.unwrap();
        b.write_all(canary.text().as_bytes()).await.unwrap();
        let mut sink = vec![0u8; 6];
        a_peer.read_exact(&mut sink).await.unwrap();
        let mut sink = vec![0u8; canary.text().len()];
        b_peer.read_exact(&mut sink).await.unwrap();
    });
    let report = scan(&log.store_set(), std::slice::from_ref(&canary)).unwrap();
    assert_eq!(
        report.hits,
        vec![("egress/cell-0/crabnebula/2/out".to_owned(), canary.text())]
    );
    assert_eq!(log.peers_contacted(), vec![Peer::Witness, Peer::CrabNebula]);
}

/// Design section 14.3, I-19: captures carry their source and the peer's
/// cell. Cell 0 to its own vault, cell 0 to cell 1's vault, and cell 0's
/// vault to the witness are three routes with three store names. A filter
/// on the source cell keeps exactly what left cell 0 and its vault.
#[test]
fn harness_egress_routes_name_source_and_destination_cells() {
    let log = EgressLog::new();
    let own = Route::new(Endpoint::cell(0), Peer::Vault, Some(0));
    let cross = Route::new(Endpoint::cell(0), Peer::Vault, Some(1));
    let vault = Route::new(Endpoint::vault(0), Peer::Witness, None);
    let other = Route::new(
        Endpoint::shared(Component::ControlPlane),
        Peer::Witness,
        None,
    );
    let (mut a, mut a_peer) = log.connect(own, 64);
    let (mut b, mut b_peer) = log.connect(cross, 64);
    let (mut c, mut c_peer) = log.connect(vault, 64);
    let (mut d, mut d_peer) = log.connect(other, 64);
    block_on(async {
        for (s, p) in [
            (&mut a, &mut a_peer),
            (&mut b, &mut b_peer),
            (&mut c, &mut c_peer),
            (&mut d, &mut d_peer),
        ] {
            s.write_all(b"ping").await.unwrap();
            let mut sink = [0u8; 4];
            p.read_exact(&mut sink).await.unwrap();
        }
    });
    let names = |set: fstp_celltest::scan::StoreSet| -> Vec<String> {
        set.stores.into_iter().map(|(n, _)| n).collect()
    };
    assert_eq!(
        (
            names(log.store_set()),
            names(log.store_set_where(|r| r.from.cell == Some(0))),
            [own, cross, vault, other].map(|r| r.crosses_cells()),
        ),
        (
            vec![
                "egress/cell-0/vault-0/1/out".to_owned(),
                "egress/cell-0/vault-1/2/out".to_owned(),
                "egress/vault-0/witness/3/out".to_owned(),
                "egress/control-plane/witness/4/out".to_owned(),
            ],
            vec![
                "egress/cell-0/vault-0/1/out".to_owned(),
                "egress/cell-0/vault-1/2/out".to_owned(),
                "egress/vault-0/witness/3/out".to_owned(),
            ],
            [false, true, false, false],
        )
    );
}
