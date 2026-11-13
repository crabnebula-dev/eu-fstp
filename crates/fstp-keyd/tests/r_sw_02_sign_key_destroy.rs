//! R-SW-02, ADR-004 "CA keys in custody", I-80: the `KeydCustody` client
//! asks `fstp-keyd` to destroy a CA sign key over its socket. Lane
//! m3/erase-cell-2.
//!
//! The request is not one of the six `Custody` operations. The server
//! applies the sign rules of the socket: the `fstp-cell` socket reaches
//! cell CA handles only. Interim, pending Daniel: the server holds no
//! sign key yet, so a permitted destroy answers `NoSignKey` and issues
//! no receipt.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code"
)]

mod common;

use common::running;
use fstp_custody::keyd::{MAX_HANDLE_LEN, SIGN_KEY_CELL_CA, SIGN_KEY_CLUSTER_CA};
use fstp_custody::{
    BackendId, Chain, Custody, CustodyError, CustodyHandle, Epoch, Refusal, RootLabel, SignKeyRef,
};
use fstp_rt::future::block_on;

fn key(backend: BackendId, handle: &[u8]) -> SignKeyRef {
    SignKeyRef {
        backend,
        handle: CustodyHandle(handle.to_vec()),
    }
}

/// R-SW-02, R-NF-08: over the cell socket, a cell CA handle finds no sign
/// key, a cluster CA handle is not permitted, a key of another backend or
/// a handle above the limit never leaves the client, and the cell's
/// roots stay usable.
#[test]
fn r_sw_02_keyd_client_destroys_sign_keys_by_the_socket_rules() {
    let (_scratch, client) = running("destroy-sign-key");
    let root = block_on(client.create_root(RootLabel {
        cell: None,
        chain: Chain::App,
        epoch: Epoch(1),
    }))
    .unwrap();
    assert_eq!(
        block_on(client.destroy_sign_key(&key(BackendId::Keyd, &[SIGN_KEY_CELL_CA, b'c']))),
        Err(CustodyError::Refused(Refusal::NoSignKey))
    );
    assert_eq!(
        block_on(client.destroy_sign_key(&key(BackendId::Keyd, &[SIGN_KEY_CLUSTER_CA, b'p']))),
        Err(CustodyError::Refused(Refusal::NotPermitted))
    );
    assert!(matches!(
        block_on(client.destroy_sign_key(&key(BackendId::Okms, &[SIGN_KEY_CELL_CA, b'c']))),
        Err(CustodyError::InvalidConfig(_))
    ));
    assert!(matches!(
        block_on(client.destroy_sign_key(&key(
            BackendId::Keyd,
            &[SIGN_KEY_CELL_CA; MAX_HANDLE_LEN + 1]
        ))),
        Err(CustodyError::Protocol(_))
    ));
    assert!(block_on(client.destroy(&root)).is_ok());
}
