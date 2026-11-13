//! The destroy receipt of `fstp-keyd` as the `KeydCustody` client checks
//! it (ADR-004 part 2 "File custody": "The receipt records each step",
//! I-81).
//!
//! A receipt confirms a destroy only when it names the destroyed chain
//! and epoch and lists every step once and in order. The planner records
//! the digest of the receipt it gets (design section 3.5, step 6), so a
//! receipt of another root, or with missing or repeated steps, must not
//! reach it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code"
)]

use fstp_custody::keyd::{DestroyStep, Receipt, decode_receipt};
use fstp_custody::{Chain, Epoch};

/// I-81, ADR-004 part 2: a full receipt round trips, and a receipt with
/// a step missing, repeated, out of order or unknown is refused.
#[test]
fn i81_keyd_receipt_needs_every_step_once_in_order() {
    let full = Receipt::full(Chain::Vault, Epoch(7));
    assert_eq!(decode_receipt(&full.encode()).unwrap(), full);
    let all = DestroyStep::ALL.to_vec();
    let mut lists: Vec<Vec<DestroyStep>> = vec![Vec::new(), vec![DestroyStep::OverwriteKey; 5]];
    for i in 0..all.len() {
        let mut short = all.clone();
        short.remove(i);
        lists.push(short);
        let mut twice = all.clone();
        twice.insert(i, all[i]);
        lists.push(twice);
    }
    let mut swapped = all.clone();
    swapped.swap(1, 2);
    lists.push(swapped);
    let mut wrong = Vec::new();
    for steps in lists {
        let r = Receipt {
            chain: Chain::Vault,
            epoch: Epoch(7),
            steps: steps.clone(),
        };
        if decode_receipt(&r.encode()).is_ok() {
            wrong.push(format!("{steps:?} accepted"));
        }
    }
    let mut unknown = full.encode();
    if let Some(last) = unknown.last_mut() {
        *last = 9;
    }
    if decode_receipt(&unknown).is_ok() {
        wrong.push("an unknown step accepted".to_owned());
    }
    assert!(wrong.is_empty(), "{wrong:?}");
}

/// I-81, ADR-004 part 2: `KeydCustody::destroy` refuses a receipt that
/// names another epoch than the root it destroyed, so the planner never
/// records a receipt that does not confirm this root's destruction. The
/// server here is a stand-in that answers every request with such a
/// receipt.
#[cfg(unix)]
#[test]
fn i81_keyd_client_refuses_a_receipt_of_another_root() {
    use fstp_custody::keyd::{FRAME_HEADER_LEN, KIND_DESTROYED, RootHandle, frame_body_len};
    use fstp_custody::{BackendId, Custody as _, CustodyHandle, KeydCustody, RootRef};
    use std::io::{Read as _, Write as _};
    use std::os::unix::net::UnixListener;

    let dir = std::env::temp_dir().join(format!("fstp-custody-receipt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let socket = dir.join("keyd.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut header = [0u8; FRAME_HEADER_LEN];
        stream.read_exact(&mut header).unwrap();
        let mut body = vec![0u8; frame_body_len(&header).unwrap()];
        stream.read_exact(&mut body).unwrap();
        let receipt = Receipt::full(Chain::App, Epoch(9)).encode();
        let mut b = (receipt.len() as u16).to_be_bytes().to_vec();
        b.extend_from_slice(&receipt);
        let mut frame = b"FKD1".to_vec();
        frame.push(KIND_DESTROYED);
        frame.extend_from_slice(&(b.len() as u32).to_be_bytes());
        frame.extend_from_slice(&b);
        stream.write_all(&frame).unwrap();
    });
    let client = KeydCustody::new(&socket).unwrap();
    let handle = RootHandle {
        chain: Chain::App,
        epoch: Epoch(1),
    };
    let root = RootRef {
        backend: BackendId::Keyd,
        cell: None,
        chain: Chain::App,
        epoch: Epoch(1),
        handle: CustodyHandle(handle.encode().to_vec()),
    };
    let r = fstp_rt::future::block_on(client.destroy(&root));
    server.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        r.is_err(),
        "a receipt of epoch 9 confirmed the destroy of epoch 1"
    );
}

/// R-SW-02, ADR-004 "CA keys in custody", lane m3/erase-cell-2: a sign
/// key receipt round trips, names its handle, and is refused with a step
/// missing, repeated or unknown, an empty or long handle, another magic,
/// a root receipt's bytes, a cut or a trailing byte.
#[test]
fn r_sw_02_keyd_sign_receipt_needs_every_step_and_one_handle() {
    use fstp_custody::keyd::{SignKeyReceipt, decode_sign_receipt};
    let handle = [fstp_custody::keyd::SIGN_KEY_CELL_CA, b'c', b'a'];
    let full = SignKeyReceipt::full(&handle);
    let bytes = full.encode().unwrap();
    assert_eq!(decode_sign_receipt(&bytes).unwrap(), full);
    assert_eq!(full.handle, handle.to_vec());
    let mut bad: Vec<Vec<u8>> = Vec::new();
    for i in 0..DestroyStep::ALL.len() {
        let mut short = full.clone();
        short.steps.remove(i);
        bad.push(short.encode().unwrap());
        let mut twice = full.clone();
        twice.steps.insert(i, DestroyStep::ALL[i]);
        bad.push(twice.encode().unwrap());
    }
    let mut unknown = bytes.clone();
    *unknown.last_mut().unwrap() = 9;
    bad.push(unknown);
    bad.push(SignKeyReceipt::full(&[]).encode().unwrap());
    assert!(SignKeyReceipt::full(&[1; 65]).encode().is_err());
    let mut magic = bytes.clone();
    magic[3] = b'2';
    bad.push(magic);
    bad.push(Receipt::full(Chain::App, Epoch(1)).encode());
    for cut in 0..bytes.len() {
        bad.push(bytes[..cut].to_vec());
    }
    let mut longer = bytes.clone();
    longer.push(0);
    bad.push(longer);
    for b in bad {
        assert!(decode_sign_receipt(&b).is_err(), "{b:02x?}");
    }
}
