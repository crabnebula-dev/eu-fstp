//! R-SW-02, I-81, ADR-004 "Decided by Daniel, 2026-11-15 (late)": the key
//! table of `fstp-keyd` holds sign-key slots beside the root slots. The
//! install creates the local cluster CA sign keys there, `fstp-pgagent`
//! signs with them, and a cell erasure destroys a CA key through
//! `SignKeyCustody` for `KeydCustody`, which overwrites the key in place.
//! Lane m3/erase-prod.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fstp_control::erase::SignKeyCustody;
use fstp_control::install::{cluster_ca_key, create_cluster_ca_keys};
use fstp_control::placement::ClusterId;
use fstp_custody::keyd::decode_sign_receipt;
use fstp_custody::{Custody, CustodyError, KeydCustody, Refusal};
use fstp_keyd::{ClientRole, ClientSocket, PassphraseSource};
use fstp_rt::future::block_on;

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A running `fstp-keyd` with a console socket and a pgagent socket, and
/// a client of each.
fn keyd() -> (Scratch, PathBuf, KeydCustody, KeydCustody) {
    let dir = std::env::temp_dir().join(format!("fstp-control-keyd-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let volume = dir.join("volume");
    std::fs::create_dir_all(&volume).unwrap();
    let console = dir.join("console.sock");
    let pgagent = dir.join("pgagent.sock");
    {
        let sockets = vec![
            ClientSocket::owner_only(&console, ClientRole::Console),
            ClientSocket::owner_only(&pgagent, ClientRole::PgAgent),
        ];
        let volume = volume.clone();
        std::thread::spawn(move || {
            let _ = fstp_keyd::serve_sockets(&sockets, &volume, PassphraseSource::Credential);
        });
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    while !(console.exists() && pgagent.exists()) {
        assert!(Instant::now() < deadline, "fstp-keyd bound no sockets");
        std::thread::sleep(Duration::from_millis(10));
    }
    let c = KeydCustody::new(&console).unwrap();
    let p = KeydCustody::new(&pgagent).unwrap();
    (Scratch(dir), volume, c, p)
}

fn files(volume: &Path) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(volume)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("sign-"))
        .collect();
    out.sort();
    out
}

/// R-SW-02, I-81, ADR-004 (2026-11-15 late): the install creates one
/// cluster CA key per local cluster in `fstp-keyd`, over the console
/// socket, and a retried install finds the same keys. The pgagent socket
/// signs a digest with each, which verifies under the public key the
/// install got. A cell erasure destroys one through `SignKeyCustody` for
/// `KeydCustody`: the receipt names the key and every destroy step, its
/// file is gone, it signs no more, and the other key still signs.
#[test]
fn r_sw_02_install_creates_cluster_ca_keys_that_erasure_destroys_in_keyd() {
    let (_scratch, volume, console, pgagent) = keyd();
    let clusters = [ClusterId([0xa1; 16]), ClusterId([0xb2; 16])];
    let keys = block_on(create_cluster_ca_keys(&console, &clusters)).unwrap();
    assert_eq!(keys.len(), 2);
    assert_ne!(keys[0].0, keys[1].0);
    assert_eq!(keys[0].0, cluster_ca_key(clusters[0]));
    assert_eq!(
        block_on(create_cluster_ca_keys(&console, &clusters)).unwrap(),
        keys
    );
    assert_eq!(files(&volume).len(), 2);
    let message = b"cluster CA certificate body";
    let digest = fstp_crypto::sha256(message);
    for (key, spki) in &keys {
        let sig = block_on(pgagent.sign(key, &digest)).unwrap();
        assert!(fstp_crypto::sig::ecdsa_p256_sha256_verify(spki, message, &sig.0).is_ok());
    }
    assert_eq!(
        block_on(console.sign(&keys[0].0, &digest)),
        Err(CustodyError::Refused(Refusal::NotPermitted)),
        "the console socket signed with a cluster CA key"
    );
    let receipt = block_on(SignKeyCustody::destroy_sign_key(&pgagent, &keys[0].0)).unwrap();
    let decoded = decode_sign_receipt(&receipt.0).unwrap();
    assert_eq!(decoded.handle, keys[0].0.handle.0);
    assert_eq!(decoded.steps, fstp_custody::keyd::DestroyStep::ALL.to_vec());
    assert_eq!(
        files(&volume).len(),
        1,
        "the destroyed key's file is still there"
    );
    assert_eq!(
        block_on(pgagent.sign(&keys[0].0, &digest)),
        Err(CustodyError::Refused(Refusal::Destroyed))
    );
    assert_eq!(
        block_on(create_cluster_ca_keys(&console, &clusters[..1])),
        Err(fstp_control::ControlError::Custody(CustodyError::Refused(
            Refusal::Destroyed
        ))),
        "a destroyed cluster CA key was created again"
    );
    assert!(block_on(pgagent.sign(&keys[1].0, &digest)).is_ok());
}
