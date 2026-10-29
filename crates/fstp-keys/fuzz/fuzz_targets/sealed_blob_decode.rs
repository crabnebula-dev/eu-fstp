//! Fuzz target `sealed_blob_decode` of `fstp-keys` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: no panic; accepted input re-encodes byte for byte; a
//! mutated byte never opens.
//!
//! Every accepted input must hold the `FSB1` header, a nonce and a tag,
//! and must re-encode byte for byte. For "a mutated byte never opens",
//! the target seals one blob once, then changes the byte and value the
//! input's first three bytes name, and checks that the result never
//! decodes and opens.

#![no_main]

use std::sync::OnceLock;

use fstp_keys::envelope::{
    DataKey, MIN_BLOB_LEN, SealContext, decode_sealed_blob, encode_sealed_blob, open_blob,
    seal_blob,
};
use fstp_keys::{CellId, Chain, GroupId, ObjectId, Purpose};
use libfuzzer_sys::fuzz_target;

const CTX: SealContext = SealContext {
    cell: CellId([1; 16]),
    chain: Chain::Vault,
    purpose: Purpose::Fact,
    group: GroupId([2; 16]),
    generation: 3,
    object: ObjectId([4; 16]),
};

/// One data key and one blob sealed under it, made once.
fn sealed() -> &'static (DataKey, Vec<u8>) {
    static ONCE: OnceLock<(DataKey, Vec<u8>)> = OnceLock::new();
    ONCE.get_or_init(|| {
        let dek = DataKey::from_bytes(&[5; 32]).unwrap_or_else(|_| std::process::abort());
        let blob = seal_blob(&dek, &CTX, b"a synthetic fuzz plaintext")
            .unwrap_or_else(|_| std::process::abort());
        let bytes = encode_sealed_blob(&blob).unwrap_or_else(|_| std::process::abort());
        (dek, bytes)
    })
}

fuzz_target!(|data: &[u8]| {
    match decode_sealed_blob(data) {
        Ok(blob) => {
            assert!(
                data.len() >= MIN_BLOB_LEN,
                "accepted a blob with no header, nonce and tag"
            );
            assert_eq!(data.get(0..4), Some(&b"FSB1"[..]), "accepted another magic");
            let again = encode_sealed_blob(&blob);
            assert_eq!(again.as_deref().ok(), Some(data), "not one spelling");
        }
        Err(e) => assert!(!format!("{e:?}").is_empty()),
    }
    if let [hi, lo, flip, ..] = *data {
        let (dek, bytes) = sealed();
        let at = usize::from(u16::from_be_bytes([hi, lo])) % bytes.len().max(1);
        let mut m = bytes.clone();
        if let Some(b) = m.get_mut(at) {
            *b ^= flip.max(1);
        }
        let opened = decode_sealed_blob(&m)
            .ok()
            .and_then(|b| open_blob(dek, &CTX, &b).ok());
        assert!(opened.is_none(), "a blob with byte {at} changed opened");
    }
});
