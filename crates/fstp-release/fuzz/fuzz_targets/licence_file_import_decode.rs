//! Fuzz target `licence_file_import_decode` of `fstp-release` (TH-26,
//! H-05, M3 design section 15, Q41).
//!
//! Design checks: no panic; signature checked before use.
//!
//! The decoder only unwraps the armour. The signature is checked next by
//! `verify_token`, which `licence_token_decode` fuzzes. Mode 0 passes
//! the rest as a file. Mode 1 armours the rest as a token. Every accepted
//! file must be exactly the armour of a token of the token length, so
//! the file has one spelling (W1g file proposal). Once lane W2j lands the
//! decoder, the armour of any token of that length must decode to it.

#![no_main]

use fstp_release::ReleaseError;
use fstp_release::licence::decode_licence_file;
use libfuzzer_sys::fuzz_target;

const BEGIN: &str = "-----BEGIN FSTP LICENCE-----\n";
const END: &str = "-----END FSTP LICENCE-----\n";
const TOKEN_LEN: usize = 113;

fn base64(bytes: &[u8]) -> String {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let n = b0 << 16 | b1 << 8 | b2;
        for i in 0..4usize {
            if i <= chunk.len() {
                out.push(char::from(B64[((n >> (18 - 6 * i)) & 0x3f) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn armour(token: &[u8]) -> Vec<u8> {
    format!("{BEGIN}{}\n{END}", base64(token)).into_bytes()
}

fuzz_target!(|data: &[u8]| {
    let Some((mode, rest)) = data.split_first() else {
        return;
    };
    let file = if mode & 1 == 0 {
        rest.to_vec()
    } else {
        armour(rest)
    };
    let result = decode_licence_file(&file);
    assert!(!format!("{result:?}").is_empty());
    match result {
        Ok(token) => {
            assert_eq!(token.len(), TOKEN_LEN, "accepted a token of another length");
            assert_eq!(armour(&token), file, "accepted a second spelling");
        }
        Err(ReleaseError::NotImplemented(_)) => {}
        #[allow(unreachable_patterns)]
        Err(_) => {
            assert!(
                !(mode & 1 == 1 && rest.len() == TOKEN_LEN),
                "refused the armour of a token"
            );
        }
    }
});
