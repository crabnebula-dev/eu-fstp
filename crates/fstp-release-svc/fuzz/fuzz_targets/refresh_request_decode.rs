//! Fuzz target `refresh_request_decode` of `fstp-release-svc` (TH-26,
//! H-05, M3 design sections 10.1 and 15, I-38).
//!
//! Design checks: only the permitted grammar.
//!
//! Every accepted input must be exactly the bytes that
//! `fstp_release::egress::encode` gives for the decoded licence id and
//! version, so the service accepts no second spelling and no extra
//! field. Mode 1 builds a valid request from the input, then applies one
//! edit, so the fuzzer works near the grammar. The W0 stubs refuse
//! everything, which these checks allow.

#![no_main]

use fstp_release::egress::{CnCall, LicenceRefresh, ProductVersion, encode};
use fstp_release::licence::LicenceId;
use fstp_release_svc::decode_refresh_request;
use libfuzzer_sys::fuzz_target;

fn call(licence: [u8; 16], v: (u16, u16, u16)) -> CnCall {
    CnCall::Licence(LicenceRefresh {
        licence: LicenceId(licence),
        version: ProductVersion(v.0, v.1, v.2),
    })
}

/// A valid request from the first 22 bytes, then one edit from the next
/// three.
fn near_grammar(data: &[u8]) -> Option<Vec<u8>> {
    let licence: [u8; 16] = data.get(..16)?.try_into().ok()?;
    let u = |i: usize| -> Option<u16> {
        Some(u16::from_be_bytes(data.get(i..i + 2)?.try_into().ok()?))
    };
    let mut bytes = encode(&call(licence, (u(16)?, u(18)?, u(20)?))).ok()?;
    if let Some(edit) = data.get(22..25) {
        let at = usize::from(edit[1]) % (bytes.len() + 1);
        match edit[0] % 3 {
            0 if at < bytes.len() => bytes[at] ^= edit[2] | 1,
            1 => bytes.insert(at, edit[2]),
            _ if at < bytes.len() => {
                bytes.remove(at);
            }
            _ => {}
        }
    }
    Some(bytes)
}

fuzz_target!(|data: &[u8]| {
    let Some((mode, rest)) = data.split_first() else {
        return;
    };
    let bytes = if mode & 1 == 0 {
        rest.to_vec()
    } else {
        match near_grammar(rest) {
            Some(b) => b,
            None => return,
        }
    };
    let result = decode_refresh_request(&bytes);
    assert!(!format!("{result:?}").is_empty());
    if let Ok(r) = result {
        let again = encode(&call(r.licence, r.version));
        assert_eq!(
            again.ok(),
            Some(bytes),
            "accepted bytes outside the template"
        );
    }
});
