//! Fuzz target `update_query_decode` of `fstp-release-svc` (TH-26, H-05,
//! M3 design sections 10.1 and 15, I-38).
//!
//! Design checks: only the permitted grammar.
//!
//! Every accepted input must be exactly the bytes that
//! `fstp_release::egress::encode` gives for the decoded channel and
//! version. The only channel is stable, code 1 in the crate tests. Mode 1
//! builds a valid query from the input, then applies one edit. The W0
//! stubs refuse everything, which these checks allow.

#![no_main]

use fstp_release::egress::{Channel, CnCall, ProductVersion, UpdateCheck, encode};
use fstp_release_svc::decode_update_query;
use libfuzzer_sys::fuzz_target;

/// The closed code of the stable channel (see the crate tests).
const STABLE_CODE: u8 = 1;

fn call(v: (u16, u16, u16)) -> CnCall {
    CnCall::Update(UpdateCheck {
        version: ProductVersion(v.0, v.1, v.2),
        channel: Channel::Stable,
    })
}

/// A valid query from the first 6 bytes, then one edit from the next
/// three.
fn near_grammar(data: &[u8]) -> Option<Vec<u8>> {
    let u = |i: usize| -> Option<u16> {
        Some(u16::from_be_bytes(data.get(i..i + 2)?.try_into().ok()?))
    };
    let mut bytes = encode(&call((u(0)?, u(2)?, u(4)?))).ok()?;
    if let Some(edit) = data.get(6..9) {
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
    let result = decode_update_query(&bytes);
    assert!(!format!("{result:?}").is_empty());
    if let Ok(q) = result {
        assert_eq!(q.channel, STABLE_CODE, "a channel outside the closed set");
        let again = encode(&call(q.version));
        assert_eq!(
            again.ok(),
            Some(bytes),
            "accepted bytes outside the template"
        );
    }
});
