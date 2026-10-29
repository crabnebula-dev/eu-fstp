//! Shared parts of the `fstp-webauthn` fuzz targets (TH-26, design
//! section 15): an input reader, an independent CBOR writer, the checks
//! on decoded CBOR, and valid registration and assertion ceremonies to
//! mutate. The writer only writes, so the targets hold no second reader.

#![allow(dead_code, reason = "each fuzz target uses a different part")]

use fstp_crypto::sig::Ed25519SigningKey;
use fstp_webauthn::cbor::Item;
use fstp_webauthn::{
    AssertionExpect, AssertionResponse, CoseKey, RegistrationExpect, RegistrationResponse,
    RelyingParty, StoredCredential,
};

/// ADR-008: the CBOR input limit.
pub const MAX_INPUT: usize = 64 * 1024;
/// ADR-008: the CBOR depth limit (a scalar is depth 0).
pub const MAX_DEPTH: usize = 4;

/// The cell host of the ceremonies.
pub const HOST: &str = "c0ffee.cells.fstp.example";
/// The challenge of the ceremonies.
pub const CHALLENGE: [u8; 32] = [0x52; 32];
/// The credential id of the ceremonies.
pub const CRED_ID: [u8; 32] = [0xc1; 32];
/// The UP flag.
pub const UP: u8 = 0x01;
/// The UV flag.
pub const UV: u8 = 0x04;
/// The AT flag.
pub const AT: u8 = 0x40;
/// The ED flag.
pub const ED: u8 = 0x80;

/// Reads fields from the front of the fuzz input. An exhausted input
/// reads as zeros.
pub struct Input<'a>(pub &'a [u8]);

impl<'a> Input<'a> {
    pub fn byte(&mut self) -> u8 {
        let (b, rest) = self.0.split_first().map_or((0, &[][..]), |(b, r)| (*b, r));
        self.0 = rest;
        b
    }

    pub fn take(&mut self, n: usize) -> &'a [u8] {
        let n = n.min(self.0.len());
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        head
    }

    pub fn u16(&mut self) -> u16 {
        u16::from_le_bytes([self.byte(), self.byte()])
    }

    pub fn u32(&mut self) -> u32 {
        u32::from_le_bytes([self.byte(), self.byte(), self.byte(), self.byte()])
    }
}

/// A CBOR head in shortest form (RFC 8949 section 3).
pub fn head(out: &mut Vec<u8>, major: u8, v: u64) {
    let m = major << 5;
    if v < 24 {
        out.push(m | v as u8);
    } else if v <= u64::from(u8::MAX) {
        out.push(m | 24);
        out.push(v as u8);
    } else if v <= u64::from(u16::MAX) {
        out.push(m | 25);
        out.extend_from_slice(&(v as u16).to_be_bytes());
    } else if v <= u64::from(u32::MAX) {
        out.push(m | 26);
        out.extend_from_slice(&(v as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&v.to_be_bytes());
    }
}

/// The shortest definite encoding of `item`.
pub fn encode(item: &Item) -> Vec<u8> {
    let mut out = Vec::new();
    write(&mut out, item);
    out
}

fn write(out: &mut Vec<u8>, item: &Item) {
    match item {
        Item::Unsigned(v) => head(out, 0, *v),
        Item::Negative(n) => head(out, 1, *n),
        Item::Bytes(b) => {
            head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Item::Text(s) => {
            head(out, 3, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
        }
        Item::Array(items) => {
            head(out, 4, items.len() as u64);
            for i in items {
                write(out, i);
            }
        }
        Item::Map(pairs) => {
            head(out, 5, pairs.len() as u64);
            for (k, v) in pairs {
                write(out, k);
                write(out, v);
            }
        }
    }
}

/// The container depth of `item`.
pub fn depth(item: &Item) -> usize {
    match item {
        Item::Array(items) => 1 + items.iter().map(depth).max().unwrap_or(0),
        Item::Map(pairs) => {
            1 + pairs
                .iter()
                .map(|(k, v)| depth(k).max(depth(v)))
                .max()
                .unwrap_or(0)
        }
        _ => 0,
    }
}

/// Whether any map in `item` repeats a key.
pub fn has_duplicate_key(item: &Item) -> bool {
    match item {
        Item::Array(items) => items.iter().any(has_duplicate_key),
        Item::Map(pairs) => {
            pairs
                .iter()
                .enumerate()
                .any(|(i, (k, _))| pairs.iter().take(i).any(|(seen, _)| seen == k))
                || pairs
                    .iter()
                    .any(|(k, v)| has_duplicate_key(k) || has_duplicate_key(v))
        }
        _ => false,
    }
}

/// Panics unless an accepted `input` meets ADR-008: at most 64 KiB,
/// depth at most 4, no repeated key, and the shortest definite encoding
/// of the item is the input byte for byte.
pub fn assert_canonical(input: &[u8], item: &Item) {
    assert!(input.len() <= MAX_INPUT, "accepted {} bytes", input.len());
    assert!(depth(item) <= MAX_DEPTH, "accepted depth {}", depth(item));
    assert!(!has_duplicate_key(item), "accepted a repeated key");
    assert_eq!(encode(item), input, "accepted a non-canonical spelling");
}

/// Base64url without padding.
pub fn b64url(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0);
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = u32::from(b0) << 16 | u32::from(b1) << 8 | u32::from(b2);
        for shift in [18u32, 12, 6, 0].into_iter().take(chunk.len() + 1) {
            out.push(char::from(A[((n >> shift) & 0x3f) as usize]));
        }
    }
    out
}

/// The client data JSON in browser member order.
pub fn client_data(kind: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
    format!(
        "{{\"type\":\"{kind}\",\"challenge\":\"{}\",\"origin\":\"{origin}\",\"crossOrigin\":false}}",
        b64url(challenge)
    )
    .into_bytes()
}

/// The origin of [`HOST`].
pub fn origin() -> String {
    format!("https://{HOST}")
}

/// Authenticator data for [`HOST`] with optional attested credential data.
pub fn auth_data(flags: u8, counter: u32, attested: Option<(&[u8], &[u8])>) -> Vec<u8> {
    let mut out = fstp_crypto::sha256(HOST.as_bytes()).to_vec();
    out.push(flags);
    out.extend_from_slice(&counter.to_be_bytes());
    if let Some((id, cose)) = attested {
        out.extend_from_slice(&[0; 16]);
        out.extend_from_slice(&(id.len() as u16).to_be_bytes());
        out.extend_from_slice(id);
        out.extend_from_slice(cose);
    }
    out
}

/// An Ed25519 COSE_Key.
pub fn ed25519_cose(x: &[u8]) -> Vec<u8> {
    let mut out = vec![0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21];
    head(&mut out, 2, x.len() as u64);
    out.extend_from_slice(x);
    out
}

/// A `none` attestation object.
pub fn none_attestation(auth_data: &[u8]) -> Vec<u8> {
    let mut out = vec![0xa3];
    out.extend_from_slice(&[0x63, b'f', b'm', b't', 0x64, b'n', b'o', b'n', b'e']);
    out.extend_from_slice(&[0x67, b'a', b't', b't', b'S', b't', b'm', b't', 0xa0]);
    out.extend_from_slice(&[0x68, b'a', b'u', b't', b'h', b'D', b'a', b't', b'a']);
    head(&mut out, 2, auth_data.len() as u64);
    out.extend_from_slice(auth_data);
    out
}

/// The relying party of [`HOST`], or `None` while it is refused.
pub fn rp() -> Option<RelyingParty> {
    RelyingParty::new(HOST).ok()
}

/// The fixed Ed25519 credential key.
pub fn key() -> Option<Ed25519SigningKey> {
    Ed25519SigningKey::from_seed(&[0x2a; 32]).ok()
}

/// A valid registration of the fixed key, and what it must match, with
/// UV required when `uv_required` is set.
pub fn registration(uv_required: bool) -> Option<(RegistrationResponse, RegistrationExpect)> {
    let key = key()?;
    let cose = ed25519_cose(&key.public_key());
    let ad = auth_data(UP | UV | AT, 0, Some((&CRED_ID, &cose)));
    let resp = RegistrationResponse {
        client_data_json: client_data("webauthn.create", &CHALLENGE, &origin()),
        attestation_object: none_attestation(&ad),
    };
    let expect = RegistrationExpect {
        rp: rp()?,
        challenge: CHALLENGE,
        user_verification: uv_required,
    };
    Some((resp, expect))
}

/// A valid assertion of the fixed key with counter `counter`, its stored
/// credential with `stored`, and what it must match.
pub fn assertion(
    counter: u32,
    stored: u32,
    uv_required: bool,
) -> Option<(AssertionResponse, StoredCredential, AssertionExpect)> {
    let key = key()?;
    let ad = auth_data(UP | UV, counter, None);
    let cd = client_data("webauthn.get", &CHALLENGE, &origin());
    let mut message = ad.clone();
    message.extend_from_slice(&fstp_crypto::sha256(&cd));
    let signature = key.sign(&message).ok()?.to_vec();
    let resp = AssertionResponse {
        credential_id: CRED_ID.to_vec(),
        client_data_json: cd,
        authenticator_data: ad,
        signature,
    };
    let cred = StoredCredential {
        id: CRED_ID.to_vec(),
        key: CoseKey::Ed25519 {
            x: key.public_key(),
        },
        sign_count: stored,
    };
    let expect = AssertionExpect {
        rp: rp()?,
        challenge: CHALLENGE,
        user_verification: uv_required,
    };
    Some((resp, cred, expect))
}

/// Applies up to eight edits from `input` to `bytes`: each edit is a
/// kind byte, a position and a value. Kinds: xor a byte, drop a byte,
/// insert a byte, truncate.
pub fn mutate(input: &mut Input<'_>, bytes: &mut Vec<u8>) {
    let edits = input.byte() % 9;
    for _ in 0..edits {
        let kind = input.byte() % 4;
        let at = usize::from(input.u16());
        let v = input.byte();
        match kind {
            0 if !bytes.is_empty() => {
                let i = at % bytes.len();
                bytes[i] ^= v.max(1);
            }
            1 if !bytes.is_empty() => {
                let i = at % bytes.len();
                bytes.remove(i);
            }
            2 => {
                let i = at % (bytes.len() + 1);
                bytes.insert(i, v);
            }
            3 if !bytes.is_empty() => {
                let i = at % bytes.len();
                bytes.truncate(i);
            }
            _ => {}
        }
    }
}
