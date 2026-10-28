//! Fuzz target `cert_build_roundtrip` of `fstp-pki` (TH-26, H-05, M3 design section 15).
//!
//! Design section 15 says: arbitrary names, serials and lifetimes build
//! certificates that rustls-webpki parses with equal fields. The lane
//! grant puts rustls-webpki on `fstp-pki`'s dev-dependencies only, so this
//! target compares against the independent reference writer in
//! `reference.rs` instead. That deviation is recorded for the lead, who
//! owns the fuzz crate's dependency lines. `tests/cert_roundtrip.rs` runs
//! the rustls-webpki half as a property.
//!
//! The input draws every field of `CertSpec`: the three kinds, an optional
//! OU on either name (a cluster kind marker or free text), DNS names from
//! a small alphabet that reaches both valid and invalid names, long names
//! at the 63-byte label and 253-byte name limits, IPv4 and
//! IPv6 addresses, and an optional issuer key identifier. For every input:
//!
//! - `tbs` never panics, and it is deterministic.
//! - `tbs` accepts exactly the specs the reference accepts. The reference
//!   predicts every refusal: serial, name lengths, the server OU marker,
//!   validity order and range, the 7-day client cap, the P-256 SPKI, SAN
//!   on a CA, the DNS name rule and a missing issuer key identifier.
//! - An accepted TBS equals the reference TBS byte for byte, extensions
//!   included.
//! - `assemble` wraps the TBS, the algorithm and the signature exactly.

#![no_main]

mod reference;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use fstp_pki::cert::{
    CertKind, CertSpec, DistinguishedName, SignatureAlgorithm, Validity, assemble, tbs,
};
use libfuzzer_sys::fuzz_target;

/// Reads the input as a sequence of fields, each one drawn from the front.
struct Input<'a>(&'a [u8]);

impl<'a> Input<'a> {
    fn byte(&mut self) -> u8 {
        let (b, rest) = self.0.split_first().map_or((0, &[][..]), |(b, r)| (*b, r));
        self.0 = rest;
        b
    }

    fn take(&mut self, n: usize) -> &'a [u8] {
        let n = n.min(self.0.len());
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        head
    }

    fn array<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        for (slot, v) in out.iter_mut().zip(self.take(N)) {
            *slot = *v;
        }
        out
    }

    fn i64(&mut self) -> i64 {
        i64::from_le_bytes(self.array())
    }
}

fn text(input: &mut Input<'_>) -> String {
    let n = usize::from(input.byte() % 80);
    String::from_utf8_lossy(input.take(n)).into_owned()
}

/// An optional OU: absent, a cluster kind marker, or free text.
fn ou(input: &mut Input<'_>) -> Option<String> {
    let pick = input.byte();
    match pick % 4 {
        0 => None,
        1 | 2 => Some(reference::CLUSTER_KINDS[usize::from(pick / 4) % 4].to_owned()),
        _ => Some(text(input)),
    }
}

/// A DNS name candidate. Most come from an alphabet biased to LDH host
/// names, with a few bytes that the rule refuses. One in four is a long
/// name of 1 to 5 labels of 1 to 64 letters, so the 63-byte label limit
/// and the 253-byte name limit are reached from both sides.
fn dns_name(input: &mut Input<'_>) -> String {
    const ALPHABET: &[u8] = b"abcxyz0129-..-aA_*";
    let mode = input.byte();
    if mode % 4 == 3 {
        let labels = 1 + usize::from(input.byte() % 5);
        let parts: Vec<String> = (0..labels)
            .map(|_| {
                let len = 1 + usize::from(input.byte() % 64);
                let letter = char::from(b'a' + input.byte() % 26);
                letter.to_string().repeat(len)
            })
            .collect();
        return parts.join(".");
    }
    let n = usize::from(mode / 4 % 24);
    input
        .take(n)
        .iter()
        .map(|b| char::from(ALPHABET[usize::from(*b) % ALPHABET.len()]))
        .collect()
}

fn ip_addr(input: &mut Input<'_>) -> IpAddr {
    if input.byte() & 1 == 0 {
        IpAddr::V4(Ipv4Addr::from(input.array::<4>()))
    } else {
        IpAddr::V6(Ipv6Addr::from(input.array::<16>()))
    }
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input(data);
    let flags = input.byte();
    let serial_len = usize::from(input.byte() % 23);
    let serial = input.take(serial_len).to_vec();
    let issuer = DistinguishedName {
        common_name: text(&mut input),
        organizational_unit: ou(&mut input),
    };
    // Half the time the subject is the issuer, so self-signed specs occur.
    let subject = if flags & 0x80 == 0 {
        issuer.clone()
    } else {
        DistinguishedName {
            common_name: text(&mut input),
            organizational_unit: ou(&mut input),
        }
    };
    let kind = match flags & 3 {
        0 => CertKind::Ca,
        1 => CertKind::Server,
        _ => CertKind::Client,
    };
    // Bias instants into the encodable range most of the time, so accepted
    // specs are common; the raw value reaches the range edges.
    let raw = input.i64();
    let not_before = if flags & 4 == 0 {
        reference::MIN_TIME.saturating_add(raw.rem_euclid(reference::SPAN))
    } else {
        raw
    };
    let delta = i64::from(i32::from_le_bytes(input.array()));
    let not_after = not_before.saturating_add(delta);
    let issuer_key_id = (flags & 0x40 != 0).then(|| input.array::<20>());
    let san = input.byte();
    let dns_names = (0..san % 3).map(|_| dns_name(&mut input)).collect();
    let ip_addrs = (0..(san / 3) % 3).map(|_| ip_addr(&mut input)).collect();
    let sig_len = usize::from(input.byte() % 80);
    let signature = input.take(sig_len).to_vec();
    let spki_der = if flags & 8 == 0 {
        reference::P256_G_SPKI.to_vec()
    } else {
        input.0.to_vec()
    };
    let spec = CertSpec {
        serial,
        issuer,
        subject,
        validity: Validity {
            not_before,
            not_after,
        },
        spki_der,
        issuer_key_id,
        kind,
        dns_names,
        ip_addrs,
        algorithm: SignatureAlgorithm::EcdsaP256Sha256,
    };
    let got = tbs(&spec);
    let again = tbs(&spec);
    assert_eq!(
        again.as_ref().map(|x| x.as_der()),
        got.as_ref().map(|x| x.as_der()),
        "tbs is not deterministic"
    );
    let expected = reference::tbs(&spec);
    let t = match (got, expected) {
        (Ok(t), Some(e)) => {
            assert_eq!(
                t.as_der(),
                e.as_slice(),
                "the TBS differs from the reference: {spec:?}"
            );
            t
        }
        (Err(_), None) => return,
        (Ok(_), None) => panic!("fstp-pki accepted a spec the reference refuses: {spec:?}"),
        (Err(e), Some(_)) => {
            panic!("fstp-pki refused ({e:?}) a spec the reference accepts: {spec:?}")
        }
    };
    match assemble(&t, &signature) {
        Ok(cert) => {
            assert!(
                !signature.is_empty(),
                "assemble accepted an empty signature"
            );
            assert_eq!(cert, reference::certificate(t.as_der(), &signature));
        }
        Err(_) => assert!(signature.is_empty(), "assemble refused a signature"),
    }
});
