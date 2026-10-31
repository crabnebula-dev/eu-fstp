//! I-19, design section 9.1, ADR-009, ADR-010, ADR-011: the closed grammars
//! of the protocol's byte-carrying field types.
//!
//! `CertDer`, `ScramVerifier`, `PopSig` and `CompositeSig` are the only
//! field types that hold bytes. Each is a closed grammar, checked on
//! decode, so no field can carry free text or a tenant byte blob. Every
//! accepted value keeps its bytes unchanged, and each grammar has one
//! spelling per value, so no byte is left free to carry data.
//!
//! The grammars come from the documents, never from the codec:
//!
//! - `ScramVerifier`: ADR-011 gives `SCRAM-SHA-256$<iterations>:<salt>$
//!   <StoredKey>:<ServerKey>` with base64 fields and no quote or
//!   backslash. ADR-011 records 4096 as the minimum iteration count, so
//!   these tests pin that 4096 and more are accepted and 4095 is refused.
//! - `PopSig`: the fstp-pki `pop` module signs with ASN.1 DER ECDSA P-256
//!   SHA-256 and bounds a signature to 8 to 72 bytes.
//! - `CompositeSig`: ADR-010 fixes `mldsaSig || tradSig`, 3373 bytes, the
//!   length `fstp_crypto::composite::CompositeSignature` checks.
//! - `CertDer`: a DER certificate as the in-house fstp-pki writer emits it.
//!
//! Lane W2h test author. Red until lane W2h writes the parsers: each
//! `parse` is a W0 stub that refuses with `ProtoError::NotImplemented`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::{
    CertParams, DerClass, Verifier, accepted, b64, certificate, certificate_with,
    composite_vector_field, der_class, is_stub, raw_signature, refused, verifier,
};
use fstp_cp_proto::{CertDer, CompositeSig, PopSig, ScramVerifier};
use fstp_prop::{Gen, prop_assert, prop_assert_eq};

// ---------------------------------------------------------------------------
// ScramVerifier (ADR-011).

/// I-19, ADR-011: every verifier of the PostgreSQL form, with 32-byte
/// keys and 4096 or more iterations, is accepted and keeps its bytes.
#[test]
fn i19_scram_verifier_accepts_the_postgresql_form() {
    fstp_prop::check(
        "i19_scram_verifier_accepts_the_postgresql_form",
        |g: &mut Gen| {
            let text = verifier(g).text();
            let v = accepted(&text, ScramVerifier::parse(text.as_bytes()))?;
            prop_assert_eq!(v.as_bytes(), text.as_bytes());
            Ok(())
        },
    );
}

/// I-19, ADR-011: a quote or a backslash anywhere in a verifier is
/// refused, so the literal `fstp-pgagent` renders in `ALTER ROLE ...
/// PASSWORD` can never close its quotes.
#[test]
fn i19_scram_verifier_refuses_quotes_and_backslashes() {
    fstp_prop::check(
        "i19_scram_verifier_refuses_quotes_and_backslashes",
        |g: &mut Gen| {
            let mut text = verifier(g).text().into_bytes();
            let at = g.usize_in(0..=text.len());
            let bad = *g.pick(b"'\\\"");
            text.insert(at, bad);
            refused(&String::from_utf8_lossy(&text), ScramVerifier::parse(&text))
        },
    );
}

/// I-19, ADR-011: forms outside the grammar are refused. A cleartext
/// password and an MD5 hash never pass, and each field has one spelling:
/// padded canonical base64, decimal iterations without a leading zero,
/// and 32-byte keys.
#[test]
fn i19_scram_verifier_refuses_other_forms() {
    let good = Verifier {
        iterations: "4096".to_owned(),
        salt: b64(&[7u8; 16]),
        stored_key: b64(&[0x11u8; 32]),
        server_key: b64(&[0x22u8; 32]),
    };
    let with = |f: &dyn Fn(&mut Verifier)| {
        let mut v = good.clone();
        f(&mut v);
        v.text()
    };
    // A 32-byte key ends with a base64 digit that carries 4 bits of data
    // and 2 zero bits, then "=". `b64(&[0x11; 32])` ends in "ERE=". The
    // digit "F" sets one of the zero bits, which no byte string spells.
    let non_canonical = {
        let mut k = b64(&[0x11u8; 32]);
        assert!(k.ends_with("ERE="), "{k}");
        k.replace_range(k.len() - 2..k.len() - 1, "F");
        k
    };
    let cases: Vec<String> = vec![
        String::new(),
        "hunter2".to_owned(),
        format!("md5{}", "0123456789abcdef".repeat(2)),
        good.text().replacen("SCRAM-SHA-256", "SCRAM-SHA-1", 1),
        good.text().replacen("SCRAM-SHA-256", "scram-sha-256", 1),
        good.text().replacen('$', "", 1),
        good.text().replacen(':', "$", 1),
        with(&|v| v.iterations = "abc".to_owned()),
        with(&|v| v.iterations = String::new()),
        with(&|v| v.iterations = "0".to_owned()),
        with(&|v| v.iterations = "4095".to_owned()),
        with(&|v| v.iterations = "2147483648".to_owned()),
        with(&|v| v.iterations = "-4096".to_owned()),
        with(&|v| v.iterations = "04096".to_owned()),
        with(&|v| v.iterations = "+4096".to_owned()),
        with(&|v| v.salt = String::new()),
        with(&|v| v.salt = "c2FsdA*=".to_owned()),
        with(&|v| v.stored_key = b64(&[0x11u8; 31])),
        with(&|v| v.server_key = b64(&[0x22u8; 33])),
        with(&|v| v.stored_key = v.stored_key.trim_end_matches('=').to_owned()),
        with(&|v| v.stored_key = non_canonical.clone()),
        with(&|v| v.server_key = format!(" {}", v.server_key)),
        format!("{}\n", good.text()),
        format!(" {}", good.text()),
        format!("{}$extra", good.text()),
        format!("{}:extra", good.text()),
        format!("{}\0", good.text()),
    ];
    // The base case itself is well-formed, so each refusal below is about
    // its one change.
    accepted(&good.text(), ScramVerifier::parse(good.text().as_bytes())).unwrap();
    let failures: Vec<String> = cases
        .iter()
        .filter_map(|c| refused(c, ScramVerifier::parse(c.as_bytes())).err())
        .collect();
    assert!(failures.is_empty(), "{failures:#?}");
}

// ---------------------------------------------------------------------------
// PopSig (fstp-pki `pop`: ASN.1 DER ECDSA P-256 SHA-256).

/// I-19: every DER `ECDSA-Sig-Value` with `r` and `s` in 1 to n - 1 is
/// accepted and keeps its bytes. The generator reaches every INTEGER
/// length, so short and padded integers both occur.
#[test]
fn i19_pop_sig_accepts_der_ecdsa_sig_values() {
    fstp_prop::check("i19_pop_sig_accepts_der_ecdsa_sig_values", |g: &mut Gen| {
        let der = fstp_pki::cert::ecdsa_sig_value_from_raw(&raw_signature(g));
        prop_assert_eq!(der_class(&der), DerClass::Valid, "reference: {der:02x?}");
        let sig = accepted("a DER signature", PopSig::parse(&der))?;
        prop_assert_eq!(sig.as_bytes(), &der[..]);
        Ok(())
    });
}

/// I-19: signatures that `fstp-crypto` makes with a fresh P-256 key, the
/// call a component's proof of possession uses, are accepted.
#[test]
fn i19_pop_sig_accepts_signatures_of_fstp_crypto() {
    let key = fstp_crypto::sig::EcdsaP256KeyPair::generate().unwrap();
    let mut failures = Vec::new();
    for i in 0u8..32 {
        let der = key.sign(&[i; 48]).unwrap();
        assert_eq!(der_class(&der), DerClass::Valid, "{der:02x?}");
        if let Err(e) = accepted("an fstp-crypto signature", PopSig::parse(&der)) {
            failures.push(e);
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// One mutation of a DER signature, from the shapes a hostile cell could
/// send: cut, extended, a flipped bit, a replaced byte, an INTEGER padded
/// with a needless zero, or bytes from nowhere.
fn mutate_signature(g: &mut Gen, der: &[u8]) -> Vec<u8> {
    let mut m = der.to_vec();
    match g.u8_in(0..=5) {
        0 => m.truncate(g.usize_in(0..=der.len() - 1)),
        1 => {
            let extra = g.bytes(1..=8);
            m.extend(extra);
        }
        2 => {
            let i = g.usize_in(0..=m.len() - 1);
            m[i] ^= 1 << g.u8_in(0..=7);
        }
        3 => {
            let i = g.usize_in(0..=m.len() - 1);
            m[i] = g.u8();
        }
        4 => {
            // Pad r with a leading zero and fix both lengths: still BER,
            // never DER.
            let r_len = usize::from(m[3]);
            m.insert(4, 0);
            m[3] = u8::try_from(r_len + 1).unwrap();
            m[1] = u8::try_from(m.len() - 2).unwrap();
        }
        _ => m = g.bytes(0..=80),
    }
    m
}

/// I-19: on mutated signatures the grammar agrees with the DER reference.
/// It accepts exactly the valid DER forms and keeps their bytes, so a
/// signature has one spelling. Forms with a zero or an out-of-range
/// INTEGER are not pinned either way.
#[test]
fn i19_pop_sig_matches_the_der_reference_on_mutations() {
    fstp_prop::check(
        "i19_pop_sig_matches_the_der_reference_on_mutations",
        |g: &mut Gen| {
            let der = fstp_pki::cert::ecdsa_sig_value_from_raw(&raw_signature(g));
            let m = mutate_signature(g, &der);
            let class = der_class(&m);
            match (class, PopSig::parse(&m)) {
                (_, Err(e)) if is_stub(&e) => Err(format!("{e:?}")),
                (DerClass::Unpinned, _) => Ok(()),
                (DerClass::Valid, Ok(sig)) => {
                    prop_assert_eq!(sig.as_bytes(), &m[..]);
                    Ok(())
                }
                (DerClass::Invalid, Err(_)) => Ok(()),
                (want, got) => Err(format!("{m:02x?}: reference {want:?}, parse {got:?}")),
            }
        },
    );
}

// ---------------------------------------------------------------------------
// CompositeSig (ADR-010 "Composite encoding", draft 19 section 4.3).

/// I-19, ADR-010: a composite signature is exactly `mldsaSig || tradSig`.
/// The grammar accepts a byte string exactly when
/// `fstp_crypto::composite::CompositeSignature::from_bytes` does, and keeps
/// its bytes.
#[test]
fn i19_composite_sig_accepts_exactly_the_composite_layout() {
    use fstp_crypto::composite::{CompositeSignature, MLDSA_SIGNATURE_LEN, SIGNATURE_LEN};
    fstp_prop::check(
        "i19_composite_sig_accepts_exactly_the_composite_layout",
        |g: &mut Gen| {
            let len = match g.u8_in(0..=4) {
                0 => SIGNATURE_LEN,
                1 => SIGNATURE_LEN - 1,
                2 => SIGNATURE_LEN + 1,
                3 => *g.pick(&[0, 64, MLDSA_SIGNATURE_LEN, 2 * SIGNATURE_LEN]),
                _ => g.usize_in(0..=4096),
            };
            let bytes = g.bytes(len..=len);
            let want = CompositeSignature::from_bytes(&bytes).is_ok();
            match CompositeSig::parse(&bytes) {
                Err(e) if is_stub(&e) => Err(format!("{e:?}")),
                Ok(sig) => {
                    prop_assert!(want, "accepted {len} bytes");
                    prop_assert_eq!(sig.as_bytes(), &bytes[..]);
                    Ok(())
                }
                Err(_) => {
                    prop_assert!(!want, "refused {len} bytes");
                    Ok(())
                }
            }
        },
    );
}

/// I-19, ADR-010: the composite signature of the draft 19 Appendix E
/// vector, 3373 bytes, is accepted, and the layout length ADR-010 records
/// is the one `fstp-crypto` checks.
#[test]
fn i19_composite_sig_accepts_the_draft19_vector() {
    let s = composite_vector_field("s");
    assert_eq!(s.len(), 3373, "ADR-010 records 3373 bytes");
    assert_eq!(fstp_crypto::composite::SIGNATURE_LEN, 3373);
    let sig = accepted("the Appendix E signature", CompositeSig::parse(&s)).unwrap();
    assert_eq!(sig.as_bytes(), &s[..]);
}

// ---------------------------------------------------------------------------
// CertDer.

/// I-19: certificates that the in-house fstp-pki writer emits, a
/// self-signed CA and a client certificate it signs, are accepted and
/// keep their bytes.
#[test]
fn i19_cert_der_accepts_certificates_fstp_pki_writes() {
    fstp_prop::check(
        "i19_cert_der_accepts_certificates_fstp_pki_writes",
        |g: &mut Gen| {
            let der = certificate(g);
            let c = accepted("an fstp-pki certificate", CertDer::parse(&der))?;
            prop_assert_eq!(c.as_bytes(), &der[..]);
            Ok(())
        },
    );
}

/// I-19: a certificate cut short, or followed by any byte, is refused. No
/// byte after the DER value can carry data.
#[test]
fn i19_cert_der_refuses_truncated_or_extended_der() {
    fstp_prop::check(
        "i19_cert_der_refuses_truncated_or_extended_der",
        |g: &mut Gen| {
            let mut der = certificate(g);
            if g.bool() {
                der.truncate(g.usize_in(0..=der.len() - 1));
            } else {
                let extra = g.bytes(1..=16);
                der.extend(extra);
            }
            refused("a cut or extended certificate", CertDer::parse(&der))
        },
    );
}

/// I-19: bytes that are no DER certificate are refused: PEM text, free
/// text, the outer SEQUENCE retagged as a SET, an outer length that does
/// not match, and a fourth element inside the outer SEQUENCE.
#[test]
fn i19_cert_der_refuses_non_der() {
    let der = certificate_with(&CertParams {
        ca: false,
        ca_name: "cluster_ca".to_owned(),
        leaf_name: "c_00112233445566778899aabbccddeeff_app".to_owned(),
        serial: vec![0x01, 0x02],
        not_before: 1_700_000_000,
    });
    let mut retagged = der.clone();
    retagged[0] = 0x31;
    // The outer length is long-form: 0x81 with one octet, or 0x82 with
    // two. Changing its last octet makes it disagree with the content.
    let mut relength = der.clone();
    let last_length_octet = match der[1] {
        0x81 => 2,
        0x82 => 3,
        other => panic!("unexpected outer length form {other:#x}"),
    };
    relength[last_length_octet] ^= 0x01;
    // A fourth element, a DER NULL, inside the outer SEQUENCE, with the
    // outer length fixed. The certificate grammar has three elements.
    let inner_extra = {
        let mut body = der[last_length_octet + 1..].to_vec();
        body.extend_from_slice(&[0x05, 0x00]);
        let len = body.len();
        let mut out = vec![0x30];
        if len < 0x100 {
            out.extend_from_slice(&[0x81, u8::try_from(len).unwrap()]);
        } else {
            out.extend_from_slice(&[0x82, u8::try_from(len >> 8).unwrap(), (len & 0xff) as u8]);
        }
        out.extend(body);
        out
    };
    let pem = format!("-----BEGIN CERTIFICATE-----\n{}\n", b64(&der));
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("PEM text", pem.into_bytes()),
        ("free text", b"canary: Ada Lovelace, 1815".to_vec()),
        ("a SET", retagged),
        ("a wrong outer length", relength),
        ("a fourth element inside", inner_extra),
        ("an empty SEQUENCE", vec![0x30, 0x00]),
    ];
    let failures: Vec<String> = cases
        .iter()
        .filter_map(|(what, b)| refused(what, CertDer::parse(b)).err())
        .collect();
    assert!(failures.is_empty(), "{failures:#?}");
}

// ---------------------------------------------------------------------------
// The empty values.

/// I-19, design section 9.1: the `empty()` placeholder of each grammar
/// type is refused by its own check, as its doc comment promises. So no
/// decoded message can hold one.
#[test]
fn i19_empty_values_fail_their_own_grammar() {
    let failures: Vec<String> = [
        refused("PopSig::empty", PopSig::parse(PopSig::empty().as_bytes())),
        refused(
            "ScramVerifier::empty",
            ScramVerifier::parse(ScramVerifier::empty().as_bytes()),
        ),
        refused(
            "CertDer::empty",
            CertDer::parse(CertDer::empty().as_bytes()),
        ),
        refused(
            "CompositeSig::empty",
            CompositeSig::parse(CompositeSig::empty().as_bytes()),
        ),
    ]
    .into_iter()
    .filter_map(Result::err)
    .collect();
    assert!(failures.is_empty(), "{failures:#?}");
}
