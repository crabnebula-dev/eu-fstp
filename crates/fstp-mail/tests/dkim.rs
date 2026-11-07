//! DKIM signing (M6 design section 5.3, ADR-001 "DKIM", lane L6-MAIL).
//!
//! Signatures are made and checked through aws-lc-rs only, by way of
//! `fstp-crypto`. Canonicalisation is relaxed/relaxed (RFC 6376 section
//! 3.4) and written in-house. Signing is off unless a signer is
//! configured.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

mod common;

use std::sync::OnceLock;

use fstp_crypto::sig::{Ed25519SigningKey, RsaPkcs1Sha256KeyPair, rsa_pkcs1_sha256_verify_spki};
use fstp_mail::dkim::{canon_body_relaxed, canon_header_relaxed};
use fstp_mail::{DkimKey, DkimPublicKey, DkimSigner, compose, dkim_verify, parse};
use fstp_prop::{check, prop_assert};

fn rsa_signer() -> &'static DkimSigner {
    static S: OnceLock<DkimSigner> = OnceLock::new();
    S.get_or_init(|| {
        let key = RsaPkcs1Sha256KeyPair::generate_2048().unwrap();
        DkimSigner::new("tenant-a.example", "m6rsa", DkimKey::Rsa(key)).unwrap()
    })
}

fn ed_signer() -> DkimSigner {
    let key = Ed25519SigningKey::from_seed(&[7u8; 32]).unwrap();
    DkimSigner::new("tenant-a.example", "m6ed", DkimKey::Ed25519(key)).unwrap()
}

/// RFC 6376 section 3.4.5, the worked example of relaxed canonicalisation.
#[test]
fn adr_001_dkim_relaxed_canonicalisation_example() {
    assert_eq!(canon_header_relaxed("A", b" X"), b"a:X".to_vec());
    assert_eq!(
        canon_header_relaxed("B ", b" Y\t\r\n\tZ  "),
        b"b:Y Z".to_vec()
    );
    assert_eq!(
        canon_body_relaxed(b" C \r\nD \t E\r\n\r\n\r\n"),
        b" C\r\nD E\r\n".to_vec()
    );
    assert_eq!(canon_body_relaxed(b""), Vec::<u8>::new());
    assert_eq!(canon_body_relaxed(b"\r\n\r\n"), Vec::<u8>::new());
    assert_eq!(canon_body_relaxed(b"x"), b"x\r\n".to_vec());
}

/// ADR-001: an rsa-sha256 signature on every composed message verifies
/// with aws-lc-rs, and changing the body or a signed header breaks it.
#[test]
fn adr_001_dkim_rsa_sha256_verifies_with_aws_lc_rs() {
    let mut cfg = common::config();
    let signer = rsa_signer();
    let public = signer.public_key().unwrap();
    // The configuration owns its signers, so a second handle of the same
    // key is loaded from its PKCS#8 form.
    let DkimKey::Rsa(k) = signer.key() else {
        panic!("rsa key expected")
    };
    let copy = RsaPkcs1Sha256KeyPair::from_pkcs8(&k.pkcs8_der().unwrap()).unwrap();
    cfg.dkim = vec![DkimSigner::new("tenant-a.example", "m6rsa", DkimKey::Rsa(copy)).unwrap()];
    check("adr_001_dkim_rsa_sha256_verifies_with_aws_lc_rs", |g| {
        let m = common::Owned::random(g);
        let raw = compose(&cfg, &m.message()).map_err(|e| format!("{e}"))?;
        prop_assert!(raw.starts_with(b"DKIM-Signature: v=1; a=rsa-sha256;"));
        dkim_verify(&raw, "tenant-a.example", "m6rsa", &public).map_err(|e| format!("{e}"))?;
        // Tamper with one body byte after the header.
        let split = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or("split")?
            + 4;
        let at = g.usize_in(split..=raw.len() - 3);
        let mut bad = raw.clone();
        g.assume(bad[at].is_ascii_alphanumeric());
        bad[at] = if bad[at] == b'A' { b'B' } else { b'A' };
        prop_assert!(dkim_verify(&bad, "tenant-a.example", "m6rsa", &public).is_err());
        // Tamper with the signed Subject.
        let bad = String::from_utf8(raw.clone())
            .map_err(|e| format!("{e}"))?
            .replacen("\r\nSubject: ", "\r\nSubject: X", 1);
        prop_assert!(dkim_verify(bad.as_bytes(), "tenant-a.example", "m6rsa", &public).is_err());
        Ok(())
    });
}

/// ADR-001, RFC 8463: an ed25519-sha256 signature verifies with aws-lc-rs.
/// Both signers may run at once, as the ADR's "RSA for receivers that need
/// it" asks.
#[test]
fn adr_001_dkim_ed25519_and_rsa_dual_signature_verifies() {
    let mut cfg = common::config();
    let ed = ed_signer();
    let ed_pub = ed.public_key().unwrap();
    let rsa_pub = rsa_signer().public_key().unwrap();
    let DkimKey::Rsa(k) = rsa_signer().key() else {
        panic!("rsa key expected")
    };
    let copy = RsaPkcs1Sha256KeyPair::from_pkcs8(&k.pkcs8_der().unwrap()).unwrap();
    cfg.dkim = vec![
        ed,
        DkimSigner::new("tenant-a.example", "m6rsa", DkimKey::Rsa(copy)).unwrap(),
    ];
    check(
        "adr_001_dkim_ed25519_and_rsa_dual_signature_verifies",
        |g| {
            let m = common::Owned::random(g);
            let raw = compose(&cfg, &m.message()).map_err(|e| format!("{e}"))?;
            dkim_verify(&raw, "tenant-a.example", "m6ed", &ed_pub).map_err(|e| format!("{e}"))?;
            dkim_verify(&raw, "tenant-a.example", "m6rsa", &rsa_pub).map_err(|e| format!("{e}"))?;
            prop_assert!(dkim_verify(&raw, "tenant-a.example", "m6ed", &rsa_pub).is_err());
            Ok(())
        },
    );
}

/// ADR-001: the signature is checked a second way here, with the header
/// hash input rebuilt by hand and passed straight to the aws-lc-rs RSA
/// verifier in `fstp-crypto`. The crate's own canonicaliser is not used.
#[test]
fn adr_001_dkim_rsa_signature_checks_against_hand_built_input() {
    let mut cfg = common::config();
    let DkimKey::Rsa(k) = rsa_signer().key() else {
        panic!("rsa key expected")
    };
    let spki = k.spki_der().unwrap();
    let copy = RsaPkcs1Sha256KeyPair::from_pkcs8(&k.pkcs8_der().unwrap()).unwrap();
    cfg.dkim = vec![DkimSigner::new("tenant-a.example", "m6rsa", DkimKey::Rsa(copy)).unwrap()];
    let owned = fstp_prop_free_message();
    let raw = compose(&cfg, &owned.message()).unwrap();
    let parsed = parse(&raw).unwrap();
    let sig = parsed.header("DKIM-Signature").unwrap().to_owned();
    let tags: Vec<(String, String)> = sig
        .split(';')
        .map(|t| {
            let (k, v) = t.split_once('=').unwrap();
            (
                k.trim().to_owned(),
                v.chars().filter(|c| !c.is_whitespace()).collect(),
            )
        })
        .collect();
    let tag = |n: &str| tags.iter().find(|(k, _)| k == n).unwrap().1.clone();
    let mut input = String::new();
    for name in tag("h").split(':') {
        let v = parsed.header(name).unwrap_or("");
        let v: Vec<&str> = v.split_whitespace().collect();
        input.push_str(&format!(
            "{}:{}\r\n",
            name.to_ascii_lowercase(),
            v.join(" ")
        ));
    }
    let b = tag("b");
    let unsigned = &sig[..sig.len() - squeeze_tag_value(&sig).len()];
    let unsigned: Vec<&str> = unsigned.split_whitespace().collect();
    input.push_str(&format!("dkim-signature:{}", unsigned.join(" ")));
    let signature = fstp_mail::encode::base64_decode(b.as_bytes()).unwrap();
    rsa_pkcs1_sha256_verify_spki(&spki, input.as_bytes(), &signature).unwrap();
}

/// The raw text of the last tag value in `sig`, which is `b=`. Base64 holds
/// no semicolon, so the tag starts after the last one.
fn squeeze_tag_value(sig: &str) -> String {
    let seg = &sig[sig.rfind(';').unwrap() + 1..];
    assert_eq!(seg.split_once('=').unwrap().0.trim(), "b");
    seg[seg.find('=').unwrap() + 1..].to_owned()
}

fn fstp_prop_free_message() -> common::Owned {
    use fstp_domain::StateTag;
    use fstp_domain::id::ProposalId;
    use fstp_domain::time::Timestamp;
    use fstp_mail::{Bindings, LinkTarget, Mailbox, Moment, Slot, Template, TemplateId, Value};
    let template = Template::latest(TemplateId::ProposalOutcome, fstp_mail::Locale::En).unwrap();
    let at = Timestamp::from_micros(1_794_000_000_000_000);
    let bindings = Bindings::new()
        .with(Slot::Proposal, Value::Proposal(ProposalId::from_raw(4242)))
        .with(Slot::State, Value::State(StateTag::NotSelected))
        .with(Slot::When, Value::Moment(Moment::new(at, 60).unwrap()))
        .with(
            Slot::Link,
            Value::Link(LinkTarget::Proposal(ProposalId::from_raw(4242))),
        );
    common::Owned {
        template,
        bindings,
        to: Mailbox::new("applicant.1@synthetic.example").unwrap(),
        idem: [1; 32],
        event: [2; 32],
        date: at,
        pdf: None,
    }
}

/// The DKIM flag: with no signer configured, no signature is added.
#[test]
fn dkim_is_off_without_a_signer() {
    let cfg = common::config();
    let m = fstp_prop_free_message();
    let raw = compose(&cfg, &m.message()).unwrap();
    assert!(parse(&raw).unwrap().header("DKIM-Signature").is_none());
}

/// The DNS record a tenant publishes names the key type and holds the
/// public key, so tenant setup can show it (ADR-001).
#[test]
fn dkim_dns_record_names_key() {
    let ed = ed_signer();
    let txt = ed.dns_txt().unwrap();
    assert!(txt.starts_with("v=DKIM1; k=ed25519; p="), "{txt}");
    let rsa = rsa_signer().dns_txt().unwrap();
    assert!(rsa.starts_with("v=DKIM1; k=rsa; p=MII"), "{rsa}");
    assert!(matches!(
        ed.public_key().unwrap(),
        DkimPublicKey::Ed25519(_)
    ));
}
