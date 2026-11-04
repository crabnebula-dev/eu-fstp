//! The codec of the control plane onboarding records (TH-26, H-05,
//! ADR-007; M4 design sections 3.5, 4.3 and 9, fuzz target
//! `cp_record_decode`).
//!
//! A record encodes to an RFC 8785 canonical JSON body and decodes back to
//! itself. Unknown or missing members and arbitrary bytes are refused with
//! a `Record` error. Every test is red against the W0 stub.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use fstp_json::{Value, parse, to_canonical};
use fstp_prop::{Gen, check};
use fstp_signup::{
    Agreement, CpRecord, ReviewOutcome, SignupError, StaffId, decode_cp_record, encode_cp_record,
};
use support::{gen_tenant, gen_text, gen_version, gen_versions};

fn gen_staff(g: &mut Gen) -> StaffId {
    StaffId::from_raw(u128::from(g.u64()))
}

fn gen_record(g: &mut Gen) -> CpRecord {
    let tenant = gen_tenant(g);
    let at = g.i64_in(0..=i64::from(u32::MAX));
    match g.u8_in(0..=4) {
        0 => CpRecord::SignedUp {
            tenant,
            legal_name: gen_text(g, false),
            billing_address: gen_text(g, true),
            contracting_signatory: gen_text(g, false),
            at,
        },
        1 => CpRecord::AgreementAccepted {
            tenant,
            agreement: *g.pick(&[
                Agreement::SaasTerms,
                Agreement::Dpa,
                Agreement::SubProcessors,
            ]),
            version: gen_version(g),
            by: gen_text(g, false),
            at,
        },
        2 => CpRecord::TenantReviewed {
            tenant,
            outcome: *g.pick(&[ReviewOutcome::Approved, ReviewOutcome::Rejected]),
            by: gen_staff(g),
            at,
        },
        3 => CpRecord::AgreementsOffered {
            versions: gen_versions(g),
            by: gen_staff(g),
            at,
        },
        _ => CpRecord::TenantProvisioned {
            tenant,
            versions: gen_versions(g),
            at,
        },
    }
}

fn is_record_error(r: &Result<CpRecord, SignupError>) -> bool {
    matches!(r, Err(SignupError::Record(_)))
}

/// TH-26, H-05, ADR-007: every record round trips, and its encoding is
/// stable under a second round trip.
#[test]
fn th26_h05_cp_record_round_trips() {
    check("th26_h05_cp_record_round_trips", |g| {
        let r = gen_record(g);
        let bytes = encode_cp_record(&r).map_err(|e| format!("encode {r:?}: {e:?}"))?;
        let back = decode_cp_record(&bytes).map_err(|e| format!("decode {r:?}: {e:?}"))?;
        if back != r {
            return Err(format!("{r:?} decodes to {back:?}"));
        }
        let again = encode_cp_record(&back).map_err(|e| format!("re-encode: {e:?}"))?;
        if again == bytes {
            Ok(())
        } else {
            Err(format!("encoding of {r:?} is not stable"))
        }
    });
}

/// ADR-007: the encoding is RFC 8785 canonical JSON.
#[test]
fn adr007_cp_record_encoding_is_canonical() {
    check("adr007_cp_record_encoding_is_canonical", |g| {
        let r = gen_record(g);
        let bytes = encode_cp_record(&r).map_err(|e| format!("encode {r:?}: {e:?}"))?;
        let value = parse(&bytes).map_err(|e| format!("not JSON: {e:?}"))?;
        let canonical = to_canonical(&value).map_err(|e| format!("{e:?}"))?;
        if canonical.as_bytes() == bytes.as_slice() {
            Ok(())
        } else {
            Err(format!(
                "not canonical: {:?}",
                String::from_utf8_lossy(&bytes)
            ))
        }
    });
}

/// Walks to the innermost object along the first object member at each
/// level, `depth` levels down, so faults reach nested record bodies too.
fn object_at(v: &mut Value, depth: usize) -> Option<&mut fstp_json::Object> {
    let Value::Object(o) = v else { return None };
    if depth == 0 {
        return Some(o);
    }
    let key = o
        .iter()
        .find(|(_, child)| matches!(child, Value::Object(_)))
        .map(|(k, _)| k.to_owned());
    match key {
        Some(k) => object_at(o.get_mut(&k)?, depth - 1),
        None => Some(o),
    }
}

/// TH-26: an unknown member, at the top level or inside a nested object,
/// is refused.
#[test]
fn th26_cp_record_unknown_member_is_refused() {
    check("th26_cp_record_unknown_member_is_refused", |g| {
        let r = gen_record(g);
        let bytes = encode_cp_record(&r).map_err(|e| format!("encode {r:?}: {e:?}"))?;
        let mut v = parse(&bytes).map_err(|e| format!("{e:?}"))?;
        let depth = g.usize_in(0..=2);
        let o = object_at(&mut v, depth).ok_or("the encoding is not an object")?;
        o.insert("zz_unknown", Value::from("x"));
        let mutated = to_canonical(&v).map_err(|e| format!("{e:?}"))?;
        let got = decode_cp_record(mutated.as_bytes());
        if is_record_error(&got) {
            Ok(())
        } else {
            Err(format!("{mutated} decodes to {got:?}"))
        }
    });
}

/// TH-26: a record with one member removed, at any level, is refused.
#[test]
fn th26_cp_record_missing_member_is_refused() {
    check("th26_cp_record_missing_member_is_refused", |g| {
        let r = gen_record(g);
        let bytes = encode_cp_record(&r).map_err(|e| format!("encode {r:?}: {e:?}"))?;
        let mut v = parse(&bytes).map_err(|e| format!("{e:?}"))?;
        let depth = g.usize_in(0..=2);
        let o = object_at(&mut v, depth).ok_or("the encoding is not an object")?;
        let keys: Vec<String> = o.iter().map(|(k, _)| k.to_owned()).collect();
        if keys.is_empty() {
            return Err("an empty object in the encoding".to_owned());
        }
        let k = g.pick(&keys).clone();
        o.remove(&k);
        let mutated = to_canonical(&v).map_err(|e| format!("{e:?}"))?;
        let got = decode_cp_record(mutated.as_bytes());
        if is_record_error(&got) {
            Ok(())
        } else {
            Err(format!("{mutated} without {k} decodes to {got:?}"))
        }
    });
}

/// TH-26, H-05: arbitrary bytes and mutated encodings never reach
/// `NotImplemented`. Each is refused with a `Record` error, or decodes to
/// a record that round trips.
#[test]
fn th26_h05_cp_record_decode_is_total() {
    check("th26_h05_cp_record_decode_is_total", |g| {
        let mut bytes = if g.bool() {
            g.bytes(0..=256)
        } else {
            let r = gen_record(g);
            encode_cp_record(&r).map_err(|e| format!("encode {r:?}: {e:?}"))?
        };
        if !bytes.is_empty() {
            let at = g.usize_in(0..=bytes.len() - 1);
            bytes[at] = g.u8();
        }
        match decode_cp_record(&bytes) {
            Err(SignupError::Record(_)) => Ok(()),
            Ok(r) => {
                let again = encode_cp_record(&r).map_err(|e| format!("{e:?}"))?;
                match decode_cp_record(&again) {
                    Ok(r2) if r2 == r => Ok(()),
                    other => Err(format!("{r:?} round trips to {other:?}")),
                }
            }
            Err(other) => Err(format!("not a record refusal: {other:?}")),
        }
    });
}

/// TH-26, ADR-007: a zero version in an offer or a provisioning record
/// is refused by the encoder and the decoder alike.
#[test]
fn th26_cp_record_zero_version_is_refused() {
    let zero = fstp_signup::AgreementVersions {
        saas_terms: 1,
        dpa: 0,
        sub_processors: 1,
    };
    let records = [
        CpRecord::AgreementsOffered {
            versions: zero,
            by: StaffId::from_raw(1),
            at: 0,
        },
        CpRecord::TenantProvisioned {
            tenant: support::T1,
            versions: zero,
            at: 0,
        },
    ];
    for r in records {
        assert!(matches!(encode_cp_record(&r), Err(SignupError::Record(_))));
    }
    let text = br#"{"at":"0","by":"00000000000000000000000000000001","dpa":"0","kind":"agreements_offered","saas_terms":"1","sub_processors":"1"}"#;
    assert!(is_record_error(&decode_cp_record(text)));
    let one = br#"{"at":"0","by":"00000000000000000000000000000001","dpa":"1","kind":"agreements_offered","saas_terms":"1","sub_processors":"1"}"#;
    assert!(decode_cp_record(one).is_ok());
}
