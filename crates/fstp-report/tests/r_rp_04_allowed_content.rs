//! R-RP-04, `funder-reporting.md` Horizon Europe profile, I-48, I-86: each
//! output holds only what the profile table allows.
//!
//! - Periodic reporting data names recipients by a pseudonymous reference.
//!   Legal form and country are joined on the vault origin at download
//!   (M5 design reading 7), so the cell's output holds neither, and no
//!   account of the platform.
//! - The audit file lists records by kind, sequence number and hash only.
//! - The open call package fails generation unless it states the five
//!   elements of I-48, and its data protection notice references the
//!   Portal Privacy Statement.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use std::collections::BTreeSet;

use fstp_json::Value;
use fstp_report::{Content, PackageInputs, ReportError, Request, generate};
use support::{
    CALL, FIN, GUIDE, PM, PRIVACY, PROGRAMME, REL, REVIEWER, fixed, lead, ledger_of, package_parts,
    periods,
};

fn keys(v: &Value) -> BTreeSet<String> {
    v.as_object()
        .map(|o| o.keys().map(str::to_owned).collect())
        .unwrap_or_default()
}

fn set(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|s| (*s).to_owned()).collect()
}

fn accounts() -> Vec<String> {
    let mut a: Vec<String> = [PM, REVIEWER, FIN, REL]
        .iter()
        .map(|a| a.raw().to_string())
        .collect();
    a.extend((0..3).map(|i| lead(i).raw().to_string()));
    a
}

/// R-RP-04, I-86: the periodic reporting data holds exactly the profile's
/// members, no vault attribute and no account.
#[test]
fn r_rp_04_periodic_data_holds_only_profile_members() {
    let snap = ledger_of(&fixed()).snapshot();
    let ps = periods();
    let out = generate(
        &snap,
        &Request::PeriodicReportingData {
            programme: PROGRAMME,
            periods: &ps,
        },
    )
    .unwrap();
    let Content::Data(v) = &out.content else {
        panic!("periodic data is data")
    };
    assert_eq!(
        keys(v),
        set(&[
            "profile",
            "output",
            "template",
            "snapshot",
            "programme",
            "currency",
            "cost_category",
            "vault_attributes",
            "periods",
            "totals",
        ])
    );
    for p in v.get("periods").and_then(Value::as_array).unwrap().iter() {
        assert_eq!(keys(p), set(&["start", "end", "recipients", "paid"]));
        for r in p
            .get("recipients")
            .and_then(Value::as_array)
            .unwrap()
            .iter()
        {
            assert_eq!(
                keys(r),
                set(&[
                    "recipient",
                    "call",
                    "committed",
                    "paid",
                    "paid_hardship",
                    "released_commitment",
                ]),
                "R-RP-04: a recipient row holds another member"
            );
        }
    }
    let text = String::from_utf8(out.bytes.clone()).unwrap();
    for a in accounts() {
        assert!(
            !text.contains(&a),
            "I-86: the periodic data names account {a}"
        );
    }
    for word in ["legal_form\":\"", "country\":\"", "iban", "IBAN"] {
        assert!(!text.contains(word), "I-86: the periodic data holds {word}");
    }
}

/// R-RP-04: the call publication record holds the frozen call fields only.
#[test]
fn r_rp_04_call_publication_record_holds_call_fields_only() {
    let snap = ledger_of(&fixed()).snapshot();
    let out = generate(
        &snap,
        &Request::CallPublicationRecord {
            call: CALL,
            identifier: "SYN-2026-01",
        },
    )
    .unwrap();
    let Content::Data(v) = &out.content else {
        panic!("the call publication record is data")
    };
    assert_eq!(
        keys(v),
        set(&[
            "profile",
            "output",
            "template",
            "snapshot",
            "call",
            "programme",
            "opens",
            "deadline",
            "deadline_time_zone",
            "budget",
            "currency",
            "frozen_policy",
            "publication_sequence",
            "published_at",
        ])
    );
    assert_eq!(v.get("call").and_then(Value::as_str), Some("SYN-2026-01"));
    assert_eq!(v.get("budget").and_then(Value::as_str), Some("500000.00"));
    assert_eq!(
        v.get("opens").and_then(Value::as_str),
        Some("2026-01-05T00:00:00Z")
    );
    let text = String::from_utf8(out.bytes.clone()).unwrap();
    for a in accounts() {
        assert!(
            !text.contains(&a),
            "the publication record names account {a}"
        );
    }
}

/// R-RP-04, I-24: every audit file line is a kind, a sequence number, a
/// time and a SHA-256, and no account is named.
#[test]
fn r_rp_04_audit_file_lists_kinds_and_hashes_only() {
    let snap = ledger_of(&fixed()).snapshot();
    let out = generate(&snap, &Request::AuditFile { call: CALL }).unwrap();
    let Content::Document(d) = &out.content else {
        panic!("the audit file is a document")
    };
    let entries: Vec<&str> = d
        .blocks
        .iter()
        .map(|b| b.text.as_str())
        .filter(|t| t.starts_with("seq "))
        .collect();
    assert!(!entries.is_empty(), "the audit file lists records");
    for e in &entries {
        let parts: Vec<&str> = e.split(", ").collect();
        assert_eq!(
            parts.len(),
            4,
            "R-RP-04: an audit line has another shape: {e}"
        );
        assert!(
            parts[3].starts_with("sha256 ") && parts[3].len() == 7 + 64,
            "{e}"
        );
    }
    for kind in [
        "GrantDecided",
        "PaymentReleased",
        "LineAccepted",
        "NoQuestionsRecorded",
    ] {
        assert!(
            entries.iter().any(|e| e.contains(kind)),
            "R-RP-04: the audit file lacks {kind}"
        );
    }
    let all: String = d
        .blocks
        .iter()
        .map(|b| b.text.clone())
        .collect::<Vec<_>>()
        .join("\n");
    for a in accounts() {
        assert!(!all.contains(&a), "the audit file names account {a}");
    }
}

/// I-48: the open call package is generated only when it states the five
/// elements, and a missing one is refused by name.
#[test]
fn i48_open_call_package_needs_the_five_elements() {
    let snap = ledger_of(&fixed()).snapshot();
    let (form, contract, dpn) = package_parts();
    let package = |guide: &'static [u8]| PackageInputs {
        guide,
        proposal_form: &[],
        contract_template: &[],
        data_protection: &[],
        privacy_statement_url: PRIVACY,
    };
    let full = PackageInputs {
        guide: GUIDE.as_bytes(),
        proposal_form: &form,
        contract_template: &contract,
        data_protection: &dpn,
        privacy_statement_url: PRIVACY,
    };
    let ok = generate(
        &snap,
        &Request::OpenCallPackage {
            call: CALL,
            package: &full,
        },
    )
    .unwrap();
    let Content::Document(d) = &ok.content else {
        panic!("the package is a document")
    };
    let all: String = d
        .blocks
        .iter()
        .map(|b| b.text.clone())
        .collect::<Vec<_>>()
        .join("\n");
    for piece in [
        "Synthetic activity A",
        "Synthetic amount criteria.",
        "Synthetic contract template clause.",
        PRIVACY,
    ] {
        assert!(all.contains(piece), "R-RP-04: the package lacks {piece:?}");
    }
    let without = GUIDE.replace(
        "[\"v\",\"P-55.list\",[\"list\",[\"Synthetic activity A\",\"Synthetic activity B\"]]]\n",
        "",
    );
    let without: &'static str = Box::leak(without.into_boxed_str());
    let mut p = package(without.as_bytes());
    p.proposal_form = &form;
    p.contract_template = &contract;
    p.data_protection = &dpn;
    match generate(
        &snap,
        &Request::OpenCallPackage {
            call: CALL,
            package: &p,
        },
    ) {
        Err(ReportError::Package(missing)) => {
            assert_eq!(missing, vec!["closed list of activity types"], "I-48")
        }
        other => panic!("I-48: a package without the activity types gave {other:?}"),
    }
    let mut p = package(GUIDE.as_bytes());
    p.proposal_form = &form;
    p.contract_template = &contract;
    match generate(
        &snap,
        &Request::OpenCallPackage {
            call: CALL,
            package: &p,
        },
    ) {
        Err(ReportError::Package(missing)) => assert!(
            missing.contains(&"data protection notice"),
            "R-RP-04: {missing:?}"
        ),
        other => panic!("a package without its data protection notice gave {other:?}"),
    }
}
