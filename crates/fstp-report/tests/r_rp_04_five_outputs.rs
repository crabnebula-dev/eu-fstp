//! R-RP-04, R-RP-01: the Horizon Europe profile generates all five outputs
//! of `SPEC/03-architecture/funder-reporting.md` from one ledger snapshot,
//! and each records its snapshot digest and template version.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use fstp_report::{Content, PackageInputs, ReportError, ReportKind, Request, Scope, generate};
use support::{CALL, GUIDE, PRIVACY, PROGRAMME, fixed, ledger_of, package_parts, periods};

/// R-RP-04: each of the five outputs is generated, with its kind, scope,
/// snapshot digest and template version (R-RP-01).
#[test]
fn r_rp_04_horizon_europe_generates_all_five_outputs() {
    let snap = ledger_of(&fixed()).snapshot();
    let digest = snap.digest().unwrap();
    let (form, contract, dpn) = package_parts();
    let package = PackageInputs {
        guide: GUIDE.as_bytes(),
        proposal_form: &form,
        contract_template: &contract,
        data_protection: &dpn,
        privacy_statement_url: PRIVACY,
    };
    let periods = periods();
    let requests = [
        Request::CallPublicationRecord {
            call: CALL,
            identifier: "SYN-2026-01",
        },
        Request::OpenCallPackage {
            call: CALL,
            package: &package,
        },
        Request::PeriodicReportingData {
            programme: PROGRAMME,
            periods: &periods,
        },
        Request::AuditFile { call: CALL },
        Request::DeliverableDraft { call: CALL },
    ];
    let mut kinds = Vec::new();
    for r in &requests {
        let out = generate(&snap, r).unwrap_or_else(|e| panic!("R-RP-04: {r:?}: {e}"));
        assert_eq!(
            out.snapshot, digest,
            "R-RP-01: the snapshot digest is recorded"
        );
        assert!(
            !out.template.is_empty(),
            "R-RP-01: the template version is recorded"
        );
        assert_eq!(
            out.digest.bytes(),
            fstp_crypto::sha256(&out.bytes),
            "R-RP-01: the document digest is the SHA-256 of its bytes"
        );
        match &out.content {
            Content::Document(_) => {
                assert!(out.bytes.starts_with(b"%PDF-"), "{:?} is a PDF", out.kind);
                assert_eq!(out.media(), "application/pdf");
            }
            Content::Data(_) => assert_eq!(out.media(), "application/json"),
        }
        let scope = match out.kind {
            ReportKind::PeriodicReportingData => Scope::Programme(PROGRAMME),
            _ => Scope::Call(CALL),
        };
        assert_eq!(out.scope, scope);
        kinds.push(out.kind);
    }
    assert_eq!(kinds, ReportKind::ALL.to_vec(), "R-RP-04: all five outputs");
}

/// R-RP-04: an output of a call the snapshot does not hold as published
/// is refused.
#[test]
fn r_rp_04_unpublished_call_is_refused() {
    let snap = ledger_of(&fixed()).snapshot();
    let r = generate(
        &snap,
        &Request::AuditFile {
            call: support::OTHER_CALL,
        },
    );
    assert!(matches!(r, Err(ReportError::UnknownCall)), "{r:?}");
}
