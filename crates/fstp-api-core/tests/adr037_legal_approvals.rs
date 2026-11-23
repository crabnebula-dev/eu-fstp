//! ADR-037 section 3: the per-text approval flag of the legal pages.
//! Approval binds the exact draft Daniel read, by its SHA-256, so an
//! approval removes the banner with no code change and any later edit
//! brings it back. A text with a pending point is never approved.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_core::legal::{
    APPROVALS_JSON, Approval, approved, approves, details_json, digest_hex, file_of, page_html,
    parse_approvals, text_keys,
};
use fstp_brand::legal::LegalDetails;

/// ADR-037: the shipped approval file names each text once, and every
/// recorded approval still matches its draft. On a mismatch the message
/// prints the digest to record after Daniel approves the new text.
#[test]
fn adr037_shipped_approvals_match_their_drafts() {
    let a = parse_approvals(APPROVALS_JSON).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(a.len(), text_keys().count());
    for (k, approval) in &a {
        let file = file_of(k).unwrap();
        let digest = digest_hex(k).unwrap();
        if let Some(ap) = approval {
            assert_eq!(
                ap.sha256, digest,
                "legal/{file} changed after its approval of {}. Its current digest is {digest}; record it only once Daniel approves the new text",
                ap.approved_on
            );
            assert!(
                approves(k, Some(ap)),
                "legal/{file} is approved but still holds a TODO(legal) or NOT BUILT marker"
            );
        }
        assert_eq!(approved(k), approval.is_some());
    }
}

/// ADR-037: the approval file grammar is closed.
#[test]
fn adr037_approval_file_grammar_is_closed() {
    let ok = r#"{"accessibility":null,"data_act":null,"imprint":{"approved_on":"2026-12-01","sha256":"PLACE"},"privacy":null,"terms":null}"#
        .replace("PLACE", &"ab".repeat(32));
    let a = parse_approvals(&ok).unwrap();
    assert!(a.get("imprint").unwrap().is_some());
    for bad in [
        "[]".to_owned(),
        r#"{"privacy":null}"#.to_owned(),
        ok.replace("2026-12-01", "1 Dec 2026"),
        ok.replace(&"ab".repeat(32), &"AB".repeat(32)),
        ok.replace("\"terms\":null", "\"terms\":true"),
        ok.replace("\"privacy\":null", "\"extra\":null"),
    ] {
        assert!(parse_approvals(&bad).is_err(), "{bad}");
    }
}

/// ADR-037: a stale digest never approves, and a matching digest approves
/// a text only once it holds no pending point. Every draft holds pending
/// points today, so none can be approved yet.
#[test]
fn adr037_approval_needs_the_exact_text_and_no_pending_point() {
    for k in text_keys() {
        let exact = Approval {
            approved_on: "2026-12-01".to_owned(),
            sha256: digest_hex(k).unwrap(),
        };
        let stale = Approval {
            approved_on: "2026-12-01".to_owned(),
            sha256: "00".repeat(32),
        };
        assert!(!approves(k, Some(&stale)), "{k}");
        assert!(!approves(k, None), "{k}");
        assert!(!approves(k, Some(&exact)), "{k}: still holds TODO(legal)");
    }
    assert_eq!(digest_hex("nope"), None);
    assert!(!approves("nope", None));
}

/// ADR-037, I-68: the page shows the tenant's values as text and the
/// banner while unapproved; the details answer holds the set fields only.
#[test]
fn i68_adr037_page_fills_the_tenant_values() {
    let d = LegalDetails::from_pairs(&[
        ("legal_name", "Synthetic Org Ltd"),
        ("company_number", "X 000000"),
    ])
    .unwrap();
    let html = page_html("/legal/imprint", Some(&d), None).unwrap();
    assert!(html.contains("Synthetic Org Ltd"));
    assert!(html.contains("X 000000"));
    assert!(html.contains("[not set: tenant.vat_number]"));
    assert!(html.contains("Draft, not yet approved"));
    let html = page_html("/legal/privacy", None, Some("/brand/x.css")).unwrap();
    assert!(html.contains("href=\"/brand/x.css\""));
    assert!(html.contains("[not set: controller.legal_name]"));
    assert_eq!(page_html("/legal/nope", None, None), None);
    assert_eq!(
        fstp_json::to_compact(&details_json(Some(&d))),
        r#"{"legal_name":"Synthetic Org Ltd","company_number":"X 000000"}"#
    );
    assert_eq!(fstp_json::to_compact(&details_json(None)), "{}");
}
