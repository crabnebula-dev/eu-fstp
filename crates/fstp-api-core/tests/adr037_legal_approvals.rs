//! ADR-037 section 3: the per-text approval flag of the legal pages.
//! Approval binds the exact draft Daniel read, by its SHA-256, so an
//! approval removes the banner with no code change and any later edit
//! brings it back. A text with a pending point is never approved.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_core::legal::{
    APPROVALS_JSON, Approval, LegalText, approved, approves, details_json, digest_hex, page_html,
    parse_approvals,
};
use fstp_brand::legal::LegalDetails;

/// ADR-037: the shipped approval file names each text once, and every
/// recorded approval still matches its draft. On a mismatch the message
/// prints the digest to record after Daniel approves the new text.
#[test]
fn adr037_shipped_approvals_match_their_drafts() {
    let a = parse_approvals(APPROVALS_JSON).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(a.len(), LegalText::ALL.len());
    for (t, approval) in &a {
        if let Some(ap) = approval {
            assert_eq!(
                ap.sha256,
                digest_hex(*t),
                "legal/{} changed after its approval of {}. Its current digest is {}; record it only once Daniel approves the new text",
                t.file(),
                ap.approved_on,
                digest_hex(*t)
            );
            assert!(
                approves(*t, Some(ap)),
                "legal/{} is approved but still holds a TODO(legal) or NOT BUILT marker",
                t.file()
            );
        }
        assert_eq!(approved(*t), approval.is_some());
    }
}

/// ADR-037: the approval file grammar is closed.
#[test]
fn adr037_approval_file_grammar_is_closed() {
    let ok = r#"{"accessibility":null,"data_act":null,"imprint":{"approved_on":"2026-12-01","sha256":"PLACE"},"privacy":null,"terms":null}"#
        .replace("PLACE", &"ab".repeat(32));
    let a = parse_approvals(&ok).unwrap();
    assert!(a.get(&LegalText::Imprint).unwrap().is_some());
    for bad in [
        "[]",
        r#"{"privacy":null}"#,
        &ok.replace("2026-12-01", "1 Dec 2026"),
        &ok.replace(&"ab".repeat(32), &"AB".repeat(32)),
        &ok.replace("\"terms\":null", "\"terms\":true"),
        &ok.replace("}", ",\"extra\":1}"),
    ] {
        assert!(parse_approvals(bad).is_err(), "{bad}");
    }
}

/// ADR-037: a matching digest approves a text only once it holds no
/// pending point; a stale digest never approves. Every draft holds
/// pending points today, so none can be approved yet.
#[test]
fn adr037_approval_needs_the_exact_text_and_no_pending_point() {
    for t in LegalText::ALL {
        let exact = Approval {
            approved_on: "2026-12-01".to_owned(),
            sha256: digest_hex(t),
        };
        let stale = Approval {
            approved_on: "2026-12-01".to_owned(),
            sha256: "00".repeat(32),
        };
        assert!(!approves(t, Some(&stale)), "{t:?}");
        assert!(!approves(t, None), "{t:?}");
        // Each draft still holds TODO(legal) markers (ADR-037 section 3).
        assert!(!approves(t, Some(&exact)), "{t:?}");
        assert_eq!(digest_hex(t).len(), 64);
    }
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
    let html = page_html(LegalText::Imprint, Some(&d), None).unwrap();
    assert!(html.contains("Synthetic Org Ltd"));
    assert!(html.contains("X 000000"));
    assert!(html.contains("[not set: tenant.vat_number]"));
    assert!(html.contains("Draft, not yet approved"));
    let html = page_html(LegalText::Privacy, None, Some("/brand/x.css")).unwrap();
    assert!(html.contains("href=\"/brand/x.css\""));
    assert!(html.contains("[not set: controller.legal_name]"));
    assert_eq!(
        fstp_json::to_compact(&details_json(Some(&d))),
        r#"{"legal_name":"Synthetic Org Ltd","company_number":"X 000000"}"#
    );
    assert_eq!(fstp_json::to_compact(&details_json(None)), "{}");
}
