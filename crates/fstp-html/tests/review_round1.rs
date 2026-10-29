//! Regression tests for the findings of review round 1 of lane W1d.
//!
//! Each test failed before its fix. They use the public API only.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use fstp_html::{
    ApprovedText, CatalogueSource, Catalogues, Document, Element, EntrySource, HtmlError, Label,
    LabelOverride, MAX_DEPTH, MessageKind, Node, check_wellformed,
};

const SECRET: &str = "APPLICANT SECRET";

fn entries() -> [EntrySource<'static>; 2] {
    [
        EntrySource {
            id: "nav.home",
            kind: MessageKind::Label,
            message: "Home",
        },
        EntrySource {
            id: "notice.synthetic",
            kind: MessageKind::Approved,
            message: "SYNTHETIC TEST WORDING. NOT LEGAL TEXT.",
        },
    ]
}

fn cats() -> Catalogues {
    let e = entries();
    Catalogues::new(
        &CatalogueSource {
            locale: "en",
            entries: &e,
        },
        &[],
    )
    .unwrap()
}

/// A page whose body is a chain of `levels` nested `div`s.
fn nested(levels: usize) -> Document {
    let mut e = Element::new("div").text("leaf");
    for _ in 1..levels {
        e = Element::new("div").child(e);
    }
    Document::new("en").title(Node::text("t")).body(e)
}

/// I-68: a chain of exactly `MAX_DEPTH` elements below `body` renders, and
/// the checker accepts it. Before the fix the writer refused it.
#[test]
fn review_i68_max_depth_levels_below_body_render() {
    let doc = nested(MAX_DEPTH).render(&cats()).unwrap();
    assert_eq!(doc.as_str().matches("<div>").count(), MAX_DEPTH);
    assert_eq!(check_wellformed(doc.as_bytes()), Ok(()));
}

/// I-68: one level more than `MAX_DEPTH` below `body` is refused whole,
/// with a typed error.
#[test]
fn review_i68_max_depth_plus_one_levels_below_body_are_refused() {
    assert_eq!(
        nested(MAX_DEPTH + 1).render(&cats()),
        Err(HtmlError::Page {
            element: "div",
            rule: "the page nests too deep",
        })
    );
}

fn assert_no_secret(e: &HtmlError) {
    let shown = format!("{e} {e:?}").to_ascii_lowercase();
    assert!(
        !shown.contains("secret"),
        "the error copies the id: {shown}"
    );
}

/// R-NF-02: an id the catalogue does not know is never copied into the
/// error, whether or not it has the shape of an id.
#[test]
fn review_r_nf_02_unknown_message_id_is_not_copied_into_the_error() {
    let cats = cats();
    for id in [SECRET, "applicant.secret"] {
        let page = Document::new("en")
            .title(Node::text("t"))
            .body(Element::new("p").label(&Label::new(id), &[]));
        let e = page.render(&cats).unwrap_err();
        assert!(matches!(e, HtmlError::Message { .. }), "{e:?}");
        assert_no_secret(&e);
        let e = cats
            .resolve_approved("en", &ApprovedText::new(id), &[])
            .unwrap_err();
        assert!(matches!(e, HtmlError::Message { .. }), "{e:?}");
        assert_no_secret(&e);
    }
}

/// R-NF-02: an id the catalogue knows is still named, so a refusal for
/// the wrong kind stays diagnosable.
#[test]
fn review_r_nf_02_known_message_id_is_named_in_the_error() {
    let e = cats()
        .resolve_label("en", &Label::new("notice.synthetic"), &[])
        .unwrap_err();
    assert_eq!(
        e,
        HtmlError::Message {
            rule: "the id is approved wording, not a label",
            id: "notice.synthetic".to_owned(),
        }
    );
}

/// R-NF-02: a locale that is not a language tag is never copied into the
/// catalogue error.
#[test]
fn review_r_nf_02_invalid_locale_is_not_copied_into_the_error() {
    let e = entries();
    let err = Catalogues::new(
        &CatalogueSource {
            locale: SECRET,
            entries: &e,
        },
        &[],
    )
    .unwrap_err();
    assert!(matches!(err, HtmlError::Catalogue { .. }), "{err:?}");
    assert_no_secret(&err);
}

/// R-NF-02, R-WL-05: a repeated override of an unknown id is refused
/// without copying the id into the error.
#[test]
fn review_r_nf_02_repeated_unknown_override_id_is_not_copied_into_the_error() {
    let o = LabelOverride {
        locale: "en",
        id: "applicant.secret",
        message: "x",
    };
    let err = cats().with_overrides(&[o, o]).unwrap_err();
    assert!(matches!(err, HtmlError::Catalogue { .. }), "{err:?}");
    assert_no_secret(&err);
}

/// I-68: every allowed `<meta name>` renders with hostile content, and the
/// checker accepts the output. A name outside the list is refused.
#[test]
fn review_i68_meta_items_render_into_documents_the_checker_accepts() {
    let cats = cats();
    let hostile = "\"><script>alert(1)</script>&amp;'";
    for name in ["description", "viewport", "robots", "color-scheme"] {
        let doc = Document::new("en")
            .title(Node::text("t"))
            .meta(name, hostile)
            .render(&cats)
            .unwrap();
        assert_eq!(check_wellformed(doc.as_bytes()), Ok(()), "{}", doc.as_str());
        assert!(!doc.as_str().contains("<script>"), "{}", doc.as_str());
    }
    let refused = Document::new("en")
        .title(Node::text("t"))
        .meta("refresh", "0;url=https://evil.example/")
        .render(&cats);
    assert!(
        matches!(refused, Err(HtmlError::Attribute { .. })),
        "{refused:?}"
    );
}
