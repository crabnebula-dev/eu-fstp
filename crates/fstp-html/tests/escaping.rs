//! Escaping in every context (I-68, R-PB-04, M4 design sections 5.2 TW-2
//! and 9: "escaped text never closes an element or attribute").
//!
//! I-68 says no tenant-supplied script, style rule or markup executes. The
//! writer is the only way server-rendered pages put tenant and applicant
//! text into HTML, so each property here renders a hostile value at one
//! place and decodes the output with the independent reference parser.
//! The decoded tree must equal the page the caller described: no element,
//! attribute or reference appears that the caller did not write, and the
//! value comes back exactly.
//!
//! The contract checked at every place (interim reading, pending Daniel):
//!
//! - a plain value is always accepted and comes back exactly;
//! - a value holding characters that are not plain is refused with a
//!   typed error, or comes back with U+FFFD in their place;
//! - a URL is accepted exactly when it is safe, and comes back exactly.
//!
//! Red against the W0 stub: the writer API does not exist yet, and
//! `common::bind` refuses with `NotImplemented`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use common::bind::{self, Catalogues};
use common::chars::{self, HOSTILE, is_safe_url, is_typed};
use common::message::{self, CatSpec};
use common::reference;
use common::spec::{self, Page, Place};
use fstp_prop::{check, prop_assert};

/// Renders `page` and checks the contract of the module documentation.
fn escaping(page: &Page, spec_cats: &CatSpec, cats: &Catalogues) -> Result<(), String> {
    let plain = spec::texts_plain(page);
    let safe = spec::urls_safe(page);
    match bind::render(page, cats) {
        Err(e) => {
            prop_assert!(is_typed(&e), "{e}");
            prop_assert!(
                !(plain && safe),
                "refused a page with plain values and safe URLs: {e}"
            );
            Ok(())
        }
        Ok(r) => {
            prop_assert!(safe, "accepted an unsafe URL");
            let shown = String::from_utf8_lossy(&r.bytes).into_owned();
            let got = reference::parse(&r.bytes)
                .map_err(|e| format!("the output leaves the subset: {e}\n{shown}"))?;
            let want = spec::expected_tree(page, spec_cats)?;
            prop_assert!(
                got == want,
                "the decoded tree differs from the page\n  got: {got:?}\n want: {want:?}\n{shown}"
            );
            Ok(())
        }
    }
}

/// One property: a hostile value at `place`, in each locale.
fn context(name: &str, place: Place) {
    let spec_cats = message::fixture();
    check(name, |g| {
        let cats = bind::catalogues(&spec_cats).map_err(|e| e.to_string())?;
        let locales = spec_cats.locales();
        let locale = *g.pick(&locales);
        let v = if place.is_url() {
            chars::url(g)
        } else {
            chars::dynamic(g)
        };
        g.note("value", &v);
        escaping(&spec::at(place, locale, &v), &spec_cats, &cats)
    });
}

/// I-68: text in a `p`.
#[test]
fn i68_escaping_text_in_p() {
    context("i68_escaping_text_in_p", Place::TextInP);
}

/// I-68: text in the `title`, an RCDATA element.
#[test]
fn i68_escaping_text_in_title() {
    context("i68_escaping_text_in_title", Place::TextInTitle);
}

/// I-68: text in a `textarea`, an RCDATA element whose first line feed
/// the HTML parser drops.
#[test]
fn i68_escaping_text_in_textarea() {
    context("i68_escaping_text_in_textarea", Place::TextInTextarea);
}

/// I-68: text in a `pre`, whose first line feed the HTML parser drops.
#[test]
fn i68_escaping_text_in_pre() {
    context("i68_escaping_text_in_pre", Place::TextInPre);
}

/// I-68: text in an `option`.
#[test]
fn i68_escaping_text_in_option() {
    context("i68_escaping_text_in_option", Place::TextInOption);
}

/// I-68: text in a table cell.
#[test]
fn i68_escaping_text_in_table_cell() {
    context("i68_escaping_text_in_table_cell", Place::TextInCell);
}

/// I-68: text in a list item.
#[test]
fn i68_escaping_text_in_list_item() {
    context("i68_escaping_text_in_list_item", Place::TextInListItem);
}

/// I-68: the `title` attribute.
#[test]
fn i68_escaping_title_attribute() {
    context("i68_escaping_title_attribute", Place::AttrTitle);
}

/// I-68: the `alt` attribute of an image.
#[test]
fn i68_escaping_alt_attribute() {
    context("i68_escaping_alt_attribute", Place::AttrAlt);
}

/// I-68: the `value` attribute of an input.
#[test]
fn i68_escaping_value_attribute() {
    context("i68_escaping_value_attribute", Place::AttrValue);
}

/// I-68: the `placeholder` attribute of a textarea.
#[test]
fn i68_escaping_placeholder_attribute() {
    context("i68_escaping_placeholder_attribute", Place::AttrPlaceholder);
}

/// I-68, R-NF-03: the `aria-label` attribute.
#[test]
fn i68_escaping_aria_label_attribute() {
    context("i68_escaping_aria_label_attribute", Place::AttrAriaLabel);
}

/// I-68, TW-2: the `href` of a link. Only safe URLs pass.
#[test]
fn i68_escaping_link_href() {
    context("i68_escaping_link_href", Place::UrlHref);
}

/// I-68: the `src` of an image. Only safe URLs pass.
#[test]
fn i68_escaping_image_src() {
    context("i68_escaping_image_src", Place::UrlSrc);
}

/// I-68: the `action` of a form. Only safe URLs pass.
#[test]
fn i68_escaping_form_action() {
    context("i68_escaping_form_action", Place::UrlAction);
}

/// I-68, R-PB-04: the stylesheet `href` in the head. Only safe URLs pass,
/// so no page loads a third-party style (TH-37).
#[test]
fn i68_escaping_stylesheet_href() {
    context("i68_escaping_stylesheet_href", Place::UrlStylesheet);
}

/// I-68, R-NF-04: a message argument in text. The message literals hold
/// characters that need escaping too.
#[test]
fn i68_escaping_message_argument_in_text() {
    context("i68_escaping_message_argument_in_text", Place::ArgInText);
}

/// I-68, R-NF-04: a message argument in an attribute.
#[test]
fn i68_escaping_message_argument_in_attribute() {
    context(
        "i68_escaping_message_argument_in_attribute",
        Place::ArgInAttr,
    );
}

/// I-68, R-PB-04: whole generated pages, with hostile values and URLs at
/// every place at once, nested in every element the generator knows.
#[test]
fn i68_escaping_round_trips_in_generated_pages() {
    let spec_cats = message::fixture();
    check("i68_escaping_round_trips_in_generated_pages", |g| {
        let cats = bind::catalogues(&spec_cats).map_err(|e| e.to_string())?;
        let page = spec::page(g, &spec_cats, spec::ANY);
        escaping(&page, &spec_cats, &cats)
    });
}

const TEXT_PLACES: &[Place] = &[
    Place::TextInP,
    Place::TextInTitle,
    Place::TextInTextarea,
    Place::TextInPre,
    Place::TextInOption,
    Place::TextInCell,
    Place::TextInListItem,
    Place::AttrTitle,
    Place::AttrAlt,
    Place::AttrValue,
    Place::AttrPlaceholder,
    Place::AttrAriaLabel,
    Place::ArgInText,
    Place::ArgInAttr,
];

const URL_PLACES: &[Place] = &[
    Place::UrlHref,
    Place::UrlSrc,
    Place::UrlAction,
    Place::UrlStylesheet,
];

/// I-68: every plain hostile fragment, alone, at every text and attribute
/// place, renders and comes back exactly. A fixed table, so a regression
/// names the fragment and the place.
#[test]
fn i68_every_hostile_fragment_round_trips_at_every_place() {
    let spec_cats = message::fixture();
    let cats = bind::catalogues(&spec_cats).unwrap_or_else(|e| panic!("{e}"));
    let mut failures = Vec::new();
    for &place in TEXT_PLACES {
        for frag in HOSTILE.iter().filter(|f| chars::all_plain(f)) {
            let page = spec::at(place, "en", frag);
            if let Err(e) = escaping(&page, &spec_cats, &cats) {
                failures.push(format!("{place:?} {frag:?}: {e}"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// I-68, TW-2: each URL that leaves the origin, runs script or can be
/// rewritten by a browser is refused at every URL place, with a typed
/// error.
#[test]
fn i68_unsafe_url_is_refused_at_every_url_place() {
    const UNSAFE: &[&str] = &[
        "",
        "javascript:alert(1)",
        "JAVASCRIPT:alert(1)",
        " javascript:alert(1)",
        "jav\tascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "vbscript:msgbox(1)",
        "//evil.example/",
        "/\\evil.example/",
        "/\t/evil.example/",
        "/\n/evil.example/",
        "/\r/evil.example/",
        "http://example.org/",
        "https:/example.org/",
        "https:///example.org/",
        "mailto:a@example.org",
        "evil.example",
        "#top",
        "/a b",
        "/\u{e9}",
    ];
    let spec_cats = message::fixture();
    let cats = bind::catalogues(&spec_cats).unwrap_or_else(|e| panic!("{e}"));
    let mut failures = Vec::new();
    for &place in URL_PLACES {
        for &u in UNSAFE {
            assert!(!is_safe_url(u), "{u:?} is safe under the reference");
            match bind::render(&spec::at(place, "en", u), &cats) {
                Ok(_) => failures.push(format!("{place:?} accepted {u:?}")),
                Err(e) if !is_typed(&e) => failures.push(format!("{place:?} {u:?}: {e}")),
                Err(_) => {}
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
