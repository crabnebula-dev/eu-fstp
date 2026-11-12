//! The corrigenda of a published Guide (I-51, I-53; P-05 and P-13
//! NOTE 7, O-52, D12; Q37 C of 2026-11-06).
//!
//! A published Guide never changes. A later change of the call's
//! effective P-05 or P-13 is a numbered entry of its effective-limits
//! record, and each entry is a corrigendum. [`corrigendum`] words one
//! entry with the Guide's own resolvers, so a corrigendum states its
//! values as the Guide does. Each corrigendum restates both limits in
//! full, so the Guide read with its latest corrigendum equals the
//! effective limits (I-51).
//!
//! [`page_with_corrigenda`] serves the stored Guide page with the
//! corrigenda after the Guide, inside its `main` element. The stored
//! bytes stay a prefix of the page, and the corrigenda go through the
//! escaping writer of `fstp-html` (I-68). With no corrigendum the page is
//! the stored page, byte for byte. Notification of corrigenda arrives
//! with M6.

use std::num::NonZeroU32;

use fstp_domain::policy::LiveSnapshot;
use fstp_domain::time::{Timestamp, ZoneName};
use fstp_html::{CatalogueSource, Catalogues, Document, Element, Node};
use fstp_programme::Compiled;

use crate::render::GUIDE_LOCALE;
use crate::resolve::{Ctx, GuideCall, GuideInputs, StoredTexts, Value, lookup};
use crate::{GuideError, known_name};

/// The end of every stored Guide page: its `main` element closes the
/// body.
const PAGE_END: &str = "</main></body></html>";

/// One corrigendum of a published Guide, as text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Corrigendum {
    /// The corrigendum number, from 1 in edit order.
    pub number: NonZeroU32,
    /// The maximum per recipient over the programme from this
    /// corrigendum on, an ADR-006 amount as the Guide shows P-05.
    pub p05: String,
    /// Who cannot apply from this corrigendum on, as the Guide shows the
    /// P-13 classes.
    pub p13: Vec<String>,
}

/// The value of `key` over `ctx`, or why it has none.
fn resolve(ctx: &Ctx<'_>, key: &'static str) -> Result<Value, GuideError> {
    let k = lookup(key).ok_or(GuideError::UnknownPlaceholder(known_name(key)))?;
    ctx.resolve(k).map_err(|reason| GuideError::Unresolved {
        key: known_name(key),
        reason,
    })
}

/// The corrigendum `number`, which sets the effective limits to `limits`
/// (module documentation). `compiled` and `texts` give the descriptions
/// of the P-13 classes, as for the Guide.
pub fn corrigendum(
    compiled: &Compiled,
    texts: &dyn StoredTexts,
    number: NonZeroU32,
    limits: &LiveSnapshot,
) -> Result<Corrigendum, GuideError> {
    let zone = ZoneName::new("UTC").ok_or(GuideError::Html("the UTC zone name"))?;
    // Only P-05 and P-13 are read, and both from `limits`. The call
    // record stays empty.
    let call = GuideCall {
        identifier: String::new(),
        opens: Timestamp::from_micros(0),
        deadline: Timestamp::from_micros(0),
        deadline_zone: zone,
        budget: String::new(),
    };
    let inputs = GuideInputs {
        compiled,
        publication: Some(limits),
        call: &call,
        guide_version: 1,
        platform_url: "",
        data_protection_summary: None,
        privacy_statement_url: None,
        texts,
        // Only P-05 and P-13 are read: the flag reaches no text.
        precheck_available: false,
    };
    let ctx = Ctx::new(&inputs);
    let p05 = match resolve(&ctx, "P-05")? {
        Value::Text(t) => t,
        _ => return Err(GuideError::Html("P-05 is not inline text")),
    };
    let p13 = match resolve(&ctx, "P-13.list")? {
        Value::List(items) => items,
        _ => return Err(GuideError::Html("P-13 is not a list")),
    };
    Ok(Corrigendum { number, p05, p13 })
}

/// The section of one corrigendum.
fn section(c: &Corrigendum) -> Element {
    let n = c.number.to_string();
    let mut classes = Element::new("ul").attr("class", "guide-value guide-locked");
    for item in &c.p13 {
        classes.push_child(Element::new("li").text(item));
    }
    let row = Element::new("tr")
        .child(Element::new("td").text("Maximum per recipient over the programme"))
        .child(
            Element::new("td").child(
                Element::new("span")
                    .attr("class", "guide-value guide-locked")
                    .text(&format!("{} EUR", c.p05)),
            ),
        );
    let table = Element::new("table")
        .child(
            Element::new("thead").child(
                Element::new("tr")
                    .child(Element::new("th").attr("scope", "col").text("Item"))
                    .child(Element::new("th").attr("scope", "col").text("Value")),
            ),
        )
        .child(Element::new("tbody").child(row));
    Element::new("section")
        .attr("class", "guide-corrigendum")
        .attr("id", &format!("corrigendum-{n}"))
        .child(Element::new("h3").text(&format!("Corrigendum {n}")))
        .child(Element::new("p").text(
            "This corrigendum corrects the Guide for Applicants above. From it on, these limits apply.",
        ))
        .child(table)
        .child(Element::new("p").text("You cannot apply if you are:"))
        .child(classes)
}

/// The stored Guide `page` with `corrigenda` after the Guide, in order
/// (module documentation). It refuses a page that does not end with the
/// Guide's `main` element.
pub fn page_with_corrigenda(page: &str, corrigenda: &[Corrigendum]) -> Result<String, GuideError> {
    if corrigenda.is_empty() {
        return Ok(page.to_owned());
    }
    let head = page.strip_suffix(PAGE_END).ok_or(GuideError::Html(
        "the stored Guide page does not end with its main element",
    ))?;
    let mut all = Element::new("section")
        .attr("class", "guide-corrigenda")
        .attr("id", "corrigenda")
        .child(Element::new("h2").text("Corrigenda"));
    for c in corrigenda {
        all.push_child(section(c));
    }
    let cats = Catalogues::new(
        &CatalogueSource {
            locale: GUIDE_LOCALE,
            entries: &[],
        },
        &[],
    )
    .map_err(|_| GuideError::Html("the empty catalogue"))?;
    let doc = Document::new(GUIDE_LOCALE)
        .title(Node::text("Corrigenda"))
        .body(all)
        .render(&cats)
        .map_err(|_| GuideError::Html("the corrigenda section"))?;
    let text = doc.as_str();
    let fragment = text
        .find("<body>")
        .and_then(|at| text.get(at.saturating_add("<body>".len())..))
        .and_then(|rest| rest.strip_suffix("</body></html>"))
        .ok_or(GuideError::Html("the corrigenda section has no body"))?;
    Ok(format!("{head}{fragment}{PAGE_END}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(n: u32) -> Corrigendum {
        Corrigendum {
            number: NonZeroU32::new(n).unwrap_or(NonZeroU32::MIN),
            p05: "350000.00".to_owned(),
            p13: vec!["Synthetic <class> & co".to_owned()],
        }
    }

    /// I-53: with no corrigendum the page is the stored page.
    #[test]
    fn i53_no_corrigendum_serves_the_stored_page() {
        let page = "<!DOCTYPE html><html><body><main>x</main></body></html>";
        assert_eq!(page_with_corrigenda(page, &[]).ok().as_deref(), Some(page));
    }

    /// I-53, I-68: the corrigenda follow the stored Guide inside its main
    /// element, escaped, and the stored bytes stay a prefix.
    #[test]
    fn i53_corrigenda_follow_the_stored_guide_escaped() {
        let page = "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>G</title></head><body><main class=\"guide\"><h1>G</h1></main></body></html>";
        let out = page_with_corrigenda(page, &[one(1), one(2)]).unwrap_or_default();
        let head = page.strip_suffix(PAGE_END).unwrap_or_default();
        assert!(out.starts_with(head));
        assert!(out.ends_with(PAGE_END));
        assert!(out.contains("Synthetic &lt;class&gt; &amp; co"));
        let first = out.find("Corrigendum 1").unwrap_or(usize::MAX);
        let second = out.find("Corrigendum 2").unwrap_or(0);
        assert!(first < second);
        assert!(fstp_html::check_wellformed(out.as_bytes()).is_ok(), "{out}");
    }

    /// I-53: a page that does not end with the Guide's main element is
    /// refused, never patched elsewhere.
    #[test]
    fn i53_foreign_page_is_refused() {
        assert!(page_with_corrigenda("<p>x</p>", &[one(1)]).is_err());
    }
}
