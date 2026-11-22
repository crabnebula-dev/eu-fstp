//! The legal pages behind the footer (ADR-037 section 2; Daniel,
//! 2026-11-22, `legal/README.md` Q6).
//!
//! Each page renders one `legal/` draft, embedded at build time, with the
//! tenant's values filled in. The page shows the part of the draft after
//! its first `---` line; the part above is drafting notes for Daniel.
//!
//! - Every draft byte and every tenant value is written as text by the
//!   escaping writer of `fstp-html`, never as markup (I-68).
//! - A placeholder with no value shows the visible marker
//!   "[not set: name]". Raw template syntax never reaches the page.
//! - Each `TODO(legal)` shows the visible marker "Pending legal review",
//!   and each `[NOT BUILT ...]` the marker "Not built yet". Nothing in the
//!   shown part is hidden.
//! - Until a text is approved (ADR-037 section 3), the page opens with the
//!   banner "Draft, not yet approved". The caller decides approval.
//! - The page holds no script and no form (R-PB-04). Its colours come
//!   from the platform tokens, so it follows the device theme (I-70).

pub mod markdown;

use std::sync::OnceLock;

use fstp_html::{
    CatalogueSource, Catalogues, Document, Element, EntrySource, HtmlError, Label, MessageKind,
    Node, SafeUrl,
};

use crate::PublicError;
use crate::html::PublicDocument;
use markdown::{Block, Inline};

/// One legal text with a page behind the footer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LegalText {
    /// The privacy notice (`legal/01-privacy-notice.md`).
    Privacy,
    /// The accessibility statement (`legal/07-accessibility-statement.md`).
    Accessibility,
    /// The imprint (`legal/06-imprint.md`).
    Imprint,
    /// The terms of use (`legal/04-terms-of-use.md`).
    Terms,
    /// The Data Act information (`legal/16-data-act-information.md`).
    DataAct,
}

/// The prefix of every legal page path.
pub const LEGAL_PREFIX: &str = "/legal/";

impl LegalText {
    /// Every text, in footer order.
    pub const ALL: [LegalText; 5] = [
        LegalText::Privacy,
        LegalText::Accessibility,
        LegalText::Imprint,
        LegalText::Terms,
        LegalText::DataAct,
    ];

    /// The text's key in `legal/page-approvals.json`.
    pub const fn key(self) -> &'static str {
        match self {
            LegalText::Privacy => "privacy",
            LegalText::Accessibility => "accessibility",
            LegalText::Imprint => "imprint",
            LegalText::Terms => "terms",
            LegalText::DataAct => "data_act",
        }
    }

    /// The page path.
    pub const fn path(self) -> &'static str {
        match self {
            LegalText::Privacy => "/legal/privacy",
            LegalText::Accessibility => "/legal/accessibility",
            LegalText::Imprint => "/legal/imprint",
            LegalText::Terms => "/legal/terms",
            LegalText::DataAct => "/legal/data-act",
        }
    }

    /// The text whose page is `path`, exactly.
    pub fn from_path(path: &str) -> Option<LegalText> {
        LegalText::ALL.into_iter().find(|t| t.path() == path)
    }

    /// The draft's file name under `legal/`.
    pub const fn file(self) -> &'static str {
        match self {
            LegalText::Privacy => "01-privacy-notice.md",
            LegalText::Accessibility => "07-accessibility-statement.md",
            LegalText::Imprint => "06-imprint.md",
            LegalText::Terms => "04-terms-of-use.md",
            LegalText::DataAct => "16-data-act-information.md",
        }
    }

    /// The whole draft, as embedded at build time.
    pub const fn source(self) -> &'static str {
        match self {
            LegalText::Privacy => include_str!("../../../../legal/01-privacy-notice.md"),
            LegalText::Accessibility => {
                include_str!("../../../../legal/07-accessibility-statement.md")
            }
            LegalText::Imprint => include_str!("../../../../legal/06-imprint.md"),
            LegalText::Terms => include_str!("../../../../legal/04-terms-of-use.md"),
            LegalText::DataAct => include_str!("../../../../legal/16-data-act-information.md"),
        }
    }

    /// The catalogue id of the text's name.
    const fn title_id(self) -> &'static str {
        match self {
            LegalText::Privacy => "legal.title.privacy",
            LegalText::Accessibility => "legal.title.accessibility",
            LegalText::Imprint => "legal.title.imprint",
            LegalText::Terms => "legal.title.terms",
            LegalText::DataAct => "legal.title.data_act",
        }
    }

    /// The `data-mandatory` key of the text's footer element (I-69).
    pub const fn mandatory_key(self) -> &'static str {
        match self {
            LegalText::Privacy => "privacy_notice",
            LegalText::Accessibility => "accessibility_statement",
            LegalText::Imprint => "imprint",
            LegalText::Terms => "terms_of_use",
            LegalText::DataAct => "data_act_information",
        }
    }

    /// The part of the draft the page shows: everything after the first
    /// line that is `---`, or the whole draft when it has none.
    pub fn shown(self) -> &'static str {
        shown_part(self.source())
    }
}

/// The part of `src` after its first `---` line, or all of `src`.
pub fn shown_part(src: &str) -> &str {
    let mut at = 0usize;
    for line in src.split_inclusive('\n') {
        at = at.saturating_add(line.len());
        if line.trim() == "---" {
            return src.get(at..).unwrap_or("");
        }
    }
    src
}

/// The number of pending points in the shown part of `src`: each
/// `TODO(legal)` and each `[NOT BUILT ...]`. A text with any is never
/// approved (ADR-037 section 3).
pub fn pending_points(src: &str) -> usize {
    markdown::parse(shown_part(src)).map_or(usize::MAX, |b| markdown::pending_points(&b))
}

/// What a legal page needs besides its text.
pub struct LegalPage<'a> {
    /// The text.
    pub text: LegalText,
    /// Whether Daniel approved this exact text (ADR-037 section 3).
    pub approved: bool,
    /// The value of a placeholder name, or `None` when it is not set.
    pub value: &'a dyn Fn(&str) -> Option<String>,
    /// The tenant's brand stylesheet path, if any.
    pub stylesheet: Option<&'a str>,
}

impl std::fmt::Debug for LegalPage<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LegalPage")
            .field("text", &self.text)
            .field("approved", &self.approved)
            .finish_non_exhaustive()
    }
}

const fn label(id: &'static str, message: &'static str) -> EntrySource<'static> {
    EntrySource {
        id,
        kind: MessageKind::Label,
        message,
    }
}

/// The interface strings of the legal pages. They name the pages and the
/// markers; none is legal wording.
const ENTRIES: &[EntrySource<'static>] = &[
    label("legal.title.privacy", "Privacy notice"),
    label("legal.title.accessibility", "Accessibility statement"),
    label("legal.title.imprint", "Imprint"),
    label("legal.title.terms", "Terms of use"),
    label("legal.title.data_act", "Data Act information"),
    label("legal.banner.title", "Draft, not yet approved"),
    label(
        "legal.banner.body",
        "This text is a draft under legal review. It may still change.",
    ),
    label(
        "legal.banner.count",
        "Points still pending legal review: {count}. Each is marked below.",
    ),
    label("legal.pending", "Pending legal review"),
    label("legal.not_built", "Not built yet:"),
    label("legal.unset", "[not set: {name}]"),
    label("legal.footer.nav", "Legal information"),
    label("legal.footer.attribution", "Runs on the FSTP platform."),
];

/// The locale of the legal pages.
const LOCALE: &str = "en";

fn catalogues() -> Result<&'static Catalogues, PublicError> {
    static CATS: OnceLock<Result<Catalogues, HtmlError>> = OnceLock::new();
    CATS.get_or_init(|| {
        Catalogues::new(
            &CatalogueSource {
                locale: LOCALE,
                entries: ENTRIES,
            },
            &[],
        )
    })
    .as_ref()
    .map_err(|_| PublicError::Html("the legal page catalogue"))
}

fn l(id: &str) -> Label {
    Label::new(id)
}

fn html_err(_: HtmlError) -> PublicError {
    PublicError::Html("the HTML writer refused a legal page")
}

/// The nodes of an inline run.
fn inline_nodes(run: &[Inline], value: &dyn Fn(&str) -> Option<String>) -> Vec<Node> {
    run.iter()
        .map(|i| match i {
            Inline::Text(s) => Node::text(s),
            Inline::Strong(inner) => Element::new("strong")
                .children(inline_nodes(inner, value))
                .into(),
            Inline::Code(s) => Element::new("code").text(s).into(),
            Inline::Placeholder(name) => match value(name) {
                Some(v) => Element::new("span")
                    .attr("class", "legal-value")
                    .text(&v)
                    .into(),
                None => Element::new("span")
                    .attr("class", "legal-unset")
                    .label(&l("legal.unset"), &[("name", name)])
                    .into(),
            },
            Inline::Pending => Element::new("span")
                .attr("class", "legal-pending")
                .label(&l("legal.pending"), &[])
                .into(),
            Inline::NotBuilt(inner) => Element::new("span")
                .attr("class", "legal-pending legal-not-built")
                .child(Element::new("strong").label(&l("legal.not_built"), &[]))
                .child(Node::text(" "))
                .children(inline_nodes(inner, value))
                .into(),
        })
        .collect()
}

/// The elements of the blocks. A draft heading of level 1 or 2 is an
/// `h2`, under the page's one `h1`.
fn block_nodes(blocks: &[Block], value: &dyn Fn(&str) -> Option<String>) -> Vec<Node> {
    let cell = |tag: &'static str, run: &[Inline]| -> Node {
        let el = Element::new(tag).children(inline_nodes(run, value));
        let el = if tag == "th" {
            el.attr("scope", "col")
        } else {
            el
        };
        el.into()
    };
    blocks
        .iter()
        .map(|b| -> Node {
            match b {
                Block::Heading(level, run) => {
                    let tag = match level {
                        0..=2 => "h2",
                        3 => "h3",
                        4 => "h4",
                        5 => "h5",
                        _ => "h6",
                    };
                    Element::new(tag).children(inline_nodes(run, value)).into()
                }
                Block::Paragraph(run) => {
                    Element::new("p").children(inline_nodes(run, value)).into()
                }
                Block::List { ordered, items } => Element::new(if *ordered { "ol" } else { "ul" })
                    .children(items.iter().map(|run| -> Node {
                        Element::new("li").children(inline_nodes(run, value)).into()
                    }))
                    .into(),
                Block::Table { head, rows } => {
                    let mut table = Element::new("table").attr("class", "legal-table");
                    if let Some(h) = head {
                        table =
                            table.child(Element::new("thead").child(
                                Element::new("tr").children(h.iter().map(|c| cell("th", c))),
                            ));
                    }
                    table
                        .child(Element::new("tbody").children(rows.iter().map(|r| -> Node {
                            Element::new("tr")
                                .children(r.iter().map(|c| cell("td", c)))
                                .into()
                        })))
                        .into()
                }
                Block::Rule => Element::new("hr").into(),
            }
        })
        .collect()
}

/// The footer of a legal page: a link to each legal page, the current one
/// marked, then the platform attribution (I-69, P-68).
fn footer(current: LegalText) -> Result<Element, PublicError> {
    let mut list = Element::new("ul");
    for t in LegalText::ALL {
        let href = SafeUrl::new(t.path()).map_err(html_err)?;
        let mut a = Element::new("a")
            .attr("data-mandatory", t.mandatory_key())
            .attr_url("href", href);
        if t == current {
            a = a.attr("aria-current", "page");
        }
        list.push_child(Element::new("li").child(a.label(&l(t.title_id()), &[])));
    }
    list.push_child(
        Element::new("li").child(
            Element::new("span")
                .attr("data-mandatory", "platform_attribution")
                .label(&l("legal.footer.attribution"), &[]),
        ),
    );
    Ok(Element::new("footer").attr("class", "site-footer").child(
        Element::new("nav")
            .attr("class", "inner")
            .attr_label("aria-label", &l("legal.footer.nav"), &[])
            .child(list),
    ))
}

/// Renders the legal page `page`.
///
/// # Errors
///
/// [`PublicError::Html`] when the draft does not parse or the writer
/// refuses the page, which signals a defect here.
pub fn render_legal(page: &LegalPage<'_>) -> Result<PublicDocument, PublicError> {
    render_source(page, page.text.shown())
}

/// Renders `page` with `src` in place of its draft's shown part. The fuzz
/// target `legal_markdown` and the property tests use it with any input.
///
/// # Errors
///
/// As [`render_legal`].
pub fn render_source(page: &LegalPage<'_>, src: &str) -> Result<PublicDocument, PublicError> {
    let blocks =
        markdown::parse(src).map_err(|_| PublicError::Html("the legal draft is too long"))?;
    let title = l(page.text.title_id());
    let mut main = Element::new("main")
        .attr("id", "main-content")
        .attr("class", "legal-page")
        .child(Element::new("h1").label(&title, &[]));
    if !page.approved {
        let count = markdown::pending_points(&blocks);
        let mut banner = Element::new("div")
            .attr("class", "legal-banner")
            .attr("role", "note")
            .child(
                Element::new("p")
                    .attr("class", "legal-banner-title")
                    .child(Element::new("strong").label(&l("legal.banner.title"), &[])),
            )
            .child(Element::new("p").label(&l("legal.banner.body"), &[]));
        if count > 0 {
            banner = banner.child(
                Element::new("p").label(&l("legal.banner.count"), &[("count", &count.to_string())]),
            );
        }
        main = main.child(banner);
    }
    main = main.child(
        Element::new("article")
            .attr("class", "legal-text")
            .children(block_nodes(&blocks, page.value)),
    );
    let mut doc = Document::new(LOCALE)
        .title(Node::label(&title, &[]))
        .meta("viewport", "width=device-width, initial-scale=1");
    if let Some(css) = page.stylesheet {
        doc = doc.stylesheet(SafeUrl::new(css).map_err(html_err)?);
    }
    doc.body(
        Element::new("div")
            .attr("class", "page-body page-body--public")
            .child(main),
    )
    .body(footer(page.text)?)
    .render(catalogues()?)
    .map(PublicDocument::from)
    .map_err(html_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R-NF-04: the catalogue of the legal pages builds.
    #[test]
    fn r_nf_04_legal_catalogue_builds() {
        assert!(catalogues().is_ok());
    }

    /// ADR-037: each path names one text, and only an exact path does.
    #[test]
    fn adr037_paths_name_one_text() {
        for t in LegalText::ALL {
            assert_eq!(LegalText::from_path(t.path()), Some(t));
            assert!(t.path().starts_with(LEGAL_PREFIX));
        }
        for bad in ["/legal/", "/legal/privacy/", "/legal/PRIVACY", "/legal/x"] {
            assert_eq!(LegalText::from_path(bad), None, "{bad}");
        }
    }

    /// ADR-037: the shown part starts after the first `---` line.
    #[test]
    fn adr037_shown_part_skips_the_drafting_notes() {
        assert_eq!(
            shown_part("notes\n---\n\nbody\n---\nmore"),
            "\nbody\n---\nmore"
        );
        assert_eq!(shown_part("no rule"), "no rule");
    }
}
