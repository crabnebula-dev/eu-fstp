//! The public page renderer. It takes only a `&PublicView` (rule A6).
//!
//! Every page is server-rendered HTML through the escaping writer of
//! `fstp-html`, with no script at all (R-PB-04, R-JV-06). The pages follow
//! the approved prototypes `calls-public`, `call-detail-public` and
//! `public-grants` (`docs/design/03-applicant-screens.md`): a top bar with
//! the programme and a public navigation, one `main` and a footer.
//!
//! The contract the tests pin, interim, pending Daniel:
//!
//! - Each page has one `main` element with one `h1`.
//! - Every dynamic text node is a text leaf of the page's part of the
//!   view, and every such leaf is written (I-87). Enum fields, such as a
//!   grant's level and status, are catalogue labels, not dynamic text.
//!   The leaves, which `tests/support/mod.rs` writes as the reference:
//!   - every page: the programme name;
//!   - the programme page: the narrative; per open call its id, title,
//!     `grant_min`, `grant_max`, deadline and deadline zone; per
//!     aggregate its call, its count in decimal and its total;
//!   - a call page: the call's id, title, opening, deadline, deadline
//!     zone, budget, `grant_min`, `grant_max` and each P-09 text;
//!   - the funded and finished pages: per grant of the phase its call,
//!     title and summary, and its grantee and amount when present.
//! - The programme page lists every open call and links its call page,
//!   `/p/{slug}/calls/{call}`, and each aggregate.
//! - A call page links its Guide, `/p/{slug}/calls/{call}/guide`, and
//!   holds the AI disclosure section, `section#ai-disclosure`, whose
//!   wording is a `TODO(legal)` catalogue text (R-LA-08).
//! - The Guide page is the call's published Guide document, byte for byte.
//! - A page that names a call the view does not hold is
//!   [`PublicError::NotFound`].
//!
//! Interim readings, pending Daniel: an empty narrative is not written;
//! a path segment is written with every byte outside `A-Z a-z 0-9 - . _ ~`
//! percent-encoded, so a link never leaves its page's origin; the sign-in
//! links name the M3 pages `/auth/login` and `/auth/signup`.

use std::sync::OnceLock;

use fstp_html::{
    ApprovedText, CatalogueSource, Catalogues, Document, Element, EntrySource, HtmlDocument,
    HtmlError, Label, MessageKind, Node, SafeUrl, TraceEvent,
};

use crate::PublicError;
use crate::view::{GrantStatus, PublicCall, PublicGrant, PublicView};

/// The bytes of one rendered public page: a page of the view, written by
/// the escaping writer of `fstp-html`, or the stored Guide page with its
/// corrigenda, which nothing here binds again (I-53).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicDocument(String);

impl PublicDocument {
    /// The page bytes, UTF-8.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// The page text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The page bytes, by value.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0.into_bytes()
    }
}

impl From<HtmlDocument> for PublicDocument {
    fn from(d: HtmlDocument) -> PublicDocument {
        PublicDocument(d.as_str().to_owned())
    }
}

/// One public page.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PublicPage {
    /// `/p/{slug}/`: the programme and its open calls.
    Programme,
    /// `/p/{slug}/calls/{call}`: one open call.
    Call(String),
    /// `/p/{slug}/calls/{call}/guide`: the Guide of one open call.
    Guide(String),
    /// `/p/{slug}/funded`.
    Funded,
    /// `/p/{slug}/finished`.
    Finished,
}

/// What every public page carries besides the view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chrome {
    /// The same-origin path of the public stylesheet, if any.
    pub stylesheet: Option<String>,
}

/// The locale of the public pages. Interim, pending the locale
/// negotiation of R-NF-04 for public visitors: English only in M4.
const LOCALE: &str = "en";

const fn label(id: &'static str, message: &'static str) -> EntrySource<'static> {
    EntrySource {
        id,
        kind: MessageKind::Label,
        message,
    }
}

/// The interface strings of the public pages.
const ENTRIES: &[EntrySource<'static>] = &[
    label("public.nav", "Public navigation"),
    label("public.nav.calls", "Open calls"),
    label("public.nav.funded", "Funded projects"),
    label("public.nav.finished", "Finished projects"),
    label("public.nav.signin", "Sign in"),
    label("public.title.call", "{title}, {programme}"),
    label("public.title.funded", "Funded projects, {programme}"),
    label("public.title.finished", "Finished projects, {programme}"),
    label("public.calls.heading", "Open calls"),
    label("public.calls.none", "There are no open calls right now."),
    label("public.call.id", "Call {id}"),
    label("public.call.open", "Open"),
    label("public.call.opens", "Opens"),
    label("public.call.closes", "Closes"),
    label("public.call.budget", "Total call budget"),
    label("public.call.range", "Grant per proposal"),
    label("public.call.range_value", "{min} to {max}"),
    label("public.call.zone", " ({zone})"),
    label(
        "public.call.amounts",
        "Amounts are shown exactly as the call states them.",
    ),
    label("public.call.eligibility", "Who can apply"),
    label(
        "public.call.eligibility_intro",
        "The call checks these eligibility rules (P-09) before any review:",
    ),
    label("public.call.guide", "Read the Guide for Applicants"),
    label("public.call.apply", "Sign in to apply"),
    label("public.call.signup", "Create an account"),
    label("public.ai.heading", "Use of AI tools"),
    label("public.aggregates.heading", "Grants so far"),
    label(
        "public.aggregates.row",
        "Call {call}: {grants} public grants, {total} in total",
    ),
    label("public.funded.heading", "Funded projects"),
    label("public.finished.heading", "Finished projects"),
    label("public.funded.none", "No funded project is public yet."),
    label("public.finished.none", "No finished project is public yet."),
    label("public.grant.call", "Call"),
    label("public.grant.status", "Status"),
    label("public.grant.grantee", "Grantee"),
    label("public.grant.amount", "Granted amount"),
    label("public.status.granted", "Granted"),
    label("public.status.in_execution", "In execution"),
    label("public.status.completed", "Completed"),
    // TODO(legal): the platform attribution (P-68), the privacy notice,
    // the accessibility statement and the funder visibility elements.
    // Daniel supplies the approved wording.
    label(
        "public.footer",
        "FSTP platform. Synthetic placeholder: the legal notices are pending approved wording.",
    ),
    // TODO(legal): the approved AI disclosure for applicants (R-LA-08, AI
    // Act Article 50). This placeholder states only what the platform
    // does, in the words of the shipped Guide template.
    EntrySource {
        id: "public.ai.disclosure",
        kind: MessageKind::Approved,
        message: "This call uses AI tools. An AI system reviews drafts at the pre-check, and AI findings support reviewers but never decide.",
    },
];

/// The built catalogue of the public pages.
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
    .map_err(html_err)
}

/// The rule an HTML error names.
fn html_err(e: &HtmlError) -> PublicError {
    PublicError::Html(match e {
        HtmlError::NotWellFormed { rule, .. }
        | HtmlError::MessageSyntax { rule, .. }
        | HtmlError::AcceptLanguage { rule }
        | HtmlError::Catalogue { rule, .. }
        | HtmlError::Message { rule, .. }
        | HtmlError::Page { rule, .. }
        | HtmlError::Attribute { rule, .. } => rule,
        HtmlError::UnsafeUrl => "an unsafe URL",
        HtmlError::UnknownLocale => "an unknown locale",
        _ => "the writer refused the page",
    })
}

fn l(id: &str) -> Label {
    Label::new(id)
}

/// An element holding one label with no argument.
fn el(tag: &'static str, id: &str) -> Element {
    Element::new(tag).label(&l(id), &[])
}

/// `s` as one path segment: every byte outside the unreserved set is
/// percent-encoded.
fn segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The same-origin URL `path`.
fn url(path: &str) -> Result<SafeUrl, PublicError> {
    SafeUrl::new(path).map_err(|e| html_err(&e))
}

/// The paths of one programme's pages.
struct Paths {
    base: String,
}

impl Paths {
    fn of(view: &PublicView) -> Paths {
        Paths {
            base: format!("/p/{}/", segment(&view.programme.slug)),
        }
    }

    fn programme(&self) -> Result<SafeUrl, PublicError> {
        url(&self.base)
    }

    fn call(&self, id: &str) -> Result<SafeUrl, PublicError> {
        url(&format!("{}calls/{}", self.base, segment(id)))
    }

    fn guide(&self, id: &str) -> Result<SafeUrl, PublicError> {
        url(&format!("{}calls/{}/guide", self.base, segment(id)))
    }

    fn funded(&self) -> Result<SafeUrl, PublicError> {
        url(&format!("{}funded", self.base))
    }

    fn finished(&self) -> Result<SafeUrl, PublicError> {
        url(&format!("{}finished", self.base))
    }
}

/// Which navigation entry is the current page.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Current {
    Calls,
    Funded,
    Finished,
    None,
}

/// A navigation entry.
fn nav_item(href: SafeUrl, id: &str, current: bool) -> Element {
    let mut a = Element::new("a").attr_url("href", href);
    if current {
        a = a.attr("aria-current", "page");
    }
    Element::new("li").child(a.label(&l(id), &[]))
}

/// The top bar: the programme, linking its page, and the public
/// navigation.
fn header(view: &PublicView, paths: &Paths, current: Current) -> Result<Element, PublicError> {
    let brand = Element::new("a")
        .attr("class", "brand")
        .attr_url("href", paths.programme()?)
        .child(Element::new("span").text(&view.programme.name));
    let nav = Element::new("nav")
        .attr("class", "main-nav")
        .attr_label("aria-label", &l("public.nav"), &[])
        .child(
            Element::new("ul")
                .child(nav_item(
                    paths.programme()?,
                    "public.nav.calls",
                    current == Current::Calls,
                ))
                .child(nav_item(
                    paths.funded()?,
                    "public.nav.funded",
                    current == Current::Funded,
                ))
                .child(nav_item(
                    paths.finished()?,
                    "public.nav.finished",
                    current == Current::Finished,
                ))
                .child(nav_item(url("/auth/login")?, "public.nav.signin", false)),
        );
    Ok(Element::new("header").attr("class", "site-header").child(
        Element::new("div")
            .attr("class", "topbar")
            .child(brand)
            .child(nav),
    ))
}

/// The footer of every page.
fn footer() -> Element {
    Element::new("footer").attr("class", "site-footer").child(
        Element::new("div")
            .attr("class", "inner")
            .child(el("p", "public.footer")),
    )
}

/// A whole page around `main`.
fn page(
    view: &PublicView,
    chrome: &Chrome,
    title: Node,
    current: Current,
    main: Element,
) -> Result<Document, PublicError> {
    let paths = Paths::of(view);
    let mut doc = Document::new(LOCALE)
        .title(title)
        .meta("viewport", "width=device-width, initial-scale=1");
    if let Some(css) = &chrome.stylesheet {
        doc = doc.stylesheet(url(css)?);
    }
    Ok(doc
        .body(header(view, &paths, current)?)
        .body(
            Element::new("div")
                .attr("class", "page-body page-body--public")
                .child(main.attr("id", "main-content")),
        )
        .body(footer()))
}

/// A deadline or opening: the instant, then its zone.
fn instant(at: &str, zone: &str) -> Element {
    Element::new("dd")
        .child(Element::new("time").attr("datetime", at).text(at))
        .child(Node::label(&l("public.call.zone"), &[("zone", zone)]))
}

/// The P-04 range of a call.
fn range(c: &PublicCall) -> Element {
    Element::new("dd").label(
        &l("public.call.range_value"),
        &[("min", &c.grant_min), ("max", &c.grant_max)],
    )
}

/// The programme page.
fn programme_page(view: &PublicView, paths: &Paths) -> Result<Element, PublicError> {
    let p = &view.programme;
    let mut main = Element::new("main").child(Element::new("h1").text(&p.name));
    if !p.narrative.is_empty() {
        main.push_child(Element::new("p").text(&p.narrative));
    }
    main.push_child(el("h2", "public.calls.heading"));
    if view.open_calls.is_empty() {
        main.push_child(el("p", "public.calls.none"));
    } else {
        let mut list = Element::new("ul").attr("class", "call-list");
        for c in &view.open_calls {
            list.push_child(
                Element::new("li")
                    .attr("class", "card")
                    .child(
                        Element::new("h3").child(
                            Element::new("a")
                                .attr_url("href", paths.call(&c.id)?)
                                .text(&c.title),
                        ),
                    )
                    .child(
                        Element::new("p")
                            .child(
                                Element::new("span")
                                    .attr("class", "badge badge--success")
                                    .label(&l("public.call.open"), &[]),
                            )
                            .child(
                                Element::new("span")
                                    .attr("class", "pid")
                                    .label(&l("public.call.id"), &[("id", &c.id)]),
                            ),
                    )
                    .child(
                        Element::new("dl")
                            .attr("class", "facts")
                            .child(el("dt", "public.call.range"))
                            .child(range(c))
                            .child(el("dt", "public.call.closes"))
                            .child(instant(&c.deadline, &c.deadline_zone)),
                    ),
            );
        }
        main.push_child(list);
    }
    if !view.aggregates.is_empty() {
        main.push_child(el("h2", "public.aggregates.heading"));
        let mut list = Element::new("ul").attr("class", "aggregates");
        for a in &view.aggregates {
            let n = a.grants.to_string();
            list.push_child(Element::new("li").label(
                &l("public.aggregates.row"),
                &[("call", &a.call), ("grants", &n), ("total", &a.total)],
            ));
        }
        main.push_child(list);
    }
    Ok(main)
}

/// The page of the open call `c`.
fn call_page(view: &PublicView, paths: &Paths, c: &PublicCall) -> Result<Element, PublicError> {
    let mut main = Element::new("main")
        .child(Element::new("h1").text(&c.title))
        .child(
            Element::new("p")
                .child(
                    Element::new("span")
                        .attr("class", "badge badge--success")
                        .label(&l("public.call.open"), &[]),
                )
                .child(
                    Element::new("span")
                        .attr("class", "pid")
                        .label(&l("public.call.id"), &[("id", &c.id)]),
                ),
        )
        .child(
            Element::new("dl")
                .attr("class", "facts card")
                .child(el("dt", "public.call.opens"))
                .child(instant(&c.opens, &c.deadline_zone))
                .child(el("dt", "public.call.closes"))
                .child(instant(&c.deadline, &c.deadline_zone))
                .child(el("dt", "public.call.budget"))
                .child(Element::new("dd").text(&c.budget))
                .child(el("dt", "public.call.range"))
                .child(range(c)),
        )
        .child(el("p", "public.call.amounts").attr("class", "text-sm muted"))
        .child(el("h2", "public.call.eligibility"));
    if !c.eligibility.is_empty() {
        main.push_child(el("p", "public.call.eligibility_intro"));
        let mut list = Element::new("ul");
        for rule in &c.eligibility {
            list.push_child(Element::new("li").text(rule));
        }
        main.push_child(list);
    }
    if c.guide.is_some() {
        main.push_child(
            Element::new("p").child(
                Element::new("a")
                    .attr_url("href", paths.guide(&c.id)?)
                    .label(&l("public.call.guide"), &[]),
            ),
        );
    }
    main.push_child(
        Element::new("section")
            .attr("id", "ai-disclosure")
            .attr("class", "callout callout--info")
            .attr("aria-labelledby", "ai-disclosure-heading")
            .child(el("h2", "public.ai.heading").attr("id", "ai-disclosure-heading"))
            .child(Element::new("p").approved(&ApprovedText::new("public.ai.disclosure"), &[])),
    );
    main.push_child(
        Element::new("div")
            .attr("class", "btn-row")
            .child(
                Element::new("a")
                    .attr("class", "btn btn--primary")
                    .attr_url("href", url("/auth/login")?)
                    .label(&l("public.call.apply"), &[]),
            )
            .child(
                Element::new("a")
                    .attr("class", "btn btn--secondary")
                    .attr_url("href", url("/auth/signup")?)
                    .label(&l("public.call.signup"), &[]),
            ),
    );
    let _ = view;
    Ok(main)
}

/// The catalogue label of a grant phase.
fn status_label(s: GrantStatus) -> &'static str {
    match s {
        GrantStatus::Granted => "public.status.granted",
        GrantStatus::InExecution => "public.status.in_execution",
        GrantStatus::Completed => "public.status.completed",
    }
}

/// The funded or finished page over `grants`.
fn grants_page(heading: &str, none: &str, grants: &[PublicGrant]) -> Element {
    let mut main = Element::new("main").child(el("h1", heading));
    if grants.is_empty() {
        main.push_child(el("p", none));
        return main;
    }
    let mut list = Element::new("ul").attr("class", "grant-list");
    for g in grants {
        let mut facts = Element::new("dl")
            .attr("class", "facts")
            .child(el("dt", "public.grant.call"))
            .child(Element::new("dd").text(&g.call))
            .child(el("dt", "public.grant.status"))
            .child(el("dd", status_label(g.status)));
        if let Some(who) = &g.grantee {
            facts.push_child(el("dt", "public.grant.grantee"));
            facts.push_child(Element::new("dd").text(who));
        }
        if let Some(amount) = &g.amount {
            facts.push_child(el("dt", "public.grant.amount"));
            facts.push_child(Element::new("dd").text(amount));
        }
        list.push_child(
            Element::new("li")
                .attr("class", "card")
                .child(Element::new("h2").text(&g.title))
                .child(Element::new("p").text(&g.summary))
                .child(facts),
        );
    }
    main.push_child(list);
    main
}

/// What one page renders: the published Guide as it is, or a page of the
/// view.
enum Built<'v> {
    Guide(&'v str),
    Page(Document),
}

/// The open call `id` of `view`.
fn find<'v>(view: &'v PublicView, id: &str) -> Result<&'v PublicCall, PublicError> {
    view.open_calls
        .iter()
        .find(|c| c.id == id)
        .ok_or(PublicError::NotFound)
}

fn build<'v>(
    view: &'v PublicView,
    page_of: &PublicPage,
    chrome: &Chrome,
) -> Result<Built<'v>, PublicError> {
    let paths = Paths::of(view);
    let name = view.programme.name.as_str();
    let doc = match page_of {
        PublicPage::Guide(id) => {
            let c = find(view, id)?;
            let g = c.guide.as_ref().ok_or(PublicError::NotFound)?;
            return Ok(Built::Guide(&g.document));
        }
        PublicPage::Programme => page(
            view,
            chrome,
            Node::text(name),
            Current::Calls,
            programme_page(view, &paths)?,
        )?,
        PublicPage::Call(id) => {
            let c = find(view, id)?;
            page(
                view,
                chrome,
                Node::label(
                    &l("public.title.call"),
                    &[("title", &c.title), ("programme", name)],
                ),
                Current::None,
                call_page(view, &paths, c)?,
            )?
        }
        PublicPage::Funded => page(
            view,
            chrome,
            Node::label(&l("public.title.funded"), &[("programme", name)]),
            Current::Funded,
            grants_page("public.funded.heading", "public.funded.none", &view.funded),
        )?,
        PublicPage::Finished => page(
            view,
            chrome,
            Node::label(&l("public.title.finished"), &[("programme", name)]),
            Current::Finished,
            grants_page(
                "public.finished.heading",
                "public.finished.none",
                &view.finished,
            ),
        )?,
    };
    Ok(Built::Page(doc))
}

/// Renders one public page of `view`.
pub fn render_html(
    view: &PublicView,
    page: &PublicPage,
    chrome: &Chrome,
) -> Result<PublicDocument, PublicError> {
    match build(view, page, chrome)? {
        Built::Guide(doc) => Ok(PublicDocument(doc.to_owned())),
        Built::Page(doc) => doc
            .render(catalogues()?)
            .map(PublicDocument::from)
            .map_err(|e| html_err(&e)),
    }
}

/// Renders one public page of `view` with the recording sink of
/// `fstp-html` (I-87 seam). The bytes equal those of [`render_html`].
/// The Guide page has no trace of its own and is refused here with
/// [`PublicError::NotFound`].
pub fn render_traced(
    view: &PublicView,
    page: &PublicPage,
    chrome: &Chrome,
) -> Result<(PublicDocument, Vec<TraceEvent>), PublicError> {
    match build(view, page, chrome)? {
        Built::Guide(_) => Err(PublicError::NotFound),
        Built::Page(doc) => doc
            .render_traced(catalogues()?)
            .map(|(d, t)| (PublicDocument::from(d), t))
            .map_err(|e| html_err(&e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R-PB-04, I-68: a path segment is percent-encoded, so a slug or id
    /// can never make a link leave its origin.
    #[test]
    fn r_pb_04_path_segments_are_percent_encoded() {
        assert_eq!(segment("supersafe-2"), "supersafe-2");
        assert_eq!(segment("a/b"), "a%2Fb");
        assert_eq!(segment("//evil"), "%2F%2Fevil");
        assert_eq!(segment("x y"), "x%20y");
    }

    /// R-NF-04: the catalogue of the public pages builds.
    #[test]
    fn r_nf_04_public_catalogue_builds() {
        assert!(catalogues().is_ok());
    }
}
