//! The anonymous public surface of a cell: the `/p` pages, the feed and
//! the public research tools (I-87, TH-06, R-PB-01 to R-PB-05; M4 design
//! section 3.10; lane m4/cellpub).
//!
//! Every answer comes from one `fstp_public::PublicView`, built per
//! request by `fstp_public::public_view_with` from the core state of this
//! cell's own engine head. Nothing is cached, so a narrowing shows on the
//! next request (R-PB-02), and no state outside the cell's own ledger and
//! its own public texts reaches a view (TH-06). The steps mirror
//! `fstp_api_core::dispatch::public`, so a cell answers the same bytes as
//! the web adapter for the same view:
//!
//! - The programme is one of the active programmes, found by its public
//!   slug or by its id in decimal (`fstp_public::slug`). Its slug, name
//!   and narrative come from its creator draft. A programme with no draft
//!   is public under its id, named "Programme" and its id.
//! - The texts are the title and P-09 wording of each call open now and
//!   the approved texts of each grantee choice. Each is read through
//!   [`PublicTextSource`], which answers public texts only. A text it
//!   refuses is left out, so its call or grant is not shown.
//! - The Guide of an open call is the one its publication stored, with
//!   its corrigenda (I-53).
//! - The page chrome links the tenant brand sheet once a brand is set, and
//!   names the funder profile the programme pins through P-53 (I-69).
//!
//! # Interim, pending Daniel
//!
//! - The cell's text store has no text class yet: a sealed text carries
//!   no mark that says it may be shown in public. So the production
//!   source, [`NoPublicTexts`], holds no public text, and a production
//!   cell shows its programme pages with no open call. A test world
//!   passes a source of its own through `crate::process::StartOptions`,
//!   and claims built on it say so.
//! - The public research tools answer as JSON on the routes of the
//!   registry that no page uses: `/p/{slug}/calls`,
//!   `/p/{slug}/deadlines` and `/p/{slug}/eligibility`. The cell serves
//!   no MCP endpoint, so `/mcp/public` is not served here.
//! - The ADR-021 setup gate reads the tenant part of the ledger. A
//!   cell whose ledger holds no tenant part is gated by programme
//!   activation only, since the cell has no M4 organisation port.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

use fstp_domain::id::{CallId, ProgrammeId, TextId};
use fstp_domain::programme::{ProgrammeStatus, programme_status};
use fstp_domain::time::Timestamp;
use fstp_engine::EngineState;
use fstp_public::{
    Chrome, FunderFooter, ProgrammeIdentity, PublicError, PublicGuide, PublicPage, PublicPart,
    PublicQuery, PublicTexts, PublicView,
};

/// The future of one public text read.
pub type PublicTextFuture<'a> = Pin<Box<dyn Future<Output = Option<String>> + Send + 'a>>;

/// Where a cell reads the texts a public view may show (module
/// documentation). It answers a text only when that text is public, so
/// no proposal or review text reaches a view (R-PB-03).
pub trait PublicTextSource: Send + Sync + 'static {
    /// The public text `id`, or `None` when it is not public or not held.
    fn get_public(&self, id: TextId) -> PublicTextFuture<'_>;
}

/// The public text source of a production cell: no text is public yet
/// (module documentation). It fails closed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NoPublicTexts;

impl PublicTextSource for NoPublicTexts {
    fn get_public(&self, id: TextId) -> PublicTextFuture<'_> {
        let _ = id;
        Box::pin(std::future::ready(None))
    }
}

/// One public operation of the cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicOp {
    /// `GET /p/{slug}/`: the programme page.
    Programme,
    /// `GET /p/{slug}/calls/{call}`: one call page.
    Call,
    /// `GET /p/{slug}/calls/{call}/guide`: the Guide page of one call.
    Guide,
    /// `GET /p/{slug}/funded`: the funded grants page.
    Funded,
    /// `GET /p/{slug}/finished`: the finished grants page.
    Finished,
    /// `GET /p/{slug}/feed.json`: the feed (P-52).
    Feed,
    /// `GET /p/{slug}/calls`: the open calls tool.
    OpenCalls,
    /// `GET /p/{slug}/deadlines`: the deadlines tool.
    Deadlines,
    /// `GET /p/{slug}/eligibility`: the eligibility tool.
    Eligibility,
}

/// The answer to one public operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicAnswer {
    /// A server-rendered page, as `fstp_public::render_html` writes it.
    Page(String),
    /// The JSON of the feed or of a tool, in its compact spelling.
    Json(String),
}

/// Why a public operation was refused, as the web adapter names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicRefusal {
    /// A malformed slug or call id: 400, rule `request`.
    BadRequest,
    /// Not public: 404, rule `Input`.
    NotFound,
    /// The organisation is not activated yet: 403, rule `ADR-021`.
    Setup,
    /// The view or page could not be built: 503, rule `R-PB-04`.
    Unavailable,
}

impl PublicRefusal {
    /// The HTTP status.
    pub const fn status(self) -> u16 {
        match self {
            PublicRefusal::BadRequest => 400,
            PublicRefusal::NotFound => 404,
            PublicRefusal::Setup => 403,
            PublicRefusal::Unavailable => 503,
        }
    }

    /// The stable JSON body of the refusal, as `fstp_api_core::ApiError`
    /// encodes it.
    pub const fn body(self) -> &'static str {
        match self {
            PublicRefusal::BadRequest => r#"{"code":"bad_request","rule":"request"}"#,
            PublicRefusal::NotFound => r#"{"code":"not_found","rule":"Input"}"#,
            PublicRefusal::Setup => r#"{"code":"refused","rule":"ADR-021"}"#,
            PublicRefusal::Unavailable => r#"{"code":"unavailable","rule":"R-PB-04"}"#,
        }
    }
}

/// The plain page a `/p` page answers before the organisation is
/// activated (ADR-021 decision 3), as the web adapter writes it with no
/// platform stylesheet.
pub const NOT_PUBLISHED: &str = "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
<title>Not published yet</title>\n</head>\n<body>\n<main>\n<h1>Not published yet</h1>\n\
<p>This organisation's pages are not published yet. \
They open once its activation has been approved.</p>\n</main>\n</body>\n</html>\n";

/// Whether `s` is a path token: 1 to 64 of `[a-z0-9_-]`
/// (`fstp_api_core::forms::token`).
fn token(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_')
}

/// The id `s` names in canonical decimal, with no sign and no leading
/// zero (`fstp_api_core::forms::canonical_id`).
fn canonical_id(s: &str) -> Option<u128> {
    let b = s.as_bytes();
    let canonical = !b.is_empty()
        && b.iter().all(u8::is_ascii_digit)
        && (b.len() == 1 || b.first() != Some(&b'0'));
    if !canonical {
        return None;
    }
    s.parse::<u128>().ok()
}

/// The programme the slug `slug` names, with its public identity: one of
/// the active programmes (module documentation).
fn programme_of(state: &EngineState, slug: &str) -> Option<(ProgrammeId, ProgrammeIdentity)> {
    let mut ids: Vec<ProgrammeId> = state
        .core
        .calls()
        .iter()
        .map(|(_, c)| c.programme())
        .chain(state.creator.drafts().map(|(p, _)| p))
        .filter(|p| programme_status(&state.core, *p) == Some(ProgrammeStatus::Active))
        .collect();
    ids.sort();
    ids.dedup();
    let drafts: Vec<(ProgrammeId, Option<ProgrammeIdentity>)> = ids
        .into_iter()
        .map(|p| (p, draft_identity(state, p)))
        .collect();
    let candidates: Vec<(ProgrammeId, Option<&str>)> = drafts
        .iter()
        .map(|(p, d)| (*p, d.as_ref().map(|d| d.slug.as_str())))
        .collect();
    let programme = fstp_public::resolve_slug(&candidates, slug)?;
    let public = fstp_public::public_slugs(&candidates).remove(&programme)?;
    let draft = drafts
        .into_iter()
        .find(|(p, _)| *p == programme)
        .and_then(|(_, d)| d);
    let identity = match draft {
        Some(d) => ProgrammeIdentity { slug: public, ..d },
        None => ProgrammeIdentity {
            slug: public,
            name: format!("Programme {}", programme.raw()),
            narrative: String::new(),
        },
    };
    Some((programme, identity))
}

/// The identity the creator draft of `programme` names, or `None` with no
/// draft.
fn draft_identity(state: &EngineState, programme: ProgrammeId) -> Option<ProgrammeIdentity> {
    fstp_creator::draft_view(&state.core, &state.creator, programme)
        .and_then(|v| ProgrammeIdentity::from_spec_json(&v.spec))
}

/// The public texts of `programme` at `now` (module documentation).
async fn texts_of(
    state: &EngineState,
    source: &dyn PublicTextSource,
    programme: ProgrammeId,
    identity: ProgrammeIdentity,
    choices: &fstp_public::GrantChoices,
    now: Timestamp,
) -> PublicTexts {
    let mut ids: Vec<TextId> = Vec::new();
    for (_, c) in choices.iter() {
        ids.extend([c.title, c.summary, c.grantee]);
    }
    for (_, v) in state.core.calls().iter() {
        if v.programme() != programme || !v.is_open_at(now) {
            continue;
        }
        ids.push(v.text().id());
        if let Some(f) = v.frozen() {
            ids.extend(f.values().p09.0.iter().map(|k| k.text.id()));
        }
    }
    let mut found: BTreeMap<TextId, String> = BTreeMap::new();
    for id in ids {
        if found.contains_key(&id) {
            continue;
        }
        if let Some(t) = source.get_public(id).await {
            let _ = found.insert(id, t);
        }
    }
    let mut texts = PublicTexts::new(identity);
    for (id, t) in &found {
        texts.insert(*id, t);
    }
    for (id, v) in state.core.calls().iter() {
        if v.programme() != programme || !v.is_open_at(now) {
            continue;
        }
        if let Ok(g) = stored_guide(state, source, id).await {
            texts.insert_guide(id, g);
        }
    }
    texts
}

/// Public texts read for the corrigenda, by text id.
struct GuideTexts(BTreeMap<TextId, String>);

impl fstp_guide::StoredTexts for GuideTexts {
    fn text(&self, text: fstp_domain::id::TextRef) -> Option<&str> {
        self.0.get(&text.id()).map(String::as_str)
    }
}

/// The Guide of the published call `id` as its publication stored it,
/// followed by its corrigenda (I-51, I-53). Nothing is bound again.
async fn stored_guide(
    state: &EngineState,
    source: &dyn PublicTextSource,
    id: CallId,
) -> Result<PublicGuide, PublicError> {
    let core = &state.core;
    let pending = fstp_domain::programme::effective_limits(core, id)
        .is_some_and(|l| !l.tightenings().is_empty());
    if !pending {
        return fstp_public::served_guide(core, id, None);
    }
    let programme = core
        .calls()
        .get(id)
        .map(|v| v.programme())
        .ok_or(PublicError::NotFound)?;
    let compiled =
        fstp_engine::compose::draft_compiled(state, programme).ok_or(PublicError::NotFound)?;
    let mut found = BTreeMap::new();
    for r in fstp_public::guide::corrigenda_text_refs(&compiled) {
        if let Some(t) = source.get_public(r.id()).await {
            let _ = found.insert(r.id(), t);
        }
    }
    let texts = GuideTexts(found);
    let src = fstp_public::CorrigendaSource {
        compiled: &compiled,
        texts: &texts,
    };
    fstp_public::served_guide(core, id, Some(&src))
}

/// The footer data of the funder profile that `programme` pins through
/// its head P-53 (I-69). A P-53 that names no profile gives none.
fn funder_footer(state: &EngineState, programme: ProgrammeId) -> Option<FunderFooter> {
    let p53 = fstp_engine::report::pinned_p53(state, fstp_report::Scope::Programme(programme))?;
    let ts = state.tenant.state();
    let profile = fstp_report::profile::for_p53_with(p53.0.as_str(), |id, v| {
        ts.and_then(|t| t.funder_profile(id, v))
            .map(|p| p.text.as_str())
    })
    .ok()?;
    Some(FunderFooter {
        profile: profile.id().to_owned(),
        version: profile.version(),
        elements: profile
            .visibility_elements()
            .iter()
            .map(|e| e.key().to_owned())
            .collect(),
    })
}

/// The same-origin path of the tenant brand sheet, once a brand is set.
fn brand_sheet(state: &EngineState) -> Option<String> {
    let (_, digest) = state.tenant.state()?.branding()?;
    let hex: String = digest.bytes().iter().map(|b| format!("{b:02x}")).collect();
    Some(format!("/brand/{hex}.css"))
}

/// The refusal of a public error.
fn refused(e: PublicError) -> PublicRefusal {
    match e {
        PublicError::NotFound | PublicError::FeedOff => PublicRefusal::NotFound,
        PublicError::Query(_) => PublicRefusal::BadRequest,
        _ => PublicRefusal::Unavailable,
    }
}

/// The answer of `op` over `view`.
fn answer(
    view: &PublicView,
    op: PublicOp,
    call: Option<String>,
    chrome: &Chrome,
) -> Result<PublicAnswer, PublicError> {
    let page = |p: PublicPage| -> Result<PublicAnswer, PublicError> {
        let doc = fstp_public::render_html(view, &p, chrome)?;
        Ok(PublicAnswer::Page(doc.as_str().to_owned()))
    };
    let tool = |part: PublicPart| -> Result<PublicAnswer, PublicError> {
        let q = PublicQuery { part, search: None };
        fstp_public::tools::select(view, &q).map(|v| PublicAnswer::Json(v.to_compact()))
    };
    match (op, call) {
        (PublicOp::Feed, _) => {
            fstp_public::feed::feed(view).map(|v| PublicAnswer::Json(v.to_compact()))
        }
        (PublicOp::Programme, _) => page(PublicPage::Programme),
        (PublicOp::Call, Some(c)) => page(PublicPage::Call(c)),
        (PublicOp::Guide, Some(c)) => page(PublicPage::Guide(c)),
        (PublicOp::Funded, _) => page(PublicPage::Funded),
        (PublicOp::Finished, _) => page(PublicPage::Finished),
        (PublicOp::OpenCalls, _) => tool(PublicPart::OpenCalls),
        (PublicOp::Deadlines, _) => tool(PublicPart::Deadlines),
        (PublicOp::Eligibility, _) => tool(PublicPart::Eligibility),
        (PublicOp::Call | PublicOp::Guide, None) => Err(PublicError::NotFound),
    }
}

/// One public operation over the engine state `state` at `now`, reading
/// its texts from `source` (module documentation). `slug` and `call` are
/// the path segments as the router captured them.
///
/// # Errors
///
/// The [`PublicRefusal`] the web adapter answers for the same request.
pub async fn read(
    state: &EngineState,
    source: &dyn PublicTextSource,
    now: Timestamp,
    op: PublicOp,
    slug: &str,
    call: Option<&str>,
) -> Result<PublicAnswer, PublicRefusal> {
    if !token(slug) {
        return Err(PublicRefusal::BadRequest);
    }
    let call = match call {
        Some(c) => Some(
            canonical_id(c)
                .ok_or(PublicRefusal::BadRequest)?
                .to_string(),
        ),
        None => None,
    };
    // ADR-021: before the organisation is activated, only onboarding runs.
    if state.tenant.state().is_some_and(|ts| !ts.is_active()) {
        return Err(PublicRefusal::Setup);
    }
    let (programme, identity) = programme_of(state, slug).ok_or(PublicRefusal::NotFound)?;
    let choices = fstp_public::grant_choices(&state.core);
    let texts = texts_of(state, source, programme, identity, &choices, now).await;
    let view = fstp_public::public_view_with(&state.core, programme, &texts, &choices, now)
        .map_err(refused)?;
    let chrome = Chrome {
        stylesheet: brand_sheet(state),
        funder: funder_footer(state, programme),
    };
    answer(&view, op, call, &chrome).map_err(refused)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// I-87, R-PB-04: the path rules of the web adapter. A slug is a path
    /// token and a call id is canonical decimal.
    #[test]
    fn i87_public_path_rules_mirror_the_web_adapter() {
        assert!(token("supersafe"));
        assert!(token("a-b_1"));
        assert!(!token(""));
        assert!(!token("Super"));
        assert!(!token(&"a".repeat(65)));
        assert_eq!(canonical_id("7"), Some(7));
        assert_eq!(canonical_id("0"), Some(0));
        assert_eq!(canonical_id("07"), None);
        assert_eq!(canonical_id("+7"), None);
        assert_eq!(canonical_id(""), None);
    }

    /// R-PB-03: the production source holds no public text, so it fails
    /// closed.
    #[test]
    fn r_pb_03_production_source_holds_no_public_text() {
        let got = futures_ready(NoPublicTexts.get_public(TextId::from_raw(1)));
        assert_eq!(got, None);
    }

    /// Polls a ready future once.
    fn futures_ready<T>(f: Pin<Box<dyn Future<Output = T> + Send + '_>>) -> T {
        use std::task::{Context, Poll, Waker};
        let mut f = f;
        let mut cx = Context::from_waker(Waker::noop());
        match f.as_mut().poll(&mut cx) {
            Poll::Ready(v) => v,
            Poll::Pending => unreachable!("a ready future"),
        }
    }
}
