//! The anonymous public surface of a cell: the `/p` pages, the feed and
//! the public research tools (I-87, TH-06, R-PB-01 to R-PB-05; M4 design
//! section 3.10; lanes m4/cellpub and m4/pubtext).
//!
//! Every answer comes from one `fstp_public::PublicView`, built per
//! request by `fstp_public::public_view_with` from the core state of this
//! cell's own engine head. Nothing is cached, so a narrowing shows on the
//! next request (R-PB-02), and no state outside the cell's own ledger and
//! its own public class reaches a view (TH-06). The steps mirror
//! `fstp_api_core::dispatch::public`, so a cell answers the same bytes as
//! the web adapter for the same view:
//!
//! - The programme is one of the active programmes, found by its public
//!   slug or by its id in decimal (`fstp_public::slug`). Its slug, name
//!   and narrative come from its creator draft. A programme with no draft
//!   is public under its id, named "Programme" and its id.
//! - The texts are the title and P-09 wording of each call open now. Each
//!   is read through [`PublicTextSource`] under its call. A text it
//!   refuses is left out, so its call is not shown.
//! - The Guide of an open call is the one its publication stored, with
//!   its corrigenda (I-53). Their stored texts are read under the call.
//! - The page chrome links the tenant brand sheet once a brand is set, and
//!   names the funder profile the programme pins through P-53 (I-69).
//!
//! # The public text class (Daniel, 2026-11-17: "copy at publication")
//!
//! When a call is published, the cell copies its title, its P-09 wording
//! and the stored texts of its Guide into [`PublicClass`], keyed by call.
//! The public view reads only that class, never the cell text store.
//! [`copy_at_publication`] takes the copy:
//!
//! - It runs after every command the route backend commits, and once at
//!   start (`crate::routes::pg::PgBackend::copy_public_texts`).
//! - For each published call it copies the texts that call names and the
//!   class does not hold yet. A text is copied once and never replaced,
//!   so a later change of the text store leaves the public copy as it was.
//! - A corrigendum recorded after publication (I-53) adds the stored
//!   texts its wording reads, from the programme's compiled draft
//!   (`fstp_public::guide::corrigenda_text_refs`). They are copied at the
//!   first copy after the record, under the corrected call.
//! - A text is read from the cell's own text store only while the ledger
//!   holds it as live (`TextPut` or `OwnedTextPut`, no erasure). A text
//!   that is not live or does not open is not copied, and the copy is
//!   tried again after the next commit.
//!
//! So no text reaches a view unless a published call names it (R-PB-03),
//! and each cell holds its own class, filled from its own store (I-87,
//! TH-06).
//!
//! # Interim, pending Daniel
//!
//! - The class lives in process memory, as the cell text store it copies
//!   from does until the keystore tables land (`crate::tasks::erasure`).
//!   The copy at start fills it again from that store.
//! - The cell's command route lets a client name any text id as a call
//!   title. The copy trusts the ids the published call names, which a
//!   programme manager approved and published with a step-up.
//! - A text the cell id names is its 16 bytes, big-endian, of the text id.
//! - The grantee choices (M9 lane P1) have no class yet, so the cell reads
//!   none of their texts, and its funded and finished pages show no
//!   grantee choice.
//! - The public research tools answer as JSON on the routes of the
//!   registry that no page uses: `/p/{slug}/calls`,
//!   `/p/{slug}/deadlines` and `/p/{slug}/eligibility`. The cell serves
//!   no MCP endpoint, so `/mcp/public` is not served here.
//! - The ADR-021 setup gate reads the tenant part of the ledger. A
//!   cell whose ledger holds no tenant part asks [`OrganisationPort`], a
//!   start option that stands for the web adapter's `TenantConfig` port
//!   and answers "not active" by default, so the gate fails closed as
//!   the web adapter's does (lane m4/pubtext).
//!
//! # The answers on the wire (`crate::routes`, `crate::http::site`)
//!
//! As the web adapter's router answers them: a page links the platform
//! stylesheets first in its head. A page before activation answers the
//! "not published yet" page. A browser page request for a public path
//! that is malformed or not found goes to the programme's public home,
//! or to home `/app/` when no programme answers there (SA-09
//! amendment). Any other request for a path under `/p/` that no route
//! matches answers 404 `{"code":"not_found","rule":"route"}`.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Mutex, MutexGuard, PoisonError};

use fstp_domain::id::{CallId, ProgrammeId, TextId, TextRef};
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
/// documentation). It answers a text only under the call it was made
/// public for, so no proposal or review text reaches a view (R-PB-03).
pub trait PublicTextSource: Send + Sync + 'static {
    /// The public text `id` of call `call`, or `None` when it is not
    /// public for that call.
    fn get_public(&self, call: CallId, id: TextId) -> PublicTextFuture<'_>;
}

/// The public text source of a backend with no text store, such as the
/// in-memory route backend: no text is public. It fails closed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NoPublicTexts;

impl PublicTextSource for NoPublicTexts {
    fn get_public(&self, call: CallId, id: TextId) -> PublicTextFuture<'_> {
        let _ = (call, id);
        Box::pin(std::future::ready(None))
    }
}

/// What the class holds for one published call.
#[derive(Clone, Debug, Default)]
struct CallCopy {
    /// The copied texts.
    texts: BTreeMap<TextId, String>,
    /// The count of corrigenda whose texts are all copied, once every
    /// text the call named at that count is copied. `None` until then.
    complete: Option<usize>,
}

/// The public text class of a cell (module documentation): the texts each
/// published call made public, copied at its publication, keyed by call.
#[derive(Debug, Default)]
pub struct PublicClass {
    calls: Mutex<BTreeMap<CallId, CallCopy>>,
}

impl PublicClass {
    fn calls(&self) -> MutexGuard<'_, BTreeMap<CallId, CallCopy>> {
        self.calls.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Every text copied for `call`, by id.
    pub fn copy_of(&self, call: CallId) -> BTreeMap<TextId, String> {
        self.calls()
            .get(&call)
            .map(|c| c.texts.clone())
            .unwrap_or_default()
    }

    /// Whether the copy of `call` is complete at `corrigenda` corrigenda.
    fn complete_at(&self, call: CallId, corrigenda: usize) -> bool {
        self.calls()
            .get(&call)
            .and_then(|c| c.complete)
            .is_some_and(|n| n >= corrigenda)
    }

    /// Whether the class holds text `id` for `call`.
    fn holds(&self, call: CallId, id: TextId) -> bool {
        self.calls()
            .get(&call)
            .is_some_and(|c| c.texts.contains_key(&id))
    }

    /// Copies `text` as text `id` of `call`, unless one is held already.
    fn insert(&self, call: CallId, id: TextId, text: String) {
        let _ = self
            .calls()
            .entry(call)
            .or_default()
            .texts
            .entry(id)
            .or_insert(text);
    }

    /// Marks the copy of `call` complete at `corrigenda` corrigenda.
    fn mark(&self, call: CallId, corrigenda: usize) {
        self.calls().entry(call).or_default().complete = Some(corrigenda);
    }
}

impl PublicTextSource for PublicClass {
    fn get_public(&self, call: CallId, id: TextId) -> PublicTextFuture<'_> {
        let t = self
            .calls()
            .get(&call)
            .and_then(|c| c.texts.get(&id).cloned());
        Box::pin(std::future::ready(t))
    }
}

/// Where the copy reads a text: the cell's own text store.
pub trait TextOpener: Sync {
    /// The text `id`, or `None` when it is not live or does not open.
    fn open(&self, id: TextId) -> PublicTextFuture<'_>;
}

/// The text store of a started cell, at the state `state` (module
/// documentation): a text opens only while the ledger holds it as live.
pub(crate) struct CellTexts<'a> {
    /// The erasure task, which owns the text store.
    pub(crate) store: &'a crate::tasks::erasure::ErasureHandle,
    /// The cell state the copy reads.
    pub(crate) state: &'a fstp_cell_core::CellState,
}

impl TextOpener for CellTexts<'_> {
    fn open(&self, id: TextId) -> PublicTextFuture<'_> {
        let raw = id.raw().to_be_bytes();
        if self.state.text(raw) != Some(fstp_cell_core::state::TextStatus::Live) {
            return Box::pin(std::future::ready(None));
        }
        let store = self.store;
        Box::pin(async move {
            let opened = store.open_text(raw).await.ok()?;
            String::from_utf8(opened.to_vec()).ok()
        })
    }
}

/// Copies into `class` the public texts of every call published in
/// `state`, read from `store` (module documentation). The corrigenda
/// texts come from each programme's compiled draft.
pub async fn copy_at_publication(state: &EngineState, class: &PublicClass, store: &dyn TextOpener) {
    let corrigenda = |p: ProgrammeId| {
        fstp_engine::compose::draft_compiled(state, p)
            .map(|c| fstp_public::guide::corrigenda_text_refs(&c))
    };
    copy_with(state, class, store, &corrigenda).await;
}

/// [`copy_at_publication`] with the corrigenda texts of each programme
/// from `corrigenda`. `None` means they cannot be named yet.
async fn copy_with(
    state: &EngineState,
    class: &PublicClass,
    store: &dyn TextOpener,
    corrigenda: &(dyn Fn(ProgrammeId) -> Option<Vec<TextRef>> + Sync),
) {
    for (id, v) in state.core.calls().iter() {
        let Some(frozen) = v.frozen() else {
            continue;
        };
        let count = fstp_domain::programme::effective_limits(&state.core, id)
            .map_or(0, |l| l.tightenings().len());
        if class.complete_at(id, count) {
            continue;
        }
        let mut wanted: Vec<TextId> = vec![v.text().id()];
        wanted.extend(frozen.values().p09.0.iter().map(|k| k.text.id()));
        let mut named = true;
        if count > 0 {
            match corrigenda(v.programme()) {
                Some(refs) => wanted.extend(refs.iter().map(|r| r.id())),
                None => named = false,
            }
        }
        let mut all = true;
        for t in wanted {
            if class.holds(id, t) {
                continue;
            }
            match store.open(t).await {
                Some(text) => class.insert(id, t, text),
                None => all = false,
            }
        }
        if all && named {
            class.mark(id, count);
        }
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

/// Whether the organisation is active, for a cell whose ledger holds no
/// tenant part yet (ADR-021 "Where the answer comes from"). The web
/// adapter asks its `TenantConfig` port then, whose default answer is
/// "not active". The cell has no such port, so this start option stands
/// for it, with the same fail-closed default. Once the ledger holds the
/// tenant part, the ledger alone answers.
///
/// A test world from before the tenant part sets it active, as the test
/// kit's fake port answers by default, and says so.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OrganisationPort {
    /// The port's answer: active or not.
    pub active: bool,
}

impl OrganisationPort {
    /// Whether the organisation is active in `state`: the ledger's tenant
    /// part when it holds one, else this port's answer.
    pub fn active_in(self, state: &EngineState) -> bool {
        state
            .tenant
            .state()
            .map_or(self.active, |ts| ts.is_active())
    }
}

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

/// The public texts of `programme` at `now` (module documentation): the
/// title and P-09 wording of each open call, each read under its call.
async fn texts_of(
    state: &EngineState,
    source: &dyn PublicTextSource,
    programme: ProgrammeId,
    identity: ProgrammeIdentity,
    now: Timestamp,
) -> PublicTexts {
    let mut found: BTreeMap<TextId, String> = BTreeMap::new();
    for (call, v) in state.core.calls().iter() {
        if v.programme() != programme || !v.is_open_at(now) {
            continue;
        }
        let mut ids = vec![v.text().id()];
        if let Some(f) = v.frozen() {
            ids.extend(f.values().p09.0.iter().map(|k| k.text.id()));
        }
        for id in ids {
            if found.contains_key(&id) {
                continue;
            }
            if let Some(t) = source.get_public(call, id).await {
                let _ = found.insert(id, t);
            }
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
        if let Some(t) = source.get_public(id, r.id()).await {
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

/// What one public read runs against: the engine state of the cell's
/// head, its public text class, the instant and the organisation port.
#[derive(Clone, Copy)]
pub struct PublicRead<'a> {
    /// The engine state.
    pub state: &'a EngineState,
    /// The public texts.
    pub source: &'a dyn PublicTextSource,
    /// The instant of the read.
    pub now: Timestamp,
    /// The organisation port of ADR-021.
    pub organisation: OrganisationPort,
}

impl PublicRead<'_> {
    /// One public operation (module documentation): [`read`].
    ///
    /// # Errors
    ///
    /// As [`read`].
    pub async fn op(
        self,
        op: PublicOp,
        slug: &str,
        call: Option<&str>,
    ) -> Result<PublicAnswer, PublicRefusal> {
        read(self, op, slug, call).await
    }

    /// The public home `/p/{slug}/` of the programme the path segment
    /// `slug` names, when the cell serves it: its page answers, or the
    /// setup gate answers its "not published yet" page. A browser that
    /// asks for a public page that does not exist goes there (SA-09
    /// amendment), as `fstp_web`'s router sends it.
    pub async fn home(self, slug: &str) -> Option<String> {
        match read(self, PublicOp::Programme, slug, None).await {
            Ok(_) | Err(PublicRefusal::Setup) => Some(format!("/p/{slug}/")),
            Err(_) => None,
        }
    }
}

/// One public operation over `ctx` (module documentation). `slug` and
/// `call` are the path segments as the router captured them.
///
/// # Errors
///
/// The [`PublicRefusal`] the web adapter answers for the same request.
pub async fn read(
    ctx: PublicRead<'_>,
    op: PublicOp,
    slug: &str,
    call: Option<&str>,
) -> Result<PublicAnswer, PublicRefusal> {
    let PublicRead {
        state,
        source,
        now,
        organisation,
    } = ctx;
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
    // A ledger with no tenant part asks the organisation port, which
    // fails closed by default, as the web adapter's does.
    if !organisation.active_in(state) {
        return Err(PublicRefusal::Setup);
    }
    let (programme, identity) = programme_of(state, slug).ok_or(PublicRefusal::NotFound)?;
    let choices = fstp_public::grant_choices(&state.core);
    let texts = texts_of(state, source, programme, identity, now).await;
    let view = fstp_public::public_view_with(&state.core, programme, &texts, &choices, now)
        .map_err(refused)?;
    let chrome = Chrome {
        stylesheet: brand_sheet(state),
        funder: funder_footer(state, programme),
        logos: fstp_api_core::port::public_chrome_logos(state, programme),
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

    /// R-PB-03: a backend with no text store, and a class before any
    /// copy, hold no public text, so both fail closed.
    #[test]
    fn r_pb_03_no_text_store_and_empty_class_hold_no_public_text() {
        let (call, id) = (CallId::from_raw(1), TextId::from_raw(1));
        assert_eq!(futures_ready(NoPublicTexts.get_public(call, id)), None);
        let class = PublicClass::default();
        assert_eq!(futures_ready(class.get_public(call, id)), None);
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

#[cfg(test)]
#[path = "public_class_tests.rs"]
mod class_tests;
