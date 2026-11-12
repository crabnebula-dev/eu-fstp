//! Dispatch of the public pages, the feed and the public tools (I-87,
//! R-PB-01 to R-PB-05; M4 design section 3.10; lane W2c).
//!
//! Every answer comes from one `fstp_public::PublicView`, built per
//! request from the current engine snapshot, so no cache exists and a
//! narrowing shows on the next request (R-PB-02). The view takes the core
//! state only (rule A4). Its texts are public texts only: each one is
//! read through `TextStore::get_public`, which refuses every text that is
//! not `TextClass::Public` (R-PB-03). No text this core remembers is
//! read here, since that memory also holds confidential texts.
//!
//! A web request answers the page as HTML. An MCP tool call answers the
//! JSON of `fstp_public::tools::select`, and the feed answers the JSON of
//! `fstp_public::feed`, which is refused while P-52 is off.
//!
//! # Interim readings, pending Daniel (design section 15.0)
//!
//! - A programme's slug, name and narrative come from its creator draft
//!   (`identity.public_slug`, `identity.name`, `identity.narrative`). A
//!   programme with no draft, such as one a test kit seeded, has no such
//!   record. It is public under its id in decimal, named "Programme" and
//!   its id, as the creator lists name it, with no narrative.
//! - A programme is also found by its id in decimal, so `/p/1/` reaches
//!   programme 1 whatever its slug. A segment made only of digits names
//!   only that id. A draft slug made only of digits, or one that another
//!   active programme's draft also names, names no programme, and its
//!   programme is public under its id (`fstp_public::slug`).
//! - The grantee choices are folded from the core's `PublicChoiceSet` and
//!   `PublicChoiceWithdrawn` records (`fstp_public::grant_choices`, M9
//!   lane P1). Their texts are read through `get_public` like every other
//!   text, so a withdrawal or a lower maximum shows on the next request.
//!
//! # Seams, each failing closed
//!
//! - The Guide page serves the Guide its publication stored, with its
//!   corrigenda (I-53). A cell whose engine supplies no Guide facts at
//!   publication stores no Guide, so its Guide route answers not found.
//! - The public stylesheet: only the tenant brand sheet (M9 lane B2),
//!   linked once the tenant set a brand. Otherwise the pages carry none.

use std::collections::BTreeMap;

use fstp_access::PublicKind;
use fstp_domain::id::{CallId, ProgrammeId, TextId};
use fstp_domain::programme::{ProgrammeStatus, programme_status};
use fstp_public::{
    Chrome, ProgrammeIdentity, PublicError, PublicGuide, PublicPage, PublicPart, PublicQuery,
    PublicTexts, PublicView,
};

use super::*;
use crate::model::PublicReply;

/// The refusal of a page, call or programme that is not public.
fn not_public() -> ApiError {
    ApiError::refused(ErrorCode::NotFound, "Input")
}

/// The programme the slug `slug` names, with its public identity: one of
/// the active programmes, as `fstp_public::slug` resolves the segment
/// (module documentation).
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
/// draft (module documentation).
fn draft_identity(state: &EngineState, programme: ProgrammeId) -> Option<ProgrammeIdentity> {
    fstp_creator::draft_view(&state.core, &state.creator, programme)
        .and_then(|v| ProgrammeIdentity::from_spec_json(&v.spec))
}

/// The public text `id`, or `None` when the store refuses it: it is not
/// a public text, or the store does not hold it.
async fn public_text<P: Seams>(call: &Call<'_, P>, id: TextId) -> Option<String> {
    let bytes = call
        .ports
        .texts()
        .get_public(crate::port::PublicTextRef(id.raw()))
        .await
        .ok()?;
    String::from_utf8(bytes).ok()
}

/// The public texts of `programme`: the title and the P-09 wording of
/// each call open now. A text the store refuses is left out, so its call
/// is not shown (`fstp_public::view`).
async fn texts_of<P: Seams>(
    call: &Call<'_, P>,
    programme: ProgrammeId,
    identity: ProgrammeIdentity,
    choices: &fstp_public::GrantChoices,
) -> PublicTexts {
    let mut ids: Vec<TextId> = Vec::new();
    // M9 lane P1: the approved texts of every grantee choice. The view
    // shows only those its filter admits.
    for (_, c) in choices.iter() {
        ids.extend([c.title, c.summary, c.grantee]);
    }
    for (_, v) in call.state.core.calls().iter() {
        if v.programme() != programme || !v.is_open_at(call.now) {
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
        if let Some(t) = public_text(call, id).await {
            let _ = found.insert(id, t);
        }
    }
    let mut texts = PublicTexts::new(identity);
    for (id, t) in &found {
        texts.insert(*id, t);
    }
    // I-53: the Guide of an open call is the one its publication stored,
    // with its corrigenda after it. A Guide that cannot be served with
    // its corrigenda is left out, so its page answers not found (I-51).
    for (id, v) in call.state.core.calls().iter() {
        if v.programme() != programme || !v.is_open_at(call.now) {
            continue;
        }
        if let Ok(g) = stored_guide(call, id).await {
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
/// followed by its corrigenda (I-51, I-53, Q37 C). Nothing is bound again.
/// The corrigenda are worded from the creator draft's compiled spec, so a
/// call with corrigenda and no draft has no Guide to serve, never one
/// without them.
pub(super) async fn stored_guide<P: Seams>(
    call: &Call<'_, P>,
    id: CallId,
) -> Result<PublicGuide, PublicError> {
    let core = &call.state.core;
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
    let compiled = fstp_engine::compose::draft_compiled(&call.state, programme)
        .ok_or(PublicError::NotFound)?;
    let mut found = BTreeMap::new();
    for r in fstp_public::guide::corrigenda_text_refs(&compiled) {
        if let Some(t) = public_text(call, r.id()).await {
            let _ = found.insert(r.id(), t);
        }
    }
    let texts = GuideTexts(found);
    let source = fstp_public::CorrigendaSource {
        compiled: &compiled,
        texts: &texts,
    };
    fstp_public::served_guide(core, id, Some(&source))
}

/// `calls.guide` (R-GA-01, I-53): the stored Guide of a published call,
/// with its corrigenda, its version and its digest. It answers not found
/// for a call with no stored Guide.
pub(super) async fn calls_guide<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
) -> Result<crate::model::StoredGuideView, ApiError> {
    let id = forms::id_param(&op.request, "call")
        .map(CallId::from_raw)
        .ok_or_else(not_public)?;
    let stored =
        fstp_domain::programme::stored_guide(&call.state.core, id).ok_or_else(not_public)?;
    let digest: String = stored
        .digest()
        .bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let g = stored_guide(call, id).await.map_err(|_| not_public())?;
    Ok(crate::model::StoredGuideView {
        call: id,
        version: g.version,
        digest,
        html: g.document,
    })
}

/// The `call` path parameter, as the view names a call.
fn call_param(op: &Op) -> Option<String> {
    forms::id_param(&op.request, "call").map(|c| c.to_string())
}

/// The refusal of a public error.
fn refused(e: PublicError) -> ApiError {
    match e {
        PublicError::NotFound | PublicError::FeedOff => not_public(),
        PublicError::Query(_) => ApiError::bad_request(forms::REQUEST_RULE),
        _ => ApiError::refused(ErrorCode::Unavailable, "R-PB-04"),
    }
}

/// The page of `kind`, for the web.
fn page_of(kind: PublicKind, call: Option<String>) -> Option<PublicPage> {
    Some(match kind {
        PublicKind::Programme => PublicPage::Programme,
        PublicKind::Call => PublicPage::Call(call?),
        PublicKind::Guide => PublicPage::Guide(call?),
        PublicKind::Funded => PublicPage::Funded,
        PublicKind::Finished => PublicPage::Finished,
        _ => return None,
    })
}

/// The tool part of `kind`.
fn part_of(kind: PublicKind, call: Option<String>) -> Option<PublicPart> {
    Some(match kind {
        PublicKind::Programme => PublicPart::Programme,
        PublicKind::ListOpenCalls => PublicPart::OpenCalls,
        PublicKind::Call => PublicPart::Call(call?),
        PublicKind::Guide => PublicPart::Guide(call?),
        PublicKind::Deadlines => PublicPart::Deadlines,
        PublicKind::Eligibility => PublicPart::Eligibility,
        PublicKind::Funded => PublicPart::Funded,
        PublicKind::Finished => PublicPart::Finished,
        _ => return None,
    })
}

/// The answer of `kind` over `view`.
fn answer(
    view: &PublicView,
    kind: PublicKind,
    call: Option<String>,
    web: bool,
    stylesheet: Option<String>,
) -> Result<PublicReply, PublicError> {
    if kind == PublicKind::Feed {
        return fstp_public::feed::feed(view).map(PublicReply::Json);
    }
    if web && let Some(page) = page_of(kind, call.clone()) {
        let chrome = Chrome { stylesheet };
        let doc = fstp_public::render_html(view, &page, &chrome)?;
        return Ok(PublicReply::Page(doc.as_str().to_owned()));
    }
    let part = part_of(kind, call).ok_or(PublicError::NotFound)?;
    let q = PublicQuery { part, search: None };
    fstp_public::tools::select(view, &q).map(PublicReply::Json)
}

/// One public operation (module documentation).
pub(super) async fn read<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    kind: PublicKind,
) -> Result<OpResult, ApiError> {
    let Some(slug) = op.request.get("slug").and_then(Value::as_str) else {
        return Err(call.refuse(ApiError::bad_request(forms::REQUEST_RULE)));
    };
    let Some((programme, identity)) = programme_of(&call.state, slug) else {
        return Err(call.refuse(not_public()));
    };
    let choices = fstp_public::grant_choices(&call.state.core);
    let texts = texts_of(call, programme, identity, &choices).await;
    let view =
        fstp_public::public_view_with(&call.state.core, programme, &texts, &choices, call.now)
            .map_err(|e| call.refuse(refused(e)))?;
    let web = call.caller.via() == Via::Web && !op.from_tool;
    let sheet = super::brand_of(&call.state).map(|b| format!("/brand/{}.css", b.digest));
    let reply =
        answer(&view, kind, call_param(op), web, sheet).map_err(|e| call.refuse(refused(e)))?;
    call.accept(ReadModel::Public(reply))
}
