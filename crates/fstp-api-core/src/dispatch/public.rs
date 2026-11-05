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
//! - No grantee choice record exists before M9, so the view is built with
//!   no choice and shows no grant (Q11).
//!
//! # Seams, each failing closed
//!
//! - The Guide page needs the data protection summary and the privacy
//!   statement address, which no port supplies yet, and the compiled spec
//!   of the programme, which only a creator draft holds. So no call page
//!   links a Guide in M4, and the Guide route answers not found.
//! - The public stylesheet: no asset of `/p` exists yet, so the pages
//!   carry no stylesheet.

use std::collections::BTreeMap;

use fstp_access::PublicKind;
use fstp_domain::id::{ProgrammeId, TextId};
use fstp_domain::programme::{ProgrammeStatus, programme_status};
use fstp_public::{
    Chrome, ProgrammeIdentity, PublicError, PublicPage, PublicPart, PublicQuery, PublicTexts,
    PublicView,
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
) -> PublicTexts {
    let mut ids: Vec<TextId> = Vec::new();
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
    texts
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
) -> Result<PublicReply, PublicError> {
    if kind == PublicKind::Feed {
        return fstp_public::feed::feed(view).map(PublicReply::Json);
    }
    if web && let Some(page) = page_of(kind, call.clone()) {
        let chrome = Chrome { stylesheet: None };
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
    let texts = texts_of(call, programme, identity).await;
    let view = fstp_public::public_view(&call.state.core, programme, &texts, call.now)
        .map_err(|e| call.refuse(refused(e)))?;
    let web = call.caller.via() == Via::Web && !op.from_tool;
    let reply = answer(&view, kind, call_param(op), web).map_err(|e| call.refuse(refused(e)))?;
    call.accept(ReadModel::Public(reply))
}
