//! The published Guide of a call (R-GA-01, I-51, I-52, I-53; M4 design
//! section 3.10).
//!
//! [`published_guide`] binds the Guide template from the core state, never
//! from the policy of the compiled spec the caller passes:
//!
//! - the frozen parameters come from the call's frozen values (I-12);
//! - P-05 and P-13 come from the call's publication snapshot
//!   (`policy.snapshot()`), never the live values (NOTE 7);
//! - every other live parameter the template shows, such as P-36, P-41,
//!   P-57 and P-67, comes from the programme's head policy in the core
//!   state.
//!
//! The caller's spec gives only the programme artefacts: the identity,
//! the narratives and the class descriptions. So an edit the caller's
//! spec carries leaves the Guide bytes unchanged (I-51). The call record
//! comes from the core state, and the version is 1 in M4.
//!
//! # The stored Guide (I-53)
//!
//! A live parameter other than P-05 and P-13 has no publication snapshot
//! (NOTE 7 names only those two). A later policy version that changes
//! P-41, say, would change the bytes a second binding gives. So this
//! function is the Guide at publication only: its bytes are stored with
//! `GuidePublished { digest }` (design section 3.10) and the public pages
//! serve that stored [`PublicGuide`] through `PublicTexts::insert_guide`.
//! No public path binds a Guide per request. The engine stores the
//! canonical document and the page in the publication entry
//! (`fstp_engine::compose`), and [`served_guide`] serves that page with
//! the call's corrigenda after it (Q37 C).
//!
//! It refuses, before binding, a template that lacks a required section,
//! with [`PublicError::GuideSectionMissing`] naming the first one in the
//! order of the specification's table (I-52). A placeholder that does not
//! resolve is [`PublicError::Guide`] with its `Unresolved` key (I-51).

use fstp_domain::State;
use fstp_domain::id::CallId;
use fstp_domain::policy::LiveSnapshot;
use fstp_guide::{Corrigendum, PublicationError, RenderedGuide, StoredTexts};
use fstp_programme::Compiled;

use crate::PublicError;
use crate::view::PublicGuide;

pub use fstp_guide::GuideSource;

/// The Guide version of every published call in M4. A corrigendum is a
/// numbered entry of the call's effective-limits record (Q37 C), so the
/// first Guide is the only one.
pub const GUIDE_VERSION: u32 = fstp_domain::programme::GUIDE_VERSION;

/// The Guide of the published call `call`, rendered (module
/// documentation). The engine takes its canonical document and page at
/// publication, in the publication entry, and stores both with their
/// digest. A call the state does not hold as published is
/// [`PublicError::NotFound`].
pub fn publication_guide(
    core: &State,
    call: CallId,
    source: &GuideSource<'_>,
) -> Result<RenderedGuide, PublicError> {
    fstp_guide::publication_guide(core, call, source).map_err(|e| match e {
        PublicationError::NotPublished => PublicError::NotFound,
        PublicationError::SectionMissing(s) => PublicError::GuideSectionMissing(s),
        PublicationError::Guide(g) => PublicError::Guide(g),
    })
}

/// The Guide of the published call `call` at publication, as a
/// [`PublicGuide`] (module documentation).
pub fn published_guide(
    core: &State,
    call: CallId,
    source: &GuideSource<'_>,
) -> Result<PublicGuide, PublicError> {
    let rendered = publication_guide(core, call, source)?;
    Ok(PublicGuide {
        version: GUIDE_VERSION,
        document: rendered.html().as_str().to_owned(),
    })
}

/// What the corrigenda of a published call are worded from: the
/// programme's compiled spec, for the descriptions of the P-13 classes,
/// and the stored texts it names.
#[derive(Clone, Copy)]
pub struct CorrigendaSource<'a> {
    /// The compiled spec, as the creator holds it now.
    pub compiled: &'a Compiled,
    /// The stored narrative texts.
    pub texts: &'a dyn StoredTexts,
}

/// The corrigenda of the published call `call`, numbered from 1: one per
/// entry of its effective-limits record after publication, each stating
/// both limits in full (I-51, NOTE 7, O-52, Q37 C). A call with no record
/// is [`PublicError::NotFound`].
pub fn corrigenda(
    core: &State,
    call: CallId,
    source: &CorrigendaSource<'_>,
) -> Result<Vec<Corrigendum>, PublicError> {
    let limits =
        fstp_domain::programme::effective_limits(core, call).ok_or(PublicError::NotFound)?;
    limits
        .tightenings()
        .iter()
        .map(|t| {
            let snapshot = LiveSnapshot {
                p05: t.p05,
                p13: t.p13.clone(),
            };
            fstp_guide::corrigendum(source.compiled, source.texts, t.corrigendum, &snapshot)
                .map_err(PublicError::Guide)
        })
        .collect()
}

/// The Guide page of the published call `call` as its publication stored
/// it, followed by its corrigenda (I-51, I-53). Nothing is bound again:
/// the stored page is served byte for byte, and with corrigenda it stays
/// the prefix of the page.
///
/// A call with no stored Guide is [`PublicError::NotFound`]. A call with
/// corrigenda needs `source` to word them, and without it the page is
/// refused, never served without its corrigenda (I-51).
pub fn served_guide(
    core: &State,
    call: CallId,
    source: Option<&CorrigendaSource<'_>>,
) -> Result<PublicGuide, PublicError> {
    let stored = fstp_domain::programme::stored_guide(core, call).ok_or(PublicError::NotFound)?;
    let pending = fstp_domain::programme::effective_limits(core, call)
        .is_some_and(|l| !l.tightenings().is_empty());
    let list = match (pending, source) {
        (false, _) => Vec::new(),
        (true, Some(s)) => corrigenda(core, call, s)?,
        (true, None) => {
            return Err(PublicError::Guide(fstp_guide::GuideError::Html(
                "the corrigenda need the compiled spec",
            )));
        }
    };
    let document =
        fstp_guide::page_with_corrigenda(stored.page(), &list).map_err(PublicError::Guide)?;
    Ok(PublicGuide {
        version: stored.version(),
        document,
    })
}

/// The stored texts the corrigenda of a call may read from `compiled`:
/// the descriptions of the P-13 classes that are stored outside the
/// ledger (ADR-007). The caller reads each one as a public text.
pub fn corrigenda_text_refs(compiled: &Compiled) -> Vec<fstp_domain::id::TextRef> {
    compiled
        .artefacts
        .class_descriptions()
        .iter()
        .filter_map(|(_, n)| match n {
            fstp_programme::Narrative::Stored(s) => Some(s.text_ref()),
            fstp_programme::Narrative::Inline(_) => None,
        })
        .collect()
}
