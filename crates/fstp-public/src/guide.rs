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
//! No public path binds a Guide per request. Storing the bytes in the
//! publication entry is the engine's publication seam (`fstp-engine`
//! `compose`), still a stub, so no cell serves a Guide in M4.
//!
//! It refuses, before binding, a template that lacks a required section,
//! with [`PublicError::GuideSectionMissing`] naming the first one in the
//! order of the specification's table (I-52). A placeholder that does not
//! resolve is [`PublicError::Guide`] with its `Unresolved` key (I-51).

use fstp_domain::State;
use fstp_domain::id::CallId;
use fstp_domain::programme::CallStatus;
use fstp_guide::{GuideCall, GuideInputs, StoredTexts, Template};
use fstp_programme::Compiled;

use crate::PublicError;
use crate::view::PublicGuide;

/// What the Guide of a published call is bound from, besides the core
/// state.
#[derive(Clone, Copy)]
pub struct GuideSource<'a> {
    /// The parsed template of the programme's funder profile.
    pub template: &'a Template,
    /// The programme's compiled spec, as the creator holds it. Only its
    /// artefacts are read: its frozen and live values give way to the
    /// core state.
    pub compiled: &'a Compiled,
    /// The call's public identifier.
    pub identifier: &'a str,
    /// The `https:` address applicants create an account on.
    pub platform_url: &'a str,
    /// The data protection summary, `{{gdpr.notice_summary}}`.
    pub data_protection_summary: Option<&'a str>,
    /// The funder's privacy statement address.
    pub privacy_statement_url: Option<&'a str>,
    /// The stored narrative texts.
    pub texts: &'a dyn StoredTexts,
}

/// The Guide version of every published call in M4. A corrigendum is its
/// own record kind (Q37), so the first Guide is the only one.
pub const GUIDE_VERSION: u32 = 1;

/// The Guide of the published call `call` (module documentation). A call
/// the state does not hold as published is [`PublicError::NotFound`].
pub fn published_guide(
    core: &State,
    call: CallId,
    source: &GuideSource<'_>,
) -> Result<PublicGuide, PublicError> {
    let view = fstp_domain::programme::call(core, call).ok_or(PublicError::NotFound)?;
    if view.status() != CallStatus::Published {
        return Err(PublicError::NotFound);
    }
    let frozen = view.frozen().ok_or(PublicError::NotFound)?;
    // I-52: the completeness is recomputed when the Guide is generated.
    if let Some(first) = fstp_guide::missing_sections(source.template).first() {
        return Err(PublicError::GuideSectionMissing(first));
    }
    // R-GA-01, I-12: the frozen values of the call stand in for the
    // spec's frozen parameters, so a later draft edit never reaches it.
    // I-51: the live values come from the core head, never the caller's
    // spec (module documentation).
    let head = fstp_domain::policy::head(core, view.programme()).ok_or(PublicError::NotFound)?;
    let mut compiled = source.compiled.clone();
    compiled.policy.frozen = frozen.values().clone();
    compiled.policy.live = head.live.clone();
    let record = GuideCall::from_view(source.identifier, view);
    let inputs = GuideInputs {
        compiled: &compiled,
        // NOTE 7: P-05 and P-13 from the publication snapshot.
        publication: Some(frozen.snapshot()),
        call: &record,
        guide_version: GUIDE_VERSION,
        platform_url: source.platform_url,
        data_protection_summary: source.data_protection_summary,
        privacy_statement_url: source.privacy_statement_url,
        texts: source.texts,
    };
    let bound = fstp_guide::bind(source.template, &inputs).map_err(PublicError::Guide)?;
    let rendered = fstp_guide::render(&bound).map_err(PublicError::Guide)?;
    Ok(PublicGuide {
        version: GUIDE_VERSION,
        document: rendered.html().clone(),
    })
}
