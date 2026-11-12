//! The Guide of a published call at its publication (R-GA-01, I-51,
//! I-52; M4 design section 3.10).
//!
//! [`publication_guide`] binds the Guide template from the core state,
//! never from the policy of the compiled spec the caller passes:
//!
//! - the frozen parameters come from the call's frozen values (I-12);
//! - P-05 and P-13 come from the call's publication snapshot, never the
//!   live values (NOTE 7);
//! - every other live parameter the template shows comes from the
//!   programme's head policy in the core state.
//!
//! The caller's spec gives only the programme artefacts. The engine calls
//! it in the publication entry and stores the result (I-53), so no later
//! binding reaches a reader. It recomputes the template's completeness
//! first (I-52).

use fstp_domain::State;
use fstp_domain::id::CallId;
use fstp_domain::programme::{CallStatus, GUIDE_VERSION};
use fstp_programme::Compiled;

use crate::{GuideCall, GuideError, GuideInputs, RenderedGuide, StoredTexts, Template};

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
    /// Whether the cell has a pre-check provider (Q38,
    /// [`GuideInputs::precheck_available`]).
    pub precheck_available: bool,
}

/// Why no Guide was bound at publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationError {
    /// The state does not hold the call as published.
    NotPublished,
    /// The template lacks this required section (I-52).
    SectionMissing(&'static str),
    /// The Guide did not bind or render (I-51).
    Guide(GuideError),
}

/// The Guide of the published call `call` (module documentation).
pub fn publication_guide(
    core: &State,
    call: CallId,
    source: &GuideSource<'_>,
) -> Result<RenderedGuide, PublicationError> {
    let view = fstp_domain::programme::call(core, call).ok_or(PublicationError::NotPublished)?;
    if view.status() != CallStatus::Published {
        return Err(PublicationError::NotPublished);
    }
    let frozen = view.frozen().ok_or(PublicationError::NotPublished)?;
    // I-52: the completeness is recomputed when the Guide is generated.
    if let Some(first) = crate::missing_sections(source.template).first() {
        return Err(PublicationError::SectionMissing(first));
    }
    let head =
        fstp_domain::policy::head(core, view.programme()).ok_or(PublicationError::NotPublished)?;
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
        precheck_available: source.precheck_available,
    };
    let bound = crate::bind(source.template, &inputs).map_err(PublicationError::Guide)?;
    crate::render(&bound).map_err(PublicationError::Guide)
}
