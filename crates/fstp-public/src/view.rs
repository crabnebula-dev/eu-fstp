//! The public view and its only constructor (I-41, I-42, I-43, P-54).

use fstp_domain::State;
use fstp_domain::id::ProgrammeId;
use fstp_domain::time::Timestamp;

use crate::PublicError;

/// Everything a public page, the feed or a public tool may show.
///
/// W0 placeholder with no fields. Lane W2c writes the designed fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicView {
    _w0: (),
}

/// Builds the public view of one programme from the core state. The design
/// makes this total. The stub returns a `Result`, so it never answers with
/// a made-up view.
pub fn public_view(
    core: &State,
    programme: ProgrammeId,
    now: Timestamp,
) -> Result<PublicView, PublicError> {
    let _ = (core, programme, now);
    Err(PublicError::NotImplemented("fstp_public::public_view"))
}
