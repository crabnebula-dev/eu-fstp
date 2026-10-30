//! Independent review of the Q6 marker exemption (`profile.rs`; I-66,
//! `LegalWordingPending`).
//!
//! Every text is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_guide::{HORIZON_EUROPE, ProfileError, ProfileFiles, ProfileSource};

/// A test source over one template text.
struct Over(String);

impl ProfileSource for Over {
    fn files(&self, _name: &str) -> Result<ProfileFiles<'_>, ProfileError> {
        Ok(ProfileFiles {
            guide: self.0.as_bytes(),
        })
    }
}

/// I-66, Q6 reproducer: the exemption for a code span of the marker
/// reaches up to the first numbered heading, but the template header
/// that is never rendered ends at the first thematic break. A section
/// between the two is rendered in the Guide, so a code span of the marker
/// there is a marker like any other. Today the profile counts as approved
/// and `LegalWordingPending` does not fail.
#[test]
fn review_invariants_rendered_code_span_marker_before_first_numbered_section() {
    let text = "# T\n\nSections marked `TODO(legal)` need approved wording.\n\n---\n\n\
## Grant agreement duties\n\nYou accept the duties `TODO(legal)` of {{action.acronym}}.\n\n\
## 9. Financial support to third parties\n\nText.\n\n\
## 10. Contract and payments\n\nPaid in two parts.\n\n\
## 11. Visibility and publication\n\nWorded.\n";
    // The section is in the rendered body: a placeholder in the template
    // header is refused, and this one is accepted.
    let template = fstp_guide::parse_template(text.as_bytes())
        .unwrap_or_else(|e| panic!("the template does not parse: {e}"));
    assert!(template.placeholders().contains(&"action.acronym"));
    let p = Over(text.to_owned()).profile(HORIZON_EUROPE).unwrap();
    assert!(
        p.legal_wording_pending(),
        "a rendered TODO(legal) code span counts as approved wording"
    );
}
